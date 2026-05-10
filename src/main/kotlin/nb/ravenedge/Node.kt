package nb.ravenedge

import io.netty.bootstrap.Bootstrap
import io.netty.buffer.Unpooled
import io.netty.channel.*
import io.netty.channel.nio.NioEventLoopGroup
import io.netty.channel.socket.DatagramPacket
import io.netty.channel.socket.nio.NioDatagramChannel
import kotlinx.coroutines.*
import org.slf4j.LoggerFactory
import java.io.File
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap

import com.google.common.collect.ImmutableSet
import com.google.common.collect.Sets
import com.google.common.primitives.UnsignedBytes

// Stats Dumper
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.lang.management.ManagementFactory
import kotlin.math.log
import kotlin.math.pow

// Native transports
import io.netty.channel.epoll.Epoll
import io.netty.channel.epoll.EpollDatagramChannel
import io.netty.channel.epoll.EpollEventLoopGroup
import io.netty.channel.uring.IoUring
import io.netty.channel.uring.IoUringDatagramChannel
import io.netty.channel.uring.IoUringIoHandler
import io.netty.channel.MultiThreadIoEventLoopGroup

class Node(
    private val ifaceConfig: InterfaceConfig,
    peerConfigs: List<PeerConfig>,
    val device: TunDevice,
    private val interfaceName: String,
    private val printStats: Boolean
) {
    private val logger = LoggerFactory.getLogger(Node::class.java)
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // ────── NATIVE EVENT LOOP ──────
    private var eventLoopGroup: EventLoopGroup? = null
    private var channel: Channel? = null

    private val peersByPublicKey = ConcurrentHashMap<Key, Peer>()
    private val peersBySessionId = ConcurrentHashMap<Int, Peer>()
    private val routingTable = RoutingTable<Peer>()
    private val secureRandom = SecureRandom()

    private val serverPrivateKey = Key.fromBase64(ifaceConfig.privateKey)
    private val serverPublicKey = privateToPublicKey(serverPrivateKey)
    val cookieGenerator = CookieGenerator(serverPublicKey)

    init {
        logger.info("Initializing Raven Edge Node...")
        reloadPeers(peerConfigs) // Initial load
    }

    suspend fun start() {
        startUdpServer()
        startTunReader()
        startPeerTimers()
        startStatsDumper()
        scope.coroutineContext[Job]?.join()
    }

    suspend fun stop() {
        logger.info("Stopping Node...")
        peersByPublicKey.values.forEach { it.stop() }
        device.down() // unblocks the TUN reader before cancelling the coroutine scope
        scope.cancel()
        channel?.close()?.awaitUninterruptibly()
        eventLoopGroup?.shutdownGracefully()?.awaitUninterruptibly()
    }

    // ==========================================
    // NATIVE EVENT LOOP
    // ==========================================
    private fun createNativeEventLoopGroup(): EventLoopGroup {
        val os = System.getProperty("os.name").lowercase()

        if (!os.contains("linux")) {
            logger.info("🌍 Non-Linux OS → using plain Java NIO")
            return NioEventLoopGroup()
        }

        if (IoUring.isAvailable()) {
            logger.info("🚀 Using native io_uring transport (best performance)")
            return MultiThreadIoEventLoopGroup(IoUringIoHandler.newFactory())
        }

        if (Epoll.isAvailable()) {
            logger.info("🚀 Using native epoll transport")
            return EpollEventLoopGroup()
        }

        logger.info("⚠️ Native transports unavailable → falling back to Java NIO")
        return NioEventLoopGroup()
    }

    private fun getNativeChannelClass(group: EventLoopGroup): Class<out Channel> = when (group) {
        is MultiThreadIoEventLoopGroup -> IoUringDatagramChannel::class.java
        is EpollEventLoopGroup         -> EpollDatagramChannel::class.java
        else                           -> NioDatagramChannel::class.java
    }

    private fun startUdpServer() {
        eventLoopGroup = createNativeEventLoopGroup()

        val bootstrap = Bootstrap()
            .group(eventLoopGroup)
            .channel(getNativeChannelClass(eventLoopGroup!!))
            .handler(object : SimpleChannelInboundHandler<DatagramPacket>() {
                override fun channelRead0(ctx: ChannelHandlerContext, msg: DatagramPacket) {
                    val data = ByteArray(msg.content().readableBytes())
                    msg.content().readBytes(data)
                    handleUdpPacket(data, msg.sender())
                }
            })

        this.channel = bootstrap.bind(ifaceConfig.listenPort ?: 0).sync().channel()
        logger.info("✅ UDP Server listening on port ${ifaceConfig.listenPort ?: "dynamic"}")
    }

    // ==========================================
    // DYNAMIC PEER MANAGEMENT API
    // ==========================================
    // ToDo Expose it later??
    fun addPeer(config: PeerConfig): Boolean {
        val key = Key.fromBase64(config.publicKey)
        if (peersByPublicKey.containsKey(key)) {
            logger.warn("Attempted to add existing peer: ${key.toBase64().take(8)}")
            return false
        }

        val peer = Peer(scope, this, serverPrivateKey, serverPublicKey, config, ifaceConfig.amnezia, ::sendUdpPacket) { packet ->
            device.writePacket(packet)
        }
        
        peersByPublicKey[key] = peer
        config.allowedIPs.forEach { routingTable.insert(it, peer) }
        logger.info("Added new peer: ${key.toBase64().take(8)}")
        return true
    }

    fun removePeer(publicKeyBase64: String): Boolean {
        val key = Key.fromBase64(publicKeyBase64)
        val peer = peersByPublicKey.remove(key) ?: return false

        peer.peerConfig.allowedIPs.forEach { routingTable.remove(it) }
        peer.getActiveSessionIds().forEach { removeSession(it) }
        peer.stop()

        logger.info("Removed peer: ${key.toBase64().take(8)}")
        return true
    }

    fun updatePeer(config: PeerConfig): Boolean {
        val key = Key.fromBase64(config.publicKey)
        val existingPeer = peersByPublicKey[key] ?: return false

        val oldIps = existingPeer.peerConfig.allowedIPs.toSet()
        val newIps = config.allowedIPs.toSet()
        (oldIps - newIps).forEach { routingTable.remove(it) }
        (newIps - oldIps).forEach { routingTable.insert(it, existingPeer) }

        existingPeer.updateConfig(config)
        logger.info("Updated configuration for peer: ${key.toBase64().take(8)}")
        return true
    }

fun reloadPeers(newPeerConfigs: List<PeerConfig>) {
        val newKeys = ImmutableSet.copyOf<Key>(
            newPeerConfigs.map { Key.fromBase64(it.publicKey) }
        )

        val currentKeys = ImmutableSet.copyOf<Key>(peersByPublicKey.keys)

        // Remove peers that disappeared from the config
        Sets.difference(currentKeys, newKeys).forEach { key ->
            removePeer(key.toBase64())
        }

        // Add new peers or update existing ones
        newPeerConfigs.forEach { config ->
            val key = Key.fromBase64(config.publicKey)
            if (!currentKeys.contains(key)) {
                addPeer(config)
            } else {
                updatePeer(config)
            }
        }
    }

    // ==========================================
    // CORE NETWORK HANDLING
    // ==========================================
    fun validatePacketSource(sourceIp: InetAddress, peer: Peer): Boolean {
        return routingTable.findBestMatch(sourceIp) == peer
    }

    private fun formatBytes(bytes: Long): String {
        if (bytes < 1000) return "$bytes B"
        val exp = (log(bytes.toDouble(), 1000.0)).toInt()
        val prefix = "KMGTPE"[exp - 1]
        return String.format("%d B (%.2f %sB)", bytes, bytes / 1000.0.pow(exp.toDouble()), prefix)
    }

    private val dateFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault())
    private fun formatHandshake(timestamp: Long): String {
        if (timestamp == 0L) return "None"
        val absoluteTime = dateFormatter.format(Instant.ofEpochMilli(timestamp))
        val agoSeconds = (System.currentTimeMillis() - timestamp) / 1000
        val relativeTime = when {
            agoSeconds < 60 -> "$agoSeconds seconds ago"
            agoSeconds < 3600 -> "${agoSeconds / 60} minutes ago"
            else -> "${agoSeconds / 3600} hours, ${(agoSeconds % 3600) / 60} minutes ago"
        }
        return "$absoluteTime ($relativeTime)"
    }

    private fun startStatsDumper() = scope.launch {
        if (!printStats) return@launch

        val statsFile = File("stats.$interfaceName.txt")
        val osBean = ManagementFactory.getOperatingSystemMXBean()

        while (isActive) {
            delay(10_000)
            val sb = StringBuilder()
            sb.append("[Interface]\n")
            sb.append("PublicKey = ${serverPublicKey.toBase64()}\n")
            sb.append("ListenPort = ${ifaceConfig.listenPort ?: "Dynamic"}\n")
            val addresses = ifaceConfig.addresses.joinToString(", ") { "${it.address.hostAddress}/${it.prefix}" }
            sb.append("Address = ${if (addresses.isNotEmpty()) addresses else "None"}\n")
            sb.append("MTU = ${ifaceConfig.mtu}\n")
            val loadAvg = osBean.systemLoadAverage
            val loadStr = if (loadAvg >= 0.0) String.format("%.2f", loadAvg) else "N/A"
            sb.append("Workers = ${Thread.activeCount()} Active Threads\n")
            sb.append("Average Load = $loadStr\n\n")

            peersByPublicKey.forEach { (_, peer) ->
                sb.append("[Peer]\n")
                sb.append("PublicKey = ${peer.peerConfig.publicKey}\n")
                if (peer.peerConfig.presharedKey != null) sb.append("PresharedKey = hidden\n")
                val allowedIps = peer.peerConfig.allowedIPs.joinToString(", ") { "${it.address.hostAddress}/${it.prefix}" }
                sb.append("AllowedIPs = ${if (allowedIps.isNotEmpty()) allowedIps else "None"}\n")
                val endpointStr = peer.endpoint?.let { "${it.address.hostAddress}:${it.port}" } ?: "Unknown"
                sb.append("Endpoint = $endpointStr\n")
                val rx = peer.rxBytes.get()
                val tx = peer.txBytes.get()
                sb.append("Transfer = ${formatBytes(rx)} received, ${formatBytes(tx)} sent\n")
                sb.append("LastHandshake = ${formatHandshake(peer.lastHandshakeTime)}\n\n")
            }
            try { statsFile.writeText(sb.toString()) } catch (e: Exception) {}
        }
    }

private fun leU32At(data: ByteArray, offset: Int): Long {
    if (data.size < offset + 4) return -1L
    return ByteBuffer.wrap(data, offset, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
}

private fun leI32At(data: ByteArray, offset: Int): Int? {
    if (data.size < offset + 4) return null
    return ByteBuffer.wrap(data, offset, 4).order(ByteOrder.LITTLE_ENDIAN).int
}

private fun sendWithPadding(msg: Message, paddingSize: Int, target: InetSocketAddress) {
    val payload = msg.toBytes()
    val packet = if (paddingSize > 0) {
        ByteArray(paddingSize + payload.size).also { out ->
            secureRandom.nextBytes(out)
            System.arraycopy(payload, 0, out, paddingSize, payload.size)
        }
    } else {
        payload
    }
    sendUdpPacket(packet, target)
}

private fun dispatchSessionPacket(
    peer: Peer?,
    sessionIndex: Int,
    packetKind: String,
    sender: InetSocketAddress,
    messageFactory: () -> Message
) {
    if (peer == null) {
        if (logger.isTraceEnabled) logger.trace("Dropped {} packet for unknown session index {} from {}", packetKind, sessionIndex, sender)
        return
    }
    peer.onUdpPacket(messageFactory(), sender)
}

/**
 * Handles incoming UDP packets (WG and obfuscated AmneziaWG).
 * Cheap shape/header/session checks happen before message objects are allocated.
 */
private fun handleUdpPacket(data: ByteArray, sender: InetSocketAddress) {
    val len = data.size
    if (len < 4) {
        if (logger.isTraceEnabled) logger.trace("Dropped too-short UDP packet len={} from={}", len, sender)
        return
    }

    //ToDo Remove sha1 here? Who even will use it??
    if (logger.isTraceEnabled) {
        logger.trace("UDP RX pre-crypto sha1={} len={} from={}", PacketFingerprint.sha1Hex(data, 0, len), len, sender)
    }

    // === Standard WireGuard packet detection (type + 3 zero bytes) ===
    if (UnsignedBytes.toInt(data[1]) == 0 &&
        UnsignedBytes.toInt(data[2]) == 0 &&
        UnsignedBytes.toInt(data[3]) == 0) {

        when (UnsignedBytes.toInt(data[0])) {
            1 -> {
                if (len == 148) scope.launch { handleHandshakeInitiation(data, sender) }
                else if (logger.isTraceEnabled) logger.trace("Dropped WG initiation with invalid len={} from={}", len, sender)
            }
            2 -> {
                if (len == 92) {
                    val idx = leI32At(data, 4) ?: return
                    dispatchSessionPacket(peersBySessionId[idx], idx, "WG handshake response", sender) {
                        HandshakeResponseMessage.fromBytes(data)
                    }
                } else if (logger.isTraceEnabled) logger.trace("Dropped WG response with invalid len={} from={}", len, sender)
            }
            3 -> {
                if (len == 64) {
                    val idx = leI32At(data, 4) ?: return
                    dispatchSessionPacket(peersBySessionId[idx], idx, "WG cookie reply", sender) {
                        CookieReplyMessage.fromBytes(data)
                    }
                } else if (logger.isTraceEnabled) logger.trace("Dropped WG cookie with invalid len={} from={}", len, sender)
            }
            4 -> {
                if (len >= 16) {
                    val idx = leI32At(data, 4) ?: return
                    dispatchSessionPacket(peersBySessionId[idx], idx, "WG data", sender) {
                        DataMessage.fromBytes(data)
                    }
                } else if (logger.isTraceEnabled) logger.trace("Dropped WG data with invalid len={} from={}", len, sender)
            }
            else -> if (logger.isTraceEnabled) logger.trace("Dropped WG-shaped packet with unknown type={} len={} from={}", UnsignedBytes.toInt(data[0]), len, sender)
        }
        return
    }

    // === AmneziaWG junk-header detection ===
    val am = ifaceConfig.amnezia
    when {
        len == 148 + am.s1 && am.h1.contains(leU32At(data, am.s1)) -> {
            val payload = data.copyOfRange(am.s1, len)
            scope.launch { handleHandshakeInitiation(payload, sender) }
        }
        len == 92 + am.s2 && am.h2.contains(leU32At(data, am.s2)) -> {
            val idx = leI32At(data, am.s2 + 4) ?: return
            val peer = peersBySessionId[idx]
            dispatchSessionPacket(peer, idx, "AWG handshake response", sender) {
                HandshakeResponseMessage.fromBytes(data.copyOfRange(am.s2, len))
            }
        }
        len == 64 + am.s3 && am.h3.contains(leU32At(data, am.s3)) -> {
            val idx = leI32At(data, am.s3 + 4) ?: return
            val peer = peersBySessionId[idx]
            dispatchSessionPacket(peer, idx, "AWG cookie reply", sender) {
                CookieReplyMessage.fromBytes(data.copyOfRange(am.s3, len))
            }
        }
        len >= 16 + am.s4 && am.h4.contains(leU32At(data, am.s4)) -> {
            val idx = leI32At(data, am.s4 + 4) ?: return
            val peer = peersBySessionId[idx]
            dispatchSessionPacket(peer, idx, "AWG data", sender) {
                DataMessage.fromBytes(data.copyOfRange(am.s4, len))
            }
        }
        else -> if (logger.isTraceEnabled) logger.trace("Dropped non-WG/non-AWG UDP packet len={} from={}", len, sender)
    }
}

    private suspend fun handleHandshakeInitiation(payload: ByteArray, sender: InetSocketAddress) {
        val msg = HandshakeInitiationMessage.fromBytes(payload)
        val mac1Key = hash(LABEL_MAC1, serverPublicKey.value)
        if (!constantTimeEquals(mac(mac1Key, msg.bytesForMac1()), msg.mac1)) {
            if (logger.isTraceEnabled) logger.trace("Dropped handshake initiation with invalid mac1 from {}", sender)
            return
        }

        val senderAddress = sender.address?.address ?: return
        if (isUnderLoad() && !cookieGenerator.consumeCookie(msg, senderAddress)) {
            val reply = cookieGenerator.createCookieReply(msg, senderAddress)
            reply.wireHeader = ifaceConfig.amnezia.h3.random()
            sendWithPadding(reply, ifaceConfig.amnezia.s3, sender)
            logger.debug("Sent early cookie challenge to {} before static-key decrypt", sender)
            return
        }

        val peer = findPeerFromInitiation(msg)
        if (peer == null) {
            if (logger.isTraceEnabled) logger.trace("Dropped handshake initiation from unknown peer after mac1 validation: {}", sender)
            return
        }
        peer.onUdpPacket(msg, sender)
    }

    private fun findPeerFromInitiation(msg: HandshakeInitiationMessage): Peer? {
        var chainingKey = hash(PROTOCOL_NAME)
        var currentHash = hash(chainingKey, IDENTIFIER)
        currentHash = hash(currentHash, serverPublicKey.value)
        currentHash = hash(currentHash, msg.unencryptedEphemeral.value)
        chainingKey = kdf1(chainingKey, msg.unencryptedEphemeral.value)
        val sharedSecret = x25519(serverPrivateKey, msg.unencryptedEphemeral)
        val (ck, key) = kdf2(chainingKey, sharedSecret)
        val decryptedStatic = Aead.chacha20Poly1305Decrypt(key, 0, msg.encryptedStatic, currentHash) ?: return null
        return peersByPublicKey[Key(decryptedStatic)]
    }

    private fun startTunReader() = scope.launch {
        while (isActive) {
            val packets = device.readBatch(64)
            for (packet in packets) {
                if (logger.isTraceEnabled) {
                    logger.trace("TUN RX pre-crypto sha1={} len={}", packet.sha1Hex(), packet.length)
                }
                val dest = IPPacketUtils.getDestinationAddress(packet.buffer, packet.length)
                if (dest == null) {
                    packet.release()
                    continue
                }

                val peer = routingTable.findBestMatch(dest)
                if (peer == null || !peer.onTunPacket(packet)) {
                    packet.release()
                }
                // Ownership is transferred to Peer.runOutboundLoop on successful enqueue.
            }
        }
    }

    private fun startPeerTimers() = scope.launch {
        while (isActive) {
            delay(1000)
            peersByPublicKey.values.forEach { it.tick() }
        }
    }

    fun registerSession(peer: Peer, keyPair: KeyPair) { peersBySessionId[keyPair.localIndex] = peer }
    fun removeSession(sessionId: Int) { peersBySessionId.remove(sessionId) }
    
    fun findAvailableIndex(): Int {
        while (true) {
            val index = secureRandom.nextInt(Int.MAX_VALUE)
            if (peersBySessionId.putIfAbsent(index, PeerDUMMY) == null) return index
        }
    }

    fun decryptCookie(msg: CookieReplyMessage, mac1: ByteArray, pubKey: Key): ByteArray? {
        val cookieKey = Key(hash(LABEL_COOKIE, pubKey.value))
        return Aead.xchacha20Poly1305Decrypt(cookieKey, msg.nonce, msg.encryptedCookie, mac1)
    }

    private fun sendUdpPacket(data: ByteArray, destination: InetSocketAddress) {
        channel?.writeAndFlush(DatagramPacket(Unpooled.wrappedBuffer(data), destination))
    }

    private val PeerDUMMY: Peer by lazy {
        val dummyPeerConfig = PeerConfig("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", null, emptyList(), null, null)
        Peer(scope, this, serverPrivateKey, serverPublicKey, dummyPeerConfig, ifaceConfig.amnezia, { _, _ -> }, {})
    } //It's Screaming >_< !1! //And I don't wanna replace this helper, NO WAY Steve!!! And you still owe me 500 Yen.

    private val osBean = ManagementFactory.getOperatingSystemMXBean()
    private val availableProcessors = Runtime.getRuntime().availableProcessors()

    fun isUnderLoad(): Boolean {
        val loadAvg = osBean.systemLoadAverage
        if (loadAvg < 0) return Thread.activeCount() > (availableProcessors * 10)
        return loadAvg > (availableProcessors * 0.9)
    }
}
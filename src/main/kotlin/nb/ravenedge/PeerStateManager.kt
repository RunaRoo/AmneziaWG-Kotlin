package nb.ravenedge

import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import org.slf4j.LoggerFactory
import java.net.InetSocketAddress
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicLong

class Peer(
    private val scope: CoroutineScope,
    private val node: Node,
    private val localStaticPrivate: Key,
    private val localStaticPublic: Key,
    @Volatile var peerConfig: PeerConfig,
    private val amConfig: AmneziaConfig,
    private val udpSender: (ByteArray, InetSocketAddress) -> Unit,
    private val tunWriter: suspend (PacketContainer) -> Unit
) {
    val publicKey: Key = Key.fromBase64(peerConfig.publicKey)
    private val logger = LoggerFactory.getLogger("Peer-${publicKey.toBase64().take(8)}")
    private val secureRandom = SecureRandom()

    @Volatile var endpoint: InetSocketAddress? = peerConfig.endpoint
    @Volatile private var keepaliveTimeoutMs: Long = (peerConfig.persistentKeepalive ?: 0) * 1000L
    @Volatile private var lastPacketReceivedTimestamp: Long = 0
    @Volatile var lastHandshakeTime: Long = 0L

    val rxBytes = AtomicLong(0L)
    val txBytes = AtomicLong(0L)

    private val noise = Noise(localStaticPrivate, localStaticPublic, publicKey, peerConfig.presharedKey?.let { Key.fromBase64(it) })

    private var currentKeyPair: KeyPair? = null
    private var nextKeyPair: KeyPair? = null
    private var pendingInitiation: PendingInitiation? = null
    private var latestRemoteInitiationTimestamp: ByteArray? = null

    private val lastHandshakeSentTimestamp = AtomicLong(0)
    private var isHandshakeInProgress = false

    private val mailbox = Channel<PeerEvent>(Channel.UNLIMITED)
    private val outboundQueue = Channel<PacketContainer>(2048)
    private var isRunning = true

    private val REKEY_AFTER_TIME_MS = 120_000L
    private val REJECT_AFTER_TIME_MS = 180_000L
    private val HANDSHAKE_TIMEOUT_MS = 5_000L
    private val MIN_HANDSHAKE_INTERVAL_MS = 1_000L

    init {
        logger.info("Initialized for endpoint ${endpoint ?: "dynamic (responder)"}")
        scope.launch { runActorLoop() }
        scope.launch { runOutboundLoop() }
        if (hasConfiguredEndpoint()) {
            mailbox.trySend(PeerEvent.InitHandshake)
        }
    }

    fun updateConfig(newConfig: PeerConfig) {
        this.peerConfig = newConfig
        if (newConfig.endpoint != null) {
            this.endpoint = newConfig.endpoint
        }
        this.keepaliveTimeoutMs = (newConfig.persistentKeepalive ?: 0) * 1000L
    }

    fun stop() {
        if (!isRunning) return
        isRunning = false
        cleanupPendingInitiation(removeReservedSession = true)
        mailbox.close()
        outboundQueue.close()
    }

    fun getActiveSessionIds(): List<Int> {
        return buildList {
            currentKeyPair?.let { add(it.localIndex) }
            nextKeyPair?.let { add(it.localIndex) }
            pendingInitiation?.let { add(it.localIndex) }
        }.distinct()
    }

    fun onUdpPacket(message: Message, sender: InetSocketAddress) {
        if (isRunning) mailbox.trySend(PeerEvent.UdpPacket(message, sender))
    }

    fun onTunPacket(packet: PacketContainer): Boolean {
        return isRunning && outboundQueue.trySend(packet).isSuccess
    }

    fun tick() {
        if (isRunning) mailbox.trySend(PeerEvent.Tick)
    }

    private fun hasConfiguredEndpoint(): Boolean = peerConfig.endpoint != null

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
        txBytes.addAndGet(packet.size.toLong())
        udpSender(packet, target)
    }

    private suspend fun runActorLoop() {
        for (event in mailbox) {
            try {
                when (event) {
                    is PeerEvent.UdpPacket -> handleUdpInternal(event.message, event.sender)
                    is PeerEvent.Tick -> handleTickInternal()
                    is PeerEvent.InitHandshake -> initiateHandshake()
                }
            } catch (e: Exception) {
                logger.error("Error in Peer actor loop", e)
            }
        }
    }

    private suspend fun runOutboundLoop() {
        for (packet in outboundQueue) {
            try {
                val kp = currentKeyPair
                if (kp == null) {
                    if (hasConfiguredEndpoint() && shouldInitiateHandshake(ProtocolClock.monotonicMillis())) {
                        mailbox.trySend(PeerEvent.InitHandshake)
                    }
                    continue
                }
                val now = ProtocolClock.monotonicMillis()
                if (hasConfiguredEndpoint() && now - kp.createdAt > REKEY_AFTER_TIME_MS) {
                    if (shouldInitiateHandshake(now)) mailbox.trySend(PeerEvent.InitHandshake)
                }
                val target = endpoint ?: continue

                if (logger.isTraceEnabled) {
                    logger.trace("TUN -> crypto sha1={} len={} peer={}", packet.sha1Hex(), packet.length, publicKey.toBase64().take(8))
                }
                val encryptedMsg = kp.encryptData(packet.buffer, 0, packet.length)
                encryptedMsg.wireHeader = amConfig.h4.random()
                sendWithPadding(encryptedMsg, amConfig.s4, target)
            } catch (e: Exception) {
                logger.error("Error in Peer outbound loop", e)
            } finally {
                packet.release()
            }
        }
    }

    private suspend fun handleUdpInternal(message: Message, sender: InetSocketAddress) {
        lastPacketReceivedTimestamp = ProtocolClock.monotonicMillis()
        when (message) {
            is HandshakeInitiationMessage -> {
                rxBytes.addAndGet((148 + amConfig.s1).toLong())
                onHandshakeInitiation(message, sender)
            }
            is HandshakeResponseMessage -> {
                rxBytes.addAndGet((92 + amConfig.s2).toLong())
                onHandshakeResponse(message, sender)
            }
            is CookieReplyMessage -> {
                rxBytes.addAndGet((64 + amConfig.s3).toLong())
                onCookieReply(message, sender)
            }
            is DataMessage -> {
                rxBytes.addAndGet((16 + message.encryptedData.size + amConfig.s4).toLong())
                onDataMessage(message, sender)
            }
        }
    }

    private suspend fun onDataMessage(msg: DataMessage, sender: InetSocketAddress) {
        val cur = currentKeyPair
        val next = nextKeyPair
        val matchingKeyPair = when (msg.receiverIndex) {
            cur?.localIndex -> cur
            next?.localIndex -> next
            else -> null
        } ?: return

        if (logger.isTraceEnabled) {
            logger.trace(
                "UDP DATA -> decrypt pre-crypto sha1={} encryptedLen={} counter={} peer={}",
                PacketFingerprint.sha1Hex(msg.encryptedData, 0, msg.encryptedData.size),
                msg.encryptedData.size,
                msg.counter,
                publicKey.toBase64().take(8)
            )
        }

        val decryptedPacket = matchingKeyPair.decryptDataToPacket(msg) ?: return
        if (logger.isTraceEnabled) {
            logger.trace("decrypt -> TUN sha1={} len={} peer={}", decryptedPacket.sha1Hex(), decryptedPacket.length, publicKey.toBase64().take(8))
        }
        var ownershipTransferred = false
        try {
            if (matchingKeyPair === next) {
                logger.info("Confirmed next session (Index ${next.localIndex}). Rotating keys.")
                currentKeyPair?.let { node.removeSession(it.localIndex) }
                currentKeyPair = next
                nextKeyPair = null
            }

            if (decryptedPacket.length > 0) {
                val sourceIp = IPPacketUtils.getSourceAddress(decryptedPacket.buffer, decryptedPacket.length)
                if (sourceIp != null && node.validatePacketSource(sourceIp, this)) {
                    maybeRoamTo(sender, "authenticated data")
                    ownershipTransferred = true
                    tunWriter(decryptedPacket)
                }
            } else {
                maybeRoamTo(sender, "authenticated keepalive")
            }
        } finally {
            if (!ownershipTransferred) decryptedPacket.release()
        }
    }

    private suspend fun onHandshakeInitiation(msg: HandshakeInitiationMessage, sender: InetSocketAddress) {
        if (node.cookieGenerator.consumeCookie(msg, sender.address.address)) {
            // valid under-load cookie MAC2
        } else if (node.isUnderLoad()) {
            val reply = node.cookieGenerator.createCookieReply(msg, sender.address.address)
            reply.wireHeader = amConfig.h3.random()
            sendWithPadding(reply, amConfig.s3, sender)
            return
        }

        val validation = validateAndDecryptInitiation(msg)
        val state = validation.state
        if (state == null) {
            logger.warn("Handshake initiation rejected: ${validation.error}")
            return
        }

        maybeRoamTo(sender, "authenticated initiation")
        latestRemoteInitiationTimestamp = validation.timestamp

        val (ephemeralPrivate, ephemeralPublic) = generateKeyPair()
        state.mixHash(ephemeralPublic.value)
        state.chainingKey = kdf1(state.chainingKey, ephemeralPublic.value)
        state.chainingKey = kdf2(state.chainingKey, x25519(ephemeralPrivate, msg.unencryptedEphemeral)).first
        state.chainingKey = kdf2(state.chainingKey, x25519(ephemeralPrivate, publicKey)).first

        val psk = peerConfig.presharedKey?.let { Key.fromBase64(it).value } ?: ByteArray(32)
        val (ck, tempKey, key) = kdf3(state.chainingKey, psk)
        state.chainingKey = ck
        state.mixHash(tempKey.value)

        val encryptedNothing = Aead.chacha20Poly1305Encrypt(key, 0, ByteArray(0), state.hash)
        state.mixHash(encryptedNothing)

        val (t1, t2) = kdf2(state.chainingKey, ByteArray(0))
        val remoteIndex = msg.senderIndex
        val localIndex = node.findAvailableIndex()
        val newKeyPair = KeyPair(t2, Key(t1), remoteIndex, localIndex)

        val response = HandshakeResponseMessage(
            localIndex,
            remoteIndex,
            ephemeralPublic,
            encryptedNothing,
            ByteArray(16),
            ByteArray(16),
            wireHeader = amConfig.h2.random()
        )
        response.mac1 = mac(hash(LABEL_MAC1, publicKey.value), response.bytesForMac1())

        if (nextKeyPair != null) node.removeSession(nextKeyPair!!.localIndex)
        node.registerSession(this, newKeyPair)
        nextKeyPair = newKeyPair

        sendWithPadding(response, amConfig.s2, sender)
        lastHandshakeTime = System.currentTimeMillis()
        logger.info("Sent Handshake Response. New Session: $localIndex")
    }

    private suspend fun onHandshakeResponse(msg: HandshakeResponseMessage, sender: InetSocketAddress) {
        val pending = pendingInitiation ?: return
        if (msg.receiverIndex != pending.localIndex) return
        if (!noise.isValidHandshakeResponseMac1(msg)) {
            logger.warn("Rejected handshake response with invalid mac1")
            return
        }

        val keyPair = noise.consumeHandshakeResponse(pending.secrets, msg) ?: return

        logger.info("Handshake completed. New session: ${keyPair.localIndex}")
        node.registerSession(this, keyPair)
        nextKeyPair = keyPair
        rotateKeys()
        cleanupPendingInitiation(removeReservedSession = false)
        isHandshakeInProgress = false
        lastHandshakeTime = System.currentTimeMillis()
        maybeRoamTo(sender, "authenticated handshake response")
    }

    private fun rotateKeys() {
        if (nextKeyPair != null) {
            currentKeyPair?.let { node.removeSession(it.localIndex) }
            currentKeyPair = nextKeyPair
            nextKeyPair = null
        }
    }

    private fun validateAndDecryptInitiation(msg: HandshakeInitiationMessage): InitiationValidationResult {
        val state = HandshakeState(hash(PROTOCOL_NAME), hash(hash(PROTOCOL_NAME), IDENTIFIER))
        state.mixHash(localStaticPublic.value)
        state.mixHash(msg.unencryptedEphemeral.value)
        state.chainingKey = kdf1(state.chainingKey, msg.unencryptedEphemeral.value)

        val sharedSecret1 = x25519(localStaticPrivate, msg.unencryptedEphemeral)
        val (ck1, key1) = kdf2(state.chainingKey, sharedSecret1)
        state.chainingKey = ck1

        val decryptedStatic = Aead.chacha20Poly1305Decrypt(key1, 0, msg.encryptedStatic, state.hash)
            ?: return InitiationValidationResult(null, null, "Decryption failed (static)")
        if (!constantTimeEquals(decryptedStatic, publicKey.value)) {
            return InitiationValidationResult(null, null, "Wrong static key")
        }
        state.mixHash(msg.encryptedStatic)

        val sharedSecret2 = x25519(localStaticPrivate, publicKey)
        val (ck2, key2) = kdf2(state.chainingKey, sharedSecret2)
        state.chainingKey = ck2

        val timestamp = Aead.chacha20Poly1305Decrypt(key2, 0, msg.encryptedTimestamp, state.hash)
            ?: return InitiationValidationResult(null, null, "Decryption failed (timestamp)")
        state.mixHash(msg.encryptedTimestamp)

        val latest = latestRemoteInitiationTimestamp
        if (latest != null && compareUnsignedByteArrays(timestamp, latest) <= 0) {
            return InitiationValidationResult(null, null, "Replay/stale initiation timestamp")
        }

        return InitiationValidationResult(state, timestamp, null)
    }

    private suspend fun onCookieReply(msg: CookieReplyMessage, sender: InetSocketAddress) {
        val pending = pendingInitiation ?: return
        if (msg.receiverIndex != pending.localIndex) return

        val decryptedCookie = node.decryptCookie(msg, pending.message.mac1, publicKey) ?: return
        if (pending.cookieRetryAttempted) return

        val newTarget = sender
        if (newTarget != pending.targetEndpoint) {
            logger.info("Cookie reply arrived from $newTarget instead of ${pending.targetEndpoint}; retrying there")
            pendingInitiation = pending.copy(targetEndpoint = newTarget, cookieRetryAttempted = true)
        } else {
            pendingInitiation = pending.copy(cookieRetryAttempted = true)
        }
        resendPendingInitiationWithCookie(decryptedCookie)
    }

    private suspend fun initiateHandshake() {
        val target = endpoint ?: return
        val now = ProtocolClock.monotonicMillis()

        val lastSent = lastHandshakeSentTimestamp.get()
        if (isHandshakeInProgress && lastSent != 0L && (now - lastSent < HANDSHAKE_TIMEOUT_MS)) return
        if (lastSent != 0L && now - lastSent < MIN_HANDSHAKE_INTERVAL_MS) return

        cleanupPendingInitiation(removeReservedSession = true)

        lastHandshakeSentTimestamp.set(now)
        isHandshakeInProgress = true

        if (!amConfig.i1.isNullOrBlank()) {
            val iPackets = listOfNotNull(amConfig.i1, amConfig.i2, amConfig.i3, amConfig.i4, amConfig.i5)
            for (pattern in iPackets) {
                try {
                    val payload = CpsParser.parse(pattern)
                    txBytes.addAndGet(payload.size.toLong())
                    udpSender(payload, target)
                } catch (e: Exception) {
                    logger.error("CPS error: $pattern", e)
                }
            }
        }

        if (amConfig.jc > 0) {
            for (i in 0 until amConfig.jc) {
                val size = (amConfig.jmin..amConfig.jmax).random()
                val junkData = ByteArray(size).apply { secureRandom.nextBytes(this) }
                txBytes.addAndGet(junkData.size.toLong())
                udpSender(junkData, target)
            }
        }

        val localIndex = node.findAvailableIndex()
        node.registerSession(this, KeyPair(Key(ByteArray(32)), Key(ByteArray(32)), 0, localIndex))

        val (msg, secrets) = noise.createHandshakeInitiation(localIndex, amConfig.h1.random())

        pendingInitiation = PendingInitiation(
            localIndex = localIndex,
            targetEndpoint = target,
            message = msg,
            secrets = secrets,
            sentAt = now,
            cookieRetryAttempted = false
        )

        sendWithPadding(msg, amConfig.s1, target)
        logger.info("Sent handshake initiation (Index $localIndex) to $target")
    }

    private fun resendPendingInitiationWithCookie(cookie: ByteArray) {
        val pending = pendingInitiation ?: return
        val msg = pending.message.copy(mac2 = mac(cookie, pending.message.bytesForMac2()))
        val now = ProtocolClock.monotonicMillis()
        pendingInitiation = pending.copy(message = msg, sentAt = now)
        lastHandshakeSentTimestamp.set(now)
        sendWithPadding(msg, amConfig.s1, pending.targetEndpoint)
        logger.info("Resent handshake initiation with cookie (Index ${pending.localIndex})")
    }

    private suspend fun handleTickInternal() {
        val now = ProtocolClock.monotonicMillis()
        if (isHandshakeInProgress && (now - lastHandshakeSentTimestamp.get() > HANDSHAKE_TIMEOUT_MS)) {
            isHandshakeInProgress = false
            cleanupPendingInitiation(removeReservedSession = true)
        }
        currentKeyPair?.let { cur ->
            if (now - cur.createdAt > REJECT_AFTER_TIME_MS) {
                node.removeSession(cur.localIndex)
                currentKeyPair = null
            }
        }
        if (hasConfiguredEndpoint() && shouldInitiateHandshake(now)) initiateHandshake()
        if (shouldSendKeepalive()) sendKeepalive()
    }

    private fun shouldInitiateHandshake(now: Long): Boolean {
        if (!hasConfiguredEndpoint()) return false
        if (isHandshakeInProgress) return false
        val lastSent = lastHandshakeSentTimestamp.get()
        if (lastSent != 0L && now - lastSent < HANDSHAKE_TIMEOUT_MS) return false

        val kp = currentKeyPair ?: return endpoint != null
        if (now - kp.createdAt > REKEY_AFTER_TIME_MS) return true

        val lastDataSent = kp.lastPacketSentTimestamp
        if (lastDataSent > 0 && (now - lastDataSent < 60_000) && (now - lastPacketReceivedTimestamp > 90_000)) return true

        return false
    }

    private fun shouldSendKeepalive(): Boolean {
        if (endpoint == null || currentKeyPair == null || keepaliveTimeoutMs <= 0) return false
        val now = ProtocolClock.monotonicMillis()
        if (now - lastPacketReceivedTimestamp < keepaliveTimeoutMs) return false
        return now - (currentKeyPair?.lastPacketSentTimestamp ?: 0) > keepaliveTimeoutMs
    }

    private suspend fun sendKeepalive() {
        val kp = currentKeyPair ?: return
        val target = endpoint ?: return
        val encMsg = kp.encryptData(ByteArray(0))
        encMsg.wireHeader = amConfig.h4.random()
        sendWithPadding(encMsg, amConfig.s4, target)
    }

    private fun maybeRoamTo(sender: InetSocketAddress, reason: String) {
        if (endpoint != sender) {
            logger.info("Peer roamed from $endpoint to $sender via $reason")
            endpoint = sender
        }
    }

    private fun cleanupPendingInitiation(removeReservedSession: Boolean) {
        val pending = pendingInitiation ?: return
        if (removeReservedSession) {
            val protectedSessionIds = setOfNotNull(currentKeyPair?.localIndex, nextKeyPair?.localIndex)
            if (pending.localIndex !in protectedSessionIds) {
                node.removeSession(pending.localIndex)
            }
        }
        pendingInitiation = null
    }

    private fun compareUnsignedByteArrays(left: ByteArray, right: ByteArray): Int {
        val maxSize = maxOf(left.size, right.size)
        for (i in 0 until maxSize) {
            val l = if (i < left.size) left[i].toInt() and 0xFF else 0
            val r = if (i < right.size) right[i].toInt() and 0xFF else 0
            if (l != r) return l.compareTo(r)
        }
        return 0
    }

    private data class PendingInitiation(
        val localIndex: Int,
        val targetEndpoint: InetSocketAddress,
        val message: HandshakeInitiationMessage,
        val secrets: HandshakeSecrets,
        val sentAt: Long,
        val cookieRetryAttempted: Boolean
    )

    private data class InitiationValidationResult(
        val state: HandshakeState?,
        val timestamp: ByteArray?,
        val error: String?
    )

    sealed class PeerEvent {
        data class UdpPacket(val message: Message, val sender: InetSocketAddress) : PeerEvent()
        object InitHandshake : PeerEvent()
        object Tick : PeerEvent()
    }
}

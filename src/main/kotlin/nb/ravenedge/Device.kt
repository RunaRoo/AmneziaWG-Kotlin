package nb.ravenedge

import com.sun.jna.LastErrorException
import com.sun.jna.Library
import com.sun.jna.Native
import com.sun.jna.Structure
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.slf4j.LoggerFactory
import java.io.File
import java.io.IOException
import java.security.MessageDigest
import java.util.concurrent.ConcurrentLinkedQueue

// ==========================================
// BUFFER POOL
// ==========================================
object BufferPool {
    private val pool = ConcurrentLinkedQueue<ByteArray>()
    const val DEFAULT_BUFFER_SIZE = 2048
    const val MAX_PACKET_SIZE = 65535
    private const val MAX_POOL_SIZE = 2048

    fun acquire(minSize: Int = DEFAULT_BUFFER_SIZE): ByteArray {
        val requested = minSize.coerceIn(DEFAULT_BUFFER_SIZE, MAX_PACKET_SIZE)
        while (true) {
            val candidate = pool.poll() ?: return ByteArray(requested)
            if (candidate.size >= requested) return candidate
            // Too small for this packet; drop it instead of returning an unsafe buffer.
        }
    }

    fun release(buffer: ByteArray) {
        if (buffer.size in DEFAULT_BUFFER_SIZE..MAX_PACKET_SIZE && pool.size < MAX_POOL_SIZE) {
            pool.offer(buffer)
        }
    }
}

//TODO: Remove redundant feature
object PacketFingerprint {
    private val sha1Digest = ThreadLocal.withInitial { MessageDigest.getInstance("SHA-1") }
    private val hexAlphabet = "0123456789abcdef".toCharArray()

    fun sha1(data: ByteArray, offset: Int = 0, length: Int = data.size): ByteArray {
        require(offset >= 0 && length >= 0 && offset + length <= data.size) { "Invalid SHA1 slice" }
        val digest = sha1Digest.get()
        digest.reset()
        digest.update(data, offset, length)
        return digest.digest()
    }

    fun toHex(hash: ByteArray): String {
        val out = CharArray(hash.size * 2)
        var j = 0
        for (b in hash) {
            val v = b.toInt() and 0xff
            out[j++] = hexAlphabet[v ushr 4]
            out[j++] = hexAlphabet[v and 0x0f]
        }
        return String(out)
    }

    fun sha1Hex(data: ByteArray, offset: Int = 0, length: Int = data.size): String =
        toHex(sha1(data, offset, length))
}

data class PacketContainer(
    val buffer: ByteArray,
    val length: Int
) {
    @Volatile private var cachedSha1Hex: String? = null

    fun sha1Hex(): String {
        val cached = cachedSha1Hex
        if (cached != null) return cached
        val computed = PacketFingerprint.sha1Hex(buffer, 0, length)
        cachedSha1Hex = computed
        return computed
    }

    fun release() = BufferPool.release(buffer)
}

// ==========================================
// JNA LINUX ONLY
// ==========================================
private interface CLibrary : Library {
    @Throws(LastErrorException::class)
    fun open(path: String, flags: Int): Int

    @Throws(LastErrorException::class)
    fun close(fd: Int): Int

    @Throws(LastErrorException::class)
    fun ioctl(fd: Int, request: Long, arg: Structure): Int

    @Throws(LastErrorException::class)
    fun read(fd: Int, buf: ByteArray, count: Long): Long

    @Throws(LastErrorException::class)
    fun write(fd: Int, buf: ByteArray, count: Long): Long

    @Throws(LastErrorException::class)
    fun poll(fds: PollFd, nfds: Long, timeout: Int): Int

    companion object {
        val INSTANCE: CLibrary by lazy { Native.load("c", CLibrary::class.java) }
    }
}

@Structure.FieldOrder("ifr_name", "ifr_flags")
internal open class IfReq : Structure() {
    @JvmField var ifr_name = ByteArray(16)
    @JvmField var ifr_flags: Short = 0

    fun setName(name: String) {
        val nameBytes = name.toByteArray()
        System.arraycopy(nameBytes, 0, ifr_name, 0, nameBytes.size.coerceAtMost(15))
    }
}

@Structure.FieldOrder("fd", "events", "revents")
internal open class PollFd : Structure() {
    @JvmField var fd: Int = -1
    @JvmField var events: Short = 0
    @JvmField var revents: Short = 0
}

private const val O_RDWR = 0x0002
private const val IFF_TUN_LINUX = 0x0001
private const val IFF_NO_PI_LINUX = 0x1000
private const val TUNSETIFF_LINUX = 0x400454caL
private const val POLLIN: Short = 0x0001
private const val POLLOUT: Short = 0x0004
private const val EINTR = 4
private const val EAGAIN = 11

// ==========================================
// INTERFACE
// ==========================================
interface TunDevice {
    val name: String
    suspend fun readBatch(maxPackets: Int): List<PacketContainer>
    suspend fun writePacket(packet: PacketContainer)
    suspend fun writeBatch(packets: List<PacketContainer>)
    fun up()
    fun down()
}

// ==========================================
// LINUX TUN DEVICE
// ==========================================
class LinuxTunDevice(override val name: String, private val config: InterfaceConfig) : TunDevice {
    private val logger = LoggerFactory.getLogger(LinuxTunDevice::class.java)
    @Volatile private var nativeFileDescriptor: Int = -1
    @Volatile private var isUp = false
    private val packetBufferSize = (config.mtu + 128).coerceIn(BufferPool.DEFAULT_BUFFER_SIZE, BufferPool.MAX_PACKET_SIZE)

    init {
        createDevice()
    }

    private fun createDevice() {
        nativeFileDescriptor = CLibrary.INSTANCE.open("/dev/net/tun", O_RDWR)
        if (nativeFileDescriptor < 0) throw IOException("Failed to open /dev/net/tun. Run as root?")

        val ifr = IfReq().apply {
            setName(name)
            ifr_flags = (IFF_TUN_LINUX or IFF_NO_PI_LINUX).toShort()
        }
        if (CLibrary.INSTANCE.ioctl(nativeFileDescriptor, TUNSETIFF_LINUX, ifr) < 0) {
            throw IOException("Failed to configure TUN interface '$name'.")
        }
    }

    private fun waitFor(events: Short, timeoutMs: Int): Boolean {
        val fd = nativeFileDescriptor
        if (fd < 0) return false

        while (true) {
            val pfd = PollFd().apply {
                this.fd = fd
                this.events = events
                this.revents = 0
            }
            pfd.write()
            val ready = try {
                CLibrary.INSTANCE.poll(pfd, 1L, timeoutMs)
            } catch (e: LastErrorException) {
                if (e.errorCode == EINTR) continue else throw e
            }
            pfd.read()

            if (ready <= 0) return false
            return (pfd.revents.toInt() and events.toInt()) != 0
        }
    }

    override suspend fun readBatch(maxPackets: Int): List<PacketContainer> = withContext(Dispatchers.IO) {
        val fd = nativeFileDescriptor
        if (fd < 0 || maxPackets <= 0) return@withContext emptyList()
        if (!waitFor(POLLIN, -1)) return@withContext emptyList()

        val packets = ArrayList<PacketContainer>(maxPackets)
        while (packets.size < maxPackets && nativeFileDescriptor >= 0) {
            val buffer = BufferPool.acquire(packetBufferSize)
            try {
                val bytesRead = CLibrary.INSTANCE.read(fd, buffer, buffer.size.toLong())
                when {
                    bytesRead > 0 -> packets.add(PacketContainer(buffer, bytesRead.toInt()))
                    else -> {
                        BufferPool.release(buffer)
                        break
                    }
                }
            } catch (e: LastErrorException) {
                BufferPool.release(buffer)
                if (e.errorCode == EINTR) continue
                if (e.errorCode == EAGAIN) break
                if (nativeFileDescriptor >= 0) logger.warn("TUN read failed: ${e.message}")
                break
            } catch (e: Exception) {
                BufferPool.release(buffer)
                if (nativeFileDescriptor >= 0) logger.warn("TUN read failed: ${e.message}")
                break
            }

            if (packets.size < maxPackets && !waitFor(POLLIN, 0)) break
        }
        packets
    }

    override suspend fun writePacket(packet: PacketContainer) = withContext(Dispatchers.IO) {
        try {
            val fd = nativeFileDescriptor
            if (fd < 0) return@withContext
            if (packet.length <= 0 || packet.length > packet.buffer.size) return@withContext

            // For TUN packet fds, a write is one whole packet. Avoid sliceArray/copy here.
            val written = CLibrary.INSTANCE.write(fd, packet.buffer, packet.length.toLong())
            if (written != packet.length.toLong()) {
                throw IOException("Short TUN write: wrote $written of ${packet.length} bytes")
            }
        } catch (e: LastErrorException) {
            if (e.errorCode != EAGAIN || !waitFor(POLLOUT, 50)) {
                logger.warn("TUN write failed: ${e.message}")
            }
        } catch (e: Exception) {
            logger.warn("TUN write failed: ${e.message}")
        } finally {
            packet.release()
        }
    }

    override suspend fun writeBatch(packets: List<PacketContainer>) {
        for (packet in packets) writePacket(packet)
    }

    override fun up() {
        if (isUp) return
        try {
            config.addresses.forEach { cidr ->
                executeCommand("ip address add ${cidr.address.hostAddress}/${cidr.prefix} dev $name")
            }
            executeCommand("ip link set dev $name mtu ${config.mtu}")
            executeCommand("ip link set dev $name up")
            isUp = true

            config.postUp.forEach { executeCommand(it.replace("%i", name)) }

            if (config.dnsServers.isNotEmpty()) {
                val dns = config.dnsServers.joinToString("\n") { "nameserver ${it.hostAddress}" }
                File("/etc/resolv.conf").writeText(dns)
            }
        } catch (e: Exception) {
            down()
            throw e
        }
    }

    override fun down() {
        val wasUp = isUp
        if (wasUp) {
            config.postDown.forEach { command ->
                executeCommand(command.replace("%i", name), suppress = true)
            }
        }

        if (nativeFileDescriptor != -1) {
            try { CLibrary.INSTANCE.close(nativeFileDescriptor) } catch (_: Exception) {}
            nativeFileDescriptor = -1
        }
        if (wasUp) executeCommand("ip link del dev $name", suppress = true)
        isUp = false
    }

    private fun executeCommand(command: String, suppress: Boolean = false) {
        try {
            val process = ProcessBuilder("/bin/sh", "-c", command).start()
            val exitCode = process.waitFor()
            if (exitCode != 0 && !suppress) {
                val stderr = process.errorStream.bufferedReader().readText().trim()
                throw IOException("Command failed ($exitCode): $command${if (stderr.isNotEmpty()) "\n$stderr" else ""}")
            }
        } catch (e: Exception) {
            if (!suppress) throw e
        }
    }
}

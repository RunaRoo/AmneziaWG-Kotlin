package nb.ravenedge

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom
import java.util.Arrays
import java.util.BitSet
import java.util.concurrent.atomic.AtomicLong

// --- Protocol Constants ---
val PROTOCOL_NAME = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".toByteArray()
val IDENTIFIER = "WireGuard v1 zx2c4 Jason@zx2c4.com".toByteArray()
val LABEL_MAC1 = "mac1----".toByteArray() 
val LABEL_COOKIE = "cookie--".toByteArray()

class Noise(
    private val localStaticPrivate: Key,
    val localStaticPublic: Key,
    private val remoteStaticPublic: Key,
    private val presharedKey: Key?
) {
    private val initialChainingKey = hash(PROTOCOL_NAME)
    private val initialHash = hash(initialChainingKey, IDENTIFIER)

    fun createHandshakeInitiation(senderIndex: Int, wireHeader: Long = 1L): Pair<HandshakeInitiationMessage, HandshakeSecrets> {
        var ck = initialChainingKey.clone()
        var hs = initialHash.clone()

        hs = hash(hs, remoteStaticPublic.value)

        val (ephemeralPrivate, ephemeralPublic) = generateKeyPair()
        val message = HandshakeInitiationMessage(senderIndex, ephemeralPublic, ByteArray(48), ByteArray(28), ByteArray(16), ByteArray(16), wireHeader)

        hs = hash(hs, message.unencryptedEphemeral.value)
        ck = kdf1(ck, message.unencryptedEphemeral.value)

        val sharedSecret1 = x25519(ephemeralPrivate, remoteStaticPublic)
        val (ck1, key1) = kdf2(ck, sharedSecret1)
        ck = ck1

        message.encryptedStatic = Aead.chacha20Poly1305Encrypt(key1, 0, localStaticPublic.value, hs)
        hs = hash(hs, message.encryptedStatic)

        val sharedSecret2 = x25519(localStaticPrivate, remoteStaticPublic)
        val (ck2, key2) = kdf2(ck, sharedSecret2)
        ck = ck2

        val timestamp = tai64n()
        message.encryptedTimestamp = Aead.chacha20Poly1305Encrypt(key2, 0, timestamp, hs)
        hs = hash(hs, message.encryptedTimestamp)

        val mac1Key = hash(LABEL_MAC1, remoteStaticPublic.value)
        message.mac1 = mac(mac1Key, message.bytesForMac1())

        // --- Hotfix: Store the senderIndex (localIndex) in secrets so we remember it later ---
        val secrets = HandshakeSecrets(ck, hs, ephemeralPrivate, senderIndex)
        return Pair(message, secrets)
    }

    fun consumeHandshakeResponse(secrets: HandshakeSecrets, response: HandshakeResponseMessage): KeyPair? {
        var ck = secrets.chainingKey
        var hs = secrets.hash

        hs = hash(hs, response.unencryptedEphemeral.value)
        ck = kdf1(ck, response.unencryptedEphemeral.value)

        val sharedSecret1 = x25519(secrets.ephemeralPrivate, response.unencryptedEphemeral)
        ck = kdf1(ck, sharedSecret1)

        val sharedSecret2 = x25519(localStaticPrivate, response.unencryptedEphemeral)
        ck = kdf1(ck, sharedSecret2)

        val pskBytes = presharedKey?.value ?: ByteArray(32)
        val (ck3, tau, k) = kdf3(ck, pskBytes)
        ck = ck3
        hs = hash(hs, tau.value)
        
        val decryptedNothing = Aead.chacha20Poly1305Decrypt(k, 0, response.encryptedNothing, hs)
        if (decryptedNothing == null) return null

        val (sendKeyBytes, receiveKeyBytes) = kdf2(ck, ByteArray(0))
        
        // --- hotfix: Use secrets.localIndex ---
        return KeyPair(Key(sendKeyBytes), Key(receiveKeyBytes.value), response.senderIndex, secrets.localIndex) 
    }


    fun isValidHandshakeResponseMac1(response: HandshakeResponseMessage): Boolean {
        val mac1Key = hash(LABEL_MAC1, localStaticPublic.value)
        val expectedMac1 = mac(mac1Key, response.bytesForMac1())
        return constantTimeEquals(expectedMac1, response.mac1)
    }
}

data class HandshakeState(var chainingKey: ByteArray, var hash: ByteArray) {
    fun mixHash(data: ByteArray) { hash = hash(hash, data) }
    override fun equals(other: Any?) = other is HandshakeState && chainingKey.contentEquals(other.chainingKey) && hash.contentEquals(other.hash)
    override fun hashCode() = Arrays.deepHashCode(arrayOf(chainingKey, hash))
}

// --- ProtocolFix: Added localIndex to HandshakeSecrets ---
data class HandshakeSecrets(
    val chainingKey: ByteArray, 
    val hash: ByteArray, 
    val ephemeralPrivate: Key,
    val localIndex: Int
) {
    override fun equals(other: Any?) = other is HandshakeSecrets && chainingKey.contentEquals(other.chainingKey) && hash.contentEquals(other.hash) && ephemeralPrivate == other.ephemeralPrivate && localIndex == other.localIndex
    override fun hashCode() = Arrays.deepHashCode(arrayOf(chainingKey, hash, ephemeralPrivate, localIndex))
}

class KeyPair(
    private val sendKey: Key,
    private val recvKey: Key,
    val remoteIndex: Int,
    val localIndex: Int,
    val createdAt: Long = ProtocolClock.monotonicMillis()
) {
    private val txNonce = AtomicLong(0L)
    private val rxReplayFilter = ReplayFilter()
    @Volatile var lastPacketSentTimestamp: Long = 0
        private set

    fun encryptData(packet: ByteArray): DataMessage = encryptData(packet, 0, packet.size)

    fun encryptData(packet: ByteArray, offset: Int, length: Int): DataMessage {
        require(offset >= 0 && length >= 0 && offset + length <= packet.size) { "Invalid plaintext slice" }
        val nonce = txNonce.getAndIncrement()
        val encrypted = ByteArray(length + AUTH_TAG_LENGTH)
        Aead.chacha20Poly1305Encrypt(sendKey, nonce, packet, offset, length, ByteArray(0), encrypted, 0)
        lastPacketSentTimestamp = ProtocolClock.monotonicMillis()
        return DataMessage(remoteIndex, nonce, encrypted)
    }

    fun decryptData(message: DataMessage): ByteArray? {
        val packet = decryptDataToPacket(message) ?: return null
        return try {
            packet.buffer.copyOf(packet.length)
        } finally {
            packet.release()
        }
    }

    fun decryptDataToPacket(message: DataMessage): PacketContainer? {
        if (message.encryptedData.size < AUTH_TAG_LENGTH) return null
        if (!rxReplayFilter.validate(message.counter)) return null

        val plaintextLength = message.encryptedData.size - AUTH_TAG_LENGTH
        val out = BufferPool.acquire(plaintextLength)
        val len = Aead.chacha20Poly1305Decrypt(
            recvKey,
            message.counter,
            message.encryptedData,
            0,
            message.encryptedData.size,
            ByteArray(0),
            out,
            0
        )
        if (len < 0) {
            BufferPool.release(out)
            return null
        }
        return PacketContainer(out, len)
    }
}

// --- Better Replay filter ---
//Test how it will handle Large ammounts of data.
//Tested: Much better now
class ReplayFilter {
    private val lock = Any()
    private val WINDOW_SIZE = 2048 
    private var maxSeq: Long = -1
    private val window = BitSet(WINDOW_SIZE)

    fun validate(seq: Long): Boolean = synchronized(lock) {
        if (seq > maxSeq) {
            val diff = seq - maxSeq
            
            if (diff >= WINDOW_SIZE) {
                window.clear()
            } else {
                // Clear bits for the range
                var i = 1L
                while (i <= diff) {
                    val idx = ((maxSeq + i) % WINDOW_SIZE).toInt()
                    window.clear(idx)
                    i++
                }
            }
            
            maxSeq = seq
            val newIdx = (seq % WINDOW_SIZE).toInt()
            window.set(newIdx)
            return true
        }

        val diff = maxSeq - seq
        if (diff >= WINDOW_SIZE) return false // Too old
        
        val idx = (seq % WINDOW_SIZE).toInt()
        if (window.get(idx)) return false // Replay
        
        window.set(idx)
        return true
    }
}

class CookieGenerator(localStaticPublic: Key) {
    private val logger = org.slf4j.LoggerFactory.getLogger(CookieGenerator::class.java)
    private val lock = Any()
    @Volatile private var currentCookieSecret: ByteArray = generateRandomKey()
    @Volatile private var previousCookieSecret: ByteArray = generateRandomKey()
    @Volatile private var lastKeyRotation = ProtocolClock.monotonicMillis()
    private val cookieReplyKey = Key(hash(LABEL_COOKIE, localStaticPublic.value))

    private fun rotateKeysIfNeeded() = synchronized(lock) {
        val now = ProtocolClock.monotonicMillis()
        if (now - lastKeyRotation > 120_000) {
            previousCookieSecret = currentCookieSecret
            currentCookieSecret = generateRandomKey()
            lastKeyRotation = now
            logger.debug("Cookie secrets rotated.")
        }
    }

    fun createCookieReply(initiationMessage: HandshakeInitiationMessage, senderAddress: ByteArray): CookieReplyMessage {
        rotateKeysIfNeeded()
        val nonce = ByteArray(24).apply { SecureRandom().nextBytes(this) }
        val cookie = mac(currentCookieSecret, senderAddress)
        val encryptedCookie = Aead.xchacha20Poly1305Encrypt(cookieReplyKey, nonce, cookie, initiationMessage.mac1)
        logger.debug("Sending cookie reply to: {}", initiationMessage.senderIndex)
        return CookieReplyMessage(initiationMessage.senderIndex, nonce, encryptedCookie)
    }

    fun consumeCookie(initiationMessage: HandshakeInitiationMessage, senderAddress: ByteArray): Boolean {
        rotateKeysIfNeeded()
        if (initiationMessage.mac2.all { it == 0.toByte() }) return false
        val expectedCookie1 = mac(currentCookieSecret, senderAddress)
        val expectedMac2FromCookie1 = mac(expectedCookie1, initiationMessage.bytesForMac2())
        if (constantTimeEquals(initiationMessage.mac2, expectedMac2FromCookie1)) return true
        val expectedCookie2 = mac(previousCookieSecret, senderAddress)
        val expectedMac2FromCookie2 = mac(expectedCookie2, initiationMessage.bytesForMac2())
        val valid = constantTimeEquals(initiationMessage.mac2, expectedMac2FromCookie2)
        if (valid) logger.debug("Received valid cookie-backed initiation")
        return valid
    }

    private fun generateRandomKey() = ByteArray(32).apply { SecureRandom().nextBytes(this) }
}

private fun tai64n(): ByteArray {
    val now = System.currentTimeMillis()
    val seconds = now / 1000 + 0x400000000000000aL
    val nanos = (now % 1000) * 1_000_000
    return ByteBuffer.allocate(12).order(ByteOrder.BIG_ENDIAN).putLong(seconds).putInt(nanos.toInt()).array()
}
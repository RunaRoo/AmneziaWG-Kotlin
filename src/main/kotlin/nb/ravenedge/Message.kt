package nb.ravenedge

import com.google.common.primitives.Bytes
import java.nio.ByteBuffer
import java.nio.ByteOrder

enum class MessageType(val id: Byte) {
    HANDSHAKE_INITIATION(1),
    HANDSHAKE_RESPONSE(2),
    COOKIE_REPLY(3),
    DATA(4);

    companion object {
        fun from(id: Byte): MessageType? = entries.find { it.id == id }
    }
}

interface Message {
    val type: MessageType
    fun toBytes(): ByteArray
}

data class HandshakeInitiationMessage(
    val senderIndex: Int,
    val unencryptedEphemeral: Key,
    var encryptedStatic: ByteArray,    // 32 bytes + 16 tag = 48 bytes
    var encryptedTimestamp: ByteArray, // 12 bytes + 16 tag = 28 bytes
    var mac1: ByteArray,               // 16 bytes
    var mac2: ByteArray,               // 16 bytes
    var wireHeader: Long = 1L          // WG Init or Amnezia H1
) : Message {
    override val type = MessageType.HANDSHAKE_INITIATION

    override fun toBytes(): ByteArray {
        val buf = ByteBuffer.allocate(148).order(ByteOrder.LITTLE_ENDIAN)
        buf.putInt(wireHeader.toInt())
        buf.putInt(senderIndex)
        buf.put(unencryptedEphemeral.value)
        buf.put(encryptedStatic)
        buf.put(encryptedTimestamp)
        buf.put(mac1)
        buf.put(mac2)
        return buf.array()
    }

    fun bytesForMac1(): ByteArray = toBytes().sliceArray(0 until (148 - 32))
    fun bytesForMac2(): ByteArray = toBytes().sliceArray(0 until (148 - 16))

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as HandshakeInitiationMessage

        if (senderIndex != other.senderIndex) return false
        if (unencryptedEphemeral != other.unencryptedEphemeral) return false
        if (!encryptedStatic.contentEquals(other.encryptedStatic)) return false
        if (!encryptedTimestamp.contentEquals(other.encryptedTimestamp)) return false
        if (!mac1.contentEquals(other.mac1)) return false
        if (!mac2.contentEquals(other.mac2)) return false
        if (wireHeader != other.wireHeader) return false

        return true
    }

    override fun hashCode(): Int {
        var result = senderIndex
        result = 31 * result + unencryptedEphemeral.hashCode()
        result = 31 * result + encryptedStatic.contentHashCode()
        result = 31 * result + encryptedTimestamp.contentHashCode()
        result = 31 * result + mac1.contentHashCode()
        result = 31 * result + mac2.contentHashCode()
        result = 31 * result + wireHeader.hashCode()
        return result
    }

    companion object {
        fun fromBytes(bytes: ByteArray): HandshakeInitiationMessage {
            require(bytes.size >= 148) { "Invalid handshake initiation size" }
            val buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
            val wireHeader = buf.int.toLong() and 0xFFFFFFFFL
            return HandshakeInitiationMessage(
                senderIndex = buf.int,
                unencryptedEphemeral = Key(ByteArray(KEY_LENGTH).also { buf.get(it) }),
                encryptedStatic = ByteArray(48).also { buf.get(it) },
                encryptedTimestamp = ByteArray(28).also { buf.get(it) },
                mac1 = ByteArray(16).also { buf.get(it) },
                mac2 = ByteArray(16).also { buf.get(it) },
                wireHeader = wireHeader
            )
        }
    }
}

data class HandshakeResponseMessage(
    val senderIndex: Int,
    val receiverIndex: Int,
    val unencryptedEphemeral: Key,
    val encryptedNothing: ByteArray,   // 0 bytes + 16 tag = 16 bytes
    var mac1: ByteArray,               // 16 bytes
    var mac2: ByteArray,               // 16 bytes
    var wireHeader: Long = 2L          // WG Resp or Amnezia H2
) : Message {
    override val type = MessageType.HANDSHAKE_RESPONSE

    override fun toBytes(): ByteArray {
        val buf = ByteBuffer.allocate(92).order(ByteOrder.LITTLE_ENDIAN)
        buf.putInt(wireHeader.toInt())
        buf.putInt(senderIndex)
        buf.putInt(receiverIndex)
        buf.put(unencryptedEphemeral.value)
        buf.put(encryptedNothing)
        buf.put(mac1)
        buf.put(mac2)
        return buf.array()
    }

    fun bytesForMac1(): ByteArray = toBytes().sliceArray(0 until (92 - 32))
    fun bytesForMac2(): ByteArray = toBytes().sliceArray(0 until (92 - 16))

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as HandshakeResponseMessage

        if (senderIndex != other.senderIndex) return false
        if (receiverIndex != other.receiverIndex) return false
        if (unencryptedEphemeral != other.unencryptedEphemeral) return false
        if (!encryptedNothing.contentEquals(other.encryptedNothing)) return false
        if (!mac1.contentEquals(other.mac1)) return false
        if (!mac2.contentEquals(other.mac2)) return false
        if (wireHeader != other.wireHeader) return false

        return true
    }

    override fun hashCode(): Int {
        var result = senderIndex
        result = 31 * result + receiverIndex
        result = 31 * result + unencryptedEphemeral.hashCode()
        result = 31 * result + encryptedNothing.contentHashCode()
        result = 31 * result + mac1.contentHashCode()
        result = 31 * result + mac2.contentHashCode()
        result = 31 * result + wireHeader.hashCode()
        return result
    }

    companion object {
        fun fromBytes(bytes: ByteArray): HandshakeResponseMessage {
            require(bytes.size >= 92) { "Invalid handshake response size" }
            val buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
            val wireHeader = buf.int.toLong() and 0xFFFFFFFFL
            return HandshakeResponseMessage(
                senderIndex = buf.int, 
                receiverIndex = buf.int,
                unencryptedEphemeral = Key(ByteArray(KEY_LENGTH).also { buf.get(it) }),
                encryptedNothing = ByteArray(16).also { buf.get(it) },
                mac1 = ByteArray(16).also { buf.get(it) }, 
                mac2 = ByteArray(16).also { buf.get(it) },
                wireHeader = wireHeader
            )
        }
    }
}

data class CookieReplyMessage(
    val receiverIndex: Int,
    val nonce: ByteArray,              // 24 bytes
    val encryptedCookie: ByteArray,    // 16 bytes cookie + 16 tag = 32 bytes
    var wireHeader: Long = 3L          // WG Cookie or Amnezia H3
) : Message {
    override val type = MessageType.COOKIE_REPLY
    
    override fun toBytes(): ByteArray {
        val buf = ByteBuffer.allocate(64).order(ByteOrder.LITTLE_ENDIAN)
        buf.putInt(wireHeader.toInt())
        buf.putInt(receiverIndex)
        buf.put(nonce)
        buf.put(encryptedCookie)
        return buf.array()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as CookieReplyMessage

        if (receiverIndex != other.receiverIndex) return false
        if (!nonce.contentEquals(other.nonce)) return false
        if (!encryptedCookie.contentEquals(other.encryptedCookie)) return false
        if (wireHeader != other.wireHeader) return false

        return true
    }

    override fun hashCode(): Int {
        var result = receiverIndex
        result = 31 * result + nonce.contentHashCode()
        result = 31 * result + encryptedCookie.contentHashCode()
        result = 31 * result + wireHeader.hashCode()
        return result
    }

    companion object {
        fun fromBytes(bytes: ByteArray): CookieReplyMessage {
            require(bytes.size >= 64) { "Invalid cookie reply size" }
            val buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
            val wireHeader = buf.int.toLong() and 0xFFFFFFFFL
            return CookieReplyMessage(
                receiverIndex = buf.int,
                nonce = ByteArray(24).apply { buf.get(this) },
                encryptedCookie = ByteArray(32).apply { buf.get(this) },
                wireHeader = wireHeader
            )
        }
    }
}

data class DataMessage(
    val receiverIndex: Int,
    val counter: Long,
    val encryptedData: ByteArray,
    var wireHeader: Long = 4L          // WG Data or Amnezia H4
) : Message {
    override val type = MessageType.DATA
    
    override fun toBytes(): ByteArray = Bytes.concat(
        ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN)
            .putInt(wireHeader.toInt())
            .putInt(receiverIndex)
            .putLong(counter)
            .array(),
        encryptedData
    )

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as DataMessage

        if (receiverIndex != other.receiverIndex) return false
        if (counter != other.counter) return false
        if (!encryptedData.contentEquals(other.encryptedData)) return false
        if (wireHeader != other.wireHeader) return false

        return true
    }

    override fun hashCode(): Int {
        var result = receiverIndex
        result = 31 * result + counter.hashCode()
        result = 31 * result + encryptedData.contentHashCode()
        result = 31 * result + wireHeader.hashCode()
        return result
    }

    companion object {
        fun fromBytes(bytes: ByteArray): DataMessage {
            require(bytes.size >= 16) { "Invalid data message size" }
            val buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
            val wireHeader = buf.int.toLong() and 0xFFFFFFFFL
            return DataMessage(
                receiverIndex = buf.int, 
                counter = buf.long,
                encryptedData = ByteArray(bytes.size - 16).apply { buf.get(this) },
                wireHeader = wireHeader
            )
        }
    }
}
package nb.ravenedge

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicInteger

object CpsParser {
    private val globalCounter = AtomicInteger(0)

    fun parse(pattern: String): ByteArray {
        val result = ByteArrayOutputStream()
        val regex = Regex("<([bctr])\\s*([^>]*)>")
        val matches = regex.findAll(pattern) 

        for (match in matches) {
            val type = match.groupValues[1]
            val arg = match.groupValues[2].trim()

            when (type) {
                "b" -> {
                    val hex = arg.removePrefix("0x").replace(" ", "")
                    result.write(hexStringToByteArray(hex))
                }
                "c" -> {
                    val buf = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN)
                        .putInt(globalCounter.getAndIncrement())
                    result.write(buf.array())
                }
                "t" -> {
                    val unixTime = (System.currentTimeMillis() / 1000).toInt()
                    val buf = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN)
                        .putInt(unixTime)
                    result.write(buf.array())
                }
                "r" -> {
                    val len = arg.toIntOrNull() ?: 0
                    if (len > 0) {
                        val rand = ByteArray(len).apply { SecureRandom().nextBytes(this) }
                        result.write(rand)
                    }
                }
                //ToDo: Add rest CPS parameters
            }
        }
        return result.toByteArray()
    }

    private fun hexStringToByteArray(s: String): ByteArray {
        val len = s.length
        val data = ByteArray(len / 2)
        var i = 0
        while (i < len) {
            data[i / 2] = ((Character.digit(s[i], 16) shl 4) + Character.digit(s[i + 1], 16)).toByte()
            i += 2
        }
        return data
    }
}
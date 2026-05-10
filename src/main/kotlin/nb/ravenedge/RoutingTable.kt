package nb.ravenedge

import com.google.common.net.InetAddresses
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.util.concurrent.locks.ReentrantReadWriteLock
import kotlin.concurrent.read
import kotlin.concurrent.write

//Version 9 SUPER: Enhanced Routing Table
class RoutingTable<T> {
    private data class IPv4Route<T>(val cidr: CIDR, val network: Int, val mask: Int, val value: T)
    private data class IPv6Route<T>(val cidr: CIDR, val network: ByteArray, val value: T)

    private val ipv4Routes = mutableListOf<IPv4Route<T>>()
    private val ipv6Routes = mutableListOf<IPv6Route<T>>()
    private val lock = ReentrantReadWriteLock()

    fun insert(cidr: CIDR, value: T) = lock.write {
        when (val addr = cidr.address) {
            is Inet4Address -> {
                val mask = ipv4Mask(cidr.prefix)
                val network = inet4ToInt(addr) and mask
                ipv4Routes.removeAll { it.cidr == cidr }
                ipv4Routes.add(IPv4Route(cidr, network, mask, value))
                ipv4Routes.sortByDescending { it.cidr.prefix }
            }
            is Inet6Address -> {
                ipv6Routes.removeAll { it.cidr == cidr }
                ipv6Routes.add(IPv6Route(cidr, normalizeIpv6(addr.address, cidr.prefix), value))
                ipv6Routes.sortByDescending { it.cidr.prefix }
            }
        }
    }

    fun remove(cidr: CIDR) = lock.write {
        when (cidr.address) {
            is Inet4Address -> ipv4Routes.removeAll { it.cidr == cidr }
            is Inet6Address -> ipv6Routes.removeAll { it.cidr == cidr }
        }
    }

    fun findBestMatch(address: InetAddress): T? = lock.read {
        when (address) {
            is Inet4Address -> {
                val key = inet4ToInt(address)
                ipv4Routes.firstOrNull { (key and it.mask) == it.network }?.value
            }
            is Inet6Address -> {
                val key = address.address
                ipv6Routes.firstOrNull { ipv6PrefixMatches(key, it.network, it.cidr.prefix) }?.value
            }
            else -> null
        }
    }

    fun clear() = lock.write {
        ipv4Routes.clear()
        ipv6Routes.clear()
    }

    fun size(): Int = lock.read { ipv4Routes.size + ipv6Routes.size }

    private fun ipv4Mask(prefix: Int): Int = if (prefix == 0) 0 else -1 shl (32 - prefix)

    private fun inet4ToInt(address: Inet4Address): Int {
        val b = address.address
        return ((b[0].toInt() and 0xFF) shl 24) or
            ((b[1].toInt() and 0xFF) shl 16) or
            ((b[2].toInt() and 0xFF) shl 8) or
            (b[3].toInt() and 0xFF)
    }

    private fun normalizeIpv6(address: ByteArray, prefix: Int): ByteArray {
        val out = address.copyOf()
        val fullBytes = prefix / 8
        val remainingBits = prefix % 8

        if (fullBytes < out.size) {
            if (remainingBits == 0) {
                for (i in fullBytes until out.size) out[i] = 0
            } else {
                val mask = (0xFF shl (8 - remainingBits)) and 0xFF
                out[fullBytes] = (out[fullBytes].toInt() and mask).toByte()
                for (i in (fullBytes + 1) until out.size) out[i] = 0
            }
        }
        return out
    }

    private fun ipv6PrefixMatches(address: ByteArray, network: ByteArray, prefix: Int): Boolean {
        val fullBytes = prefix / 8
        val remainingBits = prefix % 8

        for (i in 0 until fullBytes) {
            if (address[i] != network[i]) return false
        }
        if (remainingBits == 0) return true

        val mask = (0xFF shl (8 - remainingBits)) and 0xFF
        return (address[fullBytes].toInt() and mask) == (network[fullBytes].toInt() and mask)
    }
}

data class CIDR(val address: InetAddress, val prefix: Int) {
    companion object {
        fun fromString(cidr: String): CIDR {
            val parts = cidr.trim().split('/', limit = 2)
            require(parts.size == 2 && parts[0].isNotBlank() && parts[1].isNotBlank()) { "Invalid CIDR format: $cidr" }

            val address = try {
                InetAddresses.forString(parts[0].trim())
            } catch (e: IllegalArgumentException) {
                throw IllegalArgumentException("CIDR address must be a literal IP, not a hostname: $cidr", e)
            }

            val prefix = parts[1].trim().toInt()
            val maxPrefix = if (address is Inet4Address) 32 else 128
            require(prefix in 0..maxPrefix) { "Invalid prefix length for $cidr" }
            return CIDR(address, prefix)
        }
    }
}

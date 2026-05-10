package nb.ravenedge

import com.google.common.base.Preconditions
import com.google.common.base.Splitter
import com.google.common.net.HostAndPort
import com.google.common.net.InetAddresses
import java.io.File
import java.net.InetAddress
import java.net.InetSocketAddress

data class Range(val min: Long, val max: Long) {
    fun contains(value: Long) = value in min..max
    fun random() = if (min == max) min else (min..max).random()
}

data class AmneziaConfig(
    val jc: Int = 0,     val jmin: Int = 50, val jmax: Int = 1000,
    val s1: Int = 0,     val s2: Int = 0,    val s3: Int = 0, val s4: Int = 0,
    val h1: Range = Range(1, 1), val h2: Range = Range(2, 2),
    val h3: Range = Range(3, 3), val h4: Range = Range(4, 4),
    val i1: String? = null, val i2: String? = null,
    val i3: String? = null, val i4: String? = null, val i5: String? = null
) {
    init {
        Preconditions.checkArgument(jc >= 0, "Jc must be >= 0")
        Preconditions.checkArgument(jmin >= 0, "Jmin must be >= 0")
        Preconditions.checkArgument(jmax >= 0, "Jmax must be >= 0")
        Preconditions.checkArgument(jmin <= jmax, "Jmin must be <= Jmax")
        Preconditions.checkArgument(s1 >= 0 && s2 >= 0 && s3 >= 0 && s4 >= 0, "S1..S4 must be >= 0")
        Preconditions.checkArgument(nonOverlapping(h1, h2, h3, h4), "H1-H4 ranges must be non-overlapping")
    }

    fun validateForMtu(mtu: Int) {
        Preconditions.checkArgument(jmax <= mtu, "Jmax must not exceed MTU")
        Preconditions.checkArgument(148 + s1 <= mtu, "S1 is too large for handshake initiation MTU")
        Preconditions.checkArgument(92 + s2 <= mtu, "S2 is too large for handshake response MTU")
        Preconditions.checkArgument(64 + s3 <= mtu, "S3 is too large for cookie reply MTU")
    }

    private fun nonOverlapping(vararg ranges: Range): Boolean {
        for (i in ranges.indices) {
            for (j in (i + 1) until ranges.size) {
                if (ranges[i].min <= ranges[j].max && ranges[j].min <= ranges[i].max) {
                    return false
                }
            }
        }
        return true
    }
}

data class InterfaceConfig(
    val privateKey: String,
    val addresses: List<CIDR>,
    val listenPort: Int?,
    val dnsServers: List<InetAddress>,
    val postUp: List<String>,
    val postDown: List<String>,
    val mtu: Int,
    val amnezia: AmneziaConfig
)

data class PeerConfig(
    val publicKey: String,
    val presharedKey: String?,
    val allowedIPs: List<CIDR>,
    val endpoint: InetSocketAddress?,
    val persistentKeepalive: Int?
)

object Config {
    private val csvSplitter: Splitter = Splitter.on(',').trimResults().omitEmptyStrings()

    private fun splitCsv(values: List<String>?): List<String> =
        values?.flatMap { csvSplitter.splitToList(it) } ?: emptyList()

    private fun parseLiteralAddress(value: String, fieldName: String): InetAddress = try {
        InetAddresses.forString(value)
    } catch (e: IllegalArgumentException) {
        throw IllegalArgumentException("$fieldName must be a literal IP address, not a hostname: $value", e)
    }

    private fun parseRange(value: String?, default: Long): Range {
        if (value.isNullOrBlank()) return Range(default, default)
        val parts = value.split("-")
        return if (parts.size == 2) {
            Range(parts[0].toLong(), parts[1].toLong())
        } else {
            val exact = value.toLong()
            Range(exact, exact)
        }
    }

    fun parse(filePath: String): Pair<InterfaceConfig, List<PeerConfig>> {
        val lines = File(filePath).readLines()
        val interfaceProps = mutableMapOf<String, MutableList<String>>()
        val peerPropsList = mutableListOf<MutableMap<String, MutableList<String>>>()
        var currentProps: MutableMap<String, MutableList<String>>? = null

        for (line in lines) {
            val trimmedLine = line.trim()
            if (trimmedLine.isBlank() || trimmedLine.startsWith('#')) continue

            when {
                trimmedLine.equals("[Interface]", ignoreCase = true) -> currentProps = interfaceProps
                trimmedLine.equals("[Peer]", ignoreCase = true) -> currentProps = mutableMapOf<String, MutableList<String>>().also { peerPropsList.add(it) }
                trimmedLine.contains('=') && currentProps != null -> {
                    val (key, value) = trimmedLine.split('=', limit = 2).map { it.trim() }
                    currentProps.computeIfAbsent(key.lowercase()) { mutableListOf() }.add(value)
                }
            }
        }

        val privateKey = interfaceProps["privatekey"]?.first()
        Preconditions.checkArgument(privateKey != null, "PrivateKey missing in Interface section")

        val amnezia = AmneziaConfig(
            jc = interfaceProps["awgjc"]?.firstOrNull()?.toInt() ?: interfaceProps["jc"]?.firstOrNull()?.toInt() ?: 0,
            jmin = interfaceProps["awgjmin"]?.firstOrNull()?.toInt() ?: interfaceProps["jmin"]?.firstOrNull()?.toInt() ?: 50,
            jmax = interfaceProps["awgjmax"]?.firstOrNull()?.toInt() ?: interfaceProps["jmax"]?.firstOrNull()?.toInt() ?: 1000,
            s1 = interfaceProps["awgs1"]?.firstOrNull()?.toInt() ?: interfaceProps["s1"]?.firstOrNull()?.toInt() ?: 0,
            s2 = interfaceProps["awgs2"]?.firstOrNull()?.toInt() ?: interfaceProps["s2"]?.firstOrNull()?.toInt() ?: 0,
            s3 = interfaceProps["awgs3"]?.firstOrNull()?.toInt() ?: interfaceProps["s3"]?.firstOrNull()?.toInt() ?: 0,
            s4 = interfaceProps["awgs4"]?.firstOrNull()?.toInt() ?: interfaceProps["s4"]?.firstOrNull()?.toInt() ?: 0,
            h1 = parseRange(interfaceProps["awgh1"]?.firstOrNull() ?: interfaceProps["h1"]?.firstOrNull(), 1),
            h2 = parseRange(interfaceProps["awgh2"]?.firstOrNull() ?: interfaceProps["h2"]?.firstOrNull(), 2),
            h3 = parseRange(interfaceProps["awgh3"]?.firstOrNull() ?: interfaceProps["h3"]?.firstOrNull(), 3),
            h4 = parseRange(interfaceProps["awgh4"]?.firstOrNull() ?: interfaceProps["h4"]?.firstOrNull(), 4),
            i1 = interfaceProps["awgi1"]?.firstOrNull() ?: interfaceProps["i1"]?.firstOrNull(),
            i2 = interfaceProps["awgi2"]?.firstOrNull() ?: interfaceProps["i2"]?.firstOrNull(),
            i3 = interfaceProps["awgi3"]?.firstOrNull() ?: interfaceProps["i3"]?.firstOrNull(),
            i4 = interfaceProps["awgi4"]?.firstOrNull() ?: interfaceProps["i4"]?.firstOrNull(),
            i5 = interfaceProps["awgi5"]?.firstOrNull() ?: interfaceProps["i5"]?.firstOrNull()
        )

        amnezia.validateForMtu(interfaceProps["mtu"]?.firstOrNull()?.toInt() ?: 1420)

        val ifaceConfig = InterfaceConfig(
            privateKey = privateKey!!,
            addresses = splitCsv(interfaceProps["address"]).map { CIDR.fromString(it) },
            listenPort = interfaceProps["listenport"]?.firstOrNull()?.toInt(),
            dnsServers = splitCsv(interfaceProps["dns"]).map { parseLiteralAddress(it, "DNS") },
            postUp = interfaceProps["postup"] ?: emptyList(),
            postDown = interfaceProps["postdown"] ?: emptyList(),
            mtu = interfaceProps["mtu"]?.firstOrNull()?.toInt() ?: 1420,
            amnezia = amnezia
        )

        val peerConfigs = peerPropsList.map { props ->
            val publicKey = props["publickey"]?.first()
            Preconditions.checkArgument(publicKey != null, "PublicKey missing in a Peer section")

            PeerConfig(
                publicKey = publicKey!!,
                presharedKey = props["presharedkey"]?.firstOrNull(),
                allowedIPs = splitCsv(props["allowedips"]).map { CIDR.fromString(it) },
                endpoint = props["endpoint"]?.firstOrNull()?.let {
                    val hostAndPort = HostAndPort.fromString(it)
                    InetSocketAddress(hostAndPort.host, hostAndPort.port)
                },
                persistentKeepalive = props["persistentkeepalive"]?.firstOrNull()?.toInt()
            )
        }
        return Pair(ifaceConfig, peerConfigs)
    }
}
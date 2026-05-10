package nb.ravenedge

import kotlinx.coroutines.*
import java.io.File
import java.net.InetAddress
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import kotlin.system.exitProcess
import com.google.common.hash.Hashing

/**
 * Main entry point for the Raven Edge VPN.
 */
fun main(args: Array<String>) = runBlocking {
    // ==================== 1. KEY GENERATION ====================
    // Usage: java -jar ravenedge.jar --genkey
    // Prints ready-to-use PrivateKey + PublicKey (exactly like "wg genkey" + "wg pubkey")
    if (args.contains("--genkey") || args.contains("-genkey")) {
        val (privateKey, publicKey) = generateKeyPair()           // from Cryptography.kt
        println("PrivateKey = ${privateKey.toBase64()}")
        println("PublicKey  = ${publicKey.toBase64()}")
        exitProcess(0)
    }

    // ==================== 2. LOGGING SETUP ====================
    val logLevelStr = args.firstOrNull { it.startsWith("--log-level=") }?.substringAfter("=") ?: "info"
    val logFileArg = args.firstOrNull { it.startsWith("--log-to-file=") }?.substringAfter("=")
    val disableStats = args.contains("--disable-stats") || args.contains("--no-stats")

    System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", logLevelStr.lowercase())

    try {
        Logger.globalLevel = LogLevel.valueOf(logLevelStr.uppercase())
    } catch (e: Exception) {
        println("Invalid log level '$logLevelStr', defaulting to INFO.")
        Logger.globalLevel = LogLevel.INFO
    }

    if (logFileArg != null) {
        val file = File(logFileArg).absoluteFile
        file.parentFile?.mkdirs()
        if (!file.exists()) file.createNewFile()
        Logger.logFile = file
    }

    val logger = Logger.getLogger("MainRavenEdge")
    logger.info("========================================================")
    logger.info("= Starting Raven Edge Node")
    logger.info("= Version: 1.0.9")
    logger.info("= Log Level: ${Logger.globalLevel}")
    if (Logger.logFile != null) logger.info("= Logging to: ${Logger.logFile?.absolutePath}")
    logger.info("RavenEdge by NanoBee Corporation")
    logger.info("========================================================")

    // ==================== 3. CONFIG FILE & HOT-RELOAD SETUP ====================
    val configFile = args.firstOrNull { !it.startsWith("--") } ?: "wg0.conf"
    val configFileFile = File(configFile)

    if (!configFileFile.exists()) {
        logger.error("Configuration file not found at '$configFile'.")
        logger.error("Usage: java -jar ravenedge.jar [path/to/config.conf] [--genkey] [--hot-reload] [--disable-stats] [--log-to-file=app.log]")
        exitProcess(1)
    }
    logger.info("Using configuration file: $configFile")

    val interfaceName = configFileFile.nameWithoutExtension
    val hotReload = args.contains("--hot-reload")
    val scanInterval = args.firstOrNull { it.startsWith("--config-scan=") }
        ?.substringAfter("=")?.toLongOrNull() ?: 60L

    var device: TunDevice? = null
    var node: Node? = null

    try {
        val (ifaceConfig, peerConfigs) = Config.parse(configFile)

        val tunDevice = LinuxTunDevice(interfaceName, ifaceConfig)
        device = tunDevice
        tunDevice.up()

        node = Node(ifaceConfig, peerConfigs, tunDevice, interfaceName, !disableStats)

        Runtime.getRuntime().addShutdownHook(
            Thread {
                logger.info("Shutdown signal received. Stopping VPN node...")
                runBlocking { node?.stop() }
                logger.info("VPN node shutdown procedures complete.")
            }
        )

        // ==================== 4. HOT-RELOAD WITH MURMUR3_128 HASH ====================
        if (hotReload) {
            logger.info("Hot-Reload enabled. Scanning $configFile every $scanInterval seconds.")

            val hasher = Hashing.murmur3_128()

            launch(Dispatchers.IO) {
                var lastHash = hasher.hashBytes(configFileFile.readBytes())

                while (isActive) {
                    delay(scanInterval * 1000L)
                    try {
                        val currentHash = hasher.hashBytes(configFileFile.readBytes())

                        if (currentHash != lastHash) {
                            logger.info("Configuration change detected. Hot-reloading peers...")
                            val (_, newPeerConfigs) = Config.parse(configFile)
                            node?.reloadPeers(newPeerConfigs)
                            lastHash = currentHash
                            logger.info("Hot-reload complete.")
                        }
                    } catch (e: Exception) {
                        logger.error("Failed to hot-reload config. Retrying on next cycle.", e)
                    }
                }
            }
        }

        // ==================== 5. START THE NODE ====================
        node.start()

    } catch (e: Exception) {
        if (e !is CancellationException) {
            logger.error("A critical error has forced the node to stop.", e)
        }
    } finally {
        logger.info("Cleaning up TUN device...")
        device?.down()
        logger.info("Application has shut down.")
    }
}

// --- Utility ---

enum class LogLevel(val weight: Int) {
    TRACE(0), DEBUG(1), INFO(2), WARN(3), ERROR(4)
}

class Logger(private val name: String) {
    private val slf4j = org.slf4j.LoggerFactory.getLogger(name)

    private fun log(level: LogLevel, msg: String, e: Throwable? = null, logAction: () -> Unit) {
        if (level.weight >= globalLevel.weight) {
            logAction()
            logToFile(level, name, msg, e)
        }
    }

    fun trace(msg: String) = log(LogLevel.TRACE, msg) { slf4j.trace(msg) }
    fun debug(msg: String) = log(LogLevel.DEBUG, msg) { slf4j.debug(msg) }
    fun info(msg: String) = log(LogLevel.INFO, msg) { slf4j.info(msg) }
    fun warn(msg: String) = log(LogLevel.WARN, msg) { slf4j.warn(msg) }
    fun error(msg: String, e: Throwable? = null) = log(LogLevel.ERROR, msg, e) { slf4j.error(msg, e) }

    companion object {
        var globalLevel = LogLevel.INFO
        var logFile: File? = null
        private val lock = Any()
        private val formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS")

        fun getLogger(name: String) = Logger(name)

        private fun logToFile(level: LogLevel, name: String, msg: String, e: Throwable?) {
            logFile?.let { file ->
                synchronized(lock) {
                    try {
                        val timestamp = LocalDateTime.now().format(formatter)
                        val errorStr = e?.let { "\n" + it.stackTraceToString() } ?: ""
                        file.appendText("[$timestamp] [$level] [$name] - $msg$errorStr\n")
                    } catch (ignored: Exception) {
                        // Ignore file write errors to prevent crashing the main application loop
                    }
                }
            }
        }
    }
}

object IPPacketUtils {
    fun getDestinationAddress(packet: ByteArray, length: Int = packet.size): InetAddress? {
        if (length <= 0 || packet.isEmpty()) return null
        val version = (packet[0].toInt() shr 4) and 0xF
        return try {
            when (version) {
                4 -> {
                    if (length < 20) return null
                    InetAddress.getByAddress(packet.copyOfRange(16, 20))
                }
                6 -> {
                    if (length < 40) return null
                    InetAddress.getByAddress(packet.copyOfRange(24, 40))
                }
                else -> null
            }
        } catch (e: Exception) { null }
    }

    fun getSourceAddress(packet: ByteArray, length: Int = packet.size): InetAddress? {
        if (length <= 0 || packet.isEmpty()) return null
        val version = (packet[0].toInt() shr 4) and 0xF
        return try {
            when (version) {
                4 -> {
                    if (length < 20) return null
                    InetAddress.getByAddress(packet.copyOfRange(12, 16))
                }
                6 -> {
                    if (length < 40) return null
                    InetAddress.getByAddress(packet.copyOfRange(8, 24))
                }
                else -> null
                //Let me know when smart bulbs and other IoT nonsense will run out of
                //340 undecillion ipv6 addresses and some ipv8 will come out
            }
        } catch (e: Exception) { null }
    }
}

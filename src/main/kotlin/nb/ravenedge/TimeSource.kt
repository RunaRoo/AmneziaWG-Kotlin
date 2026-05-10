package nb.ravenedge

import com.google.common.base.Ticker
import java.util.concurrent.TimeUnit

//SUPER Update:
//Now we have separate timer for protocol handling
//System time used in Tai64n and log messages
//Implemented with Guava
object ProtocolClock {
    private val ticker: Ticker = Ticker.systemTicker()

    fun monotonicMillis(): Long = TimeUnit.NANOSECONDS.toMillis(ticker.read())
}

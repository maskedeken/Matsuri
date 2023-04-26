package moe.matsuri.nya

import android.content.Context
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.database.ProxyEntity.Companion.TYPE_NEKO
import io.nekohasekai.sagernet.fmt.AbstractBean
import io.nekohasekai.sagernet.ktx.app
import io.nekohasekai.sagernet.ktx.getColorAttr
import moe.matsuri.nya.neko.NekoPluginManager

// Settings for all protocols, built-in or plugin
object Protocols {
    // Mux

    fun shouldEnableMux(protocol: String): Boolean {
        return DataStore.muxProtocols.contains(protocol)
    }

    fun getCanMuxList(): List<String> {
        // built-in and support mux
        val list = mutableListOf("vmess", "trojan", "trojan-go")

        NekoPluginManager.getProtocols().forEach {
            if (it.protocolConfig.optBoolean("canMux")) {
                list.add(it.protocolId)
            }
        }

        return list
    }

    // Deduplication

    class Deduplication(
        val bean: AbstractBean, val type: String
    ) {

        fun hash(): String {
            return bean.serverAddress + bean.serverPort + type
        }

        override fun hashCode(): Int {
            return hash().toByteArray().contentHashCode()
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false

            other as Deduplication

            return hash() == other.hash()
        }

    }

    // Display

    fun Context.getProtocolColor(type: Int): Int {
        return when (type) {
            TYPE_NEKO -> getColorAttr(android.R.attr.textColorPrimary)
            else -> getColorAttr(R.attr.accentOrTextSecondary)
        }
    }

    // Test

    fun genFriendlyMsg(msg: String): String {
        val msgL = msg.lowercase()
        return when {
            msgL.contains("timeout") || msgL.contains("deadline") -> {
                app.getString(R.string.connection_test_timeout)
            }
            msgL.contains("refused") || msgL.contains("closed pipe") -> {
                app.getString(R.string.connection_test_refused)
            }
            else -> msg
        }
    }

}
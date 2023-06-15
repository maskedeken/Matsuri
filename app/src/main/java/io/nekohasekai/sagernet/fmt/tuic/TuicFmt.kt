/******************************************************************************
 * Copyright (C) 2022 by nekohasekai <contact-git@sekai.icu>                  *
 *                                                                            *
 * This program is free software: you can redistribute it and/or modify       *
 * it under the terms of the GNU General Public License as published by       *
 * the Free Software Foundation, either version 3 of the License, or          *
 *  (at your option) any later version.                                       *
 *                                                                            *
 * This program is distributed in the hope that it will be useful,            *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of             *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the              *
 * GNU General Public License for more details.                               *
 *                                                                            *
 * You should have received a copy of the GNU General Public License          *
 * along with this program. If not, see <http://www.gnu.org/licenses/>.       *
 *                                                                            *
 ******************************************************************************/

package io.nekohasekai.sagernet.fmt.tuic

import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.fmt.LOCALHOST
import io.nekohasekai.sagernet.ktx.isIpAddress
import io.nekohasekai.sagernet.ktx.toStringPretty
import io.nekohasekai.sagernet.ktx.wrapIPV6Host
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import moe.matsuri.nya.neko.Plugins
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.net.InetAddress

fun TuicBean.pluginId(): String {
    return when (protocolVersion) {
        5 -> "tuic-v5-plugin"
        else -> "tuic-plugin"
    }
}

fun TuicBean.buildTuicConfig(port: Int, cacheFile: (() -> File)?): String {
    if (Plugins.isUsingMatsuriExe(pluginId())) {
        if (!serverAddress.isIpAddress()) {
            runBlocking {
                finalAddress = withContext(Dispatchers.IO) {
                    InetAddress.getAllByName(serverAddress)
                }?.firstOrNull()?.hostAddress ?: "127.0.0.1"
                // TODO network on main thread, tuic don't support "sni"
            }
        }
    }
    return when (protocolVersion) {
        5 -> buildTuicConfigV5(port, cacheFile)
        else -> buildTuicConfigV4(port, cacheFile)
    }.toStringPretty()
}

fun TuicBean.buildTuicConfigV5(port: Int, cacheFile: (() -> File)?): JSONObject {
    return JSONObject().apply {
        put("relay", JSONObject().apply {
            if (sni.isNotBlank() && !disableSNI) {
                put("server", "$sni:$finalPort")
                put("ip", finalAddress)
            } else if (!serverAddress.isIpAddress()) {
                put("server", "$serverAddress:$finalPort")
                put("ip", finalAddress)
            } else {
                put("server", finalAddress.wrapIPV6Host() + ":" + finalPort)
            }

            put("uuid", uuid)
            put("password", token)

            if (caText.isNotBlank() && cacheFile != null) {
                val caFile = cacheFile()
                caFile.writeText(caText)
                put("certificates", JSONArray(listOf(caFile.absolutePath)))
            }

            put("udp_relay_mode", udpRelayMode)
            if (alpn.isNotBlank()) {
                put("alpn", JSONArray(alpn.split("\n")))
            }
            put("congestion_control", congestionController)
            put("disable_sni", disableSNI)
            put("zero_rtt_handshake", reduceRTT)
            if (allowInsecure) put("allow_insecure", true)
        })
        put("local", JSONObject().apply {
            put("server", "127.0.0.1:$port")
        })
        put("log_level", if (DataStore.enableLog) "debug" else "info")
    }
}

fun TuicBean.buildTuicConfigV4(port: Int, cacheFile: (() -> File)?): JSONObject {
    return JSONObject().apply {
        put("relay", JSONObject().apply {
            if (sni.isNotBlank() && !disableSNI) {
                put("server", sni)
                put("ip", finalAddress)
            } else if (!serverAddress.isIpAddress()) {
                put("server", serverAddress)
                put("ip", finalAddress)
            } else {
                put("server", finalAddress)
            }
            put("port", finalPort)
            put("token", token)

            if (caText.isNotBlank() && cacheFile != null) {
                val caFile = cacheFile()
                caFile.writeText(caText)
                put("certificates", JSONArray(listOf(caFile.absolutePath)))
            }

            put("udp_relay_mode", udpRelayMode)
            if (alpn.isNotBlank()) {
                put("alpn", JSONArray(alpn.split("\n")))
            }
            put("congestion_controller", congestionController)
            put("disable_sni", disableSNI)
            put("reduce_rtt", reduceRTT)
            put("max_udp_relay_packet_size", mtu)
            if (fastConnect) put("fast_connect", true)
            if (allowInsecure) put("insecure", true)
        })
        put("local", JSONObject().apply {
            put("ip", LOCALHOST)
            put("port", port)
        })
        put("log_level", if (DataStore.enableLog) "debug" else "info")
    }
}
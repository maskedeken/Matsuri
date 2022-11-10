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

package io.nekohasekai.sagernet.fmt.mieru

import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.ktx.toStringPretty
import org.json.JSONArray
import org.json.JSONObject

fun MieruBean.buildMieruConfig(port: Int): String {
    return JSONObject().apply {
        put("activeProfile", "default")
        put("socks5Port", port);
        put("loggingLevel", if (DataStore.enableLog) "DEBUG" else "WARN");
        put("profiles", JSONArray().apply {
            put(JSONObject().apply {
                put("profileName", "default")
                put("user", JSONObject().apply {
                    put("name", username)
                    put("password", password)
                })

                put("servers", JSONArray().apply {
                    put(JSONObject().apply {
                        put("ipAddress", finalAddress)
                        put("portBindings", JSONArray().apply {
                            put(JSONObject().apply {
                                put("port", finalPort)
                                when (protocol) {
                                    MieruBean.PROTOCOL_TCP -> {
                                        put("protocol", "TCP")
                                    }
                                    MieruBean.PROTOCOL_UDP -> {
                                        put("protocol", "UDP")
                                    }
                                    else -> error("unexpected protocol $protocol")
                                }
                            })
                        })
                    })
                })
            })
        })
    }.toStringPretty()
}
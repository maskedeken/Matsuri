/******************************************************************************
 *                                                                            *
 * Copyright (C) 2021 by nekohasekai <contact-sagernet@sekai.icu>             *
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

package io.nekohasekai.sagernet.group

import android.net.Uri
import com.github.shadowsocks.plugin.PluginOptions
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.database.*
import io.nekohasekai.sagernet.fmt.AbstractBean
import io.nekohasekai.sagernet.fmt.gson.gson
import io.nekohasekai.sagernet.fmt.http.HttpBean
import io.nekohasekai.sagernet.fmt.hysteria.parseHysteria
import io.nekohasekai.sagernet.fmt.shadowsocks.ShadowsocksBean
import io.nekohasekai.sagernet.fmt.shadowsocks.fixInvalidParams
import io.nekohasekai.sagernet.fmt.shadowsocks.parseShadowsocks
import io.nekohasekai.sagernet.fmt.shadowsocksr.ShadowsocksRBean
import io.nekohasekai.sagernet.fmt.shadowsocksr.parseShadowsocksR
import io.nekohasekai.sagernet.fmt.socks.SOCKSBean
import io.nekohasekai.sagernet.fmt.trojan.TrojanBean
import io.nekohasekai.sagernet.fmt.trojan_go.parseTrojanGo
import io.nekohasekai.sagernet.fmt.v2ray.V2RayConfig
import io.nekohasekai.sagernet.fmt.v2ray.VMessBean
import io.nekohasekai.sagernet.fmt.wireguard.WireGuardBean
import io.nekohasekai.sagernet.ktx.*
import libcore.Libcore
import moe.matsuri.nya.Protocols
import org.ini4j.Ini
import org.json.JSONArray
import org.json.JSONObject
import org.json.JSONTokener
import org.yaml.snakeyaml.TypeDescription
import org.yaml.snakeyaml.Yaml
import org.yaml.snakeyaml.error.YAMLException
import java.io.StringReader

@Suppress("EXPERIMENTAL_API_USAGE")
object RawUpdater : GroupUpdater() {

    override suspend fun doUpdate(
        proxyGroup: ProxyGroup,
        subscription: SubscriptionBean,
        userInterface: GroupManager.Interface?,
        byUser: Boolean
    ) {

        val link = subscription.link
        var proxies: List<AbstractBean>
        if (link.startsWith("content://")) {
            val contentText = app.contentResolver.openInputStream(Uri.parse(link))
                ?.bufferedReader()
                ?.readText()

            proxies = contentText?.let { parseRaw(contentText) }
                ?: error(app.getString(R.string.no_proxies_found_in_subscription))
        } else {

            val response = Libcore.newHttpClient().apply {
                trySocks5(DataStore.socksPort)
                when (DataStore.appTLSVersion) {
                    "1.3" -> restrictedTLS()
                }
            }.newRequest().apply {
                setURL(subscription.link)
                setUserAgent(subscription.customUserAgent.takeIf { it.isNotBlank() } ?: USER_AGENT)
            }.execute()

            proxies = parseRaw(response.contentString)
                ?: error(app.getString(R.string.no_proxies_found))

            subscription.subscriptionUserinfo = response.getHeader("Subscription-Userinfo")
        }

        val proxiesMap = LinkedHashMap<String, AbstractBean>()
        for (proxy in proxies) {
            var index = 0
            var name = proxy.displayName()
            while (proxiesMap.containsKey(name)) {
                println("Exists name: $name")
                index++
                name = name.replace(" (${index - 1})", "")
                name = "$name ($index)"
                proxy.name = name
            }
            proxiesMap[proxy.displayName()] = proxy
        }
        proxies = proxiesMap.values.toList()

        if (subscription.forceResolve) forceResolve(proxies, proxyGroup.id)

        val exists = SagerDatabase.proxyDao.getByGroup(proxyGroup.id)
        val duplicate = ArrayList<String>()
        if (subscription.deduplication) {
            Logs.d("Before deduplication: ${proxies.size}")
            val uniqueProxies = LinkedHashSet<Protocols.Deduplication>()
            val uniqueNames = HashMap<Protocols.Deduplication, String>()
            for (_proxy in proxies) {
                val proxy = Protocols.Deduplication(_proxy, _proxy.javaClass.toString())
                if (!uniqueProxies.add(proxy)) {
                    val index = uniqueProxies.indexOf(proxy)
                    if (uniqueNames.containsKey(proxy)) {
                        val name = uniqueNames[proxy]!!.replace(" ($index)", "")
                        if (name.isNotBlank()) {
                            duplicate.add("$name ($index)")
                            uniqueNames[proxy] = ""
                        }
                    }
                    duplicate.add(_proxy.displayName() + " ($index)")
                } else {
                    uniqueNames[proxy] = _proxy.displayName()
                }
            }
            uniqueProxies.retainAll(uniqueNames.keys)
            proxies = uniqueProxies.toList().map { it.bean }
        }

        Logs.d("New profiles: ${proxies.size}")

        val nameMap = proxies.associateBy { bean ->
            bean.displayName()
        }

        Logs.d("Unique profiles: ${nameMap.size}")

        val toDelete = ArrayList<ProxyEntity>()
        val toReplace = exists.mapNotNull { entity ->
            val name = entity.displayName()
            if (nameMap.contains(name)) name to entity else let {
                toDelete.add(entity)
                null
            }
        }.toMap()

        Logs.d("toDelete profiles: ${toDelete.size}")
        Logs.d("toReplace profiles: ${toReplace.size}")

        val toUpdate = ArrayList<ProxyEntity>()
        val added = mutableListOf<String>()
        val updated = mutableMapOf<String, String>()
        val deleted = toDelete.map { it.displayName() }

        var userOrder = 1L
        var changed = toDelete.size
        for ((name, bean) in nameMap.entries) {
            if (toReplace.contains(name)) {
                val entity = toReplace[name]!!
                val existsBean = entity.requireBean()
                existsBean.applyFeatureSettings(bean)
                when {
                    existsBean != bean -> {
                        changed++
                        entity.putBean(bean)
                        toUpdate.add(entity)
                        updated[entity.displayName()] = name

                        Logs.d("Updated profile: $name")
                    }
                    entity.userOrder != userOrder -> {
                        entity.putBean(bean)
                        toUpdate.add(entity)
                        entity.userOrder = userOrder

                        Logs.d("Reordered profile: $name")
                    }
                    else -> {
                        Logs.d("Ignored profile: $name")
                    }
                }
            } else {
                changed++
                SagerDatabase.proxyDao.addProxy(ProxyEntity(
                    groupId = proxyGroup.id, userOrder = userOrder
                ).apply {
                    putBean(bean)
                })
                added.add(name)
                Logs.d("Inserted profile: $name")
            }
            userOrder++
        }

        SagerDatabase.proxyDao.updateProxy(toUpdate).also {
            Logs.d("Updated profiles: $it")
        }

        SagerDatabase.proxyDao.deleteProxy(toDelete).also {
            Logs.d("Deleted profiles: $it")
        }

        val existCount = SagerDatabase.proxyDao.countByGroup(proxyGroup.id).toInt()

        if (existCount != proxies.size) {
            Logs.e("Exist profiles: $existCount, new profiles: ${proxies.size}")
        }

        subscription.lastUpdated = (System.currentTimeMillis() / 1000).toInt()
        SagerDatabase.groupDao.updateGroup(proxyGroup)
        finishUpdate(proxyGroup)

        userInterface?.onUpdateSuccess(
            proxyGroup, changed, added, updated, deleted, duplicate, byUser
        )
    }

    @Suppress("UNCHECKED_CAST")
    suspend fun parseRaw(text: String): List<AbstractBean>? {

        val proxies = mutableListOf<AbstractBean>()

        if (text.contains("proxies:")) {

            try {

                // clash
                for (proxy in (Yaml().apply {
                    addTypeDescription(TypeDescription(String::class.java, "str"))
                }.loadAs(text, Map::class.java)["proxies"] as? (List<Map<String, Any?>>) ?: error(
                    app.getString(R.string.no_proxies_found_in_file)
                ))) {
                    // Note: YAML numbers parsed as "Long"

                    when (proxy["type"] as String) {
                        "socks5" -> {
                            proxies.add(SOCKSBean().apply {
                                serverAddress = proxy["server"] as String
                                serverPort = proxy["port"].toString().toInt()
                                username = proxy["username"]?.toString()
                                password = proxy["password"]?.toString()
                                setTLS(proxy["tls"]?.toString() == "true")
                                sni = proxy["sni"]?.toString()
                                name = proxy["name"]?.toString()
                            })
                        }
                        "http" -> {
                            proxies.add(HttpBean().apply {
                                serverAddress = proxy["server"] as String
                                serverPort = proxy["port"].toString().toInt()
                                username = proxy["username"]?.toString()
                                password = proxy["password"]?.toString()
                                setTLS(proxy["tls"]?.toString() == "true")
                                sni = proxy["sni"]?.toString()
                                name = proxy["name"]?.toString()
                            })
                        }
                        "ss" -> {
                            var pluginStr = ""
                            if (proxy.contains("plugin")) {
                                val opts = proxy["plugin-opts"] as Map<String, Any?>
                                val pluginOpts = PluginOptions()
                                fun put(clash: String, origin: String = clash) {
                                    opts[clash]?.let {
                                        pluginOpts[origin] = it.toString()
                                    }
                                }
                                when (proxy["plugin"]) {
                                    "obfs" -> {
                                        pluginOpts.id = "obfs-local"
                                        put("mode", "obfs")
                                        put("host", "obfs-host")
                                    }
                                    "v2ray-plugin" -> {
                                        pluginOpts.id = "v2ray-plugin"
                                        put("mode")
                                        if (opts["tls"]?.toString() == "true") {
                                            pluginOpts["tls"] = null
                                        }
                                        put("host")
                                        put("path")
                                        if (opts["mux"]?.toString() == "true") {
                                            pluginOpts["mux"] = "8"
                                        }
                                    }
                                }
                                pluginStr = pluginOpts.toString(false)
                            }
                            proxies.add(ShadowsocksBean().apply {
                                serverAddress = proxy["server"] as String
                                serverPort = proxy["port"].toString().toInt()
                                password = proxy["password"]?.toString()
                                method = clashCipher(proxy["cipher"] as String)
                                plugin = pluginStr
                                name = proxy["name"]?.toString()

                                fixInvalidParams()
                            })
                        }
                        "vmess" -> {
                            val bean = VMessBean()
                            for (opt in proxy) {
                                when (opt.key) {
                                    "name" -> bean.name = opt.value?.toString()
                                    "server" -> bean.serverAddress = opt.value as String
                                    "port" -> bean.serverPort = opt.value.toString().toInt()
                                    "uuid" -> bean.uuid = opt.value as String
                                    "alterId" -> bean.alterId = opt.value.toString().toInt()
                                    "cipher" -> bean.encryption = opt.value as String
                                    "network" -> {
                                        bean.type = opt.value as String
                                        // Clash "network" fix
                                        when (bean.type) {
                                            "http" -> {
                                                bean.type = "tcp"
                                                bean.headerType = "http"
                                            }
                                            "h2" -> bean.type = "http"
                                        }
                                    }
                                    "tls" -> bean.security =
                                        if (opt.value?.toString() == "true") "tls" else ""
                                    "skip-cert-verify" -> bean.allowInsecure =
                                        opt.value?.toString() == "true"
                                    "ws-path" -> bean.path = opt.value?.toString()
                                    "ws-headers" -> for (wsHeader in (opt.value as Map<String, Any>)) {
                                        when (wsHeader.key.lowercase()) {
                                            "host" -> bean.host = wsHeader.value.toString()
                                        }
                                    }
                                    "ws-opts", "ws-opt" -> for (wsOpt in (opt.value as Map<String, Any>)) {
                                        when (wsOpt.key.lowercase()) {
                                            "headers" -> for (wsHeader in (wsOpt.value as Map<String, Any>)) {
                                                when (wsHeader.key.lowercase()) {
                                                    "host" -> bean.host = wsHeader.value.toString()
                                                }
                                            }
                                            "path" -> {
                                                bean.path = wsOpt.value.toString()
                                            }
                                            "max-early-data" -> {
                                                bean.wsMaxEarlyData = wsOpt.value.toString().toInt()
                                            }
                                            "early-data-header-name" -> {
                                                bean.earlyDataHeaderName = wsOpt.value.toString()
                                            }
                                        }
                                    }
                                    "servername" -> bean.host = opt.value?.toString()
                                    // The format of the VMessBean is wrong, so the `host` `path` has some strange transformations here.
                                    "h2-opts", "h2-opt" -> for (h2Opt in (opt.value as Map<String, Any>)) {
                                        when (h2Opt.key.lowercase()) {
                                            "host" -> bean.host =
                                                (h2Opt.value as List<String>).first()
                                            "path" -> bean.path = h2Opt.value.toString()
                                        }
                                    }
                                    "http-opts", "http-opt" -> for (httpOpt in (opt.value as Map<String, Any>)) {
                                        when (httpOpt.key.lowercase()) {
                                            "path" -> bean.path =
                                                (httpOpt.value as List<String>).first()
                                            "headers" -> for (hdr in (httpOpt.value as Map<String, Any>)) {
                                                when (hdr.key.lowercase()) {
                                                    "host" -> bean.host =
                                                        (hdr.value as List<String>).first()
                                                }
                                            }
                                        }
                                    }
                                    "grpc-opts", "grpc-opt" -> for (grpcOpt in (opt.value as Map<String, Any>)) {
                                        when (grpcOpt.key.lowercase()) {
                                            "grpc-service-name" -> bean.grpcServiceName =
                                                grpcOpt.value.toString()
                                        }
                                    }
                                }
                            }
                            if (bean.isTLS() && bean.sni.isNullOrBlank() && !bean.host.isNullOrBlank()) {
                                bean.sni = bean.host
                            }
                            proxies.add(bean)
                        }
                        "trojan" -> {
                            val bean = TrojanBean()
                            bean.security = "tls"
                            for (opt in proxy) {
                                when (opt.key) {
                                    "name" -> bean.name = opt.value?.toString()
                                    "server" -> bean.serverAddress = opt.value as String
                                    "port" -> bean.serverPort = opt.value.toString().toInt()
                                    "password" -> bean.password = opt.value?.toString()
                                    "sni" -> bean.sni = opt.value?.toString()
                                    "skip-cert-verify" -> bean.allowInsecure =
                                        opt.value?.toString() == "true"
                                    "network" -> when (opt.value) {
                                        "ws", "grpc" -> bean.type = opt.value?.toString()
                                    }
                                    "ws-opts", "ws-opt" -> for (wsOpt in (opt.value as Map<String, Any>)) {
                                        when (wsOpt.key.lowercase()) {
                                            "headers" -> for (wsHeader in (wsOpt.value as Map<String, Any>)) {
                                                when (wsHeader.key.lowercase()) {
                                                    "host" -> bean.host = wsHeader.value.toString()
                                                }
                                            }
                                            "path" -> {
                                                bean.path = wsOpt.value.toString()
                                            }
                                        }
                                    }
                                    "grpc-opts", "grpc-opt" -> for (grpcOpt in (opt.value as Map<String, Any>)) {
                                        when (grpcOpt.key.lowercase()) {
                                            "grpc-service-name" -> bean.grpcServiceName =
                                                grpcOpt.value.toString()
                                        }
                                    }
                                }
                            }
                            proxies.add(bean)
                        }

                        "ssr" -> {
                            val entity = ShadowsocksRBean()
                            for (opt in proxy) {
                                when (opt.key) {
                                    "name" -> entity.name = opt.value?.toString()
                                    "server" -> entity.serverAddress = opt.value as String
                                    "port" -> entity.serverPort = opt.value.toString().toInt()
                                    "cipher" -> entity.method = clashCipher(opt.value as String)
                                    "password" -> entity.password = opt.value?.toString()
                                    "obfs" -> entity.obfs = opt.value as String
                                    "protocol" -> entity.protocol = opt.value as String
                                    "obfs-param" -> entity.obfsParam = opt.value?.toString()
                                    "protocol-param" -> entity.protocolParam = opt.value?.toString()
                                }
                            }
                            proxies.add(entity)
                        }
                    }
                }
                proxies.forEach { it.initializeDefaultValues() }
                return proxies
            } catch (e: YAMLException) {
                Logs.w(e)
            }
        } else if (text.contains("[Interface]")) {
            // wireguard
            try {
                proxies.addAll(parseWireGuard(text))
                return proxies
            } catch (e: Exception) {
                Logs.w(e)
            }
        }

        try {
            val json = JSONTokener(text).nextValue()
            return parseJSON(json)
        } catch (ignored: Exception) {
        }

        try {
            return parseProxies(text.decodeBase64UrlSafe()).takeIf { it.isNotEmpty() }
                ?: error("Not found")
        } catch (e: Exception) {
            Logs.w(e)
        }

        try {
            return parseProxies(text).takeIf { it.isNotEmpty() } ?: error("Not found")
        } catch (e: SubscriptionFoundException) {
            throw e
        } catch (ignored: Exception) {
        }

        return null
    }

    fun clashCipher(cipher: String): String {
        return when (cipher) {
            "dummy" -> "none"
            else -> cipher
        }
    }

    fun parseWireGuard(conf: String): List<WireGuardBean> {
        val ini = Ini(StringReader(conf))
        val iface = ini["Interface"] ?: error("Missing 'Interface' selection")
        val bean = WireGuardBean().applyDefaultValues()
        val localAddresses = iface.getAll("Address")
        if (localAddresses.isNullOrEmpty()) error("Empty address in 'Interface' selection")
        bean.localAddress = localAddresses.flatMap { it.split(",") }.let { address ->
            address.joinToString("\n") { it.substringBefore("/") }
        }
        bean.privateKey = iface["PrivateKey"]
        bean.mtu = iface["MTU"]?.toIntOrNull()
        val peers = ini.getAll("Peer")
        if (peers.isNullOrEmpty()) error("Missing 'Peer' selections")
        val beans = mutableListOf<WireGuardBean>()
        for (peer in peers) {
            val endpoint = peer["Endpoint"]
            if (endpoint.isNullOrBlank() || !endpoint.contains(":")) {
                continue
            }

            val peerBean = bean.clone()
            peerBean.serverAddress = endpoint.substringBeforeLast(":")
            peerBean.serverPort = endpoint.substringAfterLast(":").toIntOrNull() ?: continue
            peerBean.peerPublicKey = peer["PublicKey"] ?: continue
            peerBean.peerPreSharedKey = peer["PresharedKey"]
            beans.add(peerBean.applyDefaultValues())
        }
        if (beans.isEmpty()) error("Empty available peer list")
        return beans
    }

    fun parseJSON(json: Any): List<AbstractBean> {
        val proxies = ArrayList<AbstractBean>()

        if (json is JSONObject) {
            when {
                json.has("server") && (json.has("up") || json.has("up_mbps")) -> {
                    return listOf(json.parseHysteria())
                }
                json.has("protocol_param") -> {
                    return listOf(json.parseShadowsocksR())
                }
                json.has("method") -> {
                    return listOf(json.parseShadowsocks())
                }
                json.has("protocol") -> {
                    val v2rayConfig = gson.fromJson(
                        json.toString(), V2RayConfig.OutboundObject::class.java
                    ).apply { init() }
                    return parseOutbound(v2rayConfig)
                }
                json.has("outbound") -> {
                    val v2rayConfig = gson.fromJson(
                        json.getJSONObject("outbound").toString(),
                        V2RayConfig.OutboundObject::class.java
                    ).apply { init() }
                    return parseOutbound(v2rayConfig)
                }
                json.has("outbounds") -> {/*   val fakedns = json["fakedns"]
                       if (fakedns is JSONObject) {
                           json["fakedns"] = JSONArray().apply {
                               add(fakedns)
                           }
                       }

                       val routing = json["routing"]
                       if (routing is JSONObject) {
                           val rules = routing["rules"]
                           if (rules is JSONArray) {
                               rules.filterIsInstance<JSONObject>().forEach {
                                   val inboundTag = it["inboundTag"]
                                   if (inboundTag is String) {
                                       it["inboundTag"] = JSONArray().apply {
                                           add(inboundTag)
                                       }
                                   }
                               }
                           }
                       }

                       try {
                           gson.fromJson(
                               json.toString(),
                               V2RayConfig::class.java
                           ).apply { init() }
                       } catch (e: Exception) {
                           Logs.w(e)*/
                    json.getJSONArray("outbounds").filterIsInstance<JSONObject>().forEach {
                        val v2rayConfig = gson.fromJson(
                            it.toString(), V2RayConfig.OutboundObject::class.java
                        ).apply { init() }

                        proxies.addAll(parseOutbound(v2rayConfig))
                    }/* null
                 }?.outbounds?.forEach {
                     proxies.addAll(parseOutbound(it))
                 }*/
                }
                json.has("remote_addr") -> {
                    return listOf(json.parseTrojanGo())
                }
                else -> json.forEach { _, it ->
                    if (isJsonObjectValid(it)) {
                        proxies.addAll(parseJSON(it))
                    }
                }
            }
        } else {
            json as JSONArray
            json.forEach { _, it ->
                if (isJsonObjectValid(it)) {
                    proxies.addAll(parseJSON(it))
                }
            }
        }

        proxies.forEach { it.initializeDefaultValues() }
        return proxies
    }

    fun parseOutbound(outboundObject: V2RayConfig.OutboundObject): List<AbstractBean> {
        val proxies = ArrayList<AbstractBean>()

        with(outboundObject) {
            when (protocol) {
                "http" -> {
                    val httpBean = HttpBean().applyDefaultValues()
                    streamSettings?.apply {
                        when (security) {
                            "tls" -> {
                                httpBean.setTLS(true)
                                tlsSettings?.serverName?.also {
                                    httpBean.sni = it
                                }
                            }
                        }
                    }
                    (settings.value as? V2RayConfig.HTTPOutboundConfigurationObject)?.servers?.forEach {
                        val httpBeanNext = httpBean.clone().apply {
                            serverAddress = it.address
                            serverPort = it.port
                        }
                        if (it.users.isNullOrEmpty()) {
                            proxies.add(httpBeanNext)
                        } else for (user in it.users) proxies.add(httpBeanNext.clone().apply {
                            username = user.user
                            password = user.pass
                            name = tag ?: (displayName() + " - $username")
                        })
                    }
                }
                "socks" -> {
                    val socksBean = SOCKSBean().applyDefaultValues()
                    streamSettings?.apply {
                        when (security) {
                            "tls" -> {
                                socksBean.setTLS(true)
                                tlsSettings?.serverName?.also {
                                    socksBean.sni = it
                                }
                            }
                        }
                    }
                    (settings.value as? V2RayConfig.SocksOutboundConfigurationObject)?.servers?.forEach {
                        val socksBeanNext = socksBean.clone().apply {
                            serverAddress = it.address
                            serverPort = it.port
                        }
                        if (it.users.isNullOrEmpty()) {
                            proxies.add(socksBeanNext)
                        } else for (user in it.users) proxies.add(socksBeanNext.clone().apply {
                            username = user.user
                            password = user.pass
                            name = tag ?: (displayName() + " - $username")
                        })
                    }
                }
                "vmess" -> {
                    val v2rayBean = VMessBean().applyDefaultValues()
                    streamSettings?.apply {
                        v2rayBean.security = security ?: v2rayBean.security
                        when (security) {
                            "tls" -> {
                                tlsSettings?.apply {
                                    serverName?.also {
                                        v2rayBean.sni = it
                                    }
                                    alpn?.also {
                                        v2rayBean.alpn = it.joinToString(",")
                                    }
                                    allowInsecure?.also {
                                        v2rayBean.allowInsecure = it
                                    }
                                }
                            }
                        }
                        v2rayBean.type = network ?: v2rayBean.type
                        when (network) {
                            "tcp" -> {
                                tcpSettings?.header?.apply {
                                    when (type) {
                                        "http" -> {
                                            v2rayBean.headerType = "http"
                                            request?.apply {
                                                path?.also {
                                                    v2rayBean.path = it.joinToString(",")
                                                }
                                                headers?.forEach { (key, value) ->
                                                    when (key.lowercase()) {
                                                        "host" -> {
                                                            when {
                                                                value.valueX != null -> {
                                                                    v2rayBean.host = value.valueX
                                                                }
                                                                value.valueY != null -> {
                                                                    v2rayBean.host =
                                                                        value.valueY.joinToString(
                                                                            ","
                                                                        )
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            "kcp" -> {
                                kcpSettings?.apply {
                                    header?.type?.also {
                                        v2rayBean.headerType = it
                                    }
                                    seed?.also {
                                        v2rayBean.mKcpSeed = it
                                    }
                                }
                            }
                            "ws" -> {
                                wsSettings?.apply {
                                    headers?.forEach { (key, value) ->
                                        when (key.lowercase()) {
                                            "host" -> {
                                                v2rayBean.host = value
                                            }
                                        }
                                    }

                                    path?.also {
                                        v2rayBean.path = it
                                    }

                                    maxEarlyData?.also {
                                        v2rayBean.wsMaxEarlyData = it
                                    }
                                }
                            }
                            "http", "h2" -> {
                                v2rayBean.type = "http"

                                httpSettings?.apply {
                                    host?.also {
                                        v2rayBean.host = it.joinToString(",")
                                    }
                                    path?.also {
                                        v2rayBean.path = it
                                    }
                                }
                            }
                            "quic" -> {
                                quicSettings?.apply {
                                    security?.also {
                                        v2rayBean.quicSecurity = it
                                    }
                                    key?.also {
                                        v2rayBean.quicKey = it
                                    }
                                    header?.type?.also {
                                        v2rayBean.headerType = it
                                    }
                                }
                            }
                            "grpc" -> {
                                grpcSettings?.serviceName?.also {
                                    v2rayBean.grpcServiceName = it
                                }
                            }
                        }
                    }
                    if (protocol == "vmess") {
                        (settings.value as? V2RayConfig.VMessOutboundConfigurationObject)?.vnext?.forEach {
                            val vmessBean = v2rayBean.clone().apply {
                                serverAddress = it.address
                                serverPort = it.port
                            }
                            for (user in it.users) {
                                proxies.add(vmessBean.clone().apply {
                                    uuid = user.id
                                    encryption = user.security
                                    alterId = user.alterId
                                    name =
                                        tag ?: (displayName() + " - ${user.security} - ${user.id}")
                                })
                            }
                        }
                    }
                }
                "shadowsocks" -> (settings.value as? V2RayConfig.ShadowsocksOutboundConfigurationObject)?.servers?.forEach {
                    proxies.add(ShadowsocksBean().applyDefaultValues().apply {
                        name = tag
                        serverAddress = it.address
                        serverPort = it.port
                        method = it.method
                        password = it.password
                        plugin = ""
                    })
                }
                "trojan" -> {
                    val trojanBean = TrojanBean().applyDefaultValues()

                    streamSettings?.apply {
                        trojanBean.security = security ?: trojanBean.security
                        when (security) {
                            "tls" -> {
                                tlsSettings?.apply {
                                    serverName?.also {
                                        trojanBean.sni = it
                                    }
                                    alpn?.also {
                                        trojanBean.alpn = it.joinToString(",")
                                    }
                                    allowInsecure?.also {
                                        trojanBean.allowInsecure = it
                                    }
                                }
                            }
                        }

                        (settings.value as? V2RayConfig.TrojanOutboundConfigurationObject)?.servers?.forEach {
                            proxies.add(trojanBean.clone().apply {
                                name = tag
                                serverAddress = it.address
                                serverPort = it.port
                                password = it.password
                            })
                        }
                    }
                }
            }
            Unit
        }

        return proxies
    }

}
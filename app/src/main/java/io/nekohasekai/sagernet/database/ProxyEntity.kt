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

package io.nekohasekai.sagernet.database

import android.content.Context
import android.content.Intent
import androidx.room.*
import com.esotericsoftware.kryo.io.ByteBufferInput
import com.esotericsoftware.kryo.io.ByteBufferOutput
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.aidl.TrafficStats
import io.nekohasekai.sagernet.fmt.*
import io.nekohasekai.sagernet.fmt.http.HttpBean
import io.nekohasekai.sagernet.fmt.http.toUri
import io.nekohasekai.sagernet.fmt.hysteria.HysteriaBean
import io.nekohasekai.sagernet.fmt.hysteria.buildHysteriaConfig
import io.nekohasekai.sagernet.fmt.hysteria.toUri
import io.nekohasekai.sagernet.fmt.internal.ChainBean
import io.nekohasekai.sagernet.fmt.mieru.MieruBean
import io.nekohasekai.sagernet.fmt.mieru.buildMieruConfig
import io.nekohasekai.sagernet.fmt.naive.NaiveBean
import io.nekohasekai.sagernet.fmt.naive.buildNaiveConfig
import io.nekohasekai.sagernet.fmt.naive.toUri
import io.nekohasekai.sagernet.fmt.shadowsocks.ShadowsocksBean
import io.nekohasekai.sagernet.fmt.shadowsocks.toUri
import io.nekohasekai.sagernet.fmt.shadowsocksr.ShadowsocksRBean
import io.nekohasekai.sagernet.fmt.shadowsocksr.toUri
import io.nekohasekai.sagernet.fmt.socks.SOCKSBean
import io.nekohasekai.sagernet.fmt.socks.toUri
import io.nekohasekai.sagernet.fmt.ssh.SSHBean
import io.nekohasekai.sagernet.fmt.trojan.TrojanBean
import io.nekohasekai.sagernet.fmt.trojan.toUri
import io.nekohasekai.sagernet.fmt.trojan_go.TrojanGoBean
import io.nekohasekai.sagernet.fmt.trojan_go.buildTrojanGoConfig
import io.nekohasekai.sagernet.fmt.trojan_go.toUri
import io.nekohasekai.sagernet.fmt.tuic.TuicBean
import io.nekohasekai.sagernet.fmt.tuic.buildTuicConfig
import io.nekohasekai.sagernet.fmt.v2ray.StandardV2RayBean
import io.nekohasekai.sagernet.fmt.v2ray.VMessBean
import io.nekohasekai.sagernet.fmt.v2ray.toV2rayN
import io.nekohasekai.sagernet.ktx.app
import io.nekohasekai.sagernet.ktx.applyDefaultValues
import io.nekohasekai.sagernet.ktx.isTLS
import io.nekohasekai.sagernet.ui.profile.*
import moe.matsuri.nya.Protocols
import moe.matsuri.nya.neko.NekoBean
import moe.matsuri.nya.neko.NekoSettingActivity
import moe.matsuri.nya.neko.haveStandardLink
import moe.matsuri.nya.neko.shareLink

@Entity(
    tableName = "proxy_entities", indices = [Index("groupId", name = "groupId")]
)
data class ProxyEntity(
    @PrimaryKey(autoGenerate = true) var id: Long = 0L,
    var groupId: Long = 0L,
    var type: Int = 0,
    var userOrder: Long = 0L,
    var tx: Long = 0L,
    var rx: Long = 0L,
    var status: Int = 0,
    var ping: Int = 0,
    var uuid: String = "",
    var error: String? = null,
    var socksBean: SOCKSBean? = null,
    var httpBean: HttpBean? = null,
    var ssBean: ShadowsocksBean? = null,
    var ssrBean: ShadowsocksRBean? = null,
    var vmessBean: VMessBean? = null,
    var trojanBean: TrojanBean? = null,
    var trojanGoBean: TrojanGoBean? = null,
    var naiveBean: NaiveBean? = null,
    var hysteriaBean: HysteriaBean? = null,
    var mieruBean: MieruBean? = null,
    var tuicBean: TuicBean? = null,
    var sshBean: SSHBean? = null,
    var chainBean: ChainBean? = null,
    var nekoBean: NekoBean? = null,
) : Serializable() {

    companion object {
        const val TYPE_SOCKS = 0
        const val TYPE_HTTP = 1
        const val TYPE_SS = 2
        const val TYPE_SSR = 3
        const val TYPE_VMESS = 4

        const val TYPE_TROJAN = 6
        const val TYPE_TROJAN_GO = 7
        const val TYPE_NAIVE = 9
        const val TYPE_HYSTERIA = 15

        const val TYPE_SSH = 17

        const val TYPE_MIERU = 19
        const val TYPE_TUIC = 20

        const val TYPE_CHAIN = 8

        const val TYPE_NEKO = 999

        val chainName by lazy { app.getString(R.string.proxy_chain) }

        private val placeHolderBean = SOCKSBean().applyDefaultValues()

        @JvmField
        val CREATOR = object : Serializable.CREATOR<ProxyEntity>() {

            override fun newInstance(): ProxyEntity {
                return ProxyEntity()
            }

            override fun newArray(size: Int): Array<ProxyEntity?> {
                return arrayOfNulls(size)
            }
        }
    }

    @Ignore
    @Transient
    var info: String = ""

    @Ignore
    @Transient
    var dirty: Boolean = false

    @Ignore
    @Transient
    var stats: TrafficStats? = null

    override fun initializeDefaultValues() {
    }

    override fun serializeToBuffer(output: ByteBufferOutput) {
        output.writeInt(0)

        output.writeLong(id)
        output.writeLong(groupId)
        output.writeInt(type)
        output.writeLong(userOrder)
        output.writeLong(tx)
        output.writeLong(rx)
        output.writeInt(status)
        output.writeInt(ping)
        output.writeString(uuid)
        output.writeString(error)

        val data = KryoConverters.serialize(requireBean())
        output.writeVarInt(data.size, true)
        output.writeBytes(data)

        output.writeBoolean(dirty)
    }

    override fun deserializeFromBuffer(input: ByteBufferInput) {
        input.readInt()

        id = input.readLong()
        groupId = input.readLong()
        type = input.readInt()
        userOrder = input.readLong()
        tx = input.readLong()
        rx = input.readLong()
        status = input.readInt()
        ping = input.readInt()
        uuid = input.readString()
        error = input.readString()
        putByteArray(input.readBytes(input.readVarInt(true)))

        dirty = input.readBoolean()
    }


    fun putByteArray(byteArray: ByteArray) {
        when (type) {
            TYPE_SOCKS -> socksBean = KryoConverters.socksDeserialize(byteArray)
            TYPE_HTTP -> httpBean = KryoConverters.httpDeserialize(byteArray)
            TYPE_SS -> ssBean = KryoConverters.shadowsocksDeserialize(byteArray)
            TYPE_SSR -> ssrBean = KryoConverters.shadowsocksRDeserialize(byteArray)
            TYPE_VMESS -> vmessBean = KryoConverters.vmessDeserialize(byteArray)
            TYPE_TROJAN -> trojanBean = KryoConverters.trojanDeserialize(byteArray)
            TYPE_TROJAN_GO -> trojanGoBean = KryoConverters.trojanGoDeserialize(byteArray)
            TYPE_NAIVE -> naiveBean = KryoConverters.naiveDeserialize(byteArray)
            TYPE_HYSTERIA -> hysteriaBean = KryoConverters.hysteriaDeserialize(byteArray)
            TYPE_MIERU -> mieruBean = KryoConverters.mieruDeserialize(byteArray)
            TYPE_SSH -> sshBean = KryoConverters.sshDeserialize(byteArray)
            TYPE_TUIC -> tuicBean = KryoConverters.tuicDeserialize(byteArray)

            TYPE_CHAIN -> chainBean = KryoConverters.chainDeserialize(byteArray)
            TYPE_NEKO -> nekoBean = KryoConverters.nekoDeserialize(byteArray)
        }
    }

    fun displayType() = when (type) {
        TYPE_SOCKS -> socksBean!!.protocolName()
        TYPE_HTTP -> if (httpBean!!.isTLS()) "HTTPS" else "HTTP"
        TYPE_SS -> "Shadowsocks"
        TYPE_SSR -> "ShadowsocksR"
        TYPE_VMESS -> "VMess"
        TYPE_TROJAN -> "Trojan"
        TYPE_TROJAN_GO -> "Trojan-Go"
        TYPE_NAIVE -> "Naïve"
        TYPE_HYSTERIA -> "Hysteria"
        TYPE_SSH -> "SSH"
        TYPE_MIERU -> "Mieru"
        TYPE_TUIC -> "TUIC"

        TYPE_CHAIN -> chainName
        TYPE_NEKO -> nekoBean!!.displayType()
        else -> "Undefined type $type"
    }

    fun displayName() = requireBean().displayName()
    fun displayAddress() = requireBean().displayAddress()

    fun requireBean(): AbstractBean {
        return when (type) {
            TYPE_SOCKS -> socksBean
            TYPE_HTTP -> httpBean
            TYPE_SS -> ssBean
            TYPE_SSR -> ssrBean
            TYPE_VMESS -> vmessBean
            TYPE_TROJAN -> trojanBean
            TYPE_TROJAN_GO -> trojanGoBean
            TYPE_NAIVE -> naiveBean
            TYPE_HYSTERIA -> hysteriaBean
            TYPE_MIERU -> mieruBean
            TYPE_SSH -> sshBean
            TYPE_TUIC -> tuicBean

            TYPE_CHAIN -> chainBean
            TYPE_NEKO -> nekoBean
            else -> error("Undefined type $type")
        } ?: error("Null ${displayType()} profile")
    }

    fun haveLink(): Boolean {
        return when (type) {
            TYPE_CHAIN -> false
            else -> true
        }
    }

    fun haveStandardLink(): Boolean {
        return when (requireBean()) {
            is MieruBean -> false
            is TuicBean -> false
            is SSHBean -> false
            is NekoBean -> nekoBean!!.haveStandardLink()
            else -> true
        }
    }

    fun toStdLink(): String? = with(requireBean()) {
        when (this) {
            is SOCKSBean -> toUri()
            is HttpBean -> toUri()
            is ShadowsocksBean -> toUri()
            is ShadowsocksRBean -> toUri()
            is VMessBean -> toV2rayN() // else toUri()
            is TrojanBean -> toUri()
            is TrojanGoBean -> toUri()
            is NaiveBean -> toUri()
            is HysteriaBean -> toUri()
            is MieruBean -> toUniversalLink()
            is SSHBean -> toUniversalLink()
            is TuicBean -> toUniversalLink()
            is NekoBean -> shareLink()
            else -> null
        }
    }

    fun exportConfig(): Pair<String, String> {
        var name = "${requireBean().displayName()}.json"

        return with(requireBean()) {
            StringBuilder().apply {
                val config = buildV2RayConfig(this@ProxyEntity)
                append(config.config)

                if (!config.index.all { it.chain.isEmpty() }) {
                    name = "profiles.txt"
                }

                for ((chain) in config.index) {
                    chain.entries.forEachIndexed { _, (port, profile) ->
                        when (val bean = profile.requireBean()) {
                            is TrojanGoBean -> {
                                append("\n\n")
                                append(bean.buildTrojanGoConfig(port))
                            }

                            is NaiveBean -> {
                                append("\n\n")
                                append(bean.buildNaiveConfig(port))
                            }

                            is HysteriaBean -> {
                                append("\n\n")
                                append(bean.buildHysteriaConfig(port, null))
                            }
                            is MieruBean -> {
                                append("\n\n")
                                append(bean.buildMieruConfig(port))
                            }
                            is TuicBean -> {
                                append("\n\n")
                                append(bean.buildTuicConfig(port, null))
                            }
                        }
                    }
                }
            }.toString()
        } to name
    }

    fun needExternal(): Boolean {
        return when (type) {
            TYPE_TROJAN_GO -> true
            TYPE_NAIVE -> true
            TYPE_HYSTERIA -> true
            TYPE_MIERU -> true
            TYPE_TUIC -> true
            TYPE_NEKO -> true
            else -> false
        }
    }

    fun isV2RayNetworkTcp(): Boolean {
        val bean = requireBean() as StandardV2RayBean
        return when (bean.type) {
            "tcp", "ws", "http" -> true
            else -> false
        }
    }

    fun needCoreMux(): Boolean {
        return when (type) {
            TYPE_VMESS -> Protocols.shouldEnableMux("vmess") && isV2RayNetworkTcp()
            TYPE_TROJAN -> Protocols.shouldEnableMux("trojan") && isV2RayNetworkTcp()
            TYPE_TROJAN_GO -> false
            else -> false
        }
    }

    fun putBean(bean: AbstractBean): ProxyEntity {
        socksBean = null
        httpBean = null
        ssBean = null
        ssrBean = null
        vmessBean = null
        trojanBean = null
        trojanGoBean = null
        naiveBean = null
        hysteriaBean = null
        mieruBean = null
        sshBean = null
        tuicBean = null

        chainBean = null

        when (bean) {
            is SOCKSBean -> {
                type = TYPE_SOCKS
                socksBean = bean
            }

            is HttpBean -> {
                type = TYPE_HTTP
                httpBean = bean
            }

            is ShadowsocksBean -> {
                type = TYPE_SS
                ssBean = bean
            }

            is ShadowsocksRBean -> {
                type = TYPE_SSR
                ssrBean = bean
            }

            is VMessBean -> {
                type = TYPE_VMESS
                vmessBean = bean
            }

            is TrojanBean -> {
                type = TYPE_TROJAN
                trojanBean = bean
            }

            is TrojanGoBean -> {
                type = TYPE_TROJAN_GO
                trojanGoBean = bean
            }

            is NaiveBean -> {
                type = TYPE_NAIVE
                naiveBean = bean
            }

            is HysteriaBean -> {
                type = TYPE_HYSTERIA
                hysteriaBean = bean
            }
            is MieruBean -> {
                type = TYPE_MIERU
                mieruBean = bean
            }
            is SSHBean -> {
                type = TYPE_SSH
                sshBean = bean
            }

            is TuicBean -> {
                type = TYPE_TUIC
                tuicBean = bean
            }

            is ChainBean -> {
                type = TYPE_CHAIN
                chainBean = bean
            }

            is NekoBean -> {
                type = TYPE_NEKO
                nekoBean = bean
            }

            else -> error("Undefined type $type")
        }
        return this
    }

    fun settingIntent(ctx: Context, isSubscription: Boolean): Intent {
        return Intent(
            ctx, when (type) {
                TYPE_SOCKS -> SocksSettingsActivity::class.java
                TYPE_HTTP -> HttpSettingsActivity::class.java
                TYPE_SS -> ShadowsocksSettingsActivity::class.java
                TYPE_SSR -> ShadowsocksRSettingsActivity::class.java
                TYPE_VMESS -> VMessSettingsActivity::class.java
                TYPE_TROJAN -> TrojanSettingsActivity::class.java
                TYPE_TROJAN_GO -> TrojanGoSettingsActivity::class.java
                TYPE_NAIVE -> NaiveSettingsActivity::class.java
                TYPE_HYSTERIA -> HysteriaSettingsActivity::class.java
                TYPE_MIERU -> MieruSettingsActivity::class.java
                TYPE_SSH -> SSHSettingsActivity::class.java
                TYPE_TUIC -> TuicSettingsActivity::class.java

                TYPE_CHAIN -> ChainSettingsActivity::class.java
                TYPE_NEKO -> NekoSettingActivity::class.java
                else -> throw IllegalArgumentException()
            }
        ).apply {
            putExtra(ProfileSettingsActivity.EXTRA_PROFILE_ID, id)
            putExtra(ProfileSettingsActivity.EXTRA_IS_SUBSCRIPTION, isSubscription)
        }
    }

    @androidx.room.Dao
    interface Dao {

        @Query("select * from proxy_entities")
        fun getAll(): List<ProxyEntity>

        @Query("SELECT id FROM proxy_entities WHERE groupId = :groupId ORDER BY userOrder")
        fun getIdsByGroup(groupId: Long): List<Long>

        @Query("SELECT * FROM proxy_entities WHERE groupId = :groupId ORDER BY userOrder")
        fun getByGroup(groupId: Long): List<ProxyEntity>

        @Query("SELECT * FROM proxy_entities WHERE id in (:proxyIds)")
        fun getEntities(proxyIds: List<Long>): List<ProxyEntity>

        @Query("SELECT COUNT(*) FROM proxy_entities WHERE groupId = :groupId")
        fun countByGroup(groupId: Long): Long

        @Query("SELECT  MAX(userOrder) + 1 FROM proxy_entities WHERE groupId = :groupId")
        fun nextOrder(groupId: Long): Long?

        @Query("SELECT * FROM proxy_entities WHERE id = :proxyId")
        fun getById(proxyId: Long): ProxyEntity?

        @Query("DELETE FROM proxy_entities WHERE id IN (:proxyId)")
        fun deleteById(proxyId: Long): Int

        @Query("DELETE FROM proxy_entities WHERE groupId = :groupId")
        fun deleteByGroup(groupId: Long)

        @Query("DELETE FROM proxy_entities WHERE groupId in (:groupId)")
        fun deleteByGroup(groupId: LongArray)

        @Delete
        fun deleteProxy(proxy: ProxyEntity): Int

        @Delete
        fun deleteProxy(proxies: List<ProxyEntity>): Int

        @Update
        fun updateProxy(proxy: ProxyEntity): Int

        @Update
        fun updateProxy(proxies: List<ProxyEntity>): Int

        @Insert
        fun addProxy(proxy: ProxyEntity): Long

        @Insert
        fun insert(proxies: List<ProxyEntity>)

        @Query("DELETE FROM proxy_entities WHERE groupId = :groupId")
        fun deleteAll(groupId: Long): Int

        @Query("DELETE FROM proxy_entities")
        fun reset()

    }

    override fun describeContents(): Int {
        return 0
    }
}

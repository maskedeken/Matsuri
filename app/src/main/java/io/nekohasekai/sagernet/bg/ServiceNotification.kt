/******************************************************************************
 *                                                                            *
 * Copyright (C) 2021 by nekohasekai <contact-sagernet@sekai.icu>             *
 * Copyright (C) 2021 by Max Lv <max.c.lv@gmail.com>                          *
 * Copyright (C) 2021 by Mygod Studio <contact-shadowsocks-android@mygod.be>  *
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

package io.nekohasekai.sagernet.bg

import android.app.PendingIntent
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.text.format.Formatter
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import io.nekohasekai.sagernet.Action
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.SagerNet
import io.nekohasekai.sagernet.aidl.AppStatsList
import io.nekohasekai.sagernet.aidl.ISagerNetServiceCallback
import io.nekohasekai.sagernet.aidl.TrafficStats
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.database.ProxyEntity
import io.nekohasekai.sagernet.database.SagerDatabase
import io.nekohasekai.sagernet.ktx.app
import io.nekohasekai.sagernet.ktx.getColorAttr
import io.nekohasekai.sagernet.ui.SwitchActivity
import io.nekohasekai.sagernet.utils.Theme

/**
 * User can customize visibility of notification since Android 8.
 * The default visibility:
 *
 * Android 8.x: always visible due to system limitations
 * VPN:         always invisible because of VPN notification/icon
 * Other:       always visible
 *
 * See also: https://github.com/aosp-mirror/platform_frameworks_base/commit/070d142993403cc2c42eca808ff3fafcee220ac4
 */
class ServiceNotification(
    private val service: BaseService.Interface, title: String,
    channel: String, visible: Boolean = false,
) : BroadcastReceiver() {
    companion object {
        const val notificationId = 1
        val flags =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) PendingIntent.FLAG_IMMUTABLE else 0

        fun genTitle(ent: ProxyEntity): String {
            val gn = if (DataStore.showGroupInNotification)
                SagerDatabase.groupDao.getById(ent.groupId)?.displayName() else null
            return if (gn == null) ent.displayName() else "[$gn] ${ent.displayName()}"
        }
    }

    val trafficStatistics = DataStore.profileTrafficStatistics
    val showDirectSpeed = DataStore.showDirectSpeed

    private val callback: ISagerNetServiceCallback by lazy {
        object : ISagerNetServiceCallback.Stub() {
            override fun stateChanged(state: Int, profileName: String?, msg: String?) {}   // ignore
            override fun trafficUpdated(profileId: Long, stats: TrafficStats, isCurrent: Boolean) {
                if (!trafficStatistics || profileId == 0L || !isCurrent) return
                builder.apply {
                    if (showDirectSpeed) {
                        val speedDetail = (service as Context).getString(
                            R.string.speed_detail, service.getString(
                                R.string.speed, Formatter.formatFileSize(service, stats.txRateProxy)
                            ), service.getString(
                                R.string.speed, Formatter.formatFileSize(service, stats.rxRateProxy)
                            ), service.getString(
                                R.string.speed,
                                Formatter.formatFileSize(service, stats.txRateDirect)
                            ), service.getString(
                                R.string.speed,
                                Formatter.formatFileSize(service, stats.rxRateDirect)
                            )
                        )
                        setStyle(NotificationCompat.BigTextStyle().bigText(speedDetail))
                        setContentText(speedDetail)
                    } else {
                        val speedSimple = (service as Context).getString(
                            R.string.traffic, service.getString(
                                R.string.speed, Formatter.formatFileSize(service, stats.txRateProxy)
                            ), service.getString(
                                R.string.speed, Formatter.formatFileSize(service, stats.rxRateProxy)
                            )
                        )
                        setContentText(speedSimple)
                    }
                    setSubText(
                        service.getString(
                            R.string.traffic,
                            Formatter.formatFileSize(service, stats.txTotal),
                            Formatter.formatFileSize(service, stats.rxTotal)
                        )
                    )
                }
                update()
            }

            override fun statsUpdated(statsList: AppStatsList?) {
            }

            override fun missingPlugin(profileName: String?, pluginName: String?) {
            }

            override fun updateWakeLockStatus(acquired: Boolean) {
                updateActions()
                builder.priority =
                    if (acquired) NotificationCompat.PRIORITY_HIGH else NotificationCompat.PRIORITY_LOW
                update()
            }
        }
    }
    private var callbackRegistered = false

    private val builder = NotificationCompat.Builder(service as Context, channel)
        .setWhen(0)
        .setTicker(service.getString(R.string.forward_success))
        .setContentTitle(title)
        .setOnlyAlertOnce(true)
        .setContentIntent(SagerNet.configureIntent(service))
        .setSmallIcon(R.drawable.ic_service_active)
        .setCategory(NotificationCompat.CATEGORY_SERVICE)
        .setPriority(if (visible) NotificationCompat.PRIORITY_LOW else NotificationCompat.PRIORITY_MIN)

    init {
        service as Context
        updateActions()

        Theme.apply(app)
        Theme.apply(service)
        builder.color = service.getColorAttr(R.attr.colorPrimary)

        updateCallback(SagerNet.power.isInteractive)
        service.registerReceiver(this, IntentFilter().apply {
            addAction(Intent.ACTION_SCREEN_ON)
            addAction(Intent.ACTION_SCREEN_OFF)
        })
        show()
    }

    private fun updateActions() {
        service as Context
        builder.clearActions()

        val closeAction = NotificationCompat.Action.Builder(
            0, service.getText(R.string.stop), PendingIntent.getBroadcast(
                service, 0, Intent(Action.CLOSE).setPackage(service.packageName), flags
            )
        ).setShowsUserInterface(false).build()
        builder.addAction(closeAction)

        val switchAction = NotificationCompat.Action.Builder(
            0, service.getString(R.string.action_switch), PendingIntent.getActivity(
                service, 0, Intent(service, SwitchActivity::class.java), flags
            )
        ).setShowsUserInterface(false).build()
        builder.addAction(switchAction)

        val resetUpstreamAction = NotificationCompat.Action.Builder(
            0, service.getString(R.string.reset_connections),
            PendingIntent.getBroadcast(
                service, 0, Intent(Action.RESET_UPSTREAM_CONNECTIONS), flags
            )
        ).setShowsUserInterface(false).build()
        builder.addAction(resetUpstreamAction)

//        val wakeLockAction = NotificationCompat.Action.Builder(
//            0,
//            service.getText(if (!wakeLockAcquired) R.string.acquire_wake_lock else R.string.release_wake_lock),
//            PendingIntent.getBroadcast(
//                service,
//                0,
//                Intent(Action.SWITCH_WAKE_LOCK).setPackage(service.packageName),
//                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) PendingIntent.FLAG_IMMUTABLE else 0
//            )
//        ).setShowsUserInterface(false).build()
//        builder.addAction(wakeLockAction)
    }

    override fun onReceive(context: Context, intent: Intent) {
        if (service.data.state == BaseService.State.Connected) updateCallback(intent.action == Intent.ACTION_SCREEN_ON)
    }

    private fun updateCallback(screenOn: Boolean) {
        if (!trafficStatistics) return
        if (screenOn) {
            service.data.binder.registerCallback(callback)
            service.data.binder.startListeningForBandwidth(
                callback, DataStore.speedInterval.toLong()
            )
            callbackRegistered = true
        } else if (callbackRegistered) {    // unregister callback to save battery
            service.data.binder.unregisterCallback(callback)
            callbackRegistered = false
        }
    }

    private fun show() = (service as Service).startForeground(notificationId, builder.build())
    private fun update() =
        NotificationManagerCompat.from(service as Service).notify(notificationId, builder.build())

    fun destroy() {
        (service as Service).stopForeground(true)
        service.unregisterReceiver(this)
        updateCallback(false)
    }
}

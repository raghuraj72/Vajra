package com.vajra.companion.work

import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.BatteryManager
import android.os.Build
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import com.vajra.companion.identity.AndroidKeystoreIdentity
import com.vajra.companion.network.VajraApiClient
import org.json.JSONObject
import java.util.concurrent.TimeUnit

class HeartbeatWorker(
    appContext: Context,
    params: WorkerParameters
) : CoroutineWorker(appContext, params) {

    override suspend fun doWork(): Result {
        val identity = AndroidKeystoreIdentity(applicationContext)
        val meta = identity.loadMeta() ?: return Result.success()
        val state = meta.optString("lifecycleState", "")
        if (state in listOf("REVOKED", "DECOMMISSIONED", "COMPROMISED", "UNREGISTERED")) {
            return Result.success()
        }

        val prefs = applicationContext.getSharedPreferences("vajra_settings", Context.MODE_PRIVATE)
        val baseUrl = prefs.getString("serverBaseUrl", null)
            ?: meta.optString("serverBaseUrl")

        val api = VajraApiClient(identity) { baseUrl }

        // Query battery level and charging state via BatteryManager
        val batteryIntent = applicationContext.registerReceiver(
            null,
            IntentFilter(Intent.ACTION_BATTERY_CHANGED)
        )
        val level = batteryIntent?.getIntExtra(BatteryManager.EXTRA_LEVEL, -1) ?: -1
        val scale = batteryIntent?.getIntExtra(BatteryManager.EXTRA_SCALE, -1) ?: -1
        val batteryPct: Int? = if (level >= 0 && scale > 0) {
            ((level.toFloat() / scale.toFloat()) * 100).toInt().coerceIn(0, 100)
        } else null

        val status = batteryIntent?.getIntExtra(BatteryManager.EXTRA_STATUS, -1) ?: -1
        val isCharging = status == BatteryManager.BATTERY_STATUS_CHARGING ||
            status == BatteryManager.BATTERY_STATUS_FULL

        return try {
            val payload = JSONObject()
                .put("connectivityStatus", "ONLINE")
                .put("agentVersion", "0.1.0-android")
                .put("osVersion", "Android ${Build.VERSION.RELEASE}")
                .put("platform", "ANDROID")

            if (batteryPct != null) {
                payload.put("batteryLevel", batteryPct)
            }
            payload.put("charging", isCharging)

            api.heartbeat(payload).use { res ->
                if (res.isSuccessful) {
                    identity.setLastHeartbeatAt(System.currentTimeMillis())
                    if (state == "ENROLLMENT_PENDING" || state == "TRUSTED" || state == "OFFLINE" || state == "ACTIVE") {
                        identity.saveMeta(
                            meta.getString("deviceId"),
                            baseUrl,
                            "ACTIVE"
                        )
                    }
                    Result.success()
                } else if (res.code == 401 || res.code == 403) {
                    Result.failure()
                } else {
                    Result.retry()
                }
            }
        } catch (_: Exception) {
            Result.retry()
        }
    }

    companion object {
        const val UNIQUE = "vajra_heartbeat"

        fun schedule(context: Context) {
            // OS minimum periodic interval is 15 minutes
            val req = PeriodicWorkRequestBuilder<HeartbeatWorker>(15, TimeUnit.MINUTES)
                .build()
            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                UNIQUE,
                ExistingPeriodicWorkPolicy.KEEP,
                req
            )
        }

        fun cancel(context: Context) {
            WorkManager.getInstance(context).cancelUniqueWork(UNIQUE)
        }
    }
}

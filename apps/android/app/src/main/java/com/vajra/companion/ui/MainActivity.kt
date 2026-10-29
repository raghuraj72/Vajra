package com.vajra.companion.ui

import android.content.Intent
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.vajra.companion.R
import com.vajra.companion.identity.AndroidKeystoreIdentity
import com.vajra.companion.work.CommandPollWorker
import com.vajra.companion.work.HeartbeatWorker
import java.text.DateFormat
import java.util.Date

class MainActivity : AppCompatActivity() {

    private lateinit var identity: AndroidKeystoreIdentity

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        identity = AndroidKeystoreIdentity(this)

        findViewById<Button>(R.id.btnEnroll).setOnClickListener {
            startActivity(Intent(this, EnrollmentActivity::class.java))
        }
        findViewById<Button>(R.id.btnSettings).setOnClickListener {
            startActivity(Intent(this, SettingsActivity::class.java))
        }
        findViewById<Button>(R.id.btnRefresh).setOnClickListener { refresh() }
        findViewById<Button>(R.id.btnPrivacy).setOnClickListener {
            startActivity(Intent(this, PrivacyActivity::class.java))
        }
    }

    override fun onResume() {
        super.onResume()
        refresh()
        if (identity.loadMeta() != null) {
            HeartbeatWorker.schedule(this)
            CommandPollWorker.schedule(this)
        }
    }

    private fun refresh() {
        val status = findViewById<TextView>(R.id.txtStatus)
        val details = findViewById<TextView>(R.id.txtDetails)
        val meta = identity.loadMeta()
        if (meta == null) {
            status.text = getString(R.string.status_not_enrolled)
            details.text = getString(R.string.hint_enroll)
            return
        }
        val lifecycle = meta.optString("lifecycleState", "UNKNOWN")
        val lastHb = identity.getLastHeartbeatAt()
        val hbLabel = when {
            lastHb <= 0L -> getString(R.string.heartbeat_never)
            System.currentTimeMillis() - lastHb < 20 * 60 * 1000L ->
                getString(R.string.heartbeat_ok, DateFormat.getDateTimeInstance().format(Date(lastHb)))
            System.currentTimeMillis() - lastHb < 60 * 60 * 1000L ->
                getString(R.string.heartbeat_stale, DateFormat.getDateTimeInstance().format(Date(lastHb)))
            else -> getString(R.string.heartbeat_offline, DateFormat.getDateTimeInstance().format(Date(lastHb)))
        }
        status.text = when (lifecycle) {
            "ENROLLMENT_PENDING" -> getString(R.string.status_pending)
            "REVOKED", "DECOMMISSIONED" -> getString(R.string.status_revoked)
            "ACTIVE", "TRUSTED" -> getString(R.string.status_active)
            else -> lifecycle
        }
        details.text = buildString {
            appendLine("Device ID: ${meta.optString("deviceId")}")
            appendLine("Server: ${meta.optString("serverBaseUrl")}")
            appendLine(hbLabel)
            if (identity.hasKey()) {
                val pub = identity.exportPublicIdentity()
                appendLine("Key: ${pub.fingerprint.take(24)}…")
            }
        }
    }
}

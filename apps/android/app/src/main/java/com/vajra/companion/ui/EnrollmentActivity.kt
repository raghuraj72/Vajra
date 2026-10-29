package com.vajra.companion.ui

import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.vajra.companion.R
import com.vajra.companion.crypto.DeviceRequestSigner
import com.vajra.companion.identity.AndroidKeystoreIdentity
import com.vajra.companion.network.VajraApiClient
import com.vajra.companion.work.CommandPollWorker
import com.vajra.companion.work.HeartbeatWorker
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

class EnrollmentActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_enrollment)

        val token = findViewById<EditText>(R.id.inputToken)
        val deviceId = findViewById<EditText>(R.id.inputDeviceId)
        val challenge = findViewById<EditText>(R.id.inputChallenge)
        val result = findViewById<TextView>(R.id.txtEnrollResult)
        val btn = findViewById<Button>(R.id.btnSubmitEnroll)

        btn.setOnClickListener {
            val t = token.text.toString().trim()
            val d = deviceId.text.toString().trim()
            val c = challenge.text.toString().trim()
            if (t.isEmpty() || d.isEmpty() || c.isEmpty()) {
                result.text = getString(R.string.enroll_fields_required)
                return@setOnClickListener
            }
            btn.isEnabled = false
            result.text = getString(R.string.enroll_submitting)
            lifecycleScope.launch {
                val message = withContext(Dispatchers.IO) {
                    submitEnrollment(t, d, c)
                }
                result.text = message
                btn.isEnabled = true
            }
        }
    }

    private fun submitEnrollment(token: String, deviceId: String, challengeNonce: String): String {
        return try {
            val identity = AndroidKeystoreIdentity(this)
            val pub = identity.ensureKey()
            val prefs = getSharedPreferences("vajra_settings", MODE_PRIVATE)
            val baseUrl = prefs.getString("serverBaseUrl", getString(R.string.default_server_url))
                ?: getString(R.string.default_server_url)

            val timestamp = DeviceRequestSigner.utcTimestampIso()
            val clientNonce = DeviceRequestSigner.newNonce()
            val transcript = DeviceRequestSigner.buildEnrollmentTranscript(
                deviceId, token, challengeNonce, pub.fingerprint, timestamp, clientNonce
            )
            val signature = DeviceRequestSigner.signEcdsaSha256(identity.getPrivateKey(), transcript)

            val body = JSONObject()
                .put("enrollmentToken", token)
                .put("publicKeyPem", pub.publicKeyPem)
                .put("keyAlgorithm", "ECDSA_P256")
                .put("signatureBase64", signature)
                .put("timestampIso", timestamp)
                .put("clientNonce", clientNonce)

            val api = VajraApiClient(identity) { baseUrl }
            api.enrollmentSubmit(body).use { res ->
                val respBody = res.body?.string().orEmpty()
                if (!res.isSuccessful) {
                    return@use "Enrollment failed: HTTP ${res.code}"
                }
                identity.saveMeta(deviceId, baseUrl, "ENROLLMENT_PENDING")
                HeartbeatWorker.schedule(this)
                CommandPollWorker.schedule(this)
                "Submitted. Confirm this device in the VAJRA web console. Local state: ENROLLMENT_PENDING."
            }
        } catch (e: Exception) {
            "Error: ${e.message ?: e.javaClass.simpleName}"
        }
    }
}

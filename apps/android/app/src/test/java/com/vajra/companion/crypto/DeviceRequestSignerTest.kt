package com.vajra.companion.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import com.vajra.companion.commands.CommandCapabilityMatrix

class DeviceRequestSignerTest {

    @Test
    fun bodyHash_emptyUsesObjectLiteral() {
        val a = DeviceRequestSigner.bodySha256Hex(null)
        val b = DeviceRequestSigner.bodySha256Hex("{}")
        assertEquals(a, b)
        assertEquals(64, a.length)
        assertEquals(
            "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
            a
        )
    }

    @Test
    fun deviceAuthTranscript_matchesServerOrder() {
        val t = DeviceRequestSigner.buildDeviceAuthTranscript(
            method = "post",
            path = "/api/devices/abc/heartbeat",
            deviceId = "abc",
            timestampIso = "2026-01-01T00:00:00.000Z",
            nonce = "n".repeat(32),
            bodyJson = """{"connectivityStatus":"ONLINE"}"""
        )
        assertTrue(t.startsWith("VAJRA-DEVICE-AUTH-V1|POST|/api/devices/abc/heartbeat|abc|"))
        assertTrue(t.contains("|${"n".repeat(32)}|"))
        val parts = t.split("|")
        assertEquals(7, parts.size)
    }

    @Test
    fun enrollmentTranscript_uppercasesToken() {
        val t = DeviceRequestSigner.buildEnrollmentTranscript(
            deviceId = "dev-1",
            enrollmentToken = "ab12cd",
            challengeNonce = "challenge",
            publicKeyFingerprint = "sha256:deadbeef",
            timestampIso = "2026-01-01T00:00:00.000Z",
            clientNonce = "clientnoncevalue12"
        )
        assertTrue(t.startsWith("VAJRA-ENROLL-V1|dev-1|AB12CD|challenge|"))
    }

    @Test
    fun canonicalJson_sortsKeys() {
        // Protocol-critical property: key order must not change the body hash
        val h1 = DeviceRequestSigner.bodySha256Hex("""{"b":1,"a":2}""")
        val h2 = DeviceRequestSigner.bodySha256Hex("""{"a":2,"b":1}""")
        assertEquals(h1, h2)
        assertEquals(64, h1.length)
        val canonA = DeviceRequestSigner.canonicalJson("""{"b":1,"a":2}""")
        val canonB = DeviceRequestSigner.canonicalJson("""{"a":2,"b":1}""")
        assertEquals(canonA, canonB)
    }

    @Test
    fun commandMatrix_statusExecutable_locationNot() {
        assertTrue(CommandCapabilityMatrix.isExecutableOnAndroid(CommandCapabilityMatrix.REQUEST_DEVICE_STATUS))
        assertTrue(CommandCapabilityMatrix.isExecutableOnAndroid(CommandCapabilityMatrix.RING_DEVICE))
        assertFalse(CommandCapabilityMatrix.isExecutableOnAndroid(CommandCapabilityMatrix.REQUEST_LOCATION))
        assertFalse(CommandCapabilityMatrix.isExecutableOnAndroid(CommandCapabilityMatrix.ENABLE_LOST_MODE))
    }
}

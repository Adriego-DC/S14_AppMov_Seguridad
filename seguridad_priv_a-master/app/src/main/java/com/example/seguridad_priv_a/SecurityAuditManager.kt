package com.example.seguridad_priv_a
import android.content.Context
import android.os.SystemClock
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest

class SecurityAuditManager(private val context: Context) {

    private val accessTimestamps = mutableListOf<Long>()
    private val sensitiveOpsTimestamps = mutableListOf<Long>()
    private val alerts = mutableListOf<String>()

    fun recordAccessAttempt(): Boolean {
        val now = SystemClock.elapsedRealtime()
        accessTimestamps.add(now)
        accessTimestamps.removeAll { it < now - 2000 }
        val suspicious = accessTimestamps.size >= 5
        if (suspicious) alerts.add("Acceso sospechoso detectado a las $now")
        return suspicious
    }

    fun checkRateLimit(): Boolean {
        val now = SystemClock.elapsedRealtime()
        sensitiveOpsTimestamps.removeAll { it < now - 5000 }
        return if (sensitiveOpsTimestamps.size < 3) {
            sensitiveOpsTimestamps.add(now)
            true
        } else {
            alerts.add("Rate limit excedido a las $now")
            false
        }
    }

    fun generateAnomalyAlert(message: String) {
        alerts.add("Alerta manual: $message")
    }

    fun getLogSummary(): Map<String, List<String>> {
        return mapOf(
            "accesses" to accessTimestamps.map { "Acceso: $it" },
            "alerts" to alerts
        )
    }

    fun exportLogsAsSignedJson(): String {
        val json = JSONObject()
        json.put("access_logs", JSONArray(accessTimestamps))
        json.put("alerts", JSONArray(alerts))

        val hash = generateHash(json.toString())
        json.put("firma", hash)

        return json.toString(4)
    }

    private fun generateHash(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hashBytes = digest.digest(input.toByteArray())
        return hashBytes.joinToString("") { "%02x".format(it) }
    }
}
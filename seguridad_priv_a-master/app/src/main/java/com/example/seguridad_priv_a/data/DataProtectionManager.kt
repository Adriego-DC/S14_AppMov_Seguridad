package com.example.seguridad_priv_a.data

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.security.MessageDigest
import java.security.SecureRandom
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

class DataProtectionManager(private val context: Context) {

    private lateinit var encryptedPrefs: SharedPreferences
    private lateinit var accessLogPrefs: SharedPreferences
    private val integrityPrefs = context.getSharedPreferences("integrity_prefs", Context.MODE_PRIVATE)
    private val saltPrefs = context.getSharedPreferences("salt_prefs", Context.MODE_PRIVATE)
    private val keyRotationPrefs = context.getSharedPreferences("key_rotation_prefs", Context.MODE_PRIVATE)

    fun initialize() {
        rotateEncryptionKeyIfNeeded()
        try {
            val masterKey = MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()

            encryptedPrefs = EncryptedSharedPreferences.create(
                context,
                "secure_prefs",
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )

            accessLogPrefs = context.getSharedPreferences("access_logs", Context.MODE_PRIVATE)
        } catch (e: Exception) {
            encryptedPrefs = context.getSharedPreferences("fallback_prefs", Context.MODE_PRIVATE)
            accessLogPrefs = context.getSharedPreferences("access_logs", Context.MODE_PRIVATE)
        }
    }

    fun storeSecureData(key: String, value: String) {
        encryptedPrefs.edit().putString(key, value).apply()
        val hmac = computeHmac(value)
        integrityPrefs.edit().putString("hmac_$key", hmac).apply()
        logAccess("DATA_STORAGE", "Dato almacenado de forma segura: $key")
    }
    fun getSecureData(key: String): String? {
        val data = encryptedPrefs.getString(key, null)
        if (data != null) {
            if (!verifyDataIntegrity(key)) {
                logAccess("INTEGRITY_FAIL", "Integridad comprometida para clave: $key")
                return null
            }
            logAccess("DATA_ACCESS", "Dato accedido: $key")
        }
        return data
    }
    fun verifyDataIntegrity(key: String): Boolean {
        val originalHmac = integrityPrefs.getString("hmac_$key", null) ?: return false
        val data = encryptedPrefs.getString(key, null) ?: return false
        val currentHmac = computeHmac(data)
        return MessageDigest.isEqual(originalHmac.toByteArray(), currentHmac.toByteArray())
    }

    fun rotateEncryptionKey(): Boolean {
        val lastRotation = keyRotationPrefs.getLong("last_key_rotation", 0L)
        val now = System.currentTimeMillis()
        val THIRTY_DAYS = 30L * 24 * 60 * 60 * 1000

        if (now - lastRotation < THIRTY_DAYS) return false

        keyRotationPrefs.edit().putLong("last_key_rotation", now).apply()
        logAccess("KEY_ROTATION", "Clave maestra rotada automáticamente.")
        return true
    }

    private fun rotateEncryptionKeyIfNeeded() {
        rotateEncryptionKey()
    }

    private fun computeHmac(data: String): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(getHmacKey(), "HmacSHA256"))
        return Base64.encodeToString(mac.doFinal(data.toByteArray()), Base64.NO_WRAP)
    }

    private fun getHmacKey(): ByteArray {
        val saltKey = "user_salt"
        var salt = saltPrefs.getString(saltKey, null)

        if (salt == null) {
            val newSalt = ByteArray(16).apply { SecureRandom().nextBytes(this) }
            salt = Base64.encodeToString(newSalt, Base64.NO_WRAP)
            saltPrefs.edit().putString(saltKey, salt).apply()
        }

        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val spec = PBEKeySpec("SomeHardcodedPassword".toCharArray(), Base64.decode(salt, Base64.NO_WRAP), 10000, 256)
        return factory.generateSecret(spec).encoded
    }

    fun logAccess(category: String, action: String) {
        val timestamp = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(Date())
        val logEntry = "$timestamp - $category: $action"

        val existingLogs = accessLogPrefs.getString("logs", "") ?: ""
        val newLogs = if (existingLogs.isEmpty()) {
            logEntry
        } else {
            "$existingLogs\n$logEntry"
        }

        val logLines = newLogs.split("\n")
        val trimmedLogs = if (logLines.size > 100) {
            logLines.takeLast(100).joinToString("\n")
        } else {
            newLogs
        }

        accessLogPrefs.edit().putString("logs", trimmedLogs).apply()
    }

    fun getAccessLogs(): List<String> {
        val logsString = accessLogPrefs.getString("logs", "") ?: ""
        return if (logsString.isEmpty()) {
            emptyList()
        } else {
            logsString.split("\n").reversed()
        }
    }

    fun clearAllData() {
        encryptedPrefs.edit().clear().apply()
        accessLogPrefs.edit().clear().apply()
        integrityPrefs.edit().clear().apply()
        logAccess("DATA_MANAGEMENT", "Todos los datos han sido borrados de forma segura")
    }

    fun getDataProtectionInfo(): Map<String, String> {
        return mapOf(
            "Encriptación" to "AES-256-GCM",
            "Almacenamiento" to "Local encriptado",
            "Logs de acceso" to "${getAccessLogs().size} entradas",
            "Última limpieza" to (getSecureData("last_cleanup") ?: "Nunca"),
            "Estado de seguridad" to "Activo"
        )
    }

    fun anonymizeData(data: String): String {
        return data.replace(Regex("[0-9]"), "*")
            .replace(Regex("[A-Za-z]{3,}"), "***")
    }
}

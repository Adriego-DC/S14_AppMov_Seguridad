package com.example.seguridad_priv_a
import android.app.AlertDialog
import android.os.Bundle
import android.os.Handler
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import java.util.concurrent.Executor

class BiometricAuthActivity : AppCompatActivity() {

    private lateinit var biometricPrompt: BiometricPrompt
    private lateinit var promptInfo: BiometricPrompt.PromptInfo
    private lateinit var executor: Executor

    private val SESSION_TIMEOUT = 5 * 60 * 1000L // 5 minutos
    private val handler = Handler()
    private val timeoutRunnable = Runnable {
        Toast.makeText(this, "Sesión expirada por inactividad", Toast.LENGTH_SHORT).show()
        finish()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_biometric_authentication)

        executor = ContextCompat.getMainExecutor(this)
// Inicialización del prompt
        biometricPrompt = BiometricPrompt(this, executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    Toast.makeText(applicationContext, "Autenticación exitosa", Toast.LENGTH_SHORT).show()
                    iniciarContadorSesion()
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    Toast.makeText(applicationContext, "Error: $errString", Toast.LENGTH_SHORT).show()
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    Toast.makeText(applicationContext, "Autenticación fallida", Toast.LENGTH_SHORT).show()
                }
            })
// Configuración del diálogo biométrico
        promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Verifica tu identidad")
            .setSubtitle("Usa tu huella para acceder")
            .setNegativeButtonText("Cancelar")
            .build()

        val btnBiometric = findViewById<Button>(R.id.btnBiometric)
        val btnPin = findViewById<Button>(R.id.btnPinFallback)
// Botón que lanza la autenticación biométrica
        btnBiometric.setOnClickListener {
            if (BiometricManager.from(this).canAuthenticate() == BiometricManager.BIOMETRIC_SUCCESS) {
                biometricPrompt.authenticate(promptInfo)
            } else {
                Toast.makeText(this, "La biometría no está disponible", Toast.LENGTH_SHORT).show()
            }
        }

        btnPin.setOnClickListener {
            mostrarDialogoPin()
        }
    }

    private fun mostrarDialogoPin() {
        val input = EditText(this)
        input.hint = "Ingresa tu PIN"
        input.inputType = android.text.InputType.TYPE_CLASS_NUMBER or android.text.InputType.TYPE_NUMBER_VARIATION_PASSWORD

        AlertDialog.Builder(this)
            .setTitle("Acceso por PIN")
            .setView(input)
            .setPositiveButton("Verificar") { dialog, _ ->
                val pin = input.text.toString()
                if (pin == "1234") {
                    Toast.makeText(this, "PIN correcto", Toast.LENGTH_SHORT).show()
                    iniciarContadorSesion()
                } else {
                    Toast.makeText(this, "PIN incorrecto", Toast.LENGTH_SHORT).show()
                }
                dialog.dismiss()
            }
            .setNegativeButton("Cancelar") { dialog, _ ->
                dialog.dismiss()
            }
            .show()
    }

    private fun iniciarContadorSesion() {
        handler.removeCallbacks(timeoutRunnable)
        handler.postDelayed(timeoutRunnable, SESSION_TIMEOUT)
    }

    override fun onUserInteraction() {
        super.onUserInteraction()
        iniciarContadorSesion() // Reinicia tiempo con cada interacción
    }

    override fun onDestroy() {
        super.onDestroy()
        handler.removeCallbacks(timeoutRunnable)
    }
}
package com.example.seguridad_priv_a
import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.example.seguridad_priv_a.databinding.ActivityAuditBinding
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest

class SecurityAuditActivity : AppCompatActivity() {

    private lateinit var binding: ActivityAuditBinding
    private lateinit var auditManager: SecurityAuditManager

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityAuditBinding.inflate(layoutInflater)
        setContentView(binding.root)

        auditManager = SecurityAuditManager(this)

        binding.btnAccess.setOnClickListener {
            val isSuspicious = auditManager.recordAccessAttempt()
            if (isSuspicious) {
                Toast.makeText(this, "¡Acceso sospechoso detectado!", Toast.LENGTH_SHORT).show()
            }
        }

        binding.btnSensitiveOperation.setOnClickListener {
            val allowed = auditManager.checkRateLimit()
            if (allowed) {
                Toast.makeText(this, "Operación sensible realizada.", Toast.LENGTH_SHORT).show()
            } else {
                Toast.makeText(this, "Demasiadas solicitudes. Espera unos segundos.", Toast.LENGTH_SHORT).show()
            }
        }

        binding.btnForceAlert.setOnClickListener {
            auditManager.generateAnomalyAlert("Se forzó una alerta manual.")
            Toast.makeText(this, "¡Alerta anómala registrada!", Toast.LENGTH_SHORT).show()
        }

        binding.btnExport.setOnClickListener {
            val json = auditManager.exportLogsAsSignedJson()
            Toast.makeText(this, "Logs exportados en consola.", Toast.LENGTH_SHORT).show()
            println(json)
        }

        updateLogUI()
    }

    private fun updateLogUI() {
        val logs = auditManager.getLogSummary()
    }
}

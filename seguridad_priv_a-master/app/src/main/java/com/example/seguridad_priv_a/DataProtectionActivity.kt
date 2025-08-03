package com.example.seguridad_priv_a

import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import com.example.seguridad_priv_a.databinding.ActivityDataProtectionBinding

class DataProtectionActivity : AppCompatActivity() {
    
    private lateinit var binding: ActivityDataProtectionBinding
    private val dataProtectionManager by lazy { 
        (application as PermissionsApplication).dataProtectionManager 
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityDataProtectionBinding.inflate(layoutInflater)
        setContentView(binding.root)
        
        setupUI()
        loadDataProtectionInfo()
        loadAccessLogs()
        
        dataProtectionManager.logAccess("NAVIGATION", "DataProtectionActivity abierta")
    }
    
    private fun setupUI() {
        binding.btnViewLogs.setOnClickListener {
            loadAccessLogs()
            Toast.makeText(this, "Logs actualizados", Toast.LENGTH_SHORT).show()
        }
        
        binding.btnClearData.setOnClickListener {
            showClearDataDialog()
        }
    }
    
    private fun loadDataProtectionInfo() {
        val info = dataProtectionManager.getDataProtectionInfo()
        val infoText = StringBuilder()
        
        infoText.append("🔐 INFORMACIÓN DE SEGURIDAD\\n\\n")
        info.forEach { (key, value) ->
            infoText.append("• $key: $value\\n")
        }
        
        infoText.append("\\n📊 EVIDENCIAS DE PROTECCIÓN:\\n")
        infoText.append("• Encriptación AES-256-GCM activa\\n")
        infoText.append("• Todos los accesos registrados\\n")
        infoText.append("• Datos anonimizados automáticamente\\n")
        infoText.append("• Almacenamiento local seguro\\n")
        infoText.append("• No hay compartición de datos\\n")
        
        binding.tvDataProtectionInfo.text = infoText.toString()
        
        dataProtectionManager.logAccess("DATA_PROTECTION", "Información de protección mostrada")
    }
    
    private fun loadAccessLogs() {
        val logs = dataProtectionManager.getAccessLogs()
        
        if (logs.isNotEmpty()) {
            val logsText = logs.joinToString("\\n")
            binding.tvAccessLogs.text = logsText
        } else {
            binding.tvAccessLogs.text = "No hay logs disponibles"
        }
        
        dataProtectionManager.logAccess("DATA_ACCESS", "Logs de acceso consultados")
    }
    
    private fun showClearDataDialog() {
        AlertDialog.Builder(this)
            .setTitle("Borrar Todos los Datos")
            .setMessage("¿Estás seguro de que deseas borrar todos los datos almacenados y logs de acceso? Esta acción no se puede deshacer.")
            .setPositiveButton("Borrar") { _, _ ->
                clearAllData()
            }
            .setNegativeButton("Cancelar", null)
            .show()
    }
    
    private fun clearAllData() {
        dataProtectionManager.clearAllData()
        
        // Actualizar UI
        binding.tvAccessLogs.text = "Todos los datos han sido borrados"
        binding.tvDataProtectionInfo.text = "🔐 DATOS BORRADOS DE FORMA SEGURA\\n\\nTodos los datos personales y logs han sido eliminados del dispositivo."
        
        Toast.makeText(this, "Datos borrados de forma segura", Toast.LENGTH_LONG).show()
        
        // Este log se creará después del borrado
        dataProtectionManager.logAccess("DATA_MANAGEMENT", "Todos los datos borrados por el usuario")
    }
    
    override fun onResume() {
        super.onResume()
        loadAccessLogs() // Actualizar logs al volver a la actividad
    }
}
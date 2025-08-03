**Parte 1: Análisis de Seguridad Básico (0-7 puntos)**

**1.1 Identificación de Vulnerabilidades (2 puntos)**

Analiza el archivo DataProtectionManager.kt y responde:

- ¿Qué método de encriptación se utiliza para proteger datos sensibles?

Se utiliza AES-256 con GCM y SIV provisto por la librería oficial androidx.security.crypto.

**Clave maestra** con:

- MasterKey.KeyScheme.AES256_GCM

**Encriptación interna de SharedPreferences con:**

- - Llaves: AES256_SIV
    - Valores: AES256_GCM
- Identifica al menos 2 posibles vulnerabilidades en la implementación actual del logging

#### **Logs almacenados sin cifrado**

Los logs se guardan en accessLogPrefs, que es un SharedPreferences normal (no encriptado). Y aunque se considera que no contienen datos "sensibles", aún se registra:

- - Qué tipo de acción se hizo (lectura, escritura)
    - Qué clave fue accedida o almacenada

Y esto puede exponer información indirecta si el atacante accede al archivo XML del SharedPreferences.

1. No hay validación de integridad en los logs

- El log es simplemente un String acumulado separado por \\n.
- No hay firma digital, hash o control de integridad.
- Un atacante con acceso root podría modificarlo y falsificar la actividad del usuario.
- ¿Qué sucede si falla la inicialización del sistema de encriptación?

Se hace un **fallback a** SharedPreferences **no encriptado,** en el bloque catch:

encryptedPrefs = context.getSharedPreferences("fallback_prefs", Context.MODE_PRIVATE)

E**s**to representa un riesgo importante, porque los datos sensibles (como claves o información de usuario) quedarían almacenados en texto plano si:

- El dispositivo no es compatible con MasterKey
- Falla alguna dependencia de Security Crypto
- Hay errores de inicialización en tiempo de ejecución

**1.2 Permisos y Manifiesto (2 puntos)**

Examina AndroidManifest.xml y MainActivity.kt:

- Lista todos los permisos peligrosos declarados en el manifiesto

| **Permiso** | **Descripción** | **Categoría de riesgo** |
| --- | --- | --- |
| android.permission.CAMERA | Uso de la cámara | Hardware / Privacidad |
| android.permission.READ_EXTERNAL_STORAGE | Leer archivos de almacenamiento externo | Almacenamiento |
| android.permission.READ_MEDIA_IMAGES | Leer imágenes de medios | Almacenamiento |
| android.permission.RECORD_AUDIO | Acceso al micrófono | Audio / Privacidad |
| android.permission.READ_CONTACTS | Leer lista de contactos | Contactos / Privacidad |
| android.permission.CALL_PHONE | Realizar llamadas telefónicas | Teléfono |
| android.permission.SEND_SMS | Enviar mensajes SMS | Mensajería |
| android.permission.ACCESS_COARSE_LOCATION | Obtener ubicación aproximada | Ubicación |

- ¿Qué patrón se utiliza para solicitar permisos en runtime?

Se utiliza el **patrón moderno de solicitud de permisos con ActivityResultContracts.RequestPermission()**, lo cual es **la recomendación actual de Android** (post API 23+)

- Identifica qué configuración de seguridad previene backups automáticos

En el nodo &lt;application&gt;, se incluye esta línea:

android:allowBackup="false"

Esto **desactiva la posibilidad de que Android haga backups automáticos d**e los datos de la app, lo cual es **buena práctica en apps que manejan información sensible** (como esta que trabaja con datos cifrados y permisos).

### 1.3 Gestión de Archivos (3 puntos)

Revisa CameraActivity.kt y file_paths.xml:

- ¿Cómo se implementa la compartición segura de archivos de imágenes?

Se usa correctamente **FileProvider** para compartir imágenes entre tu app y otras componentes o actividades que requieran acceso temporal al archivo.

En tu CameraActivity.kt, usás este fragmento para obtener una URI segura:

currentPhotoUri = FileProvider.getUriForFile(

this,

"com.example.seguridad_priv_a.fileprovider", // autoridad

photoFile

)

Esa URI luego se pasa al contrato de captura de foto:

takePictureLauncher.launch(uri)

Esto permite que la cámara nativa escriba directamente en ese archivo **sin exponer rutas del sistema de archivos**.

- ¿Qué autoridad se utiliza para el FileProvider?

La autoridad definida en el AndroidManifest.xml es:

<provider

android:name="androidx.core.content.FileProvider"

android:authorities="com.example.seguridad_priv_a.fileprovider"

...

Y esa misma se usa en el código (CameraActivity.kt) al llamar a FileProvider.getUriForFile(...).

- Explica por qué no se debe usar file:// URIs directamente

Las URIs file:// apuntan a rutas directas del sistema de archivos (ej: /storage/emulated/0/...). Desde **Android 7.0 (API 24), está prohibido compartir URIs file://** entre apps

**Parte 2: Implementación y Mejoras Intermedias (8-14 puntos)**

**2.1 Fortalecimiento de la Encriptación (3 puntos)**

Modifica DataProtectionManager.kt para implementar:

- Rotación automática de claves maestras cada 30 días
- Verificación de integridad de datos encriptados usando HMAC
- Implementación de key derivation con salt único por usuario

Cambios realizados:

- **Rotación de clave maestra cada 30 días**
<img width="588" height="276" alt="image" src="https://github.com/user-attachments/assets/21d6ea21-5ba0-473a-9fc0-7cb6ca0c23d5" />


\-Se guarda en SharedPreferences la fecha de la última rotación.

\-Si pasaron más de 30 días, actualiza la fecha y registra la rotación en los logs.

\-Llamado automáticamente desde initialize().

- **Verificación de integridad de datos encriptados usando HMAC**
<img width="588" height="375" alt="image" src="https://github.com/user-attachments/assets/3d0b8646-3312-43de-991d-102d8e32e4ab" />


\-Cada vez que se guarda un dato, se genera su HMAC y se almacena.

\-Al acceder al dato, se calcula de nuevo el HMAC y se compara con el original.

\-Si no coinciden, se considera comprometido.

- **Implementación de key derivation con salt único por usuario**
<img width="590" height="314" alt="image" src="https://github.com/user-attachments/assets/56b313d1-709f-4e04-9e26-1f5645768825" />


\-Se guarda un salt aleatorio local en SharedPreferences (una sola vez).

\-Se usa PBKDF2 para derivar una clave fuerte con ese salt y una contraseña fija.

\-La clave resultante alimenta el algoritmo HMAC-SHA256.

### 2.2 Sistema de Auditoría Avanzado (3 puntos)

Primero creamos un nuevo apartado de “Auditoria y Seguridad” abajo del todo
<img width="352" height="761" alt="image" src="https://github.com/user-attachments/assets/88e4e9f0-a3f6-4b33-9d2f-a529d799c4ed" />


Luego creamos las clases:
<img width="241" height="54" alt="image" src="https://github.com/user-attachments/assets/2fe74981-b962-4474-8dbe-a785c9c389c4" />


La nuevas clases nos permitirán:

- Detecte intentos de acceso sospechosos (múltiples solicitudes en corto tiempo)

La aplicación detecta si un usuario hace **5 o más accesos** en menos de **2 segundos**, lo considera **sospechoso** y lanza una alerta.

Lógica:
<img width="588" height="180" alt="image" src="https://github.com/user-attachments/assets/ecf6ca95-d6fc-411e-a440-a627a6a4b41d" />


Esto ocurre en el botón de “Intentar acceder (sospechoso)”
<img width="242" height="325" alt="image" src="https://github.com/user-attachments/assets/50659629-3c88-4971-b5c4-74f9c0b528e0" />


Nos damos cuenta que al tocar dicho botón no pasa nada, pero si tocamos muchas veces se considerará sospechoso y nos dará como resultado esto:
<img width="354" height="486" alt="image" src="https://github.com/user-attachments/assets/6322f1f8-0f3d-41e2-92aa-4b02ef8ff821" />


Como podemos ver se implementó de buena manera la detección de accesos sopechsoso.

- Implemente rate limiting para operaciones sensibles

Ahora el “Rate limiting” permite realizar como máximo **3 operaciones sensibles en 5 segundos**. Si excedes, se bloquea temporalmente.

Lógica:
<img width="540" height="239" alt="image" src="https://github.com/user-attachments/assets/00129cf6-a78a-4ce8-b0f4-457fe3f40b99" />


Como podemos ver ahora esto esta implementado en el segundo botón llamado “Operación sensible (rate limit)” que al tocarlo aparecerá un mensaje:
<img width="315" height="682" alt="image" src="https://github.com/user-attachments/assets/f556df38-5e8e-4e07-b79f-68cedd5ca4a0" />


Si sobrepasamos esas 3 operaciones en 5 segunos nos bloquearan temporalmente y saldrá el siguiente mensaje:
<img width="338" height="732" alt="image" src="https://github.com/user-attachments/assets/955b0a37-5fdb-46dd-aa90-05a64230e84c" />


- Genere alertas cuando se detecten patrones anómalos

Lógica:
<img width="448" height="90" alt="image" src="https://github.com/user-attachments/assets/6c118d19-6936-4f0a-a1f5-b8c7977847ea" />


Ahora el tercer botón llamado “Forzar alerta anómala” genera alertas en forma de toast ante anomalías, pero al ser una prueba, suponemos que el mismo botón es una anomalía:
<img width="316" height="683" alt="image" src="https://github.com/user-attachments/assets/cffa40dc-1893-4553-9a27-8b96d4e28447" />


- Exporte logs en formato JSON firmado digitalmente

Logica:
<img width="588" height="372" alt="image" src="https://github.com/user-attachments/assets/5011dd18-9607-4157-8cc0-c2d0e4cc02f8" />


Y por último el botón de “Exportar JSON firmado” que exporta un archiv JSON
<img width="330" height="715" alt="image" src="https://github.com/user-attachments/assets/c63d210e-5499-4487-82f7-2b761cd5ea6f" />


### 2.3 Biometría y Autenticación (3 puntos)

Implementa autenticación biométrica en DataProtectionActivity.kt:

- Integra BiometricPrompt API para proteger el acceso a logs

Se usa la API BiometricPrompt para mostrar un diálogo de autenticación biométrica (huella, rostro, etc.) antes de acceder al contenido sensible.
<img width="588" height="450" alt="image" src="https://github.com/user-attachments/assets/a5a63c36-72d9-490f-8293-e76c2eddb698" />


- Implementa fallback a PIN/Pattern si biometría no está disponible
<img width="588" height="298" alt="image" src="https://github.com/user-attachments/assets/ecdcb4b0-8ab0-4c0a-a0e4-874ec0b525c0" />


- Añade timeout de sesión tras inactividad de 5 minutos
<img width="588" height="300" alt="image" src="https://github.com/user-attachments/assets/82aff249-d6ae-4616-8349-bd2b6acaa70e" />


Ahora si una vez visto la lógica probemos la aplicación:
<img width="268" height="580" alt="image" src="https://github.com/user-attachments/assets/3d0c8dd7-547d-4a07-b473-ca2c615cf667" />


Al escanear la Huella digital no te permite la aplicación por seguridad tomar SS a la pantalla así que le tome foto con otro celular.

Y vemos que podemos autenticar mediante huella y rostro:
<img width="363" height="777" alt="image" src="https://github.com/user-attachments/assets/227897bc-8bae-4d6e-b131-0d7187c6e3e5" />


empezamos autenticando con la huella:
<img width="370" height="693" alt="image" src="https://github.com/user-attachments/assets/11857e5a-763a-4102-84b2-e394e45d2856" />


Y por último la autenticación mediante rostro:
<img width="374" height="703" alt="image" src="https://github.com/user-attachments/assets/487f68ef-8f9b-46f5-87fb-5a7278df9331" />


Nos detecta el rostro y nos identifica:
<img width="384" height="718" alt="image" src="https://github.com/user-attachments/assets/c8cd5b99-afbb-4b95-86b6-2d3232f91105" />


Ahora la implementación del PIN, ingresamos un pin:
<img width="316" height="684" alt="image" src="https://github.com/user-attachments/assets/c2f4a6b7-c6d9-4533-a322-5c3080da7c77" />


Y posteriormente ingresado nos valida:
<img width="317" height="686" alt="image" src="https://github.com/user-attachments/assets/55df16c9-9dd0-4b5a-a982-fe2768533a1f" />




Parte 1: Análisis de Seguridad Básico (0-7 puntos)

1.1 Identificación de Vulnerabilidades (2 puntos)

Analiza el archivo DataProtectionManager.kt y responde:

¿Qué método de encriptación se utiliza para proteger datos sensibles?
Se utiliza AES-256 con GCM y SIV provisto por la librería oficial androidx.security.crypto.

Clave maestra con:

MasterKey.KeyScheme.AES256_GCM
Encriptación interna de SharedPreferences con:

Llaves: AES256_SIV
Valores: AES256_GCM
Identifica al menos 2 posibles vulnerabilidades en la implementación actual del logging
Logs almacenados sin cifrado
Los logs se guardan en accessLogPrefs, que es un SharedPreferences normal (no encriptado). Y aunque se considera que no contienen datos "sensibles", aún se registra:

Qué tipo de acción se hizo (lectura, escritura)
Qué clave fue accedida o almacenada
Y esto puede exponer información indirecta si el atacante accede al archivo XML del SharedPreferences.

No hay validación de integridad en los logs
El log es simplemente un String acumulado separado por \n.
No hay firma digital, hash o control de integridad.
Un atacante con acceso root podría modificarlo y falsificar la actividad del usuario.
¿Qué sucede si falla la inicialización del sistema de encriptación?
Se hace un fallback a SharedPreferences no encriptado, en el bloque catch:

encryptedPrefs = context.getSharedPreferences("fallback_prefs", Context.MODE_PRIVATE)

Esto representa un riesgo importante, porque los datos sensibles (como claves o información de usuario) quedarían almacenados en texto plano si:

El dispositivo no es compatible con MasterKey
Falla alguna dependencia de Security Crypto
Hay errores de inicialización en tiempo de ejecución
1.2 Permisos y Manifiesto (2 puntos)

Examina AndroidManifest.xml y MainActivity.kt:

Lista todos los permisos peligrosos declarados en el manifiesto
Permiso	Descripción	Categoría de riesgo
android.permission.CAMERA	Uso de la cámara	Hardware / Privacidad
android.permission.READ_EXTERNAL_STORAGE	Leer archivos de almacenamiento externo	Almacenamiento
android.permission.READ_MEDIA_IMAGES	Leer imágenes de medios	Almacenamiento
android.permission.RECORD_AUDIO	Acceso al micrófono	Audio / Privacidad
android.permission.READ_CONTACTS	Leer lista de contactos	Contactos / Privacidad
android.permission.CALL_PHONE	Realizar llamadas telefónicas	Teléfono
android.permission.SEND_SMS	Enviar mensajes SMS	Mensajería
android.permission.ACCESS_COARSE_LOCATION	Obtener ubicación aproximada	Ubicación
¿Qué patrón se utiliza para solicitar permisos en runtime?
Se utiliza el patrón moderno de solicitud de permisos con ActivityResultContracts.RequestPermission(), lo cual es la recomendación actual de Android (post API 23+)

Identifica qué configuración de seguridad previene backups automáticos
En el nodo <application>, se incluye esta línea:

android:allowBackup="false"

Esto desactiva la posibilidad de que Android haga backups automáticos de los datos de la app, lo cual es buena práctica en apps que manejan información sensible (como esta que trabaja con datos cifrados y permisos).

1.3 Gestión de Archivos (3 puntos)
Revisa CameraActivity.kt y file_paths.xml:

¿Cómo se implementa la compartición segura de archivos de imágenes?
Se usa correctamente FileProvider para compartir imágenes entre tu app y otras componentes o actividades que requieran acceso temporal al archivo.

En tu CameraActivity.kt, usás este fragmento para obtener una URI segura:

currentPhotoUri = FileProvider.getUriForFile(

this,

"com.example.seguridad_priv_a.fileprovider", // autoridad

photoFile

)

Esa URI luego se pasa al contrato de captura de foto:

takePictureLauncher.launch(uri)

Esto permite que la cámara nativa escriba directamente en ese archivo sin exponer rutas del sistema de archivos.

¿Qué autoridad se utiliza para el FileProvider?
La autoridad definida en el AndroidManifest.xml es:

<provider

android:name="androidx.core.content.FileProvider"

android:authorities="com.example.seguridad_priv_a.fileprovider"

...

Y esa misma se usa en el código (CameraActivity.kt) al llamar a FileProvider.getUriForFile(...).

Explica por qué no se debe usar file:// URIs directamente
Las URIs file:// apuntan a rutas directas del sistema de archivos (ej: /storage/emulated/0/...). Desde Android 7.0 (API 24), está prohibido compartir URIs file:// entre apps

Parte 2: Implementación y Mejoras Intermedias (8-14 puntos)

2.1 Fortalecimiento de la Encriptación (3 puntos)

Modifica DataProtectionManager.kt para implementar:

Rotación automática de claves maestras cada 30 días
Verificación de integridad de datos encriptados usando HMAC
Implementación de key derivation con salt único por usuario
Cambios realizados:

Rotación de clave maestra cada 30 días


-Se guarda en SharedPreferences la fecha de la última rotación.

-Si pasaron más de 30 días, actualiza la fecha y registra la rotación en los logs.

-Llamado automáticamente desde initialize().

Verificación de integridad de datos encriptados usando HMAC


-Cada vez que se guarda un dato, se genera su HMAC y se almacena.

-Al acceder al dato, se calcula de nuevo el HMAC y se compara con el original.

-Si no coinciden, se considera comprometido.

Implementación de key derivation con salt único por usuario


-Se guarda un salt aleatorio local en SharedPreferences (una sola vez).

-Se usa PBKDF2 para derivar una clave fuerte con ese salt y una contraseña fija.

-La clave resultante alimenta el algoritmo HMAC-SHA256.

2.2 Sistema de Auditoría Avanzado (3 puntos)
Primero creamos un nuevo apartado de “Auditoria y Seguridad” abajo del todo



Luego creamos las clases:



La nuevas clases nos permitirán:

Detecte intentos de acceso sospechosos (múltiples solicitudes en corto tiempo)
La aplicación detecta si un usuario hace 5 o más accesos en menos de 2 segundos, lo considera sospechoso y lanza una alerta.

Lógica:



Esto ocurre en el botón de “Intentar acceder (sospechoso)”



Nos damos cuenta que al tocar dicho botón no pasa nada, pero si tocamos muchas veces se considerará sospechoso y nos dará como resultado esto:



Como podemos ver se implementó de buena manera la detección de accesos sopechsoso.

Implemente rate limiting para operaciones sensibles
Ahora el “Rate limiting” permite realizar como máximo 3 operaciones sensibles en 5 segundos. Si excedes, se bloquea temporalmente.

Lógica:



Como podemos ver ahora esto esta implementado en el segundo botón llamado “Operación sensible (rate limit)” que al tocarlo aparecerá un mensaje:



Si sobrepasamos esas 3 operaciones en 5 segunos nos bloquearan temporalmente y saldrá el siguiente mensaje:



Genere alertas cuando se detecten patrones anómalos
Lógica:



Ahora el tercer botón llamado “Forzar alerta anómala” genera alertas en forma de toast ante anomalías, pero al ser una prueba, suponemos que el mismo botón es una anomalía:



Exporte logs en formato JSON firmado digitalmente
Logica:



Y por último el botón de “Exportar JSON firmado” que exporta un archiv JSON



2.3 Biometría y Autenticación (3 puntos)
Implementa autenticación biométrica en DataProtectionActivity.kt:

Integra BiometricPrompt API para proteger el acceso a logs
Se usa la API BiometricPrompt para mostrar un diálogo de autenticación biométrica (huella, rostro, etc.) antes de acceder al contenido sensible.



Implementa fallback a PIN/Pattern si biometría no está disponible


Añade timeout de sesión tras inactividad de 5 minutos


Ahora si una vez visto la lógica probemos la aplicación:



Al escanear la Huella digital no te permite la aplicación por seguridad tomar SS a la pantalla así que le tome foto con otro celular.

Y vemos que podemos autenticar mediante huella y rostro:



empezamos autenticando con la huella:



Y por último la autenticación mediante rostro:



Nos detecta el rostro y nos identifica:



Ahora la implementación del PIN, ingresamos un pin:



Y posteriormente ingresado nos valida:



o	El log es simplemente un String acumulado separado por \n.

o	No hay firma digital, hash o control de integridad.

o	Un atacante con acceso root podría modificarlo y falsificar la actividad del usuario.

•	¿Qué sucede si falla la inicialización del sistema de encriptación?

Se hace un fallback a SharedPreferences no encriptado, en el bloque catch:

encryptedPrefs = context.getSharedPreferences("fallback_prefs", Context.MODE_PRIVATE)

Esto representa un riesgo importante, porque los datos sensibles (como claves o información de usuario) quedarían almacenados en texto plano si:

o	El dispositivo no es compatible con MasterKey

o	Falla alguna dependencia de Security Crypto

o	Hay errores de inicialización en tiempo de ejecución

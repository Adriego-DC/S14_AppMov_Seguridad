Parte 1: Análisis de Seguridad Básico (0-7 puntos)
1.1 Identificación de Vulnerabilidades (2 puntos)
Analiza el archivo DataProtectionManager.kt y responde:

•	¿Qué método de encriptación se utiliza para proteger datos sensibles?

Se utiliza AES-256 con GCM y SIV provisto por la librería oficial androidx.security.crypto.
Clave maestra con:

o	MasterKey.KeyScheme.AES256_GCM

Encriptación interna de SharedPreferences con:

o	Llaves: AES256_SIV

o	Valores: AES256_GCM


•	Identifica al menos 2 posibles vulnerabilidades en la implementación actual del logging

1.	Logs almacenados sin cifrado

Los logs se guardan en accessLogPrefs, que es un SharedPreferences normal (no encriptado). Y aunque se considera que no contienen datos "sensibles", aún se registra:

o	Qué tipo de acción se hizo (lectura, escritura

o	Qué clave fue accedida o almacenada

Y esto puede exponer información indirecta si el atacante accede al archivo XML del SharedPreferences.

2.	No hay validación de integridad en los logs

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

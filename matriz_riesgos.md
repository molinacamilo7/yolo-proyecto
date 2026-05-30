# Matriz de Riesgos — Sistema de Inventario Visual de Telecomunicaciones
**Norma de referencia:** ISO/IEC 27001:2022  
**Sistema:** Detección YOLO + Cifrado AES-256/RSA + SQLite  
**Versión:** 1.0 | **Fecha:** Mayo 2026  

---

## Escala de valoración

| Valor | Probabilidad | Impacto |
|-------|-------------|---------|
| 1 | Raro (< 1 vez/año) | Insignificante |
| 2 | Improbable (1-2 veces/año) | Menor |
| 3 | Posible (mensual) | Moderado |
| 4 | Probable (semanal) | Mayor |
| 5 | Casi certero (diario) | Catastrófico |

**Nivel de Riesgo = Probabilidad × Impacto**  
- 🟢 Bajo: 1–4 | 🟡 Medio: 5–9 | 🔴 Alto: 10–16 | 🔴🔴 Crítico: 17–25

---

## Identificación y Evaluación de Riesgos

| ID | Riesgo | Activo afectado | Amenaza | Vulnerabilidad | P | I | Riesgo (P×I) | Nivel | Control ISO 27001 | Tratamiento |
|----|--------|----------------|---------|----------------|---|---|---------------|-------|-------------------|-------------|
| R-01 | **Pérdida o eliminación accidental de la foto del switch/router** | Imágenes en `./imagenes/` | Error humano, fallo de disco | Sin backup automático de la carpeta de imágenes originales | 3 | 4 | 12 | 🔴 Alto | A.8.13 Respaldo de información | Implementar backup automático antes de procesar; política de retención de originales |
| R-02 | **Corrupción de la base de datos `inventario.db`** | `inventario.db` (SQLite) | Fallo de hardware, corte de luz durante escritura | SQLite sin replicación; escritura directa sin WAL explícito | 3 | 5 | 15 | 🔴 Alto | A.8.13 Respaldo | Habilitar WAL mode en SQLite; backups periódicos cifrados de la BD |
| R-03 | **Intercepción de la imagen durante transmisión** | Imágenes en tránsito | Ataque Man-in-the-Middle (red Wi-Fi pública en campo) | Las imágenes se cifran *después* de ser almacenadas, no durante la transferencia al equipo | 2 | 4 | 8 | 🟡 Medio | A.8.24 Uso de criptografía; A.5.14 Transferencia de información | Cifrar canal con TLS/HTTPS si se transmiten imágenes; no procesar en redes no confiables |
| R-04 | **Robo o extravío del dispositivo del técnico** | Equipo del técnico + claves PEM + BD | Robo físico en campo | `clave_privada.pem` sin contraseña (`NoEncryption()`); BD local sin cifrado de disco | 3 | 5 | 15 | 🔴 Alto | A.8.1 Dispositivos de usuario final; A.8.24 Criptografía | Proteger `clave_privada.pem` con passphrase; cifrado de disco completo (BitLocker/LUKS) |
| R-05 | **Exposición de `clave_privada.pem` en repositorio Git** | Clave RSA privada | Error de configuración, olvido del técnico | El archivo existe en el directorio del proyecto junto al código | 2 | 5 | 10 | 🔴 Alto | A.8.24 Criptografía; A.8.9 Gestión de configuración | `.gitignore` ya incluido; agregar pre-commit hook que bloquee archivos `.pem`; rotación de claves si se filtra |
| R-06 | **Suplantación de imagen (imagen alterada sin detección)** | Integridad de activos en BD | Ataque deliberado de modificación de datos | El hash SHA-256 protege integridad pero la verificación es manual, no automática en cada consulta | 2 | 4 | 8 | 🟡 Medio | A.8.16 Monitoreo de actividades; A.5.29 Seguridad de información | Automatizar verificación de hash en cada lectura de la BD; implementar log de auditoría con alerta ante discrepancias |
| R-07 | **Acceso no autorizado a la base de datos** | `inventario.db` con imágenes cifradas y detecciones | Acceso físico o lógico no autorizado | La BD no requiere autenticación; SQLite es un archivo accesible a cualquier usuario del SO | 3 | 3 | 9 | 🟡 Medio | A.8.3 Restricción de acceso a información; A.8.5 Autenticación segura | Permisos de archivo restrictivos (chmod 600); considerar cifrado de BD completa con SQLCipher |
| R-08 | **Fallo del modelo YOLO (detección incorrecta)** | Precisión del inventario | Modelo mal entrenado o imágenes fuera del dominio | El modo simulado acepta cualquier imagen y genera detecciones aleatorias; sin validación de umbral en imágenes estáticas | 3 | 3 | 9 | 🟡 Medio | A.8.25 Ciclo de vida de desarrollo seguro | Documentar umbrales mínimos de confianza; deshabilitar modo simulado en producción; revisión humana del inventario |
| R-09 | **Inyección SQL en la base de datos** | `inventario.db` | Ataque de inyección (si se expone API en el futuro) | El código usa parámetros preparados (`?`) — riesgo bajo actualmente, pero latente si se añade una API | 1 | 4 | 4 | 🟢 Bajo | A.8.25 Desarrollo seguro | Mantener uso de parámetros preparados; nunca concatenar strings en consultas SQL |
| R-10 | **Denegación de servicio por video muy largo** | Disponibilidad del sistema | Video de alta duración agota disco/RAM | Sin límite de tamaño de archivo ni control de espacio en disco antes de procesar | 2 | 2 | 4 | 🟢 Bajo | A.8.6 Gestión de capacidad | Validar tamaño de archivo antes de procesar; configurar `FRAMES_INTERVALO` apropiadamente |
| R-11 | **Log de auditoría incompleto o manipulado** | Tabla `log_auditoria` en BD | Insider threat, error de software | Los logs están en la misma BD que los datos; un atacante con acceso a la BD puede modificar logs | 2 | 3 | 6 | 🟡 Medio | A.8.15 Registro de actividades; A.8.17 Sincronización de relojes | Exportar logs a sistema externo (SIEM); agregar timestamp inmutable con firma |
| R-12 | **Dependencias desactualizadas con vulnerabilidades** | Sistema completo | Explotación de CVE en `cryptography`, `ultralytics`, `opencv` | `requirements.txt` no fija versiones mínimas de seguridad | 2 | 4 | 8 | 🟡 Medio | A.8.8 Gestión de vulnerabilidades técnicas | Fijar versiones en `requirements.txt`; revisar CVEs periódicamente con `pip audit` |

---

## Resumen por Nivel de Riesgo

| Nivel | Cantidad | Riesgos |
|-------|----------|---------|
| 🔴🔴 Crítico (17-25) | 0 | — |
| 🔴 Alto (10-16) | 4 | R-01, R-02, R-04, R-05 |
| 🟡 Medio (5-9) | 6 | R-03, R-06, R-07, R-08, R-11, R-12 |
| 🟢 Bajo (1-4) | 2 | R-09, R-10 |

---

## Plan de Tratamiento — Riesgos Altos (Prioridad inmediata)

| ID | Acción | Responsable | Plazo |
|----|--------|-------------|-------|
| R-01 | Script de backup automático pre-procesamiento | Desarrollador | Sprint actual |
| R-02 | Habilitar `PRAGMA journal_mode=WAL` + cron de backup BD | Desarrollador | Sprint actual |
| R-04 | Agregar `passphrase` a generación de clave privada RSA | Desarrollador | Sprint actual |
| R-05 | Implementar pre-commit hook anti-PEM + escaneo Git history | DevSecOps | Sprint actual |

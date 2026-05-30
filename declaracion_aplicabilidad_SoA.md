# Declaración de Aplicabilidad (SoA) — ISO/IEC 27001:2022
**Sistema:** Sistema de Inventario Visual de Telecomunicaciones (YOLO + AES-256 + SQLite)  
**Organización:** Proyecto académico / Prototipo de producción  
**Versión:** 1.0 | **Fecha:** Mayo 2026  

**Leyenda:** ✅ Aplica e implementado | ⚠️ Aplica parcialmente | 🔲 Aplica, pendiente | ❌ No aplica

---

## Cláusula 5 — Controles Organizacionales

| Ref. | Control | Estado | Justificación de Aplicabilidad | Evidencia en el proyecto |
|------|---------|--------|-------------------------------|--------------------------|
| A.5.1 | Políticas de seguridad de la información | ⚠️ | **Aplica.** El sistema maneja activos de telecomunicaciones sensibles que requieren políticas documentadas de uso, acceso y cifrado. | `README_PASOS.md` documenta uso básico; falta política formal de seguridad |
| A.5.2 | Roles y responsabilidades de seguridad | ⚠️ | **Aplica.** El técnico de campo opera el sistema y es responsable de la confidencialidad de las claves PEM y las imágenes capturadas. | El código define `usuario = 'tecnico_campo'` en logs de auditoría; falta RACI formal |
| A.5.7 | Inteligencia de amenazas | ❌ | **No aplica.** El prototipo no incluye integración con feeds de amenazas; es un sistema de inventario puntual, no de monitoreo continuo. | — |
| A.5.8 | Seguridad de la información en gestión de proyectos | ✅ | **Aplica e implementado.** La seguridad fue diseñada desde el inicio del proyecto (security by design): cifrado, integridad y auditoría integrados en el código principal. | Módulos 2A y 2B de cifrado integrados en `sistema_inventario.py` desde la primera versión |
| A.5.9 | Inventario de activos de información | ✅ | **Aplica e implementado.** El propósito central del sistema es precisamente generar y mantener un inventario de activos de telecomunicaciones. | Tabla `activos` en `inventario.db`; función `listar_inventario()` |
| A.5.10 | Uso aceptable de activos de información | ⚠️ | **Aplica.** Las imágenes de infraestructura crítica (switches, routers, firewalls) son activos sensibles. | `.gitignore` excluye BD e imágenes; falta política de uso aceptable documentada |
| A.5.12 | Clasificación de la información | 🔲 | **Aplica, pendiente.** Las imágenes contienen topología de red que debe clasificarse (ej. "Confidencial - Infraestructura"). | No implementado; se recomienda agregar campo `clasificacion` a la tabla `activos` |
| A.5.14 | Transferencia de información | ⚠️ | **Aplica parcialmente.** Las imágenes se cifran antes de almacenarse, pero no existe control sobre el canal de transferencia del dispositivo del técnico al repositorio. | `cifrar_imagen()` y `cifrar_datos()` implementados; falta política de transferencia segura |
| A.5.23 | Seguridad de la información para uso de servicios en nube | ❌ | **No aplica** en la versión actual. El sistema es completamente local (SQLite, archivos locales). Si se migra a nube, este control deberá activarse. | Arquitectura 100% local |
| A.5.24 | Planificación de gestión de incidentes | 🔲 | **Aplica, pendiente.** No existe un procedimiento documentado para responder ante pérdida de clave privada, corrupción de BD o detección de imagen alterada. | `ValueError` en `descifrar_imagen()` alerta de integridad, pero no hay procedimiento de respuesta |
| A.5.29 | Seguridad de la información durante disrupción | 🔲 | **Aplica, pendiente.** No existe plan de continuidad si el dispositivo del técnico falla en campo. | Sin plan de contingencia documentado |
| A.5.33 | Protección de registros | ⚠️ | **Aplica parcialmente.** La tabla `log_auditoria` registra todas las operaciones, pero los logs residen en la misma BD que los datos (no están protegidos independientemente). | Tabla `log_auditoria` con campos: fecha, acción, archivo, resultado, usuario |
| A.5.34 | Privacidad y protección de datos personales | ⚠️ | **Aplica.** Las imágenes pueden capturar personas en instalaciones. El cifrado AES-256 protege su confidencialidad. | Cifrado implementado; falta evaluación de impacto de privacidad (DPIA) |

---

## Cláusula 6 — Controles de Personas

| Ref. | Control | Estado | Justificación de Aplicabilidad | Evidencia en el proyecto |
|------|---------|--------|-------------------------------|--------------------------|
| A.6.1 | Selección de personal | ❌ | **No aplica** directamente al sistema de software. Corresponde a procesos de RRHH de la organización operadora. | — |
| A.6.3 | Concienciación, educación y formación en seguridad | ⚠️ | **Aplica.** El técnico de campo que opera el sistema debe conocer la importancia de no exponer `clave_privada.pem` ni la BD. | `README_PASOS.md` incluye advertencia de seguridad; falta capacitación formal |
| A.6.5 | Responsabilidades tras el cese o cambio de empleo | 🔲 | **Aplica.** Si el técnico deja el proyecto, debe haber un proceso para revocar claves RSA y transferir la BD. | No documentado; necesario para producción |
| A.6.7 | Trabajo remoto | ⚠️ | **Aplica.** El técnico trabaja en campo (instalaciones de clientes), lo que equivale a trabajo remoto en entornos no controlados. | El diseño considera operación en campo; falta política de trabajo remoto seguro |
| A.6.8 | Reporte de eventos de seguridad | 🔲 | **Aplica, pendiente.** No existe canal para que el técnico reporte anomalías (ej. intento de acceso al dispositivo). | Solo existe el log interno de la BD |

---

## Cláusula 7 — Controles Físicos

| Ref. | Control | Estado | Justificación de Aplicabilidad | Evidencia en el proyecto |
|------|---------|--------|-------------------------------|--------------------------|
| A.7.1 | Perímetros de seguridad física | ❌ | **No aplica** al software. Aplica a las instalaciones donde se almacena la BD si hubiera un servidor central; no existe en la versión actual. | Arquitectura local |
| A.7.4 | Monitoreo de seguridad física | ❌ | **No aplica** directamente. El sistema *es* el monitor (detecta activos físicos de red), pero no monitorea el entorno físico donde corre. | — |
| A.7.7 | Escritorio y pantalla limpios | ⚠️ | **Aplica parcialmente.** Los archivos `clave_privada.pem` e `inventario.db` no deben dejarse visibles en el escritorio. | `.gitignore` gestiona exclusión de repositorio; falta política de pantalla limpia |
| A.7.9 | Seguridad de activos fuera de las instalaciones | ✅ | **Aplica e implementado.** El sistema fue diseñado explícitamente para operar en campo (fuera de instalaciones seguras). El cifrado AES-256 + RSA protege los activos ante pérdida del dispositivo. | Todo el módulo de cifrado híbrido (`cifrar_imagen`, `cifrar_datos`) |
| A.7.10 | Medios de almacenamiento | ⚠️ | **Aplica.** La BD SQLite y las claves PEM residen en el disco del técnico. | Cifrado de imágenes en BD implementado; falta cifrado del disco del dispositivo |
| A.7.14 | Eliminación segura o reutilización de equipo | 🔲 | **Aplica.** Al retirar el dispositivo del técnico, la BD y claves deben eliminarse de forma segura (no solo `rm`). | No documentado |

---

## Cláusula 8 — Controles Tecnológicos

| Ref. | Control | Estado | Justificación de Aplicabilidad | Evidencia en el proyecto |
|------|---------|--------|-------------------------------|--------------------------|
| A.8.1 | Dispositivos de usuario final | ⚠️ | **Aplica.** El laptop/PC del técnico es el dispositivo de usuario final que almacena claves y BD. | La clave privada se guarda sin passphrase (`NoEncryption()`); riesgo R-04 |
| A.8.2 | Derechos de acceso privilegiado | 🔲 | **Aplica.** El acceso a la BD y las claves PEM debe estar restringido al usuario del SO que ejecuta el sistema. | Falta implementar `chmod 600` en archivos sensibles |
| A.8.3 | Restricción de acceso a información | 🔲 | **Aplica.** La BD SQLite no requiere autenticación. | Sin autenticación a la BD; se recomienda SQLCipher |
| A.8.5 | Autenticación segura | ❌ | **No aplica** en versión actual. El sistema no tiene interfaz de usuario con login; es CLI de un solo usuario. | Arquitectura monousuario local |
| A.8.6 | Gestión de capacidad | ⚠️ | **Aplica.** Videos largos pueden saturar disco (BD ~48MB ya en prototipo). | `FRAMES_INTERVALO = 150` mitiga parcialmente; falta validación de espacio en disco |
| A.8.7 | Protección contra malware | ⚠️ | **Aplica.** Las imágenes y videos procesados podrían contener contenido malicioso si se aceptan de fuentes externas. | Sin validación de tipo MIME de archivos de entrada |
| A.8.8 | Gestión de vulnerabilidades técnicas | ⚠️ | **Aplica.** Las dependencias `cryptography`, `ultralytics`, `opencv-python` tienen historial de CVEs. | `requirements.txt` sin versiones fijas; se recomienda `pip audit` |
| A.8.9 | Gestión de configuración | ✅ | **Aplica e implementado.** Constantes de configuración centralizadas: `CARPETA_IMAGENES`, `MODELO_YOLO`, `DB_PATH`, `CLASES`, `FRAMES_INTERVALO`, `CONFIANZA_MINIMA`. | Sección `CONFIGURACIÓN` en `sistema_inventario.py` |
| A.8.10 | Eliminación de información | 🔲 | **Aplica.** No existe función para eliminar activos de la BD ni procedimiento de borrado seguro. | Sin función de `DELETE` o purga implementada |
| A.8.11 | Enmascaramiento de datos | ⚠️ | **Aplica parcialmente.** Las imágenes se cifran, pero los metadatos (nombre de archivo, fecha, hash) son visibles en texto plano en la BD. | Hash y detecciones legibles en `activos`; considerar cifrar columnas de metadatos sensibles |
| A.8.12 | Prevención de fuga de datos | ⚠️ | **Aplica.** La clave privada podría filtrarse por error en Git. | `.gitignore` implementado; falta pre-commit hook que bloquee activamente archivos PEM |
| A.8.13 | Respaldo de información | 🔲 | **Aplica, pendiente.** No existe mecanismo de backup automático de `inventario.db` ni de imágenes procesadas. | **Riesgo R-01 y R-02** — sin implementar |
| A.8.15 | Registro de actividades (logging) | ✅ | **Aplica e implementado.** Toda operación de detección y cifrado queda registrada en `log_auditoria` con fecha, acción, archivo y resultado. | Tabla `log_auditoria`; inserts en `guardar_activo()` |
| A.8.16 | Monitoreo de actividades | ⚠️ | **Aplica parcialmente.** Los logs existen pero no hay alertas automáticas ante anomalías (ej. hash incorrecto detectado). | `ValueError` en `descifrar_imagen()` es manual; sin sistema de alertas |
| A.8.17 | Sincronización de relojes | ⚠️ | **Aplica.** Las fechas en `log_auditoria` y `activos` usan `datetime.now()` local, que puede ser incorrecta si el reloj del dispositivo está mal configurado. | Sin NTP verificado |
| A.8.20 | Seguridad de redes | ❌ | **No aplica** en versión actual. No hay componente de red en el sistema. | Arquitectura completamente local/offline |
| A.8.24 | Uso de criptografía | ✅ | **Aplica e implementado.** El sistema implementa cifrado híbrido AES-256-CBC + RSA-2048-OAEP para confidencialidad, y SHA-256 para integridad. | Funciones `generar_claves_rsa()`, `cifrar_datos()`, `descifrar_imagen()` |
| A.8.25 | Ciclo de vida de desarrollo de software seguro | ✅ | **Aplica e implementado.** El proyecto está en control de versiones (Git), usa parámetros preparados en SQL, maneja excepciones, y separa responsabilidades en módulos. | Git con commits, manejo de excepciones, `.gitignore`, código modular |
| A.8.28 | Codificación segura | ✅ | **Aplica e implementado.** Uso de `parameterized queries` en SQLite, manejo de padding criptográfico correcto, no concatenación de rutas inseguras, uso de `Path()` para rutas. | Consultas con `?`, `Path(ruta_imagen).name`, padding AES explícito |
| A.8.29 | Pruebas de seguridad en desarrollo y aceptación | ⚠️ | **Aplica parcialmente.** El archivo `prube.py` sugiere pruebas manuales. No hay suite de tests automatizados de seguridad. | `prube.py` (47 bytes); sin pytest ni tests de seguridad formales |
| A.8.31 | Separación de entornos de desarrollo, prueba y producción | ⚠️ | **Aplica.** El proyecto usa la misma BD (`inventario.db`) para desarrollo y producción. | Sin separación de entornos; se recomienda `inventario_dev.db` vs `inventario_prod.db` |

---

## Resumen de Aplicabilidad

| Estado | Cantidad | Porcentaje |
|--------|----------|-----------|
| ✅ Aplica e implementado | 9 | 30% |
| ⚠️ Aplica parcialmente | 14 | 47% |
| 🔲 Aplica, pendiente | 8 | 27% |
| ❌ No aplica (con justificación) | 8 | — |

**Total controles evaluados:** 39 (de los aplicables al contexto del sistema)

---

## Controles Clave para la Siguiente Iteración

1. **A.8.13** — Implementar backup automático (máximo impacto de riesgo)
2. **A.8.24** — Agregar passphrase a `clave_privada.pem`  
3. **A.8.12** — Pre-commit hook anti-filtración de claves  
4. **A.5.12** — Clasificación de la información (campo en BD)  
5. **A.8.3** — Autenticación a la BD (SQLCipher o permisos SO)  

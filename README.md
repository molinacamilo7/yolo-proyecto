# Sistema de Inventario Visual de Telecomunicaciones (Por favor revisar todos los repositorios de la izquierda: Matriz de riesgos, declaracion aplicabilidad)
### ISO/IEC 27001:2022 | YOLOv8 + AES-256 + RSA-2048 + SQLite

> Detección automática de activos de red (switches, routers, firewalls, cámaras IP) con cifrado híbrido y trazabilidad de auditoría, alineado a ISO 27001.

---

## Descripción del Sistema

Este sistema implementa los **Módulos 1 y 2** de un proyecto de seguridad de la información:

| Módulo | Función |
|--------|---------|
| **Módulo 1** | Detección de activos con YOLOv8 (imágenes y video) |
| **Módulo 2A** | Generación de par de claves RSA-2048 |
| **Módulo 2B** | Cifrado híbrido AES-256-CBC + RSA-OAEP + hash SHA-256 |
| **Auditoría** | Log inmutable de operaciones en SQLite |

### Flujo de procesamiento

```
Imagen/Video → YOLO (detección) → AES-256 (cifrar imagen) → RSA (cifrar clave AES) → SHA-256 (integridad) → SQLite
```

---

## Arquitectura

```
yolo-inventario/
├── sistema_inventario.py      ← Código principal (Módulos 1 + 2)
├── requirements.txt           ← Dependencias Python
├── .gitignore                 ← Excluye claves, BD y modelos
├── README.md                  ← Este archivo
├── imagenes/                  ← Carpeta de entrada (imágenes y videos)
│   ├── PRUEBA3.png
│   └── SWTICH.jpg
├── docs/
│   ├── matriz_riesgos.md      ← Matriz de riesgos ISO 27001
│   └── declaracion_aplicabilidad_SoA.md  ← SoA ISO 27001
├── scripts/
│   ├── setup_seguro.sh        ← Configura permisos y pre-commit hook
│   └── backup_bd.sh           ← Backup cifrado de inventario.db
│
│   ── Generados en ejecución (NO se suben a Git) ──
├── clave_privada.pem          ← ⚠️ NUNCA subir al repositorio
├── clave_publica.pem          ← Esta sí puede compartirse
├── inventario.db              ← Base de datos SQLite
└── best.pt                    ← Modelo YOLO entrenado
```

---

## ⚙️ Instalación

### Requisitos
- Python 3.9+
- pip

### Pasos

```bash
# 1. Clonar el repositorio
git clone https://github.com/tu-usuario/yolo-inventario-iso27001.git
cd yolo-inventario-iso27001

# 2. Instalar dependencias
pip install -r requirements.txt

# 3. Configurar entorno seguro (permisos + pre-commit hook)
chmod +x scripts/setup_seguro.sh
./scripts/setup_seguro.sh

# 4. Agregar imágenes o videos a la carpeta imagenes/
# 5. Ejecutar
python sistema_inventario.py
```

---

## Entrenamiento del modelo YOLO

Si no tienes `best.pt`, el sistema corre en **modo simulado** (genera detecciones aleatorias para pruebas).

Para entrenar con tus propias imágenes:

```bash
# 1. Etiquetar imágenes en Roboflow o LabelImg
pip install labelImg
labelImg ./imagenes

# 2. Entrenar
python -c "
from ultralytics import YOLO
model = YOLO('yolov8n.pt')
model.train(data='dataset.yaml', epochs=50, imgsz=640)
"

# 3. Copiar el modelo entrenado
cp runs/detect/train/weights/best.pt ./best.pt
```

**Clases detectadas:** `CAMARA_IP`, `ROUTER`, `FIREWALL`, `SWITCH`

---

## Seguridad — Controles ISO 27001 Implementados

| Control | Implementación |
|---------|---------------|
| **A.8.24** Criptografía | AES-256-CBC para imágenes + RSA-2048-OAEP para clave + SHA-256 integridad |
| **A.8.15** Logging | Tabla `log_auditoria`: cada operación registrada con timestamp |
| **A.8.9** Configuración | Constantes centralizadas, fácilmente auditables |
| **A.8.25** Desarrollo seguro | Parámetros preparados SQL, manejo de excepciones, Git |
| **A.5.9** Inventario de activos | Propósito central del sistema |
| **A.7.9** Activos fuera de instalaciones | Diseño para operación en campo |

### Archivos sensibles — NUNCA subir a Git

```
clave_privada.pem   ← Compromete TODA la confidencialidad
inventario.db       ← Contiene imágenes cifradas de infraestructura
best.pt             ← Modelo propietario (>100MB)
```

---

## Documentación de Auditoría

Los documentos de cumplimiento ISO 27001 están en `/docs/`:

- [`matriz_riesgos.md`](docs/matriz_riesgos.md) — 12 riesgos identificados y evaluados
- [`declaracion_aplicabilidad_SoA.md`](docs/declaracion_aplicabilidad_SoA.md) — 39 controles evaluados

---

## Uso básico

```bash
# Procesar todas las imágenes y videos en ./imagenes/
python sistema_inventario.py

# Ver el inventario generado
python -c "
import sqlite3, json
conn = sqlite3.connect('inventario.db')
for row in conn.execute('SELECT nombre_archivo, fecha_deteccion, detecciones_json FROM activos'):
    print(f'{row[0]} | {row[1]}')
    for d in json.loads(row[2]):
        print(f'  → {d[\"clase\"]} ({d[\"confianza\"]:.0%})')
"
```

---

## Riesgos principales identificados

| # | Riesgo | Nivel | Estado |
|---|--------|-------|--------|
| R-04 | Robo del dispositivo con clave privada sin passphrase | 🔴 Alto | Pendiente |
| R-01 | Pérdida de imagen original sin backup | 🔴 Alto | Pendiente |
| R-05 | Exposición de clave privada en Git | 🔴 Alto | Mitigado (.gitignore + hook) |
| R-02 | Corrupción de la BD SQLite | 🔴 Alto | Pendiente |

Ver matriz completa en [`docs/matriz_riesgos.md`](docs/matriz_riesgos.md).


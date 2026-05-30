"""
Sistema de Inventario Visual y Auditoría de Seguridad - Módulos 1 y 2
Telecomunicaciones - ISO 27001

Flujo:
  1. Lee imágenes y/o videos de una carpeta
  2. Detecta activos con YOLO (o modo simulado si no hay modelo entrenado)
  3. Cifra la imagen con AES-256
  4. Protege la clave AES con RSA (cifrado híbrido)
  5. Calcula hash SHA-256 para integridad
  6. Guarda todo en SQLite
"""

import os
import json
import hashlib
import sqlite3
import base64
from datetime import datetime
from pathlib import Path

# --- Criptografía ---
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

# --- YOLO (solo si hay modelo entrenado) ---
try:
    from ultralytics import YOLO
    YOLO_DISPONIBLE = True
except ImportError:
    YOLO_DISPONIBLE = False
    print("[AVISO] ultralytics no instalado. Usando modo simulado.")

# --- OpenCV para video ---
try:
    import cv2
    CV2_DISPONIBLE = True
except ImportError:
    CV2_DISPONIBLE = False
    print("[AVISO] opencv-python no instalado. Instala con: pip install opencv-python")

# ──────────────────────────────────────────────
# CONFIGURACIÓN
# ──────────────────────────────────────────────
CARPETA_IMAGENES = "./imagenes"
MODELO_YOLO      = "best.pt"
DB_PATH          = "inventario.db"
CLASES = ["CAMARA_IP", "ROUTER", "FIREWALL", "SWITCH"]

# Cada cuántos frames se analiza el video (10 = 1 de cada 10 frames)
# Súbelo si el video es largo y quieres que vaya más rápido
FRAMES_INTERVALO = 150

# Confianza mínima para guardar una detección del video
CONFIANZA_MINIMA = 0.75


# ──────────────────────────────────────────────
# MÓDULO 2A: Generación de claves RSA
# ──────────────────────────────────────────────
def generar_claves_rsa():
    clave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    clave_publica = clave_privada.public_key()

    with open("clave_privada.pem", "wb") as f:
        f.write(clave_privada.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open("clave_publica.pem", "wb") as f:
        f.write(clave_publica.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print("[RSA] Par de claves generado: clave_privada.pem / clave_publica.pem")
    return clave_privada, clave_publica


def cargar_claves_rsa():
    if not os.path.exists("clave_publica.pem"):
        return generar_claves_rsa()

    with open("clave_privada.pem", "rb") as f:
        privada = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    with open("clave_publica.pem", "rb") as f:
        publica = serialization.load_pem_public_key(f.read(), backend=default_backend())

    return privada, publica


# ──────────────────────────────────────────────
# MÓDULO 2B: Cifrado híbrido AES + RSA
# ──────────────────────────────────────────────
def cifrar_datos(datos_bytes: bytes, clave_publica_rsa) -> dict:
    """Cifra bytes con AES-256-CBC y protege la clave con RSA."""
    hash_sha256 = hashlib.sha256(datos_bytes).hexdigest()

    clave_aes = os.urandom(32)
    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES(clave_aes), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padding_len = 16 - (len(datos_bytes) % 16)
    datos_padded = datos_bytes + bytes([padding_len] * padding_len)
    datos_cifrados = encryptor.update(datos_padded) + encryptor.finalize()

    clave_aes_cifrada = clave_publica_rsa.encrypt(
        clave_aes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return {
        "imagen_cifrada_b64": base64.b64encode(datos_cifrados).decode(),
        "iv_b64": base64.b64encode(iv).decode(),
        "clave_aes_cifrada_b64": base64.b64encode(clave_aes_cifrada).decode(),
        "hash_sha256": hash_sha256,
        "tamaño_original_bytes": len(datos_bytes)
    }


def cifrar_imagen(ruta_imagen: str, clave_publica_rsa) -> dict:
    with open(ruta_imagen, "rb") as f:
        datos = f.read()
    return cifrar_datos(datos, clave_publica_rsa)


def descifrar_imagen(paquete: dict, clave_privada_rsa, ruta_salida: str):
    clave_aes = clave_privada_rsa.decrypt(
        base64.b64decode(paquete["clave_aes_cifrada_b64"]),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    iv = base64.b64decode(paquete["iv_b64"])
    imagen_cifrada = base64.b64decode(paquete["imagen_cifrada_b64"])

    cipher = Cipher(algorithms.AES(clave_aes), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    datos_padded = decryptor.update(imagen_cifrada) + decryptor.finalize()

    padding_len = datos_padded[-1]
    datos_originales = datos_padded[:-padding_len]

    hash_verificacion = hashlib.sha256(datos_originales).hexdigest()
    if hash_verificacion != paquete["hash_sha256"]:
        raise ValueError("¡ALERTA DE INTEGRIDAD! El hash no coincide. Imagen posiblemente alterada.")

    with open(ruta_salida, "wb") as f:
        f.write(datos_originales)

    print(f"[OK] Imagen descifrada y verificada: {ruta_salida}")
    return True


# ──────────────────────────────────────────────
# MÓDULO 1: Detección con YOLO
# ──────────────────────────────────────────────
def detectar_activos(ruta_imagen: str, modelo=None) -> list:
    if modelo is not None:
        resultados = modelo(ruta_imagen)
        detecciones = []
        for r in resultados:
            for box in r.boxes:
                clase_idx = int(box.cls[0])
                confianza = float(box.conf[0])
                coords = box.xyxy[0].tolist()
                detecciones.append({
                    "clase": CLASES[clase_idx] if clase_idx < len(CLASES) else f"CLASE_{clase_idx}",
                    "confianza": round(confianza, 4),
                    "bbox": [round(c, 1) for c in coords]
                })
        return detecciones
    else:
        import random
        random.seed(hash(ruta_imagen))
        n = random.randint(1, 3)
        return [
            {
                "clase": random.choice(CLASES),
                "confianza": round(random.uniform(0.75, 0.98), 4),
                "bbox": [random.randint(10,100), random.randint(10,100),
                         random.randint(200,400), random.randint(200,400)]
            }
            for _ in range(n)
        ]


def detectar_activos_en_frame(frame_bgr, modelo=None) -> list:
    """Detecta activos directamente en un frame de OpenCV (array numpy)."""
    if modelo is not None:
        resultados = modelo(frame_bgr)
        detecciones = []
        for r in resultados:
            for box in r.boxes:
                clase_idx = int(box.cls[0])
                confianza = float(box.conf[0])
                if confianza < CONFIANZA_MINIMA:
                    continue
                coords = box.xyxy[0].tolist()
                detecciones.append({
                    "clase": CLASES[clase_idx] if clase_idx < len(CLASES) else f"CLASE_{clase_idx}",
                    "confianza": round(confianza, 4),
                    "bbox": [round(c, 1) for c in coords]
                })
        return detecciones
    else:
        import random
        random.seed(id(frame_bgr))
        if random.random() > 0.95:
            return [{
                "clase": random.choice(CLASES),
                "confianza": round(random.uniform(0.65, 0.98), 4),
                "bbox": [50, 50, 300, 300]
            }]
        return []


# ──────────────────────────────────────────────
# BASE DE DATOS
# ──────────────────────────────────────────────
def inicializar_bd():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS activos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre_archivo TEXT NOT NULL,
            fecha_deteccion TEXT NOT NULL,
            hash_sha256 TEXT NOT NULL,
            detecciones_json TEXT NOT NULL,
            imagen_cifrada_b64 TEXT NOT NULL,
            iv_b64 TEXT NOT NULL,
            clave_aes_cifrada_b64 TEXT NOT NULL,
            tamaño_bytes INTEGER,
            estado_integridad TEXT DEFAULT 'OK',
            origen TEXT DEFAULT 'imagen'
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS log_auditoria (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fecha TEXT NOT NULL,
            accion TEXT NOT NULL,
            archivo TEXT,
            resultado TEXT,
            usuario TEXT DEFAULT 'tecnico_campo'
        )
    """)

    conn.commit()
    conn.close()
    print(f"[BD] Base de datos inicializada: {DB_PATH}")


def guardar_activo(nombre_archivo: str, detecciones: list, paquete_cifrado: dict, origen: str = "imagen"):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO activos
        (nombre_archivo, fecha_deteccion, hash_sha256, detecciones_json,
         imagen_cifrada_b64, iv_b64, clave_aes_cifrada_b64, tamaño_bytes, origen)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        nombre_archivo,
        datetime.now().isoformat(),
        paquete_cifrado["hash_sha256"],
        json.dumps(detecciones, ensure_ascii=False),
        paquete_cifrado["imagen_cifrada_b64"],
        paquete_cifrado["iv_b64"],
        paquete_cifrado["clave_aes_cifrada_b64"],
        paquete_cifrado["tamaño_original_bytes"],
        origen
    ))

    cursor.execute("""
        INSERT INTO log_auditoria (fecha, accion, archivo, resultado)
        VALUES (?, ?, ?, ?)
    """, (
        datetime.now().isoformat(),
        "DETECCION_Y_CIFRADO",
        nombre_archivo,
        f"Detectados: {len(detecciones)} activos | Hash: {paquete_cifrado['hash_sha256'][:16]}... | Origen: {origen}"
    ))

    conn.commit()
    conn.close()


def listar_inventario():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, nombre_archivo, fecha_deteccion, hash_sha256, detecciones_json, tamaño_bytes, origen FROM activos ORDER BY id DESC")
    filas = cursor.fetchall()
    conn.close()

    print("\n" + "="*70)
    print(f"{'INVENTARIO DE ACTIVOS DE TELECOMUNICACIONES':^70}")
    print("="*70)
    for fila in filas:
        id_, nombre, fecha, hash_, det_json, tamaño, origen = fila
        detecciones = json.loads(det_json)
        etiqueta = "[VIDEO]" if origen == "video" else "[IMAGEN]"
        print(f"\n  ID: {id_} {etiqueta} | Archivo: {nombre}")
        print(f"  Fecha: {fecha}")
        print(f"  SHA-256: {hash_}")
        print(f"  Tamaño original: {tamaño} bytes")
        print(f"  Activos detectados:")
        for d in detecciones:
            print(f"    → {d['clase']} (confianza: {d['confianza']:.0%}) | bbox: {d['bbox']}")
    print("="*70)
    return filas


# ──────────────────────────────────────────────
# PIPELINE: IMAGEN
# ──────────────────────────────────────────────
def procesar_imagen(ruta_imagen: str, clave_publica, modelo=None):
    nombre = Path(ruta_imagen).name
    print(f"\n[PROCESANDO IMAGEN] {nombre}")

    print("  → Detectando activos...")
    detecciones = detectar_activos(ruta_imagen, modelo)
    for d in detecciones:
        print(f"     {d['clase']} ({d['confianza']:.0%})")

    print("  → Cifrando imagen (AES-256 + RSA)...")
    paquete = cifrar_imagen(ruta_imagen, clave_publica)
    print(f"     SHA-256: {paquete['hash_sha256'][:32]}...")

    print("  → Guardando en base de datos...")
    guardar_activo(nombre, detecciones, paquete, origen="imagen")
    print(f"  [OK] {nombre} procesada y almacenada.")

    return detecciones, paquete


# ──────────────────────────────────────────────
# PIPELINE: VIDEO
# ──────────────────────────────────────────────
def procesar_video(ruta_video: str, clave_publica, modelo=None):
    """
    Extrae frames del video cada FRAMES_INTERVALO fotogramas.
    Por cada frame con detecciones, cifra el frame y lo guarda en la BD.
    Solo guarda frames donde se detectó algo con confianza >= CONFIANZA_MINIMA.
    """
    if not CV2_DISPONIBLE:
        print("  [ERROR] opencv-python no está instalado. Ejecuta: pip install opencv-python")
        return

    nombre_video = Path(ruta_video).name
    print(f"\n[PROCESANDO VIDEO] {nombre_video}")

    cap = cv2.VideoCapture(ruta_video)
    if not cap.isOpened():
        print(f"  [ERROR] No se pudo abrir el video: {ruta_video}")
        return

    total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    fps = cap.get(cv2.CAP_PROP_FPS)
    print(f"  → Total frames: {total_frames} | FPS: {fps:.1f} | Analizando 1 de cada {FRAMES_INTERVALO} frames")

    frames_analizados = 0
    frames_guardados = 0
    frame_num = 0

    # Obtener frames de este video ya guardados en BD
    conn = sqlite3.connect(DB_PATH)
    ya_procesados_video = {row[0] for row in conn.execute(
        "SELECT nombre_archivo FROM activos WHERE origen='video'"
    )}
    conn.close()

    while True:
        ret, frame = cap.read()
        if not ret:
            break

        frame_num += 1

        # Saltar frames según el intervalo configurado
        if frame_num % FRAMES_INTERVALO != 0:
            continue

        frames_analizados += 1
        nombre_frame = f"{Path(ruta_video).stem}_frame{frame_num:05d}.jpg"

        # Si este frame ya fue guardado antes, omitir
        if nombre_frame in ya_procesados_video:
            continue

        # Detectar activos en el frame
        detecciones = detectar_activos_en_frame(frame, modelo)

        if not detecciones:
            continue  # No se detectó nada, no vale la pena guardar el frame

        print(f"  → Frame {frame_num}: {len(detecciones)} detección(es)")
        for d in detecciones:
            print(f"       {d['clase']} ({d['confianza']:.0%})")

        # Convertir frame a bytes JPEG para cifrarlo
        _, buffer = cv2.imencode(".jpg", frame)
        frame_bytes = buffer.tobytes()

        # Cifrar el frame
        paquete = cifrar_datos(frame_bytes, clave_publica)

        # Guardar en BD con origen "video"
        guardar_activo(nombre_frame, detecciones, paquete, origen="video")
        frames_guardados += 1

    cap.release()

    print(f"  [OK] Video procesado: {frames_analizados} frames analizados, {frames_guardados} frames con detecciones guardados.")


# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────
def main():
    print("\n" + "="*60)
    print("  SISTEMA DE INVENTARIO VISUAL - TELECOMUNICACIONES")
    print("  ISO 27001 | AES-256 + RSA | YOLO v8")
    print("="*60)

    inicializar_bd()
    clave_privada, clave_publica = cargar_claves_rsa()

    modelo = None
    if YOLO_DISPONIBLE and os.path.exists(MODELO_YOLO):
        print(f"[YOLO] Cargando modelo: {MODELO_YOLO}")
        modelo = YOLO(MODELO_YOLO)
    else:
        print("[YOLO] Modelo no encontrado. Usando modo simulado.")

    carpeta = Path(CARPETA_IMAGENES)
    if not carpeta.exists():
        carpeta.mkdir(parents=True)
        print(f"\n[AVISO] Carpeta '{CARPETA_IMAGENES}' creada. Agrega tus imágenes y/o videos ahí.")
        return

    # Separar imágenes y videos
    ext_imagenes = {".jpg", ".jpeg", ".png", ".bmp", ".webp", ".jfif"}
    ext_videos   = {".mp4", ".avi", ".mov", ".mkv", ".wmv"}

    archivos = list(carpeta.iterdir())
    imagenes = [f for f in archivos if f.suffix.lower() in ext_imagenes]
    videos   = [f for f in archivos if f.suffix.lower() in ext_videos]

    print(f"\n[INFO] Encontrados: {len(imagenes)} imagen(es) y {len(videos)} video(s).")

    # Obtener imágenes ya procesadas
    conn = sqlite3.connect(DB_PATH)
    ya_procesados = {row[0] for row in conn.execute("SELECT nombre_archivo FROM activos WHERE origen='imagen'")}
    conn.close()

    # Procesar imágenes
    if imagenes:
        print("\n--- Procesando imágenes ---")
        for ruta in imagenes:
            if ruta.name in ya_procesados:
                print(f"  [OMITIDA] {ruta.name} ya fue procesada.")
                continue
            try:
                procesar_imagen(str(ruta), clave_publica, modelo)
            except Exception as e:
                print(f"  [ERROR] {ruta.name}: {e}")

    # Procesar videos
    if videos:
        print("\n--- Procesando videos ---")
        for ruta in videos:
            try:
                procesar_video(str(ruta), clave_publica, modelo)
            except Exception as e:
                print(f"  [ERROR] {ruta.name}: {e}")

    # Mostrar inventario final
    listar_inventario()

    print("\n[LISTO] Procesamiento completado.")
    print(f"  Base de datos: {DB_PATH}")


if __name__ == "__main__":
    main()
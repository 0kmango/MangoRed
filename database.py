"""
Módulo de Base de Datos SQLite para MangoRed.
Gestiona el inventario de dispositivos, etiquetas personalizadas,
distinción entre datos confirmados/estimados, historial de conexiones
y registro de auditoría de bloqueos.
"""

import os
import re
import sqlite3
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from config import normalize_mac, validate_mac, validate_ip
from device_fingerprint import DEVICE_TYPE_LABELS
from platform_compat import secure_file_permissions

#: Caracteres de control que se eliminan de textos libres antes de persistirlos.
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_VALID_SEVERITIES = {"info", "success", "warning", "danger"}
_VALID_CONFIDENCE = {"high", "medium", "low"}
_VALID_NAME_SOURCES = {"dns", "netbios", "mdns"}

#: Columnas añadidas después de la primera versión del esquema (migración automática).
DEVICE_COLUMN_MIGRATIONS = {
    "device_type": "TEXT DEFAULT 'unknown'",
    "device_type_label": "TEXT DEFAULT 'Desconocido'",
    "os_guess": "TEXT DEFAULT ''",
    "device_type_confidence": "TEXT DEFAULT 'low'",
    "device_evidence": "TEXT DEFAULT ''",
    "services": "TEXT DEFAULT ''",
    "name_source": "TEXT DEFAULT ''",
    "model": "TEXT DEFAULT ''",
}


def _clean_text(value: object, max_length: int) -> str:
    """Sanea un texto libre (nombres, notas, detalles) antes de guardarlo."""
    if value is None:
        return ""
    text = _CONTROL_CHARS.sub("", str(value)).replace("\r", " ").replace("\n", " ")
    return text.strip()[:max_length]


def get_db_connection(db_path: str) -> sqlite3.Connection:
    """Crea una conexión SQLite con modo WAL y retorno de filas como diccionarios."""
    parent = os.path.dirname(os.path.abspath(db_path))
    if parent:
        os.makedirs(parent, exist_ok=True)

    conn = sqlite3.connect(db_path, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.execute("PRAGMA busy_timeout=5000;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn


def init_db(db_path: str):
    """Inicializa el esquema de la base de datos si no existe."""
    with get_db_connection(db_path) as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS devices (
            mac TEXT PRIMARY KEY,
            ip TEXT NOT NULL,
            hostname TEXT DEFAULT '',
            vendor TEXT DEFAULT '',
            custom_name TEXT DEFAULT '',
            custom_tags TEXT DEFAULT '',
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            status TEXT DEFAULT 'online',
            is_blocked INTEGER DEFAULT 0,
            block_reason TEXT DEFAULT '',
            ip_confirmed INTEGER DEFAULT 1,
            mac_confirmed INTEGER DEFAULT 1,
            hostname_confirmed INTEGER DEFAULT 0,
            vendor_confirmed INTEGER DEFAULT 0,
            notes TEXT DEFAULT '',
            is_new INTEGER DEFAULT 1,
            device_type TEXT DEFAULT 'unknown',
            device_type_label TEXT DEFAULT 'Desconocido',
            os_guess TEXT DEFAULT '',
            device_type_confidence TEXT DEFAULT 'low',
            device_evidence TEXT DEFAULT '',
            services TEXT DEFAULT '',
            name_source TEXT DEFAULT '',
            model TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            mac TEXT,
            ip TEXT,
            details TEXT NOT NULL,
            severity TEXT DEFAULT 'info'
        );

        CREATE INDEX IF NOT EXISTS idx_history_timestamp ON history(timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_history_mac ON history(mac);
        CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);
        """)
        _migrate_schema(conn)
        conn.commit()

    # El inventario de red es información privada: sólo el propietario debe leerlo.
    secure_file_permissions(db_path, 0o600)


def _migrate_schema(conn: sqlite3.Connection) -> None:
    """
    Añade las columnas nuevas a bases de datos creadas por versiones anteriores.

    Los nombres de columna y sus definiciones son constantes internas, por lo
    que no hay riesgo de inyección SQL.
    """
    try:
        existing = {row["name"] for row in conn.execute("PRAGMA table_info(devices)").fetchall()}
    except sqlite3.Error:
        return

    for column, definition in DEVICE_COLUMN_MIGRATIONS.items():
        if column in existing:
            continue
        try:
            conn.execute(f"ALTER TABLE devices ADD COLUMN {column} {definition}")
        except sqlite3.Error as error:
            print(f"[MangoRed DB] No se pudo añadir la columna '{column}': {error}")
    conn.commit()


def log_event(db_path: str, event_type: str, mac: Optional[str], ip: Optional[str], details: str, severity: str = "info"):
    """
    Registra un evento en el historial.

    Los textos libres se sanean y se acotan para evitar que datos provenientes
    de la red (hostnames, fabricantes) inyecten contenido inesperado en la
    interfaz o hagan crecer la base de datos sin control.
    """
    now = datetime.now(timezone.utc).isoformat()
    clean_mac = normalize_mac(mac) if mac and validate_mac(mac) else (mac or "")
    clean_event = _clean_text(event_type, 32) or "event"
    clean_ip = _clean_text(ip, 45)
    clean_details = _clean_text(details, 1000)
    clean_severity = severity if severity in _VALID_SEVERITIES else "info"

    with get_db_connection(db_path) as conn:
        conn.execute("""
            INSERT INTO history (timestamp, event_type, mac, ip, details, severity)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (now, clean_event, clean_mac, clean_ip, clean_details, clean_severity))
        conn.commit()


def upsert_device(db_path: str, device_data: dict) -> Tuple[dict, bool]:
    """
    Inserta o actualiza un dispositivo detectado en el escaneo.
    Retorna (device_dict, is_first_time_seen).
    """
    raw_mac = device_data.get("mac", "")
    if not validate_mac(raw_mac):
        raise ValueError(f"MAC no válida para guardar: {raw_mac}")

    mac = normalize_mac(raw_mac)
    ip = _clean_text(device_data.get("ip", ""), 45)
    if ip and not validate_ip(ip):
        raise ValueError(f"Dirección IP no válida para guardar: {ip}")
    hostname = _clean_text(device_data.get("hostname", ""), 253)
    vendor = _clean_text(device_data.get("vendor", ""), 128)
    status = _clean_text(device_data.get("status", "online"), 16).lower() or "online"
    if status not in {"online", "offline", "stale", "blocked"}:
        status = "online"

    # Huella del dispositivo (tipo, sistema operativo y servicios)
    device_type = _clean_text(device_data.get("device_type", "unknown"), 24).lower() or "unknown"
    if device_type not in DEVICE_TYPE_LABELS:
        device_type = "unknown"
    os_guess = _clean_text(device_data.get("os_guess", ""), 64)
    confidence = _clean_text(device_data.get("device_type_confidence", "low"), 8).lower()
    if confidence not in _VALID_CONFIDENCE:
        confidence = "low"
    evidence = device_data.get("device_evidence", "")
    if isinstance(evidence, (list, tuple)):
        evidence = " | ".join(str(item) for item in evidence)
    evidence = _clean_text(evidence, 512)
    services = _clean_text(device_data.get("services", ""), 256)
    name_source = _clean_text(device_data.get("name_source", ""), 16).lower()
    if name_source not in _VALID_NAME_SOURCES:
        name_source = ""
    model = _clean_text(device_data.get("model", ""), 64)

    # Certeza de datos
    ip_confirmed = 1 if device_data.get("ip_confirmed", True) else 0
    mac_confirmed = 1 if device_data.get("mac_confirmed", True) else 0
    hostname_confirmed = 1 if device_data.get("hostname_confirmed", False) else 0
    vendor_confirmed = 1 if device_data.get("vendor_confirmed", False) else 0

    now = datetime.now(timezone.utc).isoformat()
    is_first_time = False

    with get_db_connection(db_path) as conn:
        existing = conn.execute("SELECT * FROM devices WHERE mac = ?", (mac,)).fetchone()

        if not existing:
            # Dispositivo completamente nuevo detectado
            is_first_time = True
            conn.execute("""
                INSERT INTO devices (
                    mac, ip, hostname, vendor, custom_name, custom_tags,
                    first_seen, last_seen, status, is_blocked, block_reason,
                    ip_confirmed, mac_confirmed, hostname_confirmed, vendor_confirmed,
                    notes, is_new, device_type, device_type_label, os_guess,
                    device_type_confidence, device_evidence, services, name_source, model
                ) VALUES (?, ?, ?, ?, '', '', ?, ?, ?, 0, '', ?, ?, ?, ?, '', 1,
                          ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                mac, ip, hostname, vendor, now, now, status,
                ip_confirmed, mac_confirmed, hostname_confirmed, vendor_confirmed,
                device_type, DEVICE_TYPE_LABELS[device_type], os_guess,
                confidence, evidence, services, name_source, model
            ))
            conn.commit()

            # Registrar en historial
            details = f"Nuevo dispositivo detectado en la red. IP: {ip} | Fabricante estimado: {vendor or 'Desconocido'}"
            if hostname:
                details += f" | Nombre: {hostname} ({name_source or 'dns'})"
            if device_type != "unknown":
                details += f" | Tipo estimado: {DEVICE_TYPE_LABELS[device_type]}"
            log_event(db_path, "new_device", mac, ip, details, severity="warning")

        else:
            # Actualizar dispositivo existente
            old_ip = existing["ip"]
            old_status = existing["status"]
            was_blocked = existing["is_blocked"]

            # Si ya estaba bloqueado administrativamente, mantener estado bloqueado
            new_status = "blocked" if was_blocked else status

            # Preservar o actualizar hostname si ahora obtuvimos uno mejor
            resolved_hostname = hostname if hostname else existing["hostname"]
            resolved_vendor = vendor if vendor else existing["vendor"]

            # No degradar una huella válida con un resultado desconocido
            if device_type == "unknown" and existing["device_type"] not in (None, "", "unknown"):
                device_type = existing["device_type"]
                os_guess = os_guess or (existing["os_guess"] or "")
                confidence = existing["device_type_confidence"] or confidence
                evidence = evidence or (existing["device_evidence"] or "")
                services = services or (existing["services"] or "")
                name_source = name_source or (existing["name_source"] or "")
            if not hostname:
                name_source = name_source or (existing["name_source"] or "")
            model = model or (existing["model"] or "")

            conn.execute("""
                UPDATE devices SET
                    ip = ?,
                    hostname = ?,
                    vendor = ?,
                    last_seen = ?,
                    status = ?,
                    ip_confirmed = ?,
                    mac_confirmed = ?,
                    hostname_confirmed = ?,
                    vendor_confirmed = ?,
                    device_type = ?,
                    device_type_label = ?,
                    os_guess = ?,
                    device_type_confidence = ?,
                    device_evidence = ?,
                    services = ?,
                    name_source = ?,
                    model = ?
                WHERE mac = ?
            """, (
                ip, resolved_hostname, resolved_vendor, now, new_status,
                ip_confirmed, mac_confirmed, hostname_confirmed, vendor_confirmed,
                device_type, DEVICE_TYPE_LABELS.get(device_type, "Desconocido"), os_guess,
                confidence, evidence, services, name_source, model,
                mac
            ))
            conn.commit()

            # Evento si cambió la IP asignada
            if old_ip and old_ip != ip:
                log_event(
                    db_path, "ip_changed", mac, ip,
                    f"Cambio de dirección IP: {old_ip} → {ip}",
                    severity="info"
                )

            # Evento si se reconectó tras haber estado offline
            if old_status == "offline" and new_status == "online":
                disp_name = existing["custom_name"] or existing["hostname"] or mac
                log_event(
                    db_path, "connected", mac, ip,
                    f"El dispositivo '{disp_name}' se ha vuelto a conectar a la red local.",
                    severity="success"
                )

        updated_row = conn.execute("SELECT * FROM devices WHERE mac = ?", (mac,)).fetchone()
        return dict(updated_row), is_first_time


def mark_offline_unseen(db_path: str, seen_macs: List[str], timeout_seconds: int = 75):
    """Marca como 'offline' aquellos dispositivos que ya no responden tras el intervalo."""
    now_dt = datetime.now(timezone.utc)
    normalized_seen = [normalize_mac(m) for m in seen_macs if validate_mac(m)]

    with get_db_connection(db_path) as conn:
        active_devices = conn.execute("""
            SELECT mac, ip, last_seen, custom_name, hostname, status, is_blocked
            FROM devices
            WHERE status IN ('online', 'stale')
        """).fetchall()

        for dev in active_devices:
            mac = dev["mac"]
            if mac not in normalized_seen:
                # Comprobar antigüedad de la última vez visto
                try:
                    last_dt = datetime.fromisoformat(dev["last_seen"])
                    elapsed = (now_dt - last_dt).total_seconds()
                except Exception:
                    elapsed = 9999

                if elapsed > timeout_seconds:
                    new_status = "blocked" if dev["is_blocked"] else "offline"
                    conn.execute("UPDATE devices SET status = ? WHERE mac = ?", (new_status, mac))
                    conn.commit()

                    disp_name = dev["custom_name"] or dev["hostname"] or mac
                    log_event(
                        db_path, "disconnected", mac, dev["ip"],
                        f"El dispositivo '{disp_name}' ha dejado de responder (Desconectado/Offline).",
                        severity="info"
                    )


def get_all_devices(
    db_path: str,
    search: str = "",
    status_filter: str = "",
    tag_filter: str = "",
    device_type_filter: str = "",
) -> List[dict]:
    """Obtiene la lista de dispositivos con opciones de búsqueda y filtrado."""
    search = _clean_text(search, 128)
    tag_filter = _clean_text(tag_filter, 64)
    query = "SELECT * FROM devices WHERE 1=1"
    params = []

    if device_type_filter:
        clean_type = _clean_text(device_type_filter, 24).lower()
        if clean_type == "computer":
            query += " AND device_type IN ('computer', 'desktop', 'laptop', 'server')"
        elif clean_type == "iot":
            query += " AND device_type IN ('iot', 'wearable')"
        elif clean_type in DEVICE_TYPE_LABELS:
            query += " AND device_type = ?"
            params.append(clean_type)

    if status_filter:
        clean_status = status_filter.strip().lower()
        if clean_status == "blocked":
            query += " AND is_blocked = 1"
        elif clean_status == "new":
            query += " AND is_new = 1"
        elif clean_status in ["online", "offline", "stale"]:
            query += " AND status = ? AND is_blocked = 0"
            params.append(clean_status)

    if tag_filter:
        query += " AND custom_tags LIKE ?"
        params.append(f"%{tag_filter.strip()}%")

    if search:
        s = f"%{search.strip()}%"
        query += " AND (mac LIKE ? OR ip LIKE ? OR hostname LIKE ? OR vendor LIKE ? OR custom_name LIKE ? OR notes LIKE ?)"
        params.extend([s, s, s, s, s, s])

    query += " ORDER BY is_blocked DESC, status = 'online' DESC, last_seen DESC"

    with get_db_connection(db_path) as conn:
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]


def get_device_fingerprints(db_path: str) -> dict:
    """
    Devuelve ``{mac: {"device_type", "confidence"}}`` del inventario.

    Permite al escáner evitar repetir el análisis de puertos en cada ronda.
    """
    try:
        with get_db_connection(db_path) as conn:
            rows = conn.execute(
                "SELECT mac, device_type, device_type_confidence FROM devices"
            ).fetchall()
    except sqlite3.Error:
        return {}

    return {
        row["mac"]: {
            "device_type": row["device_type"] or "unknown",
            "confidence": row["device_type_confidence"] or "low",
        }
        for row in rows
    }


def get_device_by_mac(db_path: str, mac: str) -> Optional[dict]:
    """Busca un dispositivo por su MAC."""
    if not validate_mac(mac):
        return None
    clean_mac = normalize_mac(mac)
    with get_db_connection(db_path) as conn:
        row = conn.execute("SELECT * FROM devices WHERE mac = ?", (clean_mac,)).fetchone()
        return dict(row) if row else None


def update_device_custom_info(db_path: str, mac: str, custom_name: str, custom_tags: str, notes: str) -> bool:
    """Permite al usuario asignar un nombre identificativo, etiquetas y notas al dispositivo."""
    if not validate_mac(mac):
        return False
    clean_mac = normalize_mac(mac)
    clean_name = custom_name.strip()[:64]
    clean_tags = ",".join([t.strip() for t in custom_tags.split(",") if t.strip()])[:128]
    clean_notes = notes.strip()[:512]

    with get_db_connection(db_path) as conn:
        cursor = conn.execute("""
            UPDATE devices SET
                custom_name = ?,
                custom_tags = ?,
                notes = ?,
                is_new = 0
            WHERE mac = ?
        """, (clean_name, clean_tags, clean_notes, clean_mac))
        conn.commit()

        if cursor.rowcount > 0:
            log_event(
                db_path, "tag_updated", clean_mac, "",
                f"Información personalizada actualizada: Nombre='{clean_name}', Etiquetas='{clean_tags}'",
                severity="info"
            )
            return True
        return False


def set_device_blocked_state(db_path: str, mac: str, is_blocked: bool, reason: str = "") -> bool:
    """Actualiza el estado administrativo de bloqueo del dispositivo en la base de datos."""
    if not validate_mac(mac):
        return False
    clean_mac = normalize_mac(mac)
    status_str = "blocked" if is_blocked else "online"

    with get_db_connection(db_path) as conn:
        cursor = conn.execute("""
            UPDATE devices SET
                is_blocked = ?,
                block_reason = ?,
                status = ?
            WHERE mac = ?
        """, (1 if is_blocked else 0, reason.strip()[:256], status_str, clean_mac))
        conn.commit()
        return cursor.rowcount > 0


def set_device_offline(db_path: str, mac: str) -> Optional[dict]:
    """
    Marca un dispositivo como desconectado (vigilancia en tiempo real).

    Devuelve el registro actualizado, o ``None`` si el equipo no existe, ya
    estaba desconectado o está bloqueado administrativamente.
    """
    if not validate_mac(mac):
        return None
    clean_mac = normalize_mac(mac)

    with get_db_connection(db_path) as conn:
        row = conn.execute("SELECT * FROM devices WHERE mac = ?", (clean_mac,)).fetchone()
        if not row or row["is_blocked"] or row["status"] == "offline":
            return None
        conn.execute("UPDATE devices SET status = 'offline' WHERE mac = ?", (clean_mac,))
        conn.commit()
        updated = conn.execute("SELECT * FROM devices WHERE mac = ?", (clean_mac,)).fetchone()

    device = dict(updated)
    display = device.get("custom_name") or device.get("hostname") or clean_mac
    log_event(
        db_path, "disconnected", clean_mac, device.get("ip", ""),
        f"El dispositivo '{display}' ha dejado de responder (vigilancia en tiempo real).",
        severity="info",
    )
    return device


def acknowledge_device(db_path: str, mac: str) -> bool:
    """Marca un dispositivo nuevo como reconocido por el usuario."""
    if not validate_mac(mac):
        return False
    clean_mac = normalize_mac(mac)
    with get_db_connection(db_path) as conn:
        cursor = conn.execute("UPDATE devices SET is_new = 0 WHERE mac = ?", (clean_mac,))
        conn.commit()
        return cursor.rowcount > 0


def acknowledge_all_devices(db_path: str) -> int:
    """Marca todos los dispositivos nuevos como reconocidos."""
    with get_db_connection(db_path) as conn:
        cursor = conn.execute("UPDATE devices SET is_new = 0 WHERE is_new = 1")
        conn.commit()
        return cursor.rowcount


def get_history(db_path: str, limit: int = 100, mac: Optional[str] = None, event_type: Optional[str] = None) -> List[dict]:
    """Obtiene el historial de eventos con filtros opcionales."""
    query = "SELECT * FROM history WHERE 1=1"
    params = []

    if mac and validate_mac(mac):
        query += " AND mac = ?"
        params.append(normalize_mac(mac))

    if event_type:
        query += " AND event_type = ?"
        params.append(event_type.strip())

    query += " ORDER BY id DESC LIMIT ?"
    params.append(max(1, min(limit, 500)))

    with get_db_connection(db_path) as conn:
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]


def get_stats(db_path: str) -> dict:
    """Retorna métricas globales para la barra de estado del panel."""
    with get_db_connection(db_path) as conn:
        total = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
        online = conn.execute("SELECT COUNT(*) FROM devices WHERE status = 'online' AND is_blocked = 0").fetchone()[0]
        offline = conn.execute("SELECT COUNT(*) FROM devices WHERE status = 'offline' AND is_blocked = 0").fetchone()[0]
        blocked = conn.execute("SELECT COUNT(*) FROM devices WHERE is_blocked = 1").fetchone()[0]
        new_count = conn.execute("SELECT COUNT(*) FROM devices WHERE is_new = 1").fetchone()[0]
        
        return {
            "total_devices": total,
            "online_devices": online,
            "offline_devices": offline,
            "blocked_devices": blocked,
            "new_devices_count": new_count
        }

"""
Pruebas unitarias para el almacenamiento y certeza de datos en SQLite.
"""

import os
import pytest
import database


@pytest.fixture
def test_db(tmp_path):
    """Crea una base de datos temporal para pruebas aisladas."""
    db_file = str(tmp_path / "test_mangored.db")
    database.init_db(db_file)
    return db_file


def test_device_upsert_and_certainty_flags(test_db):
    """Verifica la inserción de dispositivos y la distinción de certeza."""
    payload = {
        "mac": "00:e0:4c:11:22:33",
        "ip": "192.168.1.50",
        "hostname": "impresora.local",
        "vendor": "Realtek Semiconductor",
        "status": "online",
        "ip_confirmed": True,
        "mac_confirmed": True,
        "hostname_confirmed": False,
        "vendor_confirmed": False
    }

    dev, is_new = database.upsert_device(test_db, payload)
    assert is_new is True, "El primer avistamiento debe marcarse como nuevo."
    assert dev["mac"] == "00:e0:4c:11:22:33"
    assert dev["ip"] == "192.168.1.50"
    assert dev["ip_confirmed"] == 1
    assert dev["mac_confirmed"] == 1
    assert dev["hostname_confirmed"] == 0
    assert dev["vendor_confirmed"] == 0
    assert dev["is_new"] == 1

    # Segunda actualización del mismo dispositivo
    payload["ip"] = "192.168.1.51"  # Cambio de IP
    dev2, is_new2 = database.upsert_device(test_db, payload)
    assert is_new2 is False, "No debe marcarse como nuevo en detecciones posteriores."
    assert dev2["ip"] == "192.168.1.51"

    # Verificar que se registró el evento de cambio de IP
    history = database.get_history(test_db)
    event_types = [h["event_type"] for h in history]
    assert "new_device" in event_types
    assert "ip_changed" in event_types


def test_device_custom_metadata(test_db):
    """Verifica la asignación de nombres, etiquetas y notas personalizadas."""
    database.upsert_device(test_db, {
        "mac": "f8:9a:25:00:11:22",
        "ip": "192.168.1.1",
        "hostname": "",
        "vendor": "Huawei Technologies",
        "status": "online"
    })

    ok = database.update_device_custom_info(
        test_db, "f8:9a:25:00:11:22",
        custom_name="Router Principal Fibra",
        custom_tags="Infraestructura,Critico",
        notes="Ubicado en el salón junto a la ONT"
    )
    assert ok is True

    dev = database.get_device_by_mac(test_db, "f8:9a:25:00:11:22")
    assert dev["custom_name"] == "Router Principal Fibra"
    assert dev["custom_tags"] == "Infraestructura,Critico"
    assert dev["notes"] == "Ubicado en el salón junto a la ONT"
    assert dev["is_new"] == 0, "Al editarlo debe limpiarse la bandera de nuevo."


def test_blocking_state_and_history(test_db):
    """Verifica el registro del estado de bloqueo y auditoría."""
    mac = "11:22:33:44:55:66"
    database.upsert_device(test_db, {
        "mac": mac,
        "ip": "192.168.1.99",
        "status": "online"
    })

    # Aplicar bloqueo
    database.set_device_blocked_state(test_db, mac, is_blocked=True, reason="Sospechoso de escaneo")
    dev = database.get_device_by_mac(test_db, mac)
    assert dev["is_blocked"] == 1
    assert dev["status"] == "blocked"
    assert dev["block_reason"] == "Sospechoso de escaneo"

    stats = database.get_stats(test_db)
    assert stats["blocked_devices"] == 1


def test_device_payload_is_sanitized(test_db):
    """Los textos provenientes de la red se sanean y se acotan antes de guardarse."""
    dev, _is_new = database.upsert_device(test_db, {
        "mac": "00:e0:4c:aa:bb:cc",
        "ip": "192.168.1.60",
        "hostname": "host\x00name\ncon salto" + ("x" * 400),
        "vendor": "Fabricante\r\ninyectado",
        "status": "estado-inventado",
    })

    assert "\x00" not in dev["hostname"]
    assert "\n" not in dev["hostname"]
    assert len(dev["hostname"]) <= 253
    assert "\n" not in dev["vendor"]
    # Un estado no reconocido cae en el valor seguro 'online'
    assert dev["status"] in {"online", "offline", "stale", "blocked"}


def test_upsert_rejects_invalid_ip(test_db):
    """Una IP malformada no debe persistirse en el inventario."""
    import pytest as _pytest

    with _pytest.raises(ValueError):
        database.upsert_device(test_db, {
            "mac": "00:e0:4c:aa:bb:cd",
            "ip": "999.999.999.999",
            "status": "online",
        })


def test_log_event_sanitizes_and_validates_severity(test_db):
    """El historial guarda texto saneado y una severidad dentro del conjunto válido."""
    database.log_event(
        test_db,
        "event_type_largo" + "x" * 80,
        None,
        "no-es-una-ip",
        "Detalle con \x07control y \n salto de línea",
        severity="severidad-inventada",
    )

    history = database.get_history(test_db)
    assert len(history) == 1
    entry = history[0]
    assert len(entry["event_type"]) <= 32
    assert "\n" not in entry["details"]
    assert "\x07" not in entry["details"]
    assert entry["severity"] == "info"


def test_history_limit_is_clamped(test_db):
    """El parámetro limit se acota entre 1 y 500 registros."""
    for index in range(5):
        database.log_event(test_db, "test", None, "", f"evento {index}")

    assert len(database.get_history(test_db, limit=0)) == 1
    assert len(database.get_history(test_db, limit=100000)) == 5


def test_set_device_offline(test_db):
    """La vigilancia en tiempo real marca offline y registra un evento."""
    mac = "aa:bb:cc:00:11:50"
    database.upsert_device(test_db, {"mac": mac, "ip": "192.168.1.150", "status": "online"})

    device = database.set_device_offline(test_db, mac)
    assert device is not None
    assert device["status"] == "offline"

    # Ya estaba offline: no se repite el evento
    assert database.set_device_offline(test_db, mac) is None

    events = database.get_history(test_db, event_type="disconnected")
    assert len(events) == 1


def test_set_device_offline_keeps_blocked_state(test_db):
    """Un equipo bloqueado administrativamente no pasa a 'offline'."""
    mac = "aa:bb:cc:00:11:51"
    database.upsert_device(test_db, {"mac": mac, "ip": "192.168.1.151", "status": "online"})
    database.set_device_blocked_state(test_db, mac, is_blocked=True, reason="prueba")

    assert database.set_device_offline(test_db, mac) is None
    assert database.get_device_by_mac(test_db, mac)["status"] == "blocked"


def test_set_device_offline_unknown_mac(test_db):
    assert database.set_device_offline(test_db, "aa:bb:cc:00:11:52") is None
    assert database.set_device_offline(test_db, "no-es-mac") is None


def test_database_file_has_restricted_permissions(test_db):
    """El inventario de red no debe ser legible por otros usuarios (POSIX)."""
    if os.name == "nt":
        return
    mode = test_db and (os.stat(test_db).st_mode & 0o777)
    assert mode == 0o600


# ============================================================================
# Huella de dispositivos (tipo, sistema operativo y servicios)
# ============================================================================

def test_device_fingerprint_is_stored(test_db):
    """El tipo, SO y evidencias se persisten y se devuelven al consultar."""
    dev, _is_new = database.upsert_device(test_db, {
        "mac": "aa:bb:cc:00:11:22",
        "ip": "192.168.1.70",
        "hostname": "iPhone-de-Luis",
        "device_type": "smartphone",
        "device_type_confidence": "high",
        "device_evidence": ["El nombre contiene 'iPhone'", "Nombre visible: iPhone-de-Luis"],
        "os_guess": "iOS",
        "services": "62078 (Sincronización iPhone)",
        "name_source": "netbios",
        "model": "iPhone14,2",
    })

    assert dev["device_type"] == "smartphone"
    assert dev["device_type_label"] == "Móvil"
    assert dev["os_guess"] == "iOS"
    assert dev["name_source"] == "netbios"
    assert dev["model"] == "iPhone14,2"
    assert "iPhone" in dev["device_evidence"]
    assert "62078" in dev["services"]


def test_device_fingerprint_defaults_to_unknown(test_db):
    """Sin huella, el dispositivo queda como desconocido (nunca nulo)."""
    dev, _is_new = database.upsert_device(test_db, {
        "mac": "aa:bb:cc:00:11:23",
        "ip": "192.168.1.71",
    })
    assert dev["device_type"] == "unknown"
    assert dev["device_type_label"] == "Desconocido"
    assert dev["device_type_confidence"] == "low"


def test_unknown_fingerprint_does_not_overwrite_known_type(test_db):
    """Una ronda posterior sin evidencia no debe degradar la clasificación."""
    mac = "aa:bb:cc:00:11:24"
    database.upsert_device(test_db, {
        "mac": mac,
        "ip": "192.168.1.72",
        "device_type": "printer",
        "device_type_confidence": "high",
        "services": "9100 (Impresora RAW)",
    })

    dev, _is_new = database.upsert_device(test_db, {
        "mac": mac,
        "ip": "192.168.1.72",
        "device_type": "unknown",
    })

    assert dev["device_type"] == "printer"
    assert dev["device_type_confidence"] == "high"
    assert "9100" in dev["services"]


def test_get_all_devices_filters_by_device_type(test_db):
    """El filtro por tipo agrupa ordenadores y permite filtrar por móviles."""
    database.upsert_device(test_db, {
        "mac": "aa:bb:cc:00:11:30", "ip": "192.168.1.80",
        "device_type": "smartphone", "os_guess": "Android",
    })
    database.upsert_device(test_db, {
        "mac": "aa:bb:cc:00:11:31", "ip": "192.168.1.81",
        "device_type": "desktop", "os_guess": "Windows",
    })
    database.upsert_device(test_db, {
        "mac": "aa:bb:cc:00:11:32", "ip": "192.168.1.82",
        "device_type": "router",
    })

    phones = database.get_all_devices(test_db, device_type_filter="smartphone")
    assert len(phones) == 1 and phones[0]["device_type"] == "smartphone"

    computers = database.get_all_devices(test_db, device_type_filter="computer")
    assert len(computers) == 1 and computers[0]["device_type"] == "desktop"

    routers = database.get_all_devices(test_db, device_type_filter="router")
    assert len(routers) == 1

    assert len(database.get_all_devices(test_db)) == 3


def test_get_device_fingerprints(test_db):
    database.upsert_device(test_db, {
        "mac": "aa:bb:cc:00:11:40", "ip": "192.168.1.90",
        "device_type": "tv", "device_type_confidence": "medium",
    })
    fingerprints = database.get_device_fingerprints(test_db)
    assert fingerprints["aa:bb:cc:00:11:40"] == {"device_type": "tv", "confidence": "medium"}


def test_schema_migration_from_old_database(tmp_path):
    """
    Una base de datos creada por una versión anterior se migra sin perder datos.
    """
    import sqlite3

    db_file = str(tmp_path / "mangored_antigua.db")
    conn = sqlite3.connect(db_file)
    conn.executescript("""
        CREATE TABLE devices (
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
            is_new INTEGER DEFAULT 1
        );
    """)
    conn.execute(
        "INSERT INTO devices (mac, ip, first_seen, last_seen) VALUES (?, ?, ?, ?)",
        ("aa:bb:cc:dd:ee:ff", "192.168.1.5",
         "2026-01-01T00:00:00+00:00", "2026-01-01T00:00:00+00:00"),
    )
    conn.commit()
    conn.close()

    database.init_db(db_file)

    with database.get_db_connection(db_file) as conn:
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(devices)")}
        row = conn.execute("SELECT * FROM devices WHERE mac = ?", ("aa:bb:cc:dd:ee:ff",)).fetchone()

    for column in ("device_type", "device_type_label", "os_guess",
                   "device_type_confidence", "device_evidence", "services",
                   "name_source", "model"):
        assert column in columns

    # Los datos previos se conservan
    assert row["ip"] == "192.168.1.5"
    assert row["device_type"] == "unknown"

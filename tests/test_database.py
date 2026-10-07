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

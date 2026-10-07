"""
Pruebas de seguridad para controladores de router y validación de permisos.
Garantiza que el bloqueo solo se ejecute con confirmación y cuando no esté en modo solo lectura.
"""

import pytest
from app import app
from config import config
import database
from router.simulator import SimulatorRouterDriver


@pytest.fixture
def client(tmp_path):
    """Cliente de pruebas HTTP para Flask con base de datos temporal."""
    test_db = str(tmp_path / "test_api.db")
    database.init_db(test_db)
    config.db_path = test_db
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_simulator_driver_functionality():
    """Verifica que el controlador de simulación responda adecuadamente."""
    driver = SimulatorRouterDriver(config)
    ok, msg = driver.test_connection()
    assert ok is True

    # Bloqueo simulado
    b_ok, b_msg = driver.block_device("aa:bb:cc:dd:ee:ff", "192.168.1.44", "Camara-Test")
    assert b_ok is True
    assert "[MODO SIMULADOR]" in b_msg

    caps = driver.get_capabilities()
    assert caps["is_simulated"] is True
    assert caps["blocked_count"] >= 1

    # Desbloqueo
    u_ok, u_msg = driver.unblock_device("aa:bb:cc:dd:ee:ff")
    assert u_ok is True


def test_block_denied_in_read_only_mode(client):
    """Comprueba que intentar bloquear con READ_ONLY=True retorne HTTP 403 Forbidden."""
    config.read_only = True
    mac = "00:11:22:33:44:55"

    # Insertar dispositivo primero
    database.upsert_device(config.db_path, {
        "mac": mac,
        "ip": "192.168.1.100",
        "status": "online"
    })

    res = client.post("/api/router/block", json={
        "mac": mac,
        "confirmed": True,
        "reason": "Prueba de bloqueo"
    })

    assert res.status_code == 403
    data = res.get_json()
    assert data["success"] is False
    assert "Modo Solo Lectura" in data["error"]


def test_block_requires_explicit_confirmation(client):
    """Comprueba que intentar bloquear sin confirmación explícita retorne error 400."""
    config.read_only = False  # Permitir escritura para probar la validación de confirmación
    mac = "00:11:22:33:44:55"

    database.upsert_device(config.db_path, {
        "mac": mac,
        "ip": "192.168.1.100",
        "status": "online"
    })

    res = client.post("/api/router/block", json={
        "mac": mac,
        "confirmed": False,  # Sin confirmación
        "reason": "Prueba"
    })

    assert res.status_code == 400
    data = res.get_json()
    assert data["success"] is False
    assert "confirmación explícita" in data["error"].lower()

    # Restaurar modo seguro
    config.read_only = True


def test_block_with_confirmation_and_write_mode(client):
    """Comprueba que con confirmación y modo escritura habilitado el bloqueo se ejecute en el simulador."""
    config.read_only = False
    mac = "00:11:22:33:44:55"

    database.upsert_device(config.db_path, {
        "mac": mac,
        "ip": "192.168.1.100",
        "status": "online"
    })

    res = client.post("/api/router/block", json={
        "mac": mac,
        "confirmed": True,
        "reason": "Bloqueo autorizado de prueba"
    })

    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True

    # Verificar que el dispositivo quedó marcado como bloqueado en la base de datos
    dev = database.get_device_by_mac(config.db_path, mac)
    assert dev["is_blocked"] == 1
    assert dev["status"] == "blocked"

    # Restaurar modo seguro
    config.read_only = True

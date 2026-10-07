"""
Pruebas integrales de la API REST de MangoRed.
"""

import pytest
from app import app
from config import config
import database


@pytest.fixture
def client(tmp_path):
    test_db = str(tmp_path / "test_api_endpoints.db")
    database.init_db(test_db)
    config.db_path = test_db
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_index_page(client):
    """Comprueba que la página principal HTML cargue con código 200."""
    res = client.get("/")
    assert res.status_code == 200
    assert b"MangoRed" in res.data
    assert b"Modo Solo Lectura" in res.data


def test_devices_endpoints(client):
    """Comprueba el listado y actualización de dispositivos."""
    # Listado vacío inicial
    res = client.get("/api/devices")
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["count"] == 0

    # Insertar dispositivo
    mac = "98:22:ef:87:a4:61"
    database.upsert_device(config.db_path, {
        "mac": mac,
        "ip": "192.168.1.15",
        "hostname": "kali-host",
        "vendor": "Liteon",
        "status": "online"
    })

    # Consultar de nuevo
    res = client.get("/api/devices")
    data = res.get_json()
    assert data["count"] == 1
    assert data["devices"][0]["mac"] == mac

    # Consultar por MAC individual
    res_ind = client.get(f"/api/devices/{mac}")
    assert res_ind.status_code == 200
    assert res_ind.get_json()["device"]["ip"] == "192.168.1.15"

    # Actualizar metadata personalizada
    res_custom = client.post(f"/api/devices/{mac}/custom", json={
        "custom_name": "Estación Kali de Pruebas",
        "custom_tags": "Seguridad,Auditoría",
        "notes": "Equipo de laboratorio"
    })
    assert res_custom.status_code == 200
    assert res_custom.get_json()["success"] is True

    # Verificar actualización
    res_updated = client.get(f"/api/devices/{mac}")
    assert res_updated.get_json()["device"]["custom_name"] == "Estación Kali de Pruebas"


def test_stats_and_guide_endpoints(client):
    """Comprueba los endpoints de métricas y guía oficial."""
    res_stats = client.get("/api/stats")
    assert res_stats.status_code == 200
    stats_data = res_stats.get_json()
    assert "stats" in stats_data
    assert "read_only" in stats_data

    res_guide = client.get("/api/guide")
    assert res_guide.status_code == 200
    guide_data = res_guide.get_json()
    assert guide_data["success"] is True
    assert "ethics_and_security" in guide_data["guide"]
    assert "huawei" in guide_data["guide"]

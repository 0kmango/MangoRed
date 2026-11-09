"""
Pruebas integrales de la API REST de MangoRed.

Incluye la verificación de las defensas transversales: token local
obligatorio en operaciones de escritura y validación de la cabecera Host.
"""

import pytest
from app import app, api_token
from config import config
import database

#: Cabeceras con el token local efímero generado al arrancar el proceso.
AUTH_HEADERS = {"X-MangoRed-Token": api_token.value}


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
    # El token se inyecta en el propio documento para el cliente JS.
    assert api_token.value.encode() in res.data


def test_security_headers_present(client):
    """Verifica las cabeceras defensivas en las respuestas."""
    res = client.get("/api/health")
    assert res.status_code == 200
    assert res.headers["X-Content-Type-Options"] == "nosniff"
    assert res.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'self'" in res.headers["Content-Security-Policy"]
    assert "script-src 'self'" in res.headers["Content-Security-Policy"]
    assert "unsafe-inline" not in res.headers["Content-Security-Policy"].split("script-src")[1].split(";")[0]
    assert res.headers["Cache-Control"].startswith("no-store")


def test_host_header_validation(client):
    """Una cabecera Host ajena (DNS rebinding) debe ser rechazada."""
    res = client.get("/api/health", headers={"Host": "evil.example.com"})
    assert res.status_code == 403
    assert res.get_json()["success"] is False


def test_write_requires_token(client):
    """Toda operación de escritura sin token local debe responderse con 403."""
    res = client.post("/api/scan")
    assert res.status_code == 403
    assert "Token" in res.get_json()["error"]


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

    # Actualizar metadata personalizada (requiere token)
    res_custom = client.post(f"/api/devices/{mac}/custom", json={
        "custom_name": "Estación de Pruebas",
        "custom_tags": "Seguridad,Auditoría",
        "notes": "Equipo de laboratorio"
    }, headers=AUTH_HEADERS)
    assert res_custom.status_code == 200
    assert res_custom.get_json()["success"] is True

    # Verificar actualización
    res_updated = client.get(f"/api/devices/{mac}")
    assert res_updated.get_json()["device"]["custom_name"] == "Estación de Pruebas"


def test_stats_and_guide_endpoints(client):
    """Comprueba los endpoints de métricas, guía e interfaces."""
    res_stats = client.get("/api/stats")
    assert res_stats.status_code == 200
    stats_data = res_stats.get_json()
    assert "stats" in stats_data
    assert "read_only" in stats_data
    assert "platform" in stats_data

    res_guide = client.get("/api/guide")
    assert res_guide.status_code == 200
    guide_data = res_guide.get_json()
    assert guide_data["success"] is True
    assert "ethics_and_security" in guide_data["guide"]
    assert "huawei" in guide_data["guide"]

    res_ifaces = client.get("/api/interfaces")
    assert res_ifaces.status_code == 200
    assert isinstance(res_ifaces.get_json()["interfaces"], list)


def test_history_limit_validation(client):
    """Un 'limit' no numérico debe devolver 400 y no un error 500."""
    res = client.get("/api/history?limit=abc")
    assert res.status_code == 400
    assert res.get_json()["success"] is False


def test_health_endpoint_reports_platform(client):
    """El endpoint de salud informa de la plataforma y herramientas disponibles."""
    res = client.get("/api/health")
    payload = res.get_json()
    assert payload["status"] == "ok"
    assert payload["platform"] in {"Linux", "Windows", "macOS"}
    assert "tools" in payload["system"]


def test_events_endpoint_reports_watcher_state(client):
    """El endpoint de tiempo real devuelve eventos, último id y estado del vigilante."""
    res = client.get("/api/events?since=0")
    assert res.status_code == 200

    payload = res.get_json()
    assert payload["success"] is True
    assert isinstance(payload["events"], list)
    assert isinstance(payload["latest"], int)
    assert "running" in payload["watcher"]
    assert payload["watcher"]["interval"] >= 2


def test_events_endpoint_validates_since(client):
    assert client.get("/api/events?since=abc").status_code == 400


def test_devices_type_filter(client):
    """El inventario se puede filtrar por tipo de dispositivo detectado."""
    database.upsert_device(config.db_path, {
        "mac": "aa:bb:cc:11:22:33", "ip": "192.168.1.60",
        "device_type": "smartphone", "os_guess": "Android",
    })
    database.upsert_device(config.db_path, {
        "mac": "aa:bb:cc:11:22:34", "ip": "192.168.1.61",
        "device_type": "desktop", "os_guess": "Windows",
    })

    phones = client.get("/api/devices?type=smartphone").get_json()
    assert phones["count"] == 1
    assert phones["devices"][0]["device_type"] == "smartphone"
    assert phones["devices"][0]["device_type_label"] == "Móvil"

    computers = client.get("/api/devices?type=computer").get_json()
    assert computers["count"] == 1
    assert computers["devices"][0]["os_guess"] == "Windows"

    unknown = client.get("/api/devices?type=unknown").get_json()
    assert unknown["count"] == 0

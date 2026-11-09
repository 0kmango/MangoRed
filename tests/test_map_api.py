"""
Pruebas de la vista "Mango LAN Map": endpoints, posiciones y plano de planta.

Se aísla la base de datos en un directorio temporal y se simula el contexto de
red para que las pruebas no dependan de la red real del equipo.
"""

import io

import pytest

import app as app_module
import database
import map_layout
import scanner
from app import api_token, app
from config import config

MAC = "aa:bb:cc:dd:ee:01"
MAC2 = "aa:bb:cc:dd:ee:02"
AUTH_HEADERS = {"X-MangoRed-Token": api_token.value}
PNG_BYTES = b"\x89PNG\r\n\x1a\n" + b"0" * 64
JPEG_BYTES = b"\xff\xd8\xff" + b"0" * 64


@pytest.fixture
def map_client(tmp_path, monkeypatch):
    db_file = str(tmp_path / "map.db")
    database.init_db(db_file)
    monkeypatch.setattr(config, "db_path", db_file)
    monkeypatch.setattr(app_module, "MAP_ASSETS_DIR", tmp_path / "map_assets")
    monkeypatch.setattr(
        scanner, "detect_network_context",
        lambda preferred="": {
            "interface": "wlan0",
            "local_ip": "192.168.1.10",
            "local_mac": "aa:bb:cc:dd:ee:00",
            "subnet": "192.168.1.0/24",
            "gateway": "192.168.1.1",
        },
    )
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def seed_devices():
    database.upsert_device(config.db_path, {
        "mac": MAC, "ip": "192.168.1.1", "hostname": "router",
        "vendor": "Huawei", "device_type": "router",
        "device_type_label": "Router / Punto de acceso", "status": "online",
    })
    database.upsert_device(config.db_path, {
        "mac": MAC2, "ip": "192.168.1.20", "hostname": "movil",
        "vendor": "Xiaomi", "device_type": "smartphone",
        "device_type_label": "Móvil", "os_guess": "Android", "status": "online",
    })


def upload(client, payload, filename, headers=None):
    data = {"file": (io.BytesIO(payload), filename)}
    return client.post(
        "/api/map/floorplan",
        data=data,
        headers=headers or {},
        content_type="multipart/form-data",
    )


# ============================================================================
# Vista y estado del mapa
# ============================================================================

def test_map_page_renders_with_token(map_client):
    response = map_client.get("/map")
    assert response.status_code == 200
    assert b"Mango LAN Map" in response.data
    assert api_token.value.encode() in response.data
    assert b"/static/js/map.js" in response.data


def test_main_panel_links_to_map(map_client):
    response = map_client.get("/")
    assert response.status_code == 200
    assert b'href="/map"' in response.data


def test_map_endpoint_returns_nodes_with_layout(map_client):
    seed_devices()
    payload = map_client.get("/api/map").get_json()

    assert payload["success"] is True
    assert payload["gateway_ip"] == "192.168.1.1"
    assert len(payload["nodes"]) == 2

    by_mac = {node["mac"]: node for node in payload["nodes"]}
    gateway = by_mac[MAC]
    assert gateway["center"] is True
    assert (gateway["x"], gateway["y"]) == (50.0, 50.0)

    phone = by_mac[MAC2]
    assert map_layout.MIN_COORD <= phone["x"] <= map_layout.MAX_COORD
    assert phone["display_name"] == "movil"
    assert phone["device_type"] == "smartphone"

    assert payload["stats"]["total_devices"] == 2
    assert "watcher" in payload
    assert payload["floorplan"] is False


def test_map_endpoint_validates_since(map_client):
    assert map_client.get("/api/map?since=abc").status_code == 400


# ============================================================================
# Posiciones
# ============================================================================

def test_positions_require_token(map_client):
    response = map_client.post("/api/map/positions", json={"positions": {MAC: [10, 20]}})
    assert response.status_code == 403


def test_positions_are_saved_and_reset(map_client):
    seed_devices()

    response = map_client.post(
        "/api/map/positions",
        json={"positions": {MAC2: [12.5, 88.0]}},
        headers=AUTH_HEADERS,
    )
    assert response.status_code == 200
    assert response.get_json()["saved"] == 1

    payload = map_client.get("/api/map").get_json()
    phone = next(node for node in payload["nodes"] if node["mac"] == MAC2)
    assert phone["pinned"] is True
    assert phone["x"] == 12.5 and phone["y"] == 88.0
    assert payload["pinned_count"] == 1

    response = map_client.post(
        "/api/map/positions/reset", json={"mac": MAC2}, headers=AUTH_HEADERS
    )
    assert response.get_json()["reset"] == 1

    payload = map_client.get("/api/map").get_json()
    phone = next(node for node in payload["nodes"] if node["mac"] == MAC2)
    assert phone["pinned"] is False


def test_positions_reject_invalid_values(map_client):
    seed_devices()

    response = map_client.post(
        "/api/map/positions",
        json={"positions": {MAC2: [500, -10]}},
        headers=AUTH_HEADERS,
    )
    assert response.get_json()["saved"] == 0

    response = map_client.post(
        "/api/map/positions", json={"positions": {}}, headers=AUTH_HEADERS
    )
    assert response.status_code == 400


def test_positions_reset_all(map_client):
    seed_devices()
    map_client.post(
        "/api/map/positions",
        json={"positions": {MAC: [20, 20], MAC2: [80, 80]}},
        headers=AUTH_HEADERS,
    )
    response = map_client.post(
        "/api/map/positions/reset", json={}, headers=AUTH_HEADERS
    )
    assert response.get_json()["reset"] == 2
    assert map_client.get("/api/map").get_json()["pinned_count"] == 0


def test_positions_reset_rejects_invalid_mac(map_client):
    response = map_client.post(
        "/api/map/positions/reset", json={"mac": "no-es-mac"}, headers=AUTH_HEADERS
    )
    assert response.status_code == 400


# ============================================================================
# Plano de planta
# ============================================================================

def test_floorplan_rejects_non_image(map_client):
    # Un archivo de texto renombrado a .png se rechaza por su firma
    response = upload(map_client, b"esto no es una imagen", "plano.png", AUTH_HEADERS)
    assert response.status_code == 400


def test_floorplan_upload_get_and_delete(map_client):
    response = upload(map_client, PNG_BYTES, "plano.png", AUTH_HEADERS)
    assert response.status_code == 200
    assert response.get_json()["mimetype"] == "image/png"

    served = map_client.get("/api/map/floorplan")
    assert served.status_code == 200
    assert served.mimetype == "image/png"
    assert served.data == PNG_BYTES

    assert map_client.get("/api/map").get_json()["floorplan"] is True

    deleted = map_client.delete("/api/map/floorplan", headers=AUTH_HEADERS)
    assert deleted.get_json()["success"] is True
    assert map_client.get("/api/map/floorplan").status_code == 404


def test_floorplan_rejects_wrong_extension(map_client):
    response = upload(map_client, PNG_BYTES, "plano.gif", AUTH_HEADERS)
    assert response.status_code == 400


def test_floorplan_requires_token(map_client):
    response = upload(map_client, PNG_BYTES, "plano.png")
    assert response.status_code == 403


def test_floorplan_accepts_jpeg(map_client):
    response = upload(map_client, JPEG_BYTES, "plano.jpg", AUTH_HEADERS)
    assert response.status_code == 200
    assert response.get_json()["mimetype"] == "image/jpeg"


# ============================================================================
# Persistencia en la base de datos
# ============================================================================

def test_database_map_positions(map_client):
    seed_devices()

    assert database.set_device_map_position(config.db_path, MAC2, 30, 40) is True
    device = database.get_device_by_mac(config.db_path, MAC2)
    assert (device["map_x"], device["map_y"], device["map_pinned"]) == (30.0, 40.0, 1)

    assert database.reset_map_positions(config.db_path) == 1
    device = database.get_device_by_mac(config.db_path, MAC2)
    assert device["map_pinned"] == 0


def test_database_map_position_validates_input(map_client):
    assert database.set_device_map_position(config.db_path, "no-es-mac", 10, 10) is False
    assert database.set_device_map_position(config.db_path, MAC, 150, 10) is False


def test_database_app_meta_roundtrip(map_client):
    database.set_meta(config.db_path, "floorplan", "floorplan.png")
    assert database.get_meta(config.db_path, "floorplan") == "floorplan.png"
    database.delete_meta(config.db_path, "floorplan")
    assert database.get_meta(config.db_path, "floorplan", "vacio") == "vacio"
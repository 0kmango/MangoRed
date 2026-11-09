"""
Pruebas de seguridad para controladores de router y validación de permisos.

Garantiza que el bloqueo solo se ejecute con autorización explícita,
confirmación del usuario y cuando no esté en modo solo lectura.
"""

import pytest

import app as app_module
from app import app, api_token
from config import config
import database

#: Cabeceras con el token local efímero exigido en operaciones de escritura.
AUTH_HEADERS = {"X-MangoRed-Token": api_token.value}


class _StubDriver:
    """Controlador de pruebas: simula respuestas reales sin tocar la red."""

    name = "Stub de pruebas"

    def test_connection(self):
        return True, "conexión simulada correcta"

    def block_device(self, mac, ip="", hostname=""):
        return True, f"bloqueo aplicado a {mac}"

    def unblock_device(self, mac, ip=""):
        return True, f"desbloqueo aplicado a {mac}"

    def get_capabilities(self):
        return {"driver": "stub", "is_simulated": False, "blocks_network": True}


@pytest.fixture
def client(tmp_path):
    """Cliente de pruebas HTTP para Flask con base de datos temporal."""
    test_db = str(tmp_path / "test_api.db")
    database.init_db(test_db)
    config.db_path = test_db
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


@pytest.fixture
def stub_driver(monkeypatch):
    """Sustituye el controlador real para probar la lógica del endpoint."""
    monkeypatch.setattr(app_module, "get_router_driver", lambda cfg: _StubDriver())
    monkeypatch.setattr(config, "authorization_confirmed", True)
    yield _StubDriver()
    config.authorization_confirmed = False


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
    }, headers=AUTH_HEADERS)

    assert res.status_code == 403
    data = res.get_json()
    assert data["success"] is False
    assert "Modo Solo Lectura" in data["error"]


def test_block_requires_explicit_confirmation(client, stub_driver):
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
    }, headers=AUTH_HEADERS)

    assert res.status_code == 400
    data = res.get_json()
    assert data["success"] is False
    assert "confirmación explícita" in data["error"].lower()

    # Restaurar modo seguro
    config.read_only = True


def test_block_with_confirmation_and_write_mode(client, stub_driver):
    """Con autorización, confirmación y escritura habilitada, el bloqueo se aplica."""
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
    }, headers=AUTH_HEADERS)

    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True

    # Verificar que el dispositivo quedó marcado como bloqueado en la base de datos
    dev = database.get_device_by_mac(config.db_path, mac)
    assert dev["is_blocked"] == 1
    assert dev["status"] == "blocked"

    # Restaurar modo seguro
    config.read_only = True


# ============================================================================
# Controladores reales: composición de URL y ausencia de falsos positivos
# ============================================================================

class _FakeConfig:
    """Configuración mínima aislada para probar los controladores sin tocar la real."""

    def __init__(self, host: str = "192.168.1.1", use_https: bool = False):
        self.router_host = host
        self.router_port = 443 if use_https else 80
        self.router_user = "admin"
        self.router_password = ""
        self.router_api_token = ""
        self.router_use_https = use_https
        self.router_verify_ssl = True
        self.router_timeout = 5


def test_base_driver_url_composition():
    """Las URLs se construyen desde la configuración validada del router."""
    from router.mikrotik import MikroTikRouterDriver
    from router.openwrt import OpenWrtRouterDriver

    mikrotik = MikroTikRouterDriver(_FakeConfig())
    assert mikrotik._get_base_url() == "http://192.168.1.1:80/rest"

    openwrt = OpenWrtRouterDriver(_FakeConfig(use_https=True))
    assert openwrt._get_base_url() == "https://192.168.1.1:443/ubus"

    generic = OpenWrtRouterDriver(_FakeConfig())
    assert generic.timeout == 5
    assert generic.verify_ssl is True


def test_openwrt_driver_does_not_fake_success_without_host():
    """
    El controlador de OpenWrt ya no devuelve éxito sin aplicar nada: sin IP de
    router configurada la operación se rechaza explícitamente.
    """
    from router.openwrt import OpenWrtRouterDriver

    driver = OpenWrtRouterDriver(_FakeConfig(host=""))

    ok, message = driver.block_device("aa:bb:cc:dd:ee:ff")
    assert ok is False
    assert "Configura primero" in message

    ok, message = driver.test_connection()
    assert ok is False
    assert "Configura primero" in message

    ok, message = driver.unblock_device("aa:bb:cc:dd:ee:ff")
    assert ok is False
    assert "Configura primero" in message


def test_openwrt_driver_rejects_invalid_mac():
    from router.openwrt import OpenWrtRouterDriver

    driver = OpenWrtRouterDriver(_FakeConfig())
    ok, message = driver.block_device("no-es-mac")
    assert ok is False
    assert "MAC inválida" in message


def test_router_drivers_warn_about_plain_http():
    """Los controladores avisan cuando el canal no está cifrado."""
    from router.generic_webhook import GenericWebhookRouterDriver
    from router.mikrotik import MikroTikRouterDriver
    from router.openwrt import OpenWrtRouterDriver

    for driver_class in (GenericWebhookRouterDriver, MikroTikRouterDriver, OpenWrtRouterDriver):
        capabilities = driver_class(_FakeConfig()).get_capabilities()
        assert capabilities["is_simulated"] is False
        assert "https" in capabilities["notice"].lower()
        assert capabilities["timeout_seconds"] == 5


def test_router_factory_falls_back_to_ssh():
    """No hay simulador: un tipo desconocido usa el controlador SSH real."""
    from router import get_router_driver
    from router.ssh_router import SSHRouterDriver

    class _UnknownConfig(_FakeConfig):
        router_type = "desconocido"

    driver = get_router_driver(_UnknownConfig())
    assert isinstance(driver, SSHRouterDriver)


# ============================================================================
# Salvaguarda de autorización (uso defensivo)
# ============================================================================

def test_real_driver_requires_authorization_declaration(client):
    """
    Con un controlador real y sin aceptar la declaración de autorización,
    el bloqueo debe rechazarse (403) y no tocar el router.
    """
    config.read_only = False
    config.router_type = "ssh"
    config.authorization_confirmed = False
    mac = "00:11:22:33:44:55"

    database.upsert_device(config.db_path, {
        "mac": mac,
        "ip": "192.168.1.101",
        "status": "online",
    })

    res = client.post("/api/router/block", json={
        "mac": mac,
        "confirmed": True,
        "reason": "Prueba de autorización",
    }, headers=AUTH_HEADERS)

    assert res.status_code == 403
    assert "autorización" in res.get_json()["error"].lower()

    # El dispositivo no debe haberse marcado como bloqueado
    assert database.get_device_by_mac(config.db_path, mac)["is_blocked"] == 0

    # Restaurar estado seguro
    config.router_type = "ssh"
    config.authorization_confirmed = False
    config.read_only = True


def test_router_test_endpoint_reports_diagnostics(client, monkeypatch):
    """Si la conexión falla, el endpoint devuelve un diagnóstico de servicios."""
    class _FailDriver:
        name = "SSH del Router"

        def test_connection(self):
            return False, "No se puede conectar por SSH a 192.168.1.1:22"

        def get_capabilities(self):
            return {"driver": "ssh", "is_simulated": False}

        def block_device(self, mac, ip="", hostname=""):
            return False, "no usado"

        def unblock_device(self, mac, ip=""):
            return False, "no usado"

    monkeypatch.setattr(app_module, "get_router_driver", lambda cfg: _FailDriver())
    monkeypatch.setattr(
        app_module, "probe_router_ports",
        lambda host, timeout=0.8: {"ssh": False, "http": True},
    )
    monkeypatch.setattr(app_module, "describe_open_ports", lambda ports: "Interfaz web HTTP (80)")
    monkeypatch.setattr(app_module, "suggest_router_action", lambda ports: "usa la guía")

    res = client.post("/api/router/test", headers=AUTH_HEADERS)
    assert res.status_code == 200

    data = res.get_json()
    assert data["success"] is False
    assert data["diagnostics"]["ports"] == {"ssh": False, "http": True}
    assert data["diagnostics"]["open_services"] == "Interfaz web HTTP (80)"
    assert data["diagnostics"]["suggestion"] == "usa la guía"


def test_unblock_requires_authorization_declaration(client):
    """El desbloqueo también exige la declaración de autorización."""
    config.read_only = False
    config.authorization_confirmed = False
    mac = "00:11:22:33:44:67"

    database.upsert_device(config.db_path, {
        "mac": mac,
        "ip": "192.168.1.103",
        "status": "blocked",
    })

    res = client.post("/api/router/unblock", json={"mac": mac}, headers=AUTH_HEADERS)

    assert res.status_code == 403
    assert "autorización" in res.get_json()["error"].lower()

    config.read_only = True

"""
Pruebas del controlador SSH (router/ssh_router.py).

Se valida la construcción de comandos (sin inyección posible), el bloqueo
completo (expulsión Wi-Fi + cortafuegos), la verificación posterior y el
comportamiento ante errores del router.
"""

import pytest

import router.ssh_router as ssh_module
from router import get_router_driver
from router.ssh_router import (
    SSHRouterDriver,
    describe_open_ports,
    probe_router_ports,
    suggest_router_action,
    tcp_port_open,
)

MAC = "aa:bb:cc:dd:ee:ff"
MAC_UPPER = "AA:BB:CC:DD:EE:FF"


class FakeConfig:
    router_host = "192.168.1.1"
    router_port = 80
    router_user = "root"
    router_password = "secreto"
    router_api_token = ""
    router_use_https = False
    router_verify_ssl = True
    router_timeout = 5
    router_type = "ssh"
    router_block_mode = "full"
    router_ssh_port = 22
    router_ssh_profile = "openwrt"
    router_ssh_key = ""
    router_ssh_accept_new_host_key = False


def make_driver(**overrides) -> SSHRouterDriver:
    config = FakeConfig()
    for key, value in overrides.items():
        setattr(config, key, value)
    return SSHRouterDriver(config)


# ============================================================================
# Comandos: perfil OpenWrt
# ============================================================================

def test_openwrt_block_commands_full_mode():
    script = make_driver().build_script("block", MAC)

    # Cortafuegos
    assert "uci set firewall.mangored_aabbccddeeff=rule" in script
    assert f"src_mac='{MAC_UPPER}'" in script
    assert "target='DROP'" in script
    assert "uci commit firewall" in script
    # Expulsión del Wi-Fi (lista MAC del AP + hostapd)
    assert "macfilter='deny'" in script
    assert f"uci add_list $s.maclist='{MAC_UPPER}'" in script
    assert "wifi reload" in script
    assert f"hostapd_cli -i $i deauthenticate {MAC_UPPER}" in script
    # Marcadores de verificación
    assert "echo MANGORED_FIREWALL=" in script
    assert "echo MANGORED_WIFI=" in script


def test_openwrt_block_internet_mode_does_not_touch_wifi():
    script = make_driver(router_block_mode="internet").build_script("block", MAC)

    assert "target='DROP'" in script
    assert "maclist" not in script
    assert "hostapd_cli" not in script
    assert "echo MANGORED_WIFI=0" in script


def test_openwrt_unblock_commands():
    script = make_driver().build_script("unblock", MAC)

    assert f"uci del_list $s.maclist='{MAC_UPPER}'" in script
    assert "uci -q delete firewall.mangored_aabbccddeeff" in script
    assert "echo MANGORED_FIREWALL=$(uci -q get firewall.mangored_aabbccddeeff" in script
    assert "echo MANGORED_WIFI=" in script


# ============================================================================
# Comandos: perfil iptables
# ============================================================================

def test_iptables_block_commands_full_mode():
    script = make_driver(router_ssh_profile="iptables").build_script("block", MAC)

    assert "iptables -N MANGORED" in script
    assert "iptables -C FORWARD -j MANGORED" in script
    assert f"--mac-source {MAC_UPPER} -j DROP" in script
    # En modo completo también se aísla el acceso al propio router
    assert "MANGORED_IN" in script
    assert "iptables -C INPUT -j MANGORED_IN" in script
    assert f"hostapd_cli -i $i deauthenticate {MAC_UPPER}" in script
    assert "echo MANGORED_FIREWALL=" in script


def test_iptables_block_internet_mode():
    script = make_driver(
        router_ssh_profile="iptables", router_block_mode="internet"
    ).build_script("block", MAC)

    assert "--mac-source" in script
    assert "MANGORED_IN" not in script
    assert "hostapd_cli" not in script


def test_iptables_unblock_commands():
    script = make_driver(router_ssh_profile="iptables").build_script("unblock", MAC)

    assert "while iptables -D MANGORED" in script
    assert "while iptables -D MANGORED_IN" in script
    assert "echo MANGORED_FIREWALL=$(iptables -C MANGORED" in script


# ============================================================================
# Seguridad de los comandos
# ============================================================================

def test_mac_is_normalized_and_section_has_no_separators():
    driver = make_driver()
    commands = driver.build_commands("block", "AA-BB-CC-DD-EE-FF")
    assert any("mangored_aabbccddeeff" in c for c in commands)
    assert driver.rule_name(MAC) == "mangored_aabbccddeeff"


def test_invalid_mac_is_rejected_without_building_commands():
    driver = make_driver()
    with pytest.raises(ValueError):
        driver.build_commands("block", "aa:bb:cc:dd:ee")
    with pytest.raises(ValueError):
        driver.build_commands("block", "aa:bb:cc:dd:ee:ff; rm -rf /")


def test_unknown_action_is_rejected():
    with pytest.raises(ValueError):
        make_driver().build_commands("format", MAC)


# ============================================================================
# Ejecución (transporte simulado)
# ============================================================================

def test_block_device_full_mode_reports_wifi_disconnection(monkeypatch):
    driver = make_driver()
    monkeypatch.setattr(
        driver, "_run",
        lambda script: (True, "MANGORED_FIREWALL=DROP\nMANGORED_WIFI=2"),
    )

    ok, message = driver.block_device(MAC, "192.168.1.50", "Mi Movil")
    assert ok is True
    assert "desconectado de la red" in message.lower()
    assert "expulsado del Wi-Fi" in message
    assert "2 interfaz" in message
    assert MAC_UPPER in message


def test_block_device_reports_internet_only_when_no_wifi(monkeypatch):
    """Equipo por cable o router sin hostapd: se informa de lo que sí se aplicó."""
    driver = make_driver()
    monkeypatch.setattr(
        driver, "_run",
        lambda script: (True, "MANGORED_FIREWALL=DROP\nMANGORED_WIFI=0"),
    )

    ok, message = driver.block_device(MAC)
    assert ok is True
    assert "sin acceso a Internet" in message
    assert "No se pudo añadir la lista MAC del Wi-Fi" in message


def test_block_device_internet_mode_message(monkeypatch):
    driver = make_driver(router_block_mode="internet")
    monkeypatch.setattr(
        driver, "_run",
        lambda script: (True, "MANGORED_FIREWALL=DROP\nMANGORED_WIFI=0"),
    )

    ok, message = driver.block_device(MAC)
    assert ok is True
    assert "sigue conectado al Wi-Fi" in message


def test_block_device_fails_if_firewall_not_verified(monkeypatch):
    """Si el router no confirma target=DROP, no se reporta éxito."""
    driver = make_driver()
    monkeypatch.setattr(driver, "_run", lambda script: (True, "MANGORED_FIREWALL=MISSING"))

    ok, message = driver.block_device(MAC)
    assert ok is False
    assert "no se pudo verificar" in message.lower()


def test_block_device_reports_router_error(monkeypatch):
    driver = make_driver()
    monkeypatch.setattr(driver, "_run", lambda script: (False, "uci: command not found"))

    ok, message = driver.block_device(MAC)
    assert ok is False
    assert "uci: command not found" in message


def test_unblock_device_success(monkeypatch):
    driver = make_driver()
    monkeypatch.setattr(
        driver, "_run",
        lambda script: (True, "MANGORED_FIREWALL=REMOVED\nMANGORED_WIFI=0"),
    )

    ok, message = driver.unblock_device(MAC)
    assert ok is True
    assert "desbloqueado" in message.lower()
    assert "lista negra Wi-Fi" in message


def test_unblock_device_warns_about_remaining_wifi_entries(monkeypatch):
    driver = make_driver()
    monkeypatch.setattr(
        driver, "_run",
        lambda script: (True, "MANGORED_FIREWALL=REMOVED\nMANGORED_WIFI=1"),
    )

    ok, message = driver.unblock_device(MAC)
    assert ok is True
    assert "quedan 1 entrada" in message


def test_unblock_device_fails_if_not_verified(monkeypatch):
    driver = make_driver()
    monkeypatch.setattr(driver, "_run", lambda script: (True, "MANGORED_FIREWALL=PRESENT"))

    ok, message = driver.unblock_device(MAC)
    assert ok is False
    assert "no se pudo verificar" in message.lower()


def test_block_requires_router_host(monkeypatch):
    driver = make_driver(router_host="")
    ok, message = driver.block_device(MAC)
    assert ok is False
    assert "Configura primero" in message

    ok, message = driver.test_connection()
    assert ok is False
    assert "Configura primero" in message


def test_test_connection_reports_wifi_capability(monkeypatch):
    driver = make_driver()
    monkeypatch.setattr(
        driver, "_run",
        lambda script: (True, "Linux 5.15.0\nOpenWrt\n/usr/sbin/hostapd_cli"),
    )

    ok, message = driver.test_connection()
    assert ok is True
    assert "Linux 5.15.0" in message
    assert "hostapd): sí" in message
    assert "expulsión Wi-Fi + Internet" in message


def test_test_connection_detects_missing_iptables(monkeypatch):
    driver = make_driver(router_ssh_profile="iptables")
    monkeypatch.setattr(driver, "_run", lambda script: (True, "Linux 5.10\nroot"))

    ok, message = driver.test_connection()
    assert ok is False
    assert "iptables" in message


def test_capabilities_state_real_network_disconnection():
    capabilities = make_driver().get_capabilities()
    assert capabilities["driver"] == "ssh"
    assert capabilities["is_simulated"] is False
    assert capabilities["blocks_internet"] is True
    assert capabilities["blocks_network"] is True
    assert capabilities["block_mode"] == "full"

    internet_only = make_driver(router_block_mode="internet").get_capabilities()
    assert internet_only["blocks_network"] is False


def test_factory_returns_ssh_driver():
    driver = get_router_driver(FakeConfig())
    assert isinstance(driver, SSHRouterDriver)


# ============================================================================
# Diagnóstico del router (puerto SSH cerrado / sin API)
# ============================================================================

def test_tcp_port_open_handles_invalid_input():
    assert tcp_port_open("", 22) is False
    assert tcp_port_open("no-es-ip", 22, timeout=0.2) is False


def test_probe_router_ports_returns_known_keys(monkeypatch):
    monkeypatch.setattr(
        ssh_module, "tcp_port_open",
        lambda host, port, timeout=0.8: port == 80,
    )
    ports = probe_router_ports("192.168.1.1")

    assert set(ports) == {"ssh", "http", "https", "mikrotik_api", "winbox"}
    assert ports["http"] is True
    assert ports["ssh"] is False


def test_describe_open_ports_and_suggestion():
    assert "SSH (22)" in describe_open_ports({"ssh": True, "http": False})
    assert describe_open_ports({}) == "ninguno"
    assert describe_open_ports({"ssh": False, "http": False}) == "ninguno"

    assert "MikroTik" in suggest_router_action({"mikrotik_api": True})
    assert "interfaz web" in suggest_router_action({"http": True})
    assert "revisa usuario" in suggest_router_action({"ssh": True})
    assert "IP del router" in suggest_router_action({})


def test_unreachable_message_is_actionable(monkeypatch):
    """Con el puerto SSH cerrado, el mensaje explica el motivo y qué hacer."""
    monkeypatch.setattr(
        ssh_module, "probe_router_ports",
        lambda host, timeout=0.8: {"ssh": False, "http": True, "https": True},
    )
    message = make_driver()._unreachable_message()

    assert "192.168.1.1:22" in message
    assert "Interfaz web HTTP (80)" in message
    assert "pestaña Guía" in message
    assert "ONT" in message  # aviso para routers de operadora sin SSH


def test_block_fails_fast_when_ssh_port_is_closed(monkeypatch):
    """No se espera al timeout del handshake: se detecta el puerto cerrado."""
    driver = make_driver()
    monkeypatch.setattr(driver, "_ssh_reachable", lambda: False)
    monkeypatch.setattr(
        ssh_module, "probe_router_ports",
        lambda host, timeout=0.8: {"ssh": False, "http": True},
    )

    ok, message = driver.block_device(MAC)
    assert ok is False
    assert "No se puede conectar por SSH" in message
    assert "Servicios detectados" in message


def test_test_connection_uses_same_diagnostic(monkeypatch):
    driver = make_driver()
    monkeypatch.setattr(driver, "_ssh_reachable", lambda: False)
    monkeypatch.setattr(
        ssh_module, "probe_router_ports",
        lambda host, timeout=0.8: {"ssh": False, "mikrotik_api": True},
    )

    ok, message = driver.test_connection()
    assert ok is False
    assert "API MikroTik (8728)" in message
    assert "controlador MikroTik" in message
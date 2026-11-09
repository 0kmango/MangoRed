"""
Pruebas unitarias para el módulo de configuración y seguridad de MangoRed.
"""

import json
import os

import pytest

from config import (
    ALLOWED_ROUTER_TYPES,
    Config,
    is_local_address,
    normalize_mac,
    resolve_db_path,
    sanitize_interface,
    sanitize_text,
    validate_ip,
    validate_mac,
)


def test_default_read_only_mode(tmp_path):
    """Verifica que el modo de solo lectura esté estrictamente activado por defecto."""
    cfg = Config()
    assert cfg.read_only is True, "El modo de solo lectura debe estar activo por defecto."


def test_default_secure_values():
    """Los valores por defecto deben ser seguros (TLS verificado, sin credenciales)."""
    cfg = Config()
    assert cfg.router_verify_ssl is True
    assert cfg.router_use_https is False
    assert cfg.router_password == ""
    assert cfg.router_api_token == ""
    assert 1 <= cfg.router_timeout <= 30
    assert 1 <= cfg.scan_max_hosts <= 4096


def test_router_host_must_be_local():
    """
    La IP del router debe ser local: evita usar MangoRed como proxy SSRF
    hacia servicios de Internet.
    """
    assert is_local_address("192.168.1.1") is True
    assert is_local_address("10.1.2.3") is True
    assert is_local_address("172.20.5.5") is True
    assert is_local_address("127.0.0.1") is True
    assert is_local_address("169.254.10.10") is True   # link-local
    assert is_local_address("100.64.0.10") is True     # CGNAT
    assert is_local_address("8.8.8.8") is False
    assert is_local_address("no-es-ip") is False


def test_update_settings_rejects_non_local_router_host():
    cfg = Config()
    ok, message = cfg.update_settings({"router_host": "8.8.8.8", "read_only": True})
    assert ok is False
    assert "red local" in message
    assert cfg.router_host != "8.8.8.8"


def test_mac_validation():
    """Verifica la validación estricta de direcciones MAC."""
    valid_macs = [
        "00:11:22:33:44:55",
        "AA:BB:CC:DD:EE:FF",
        "00-11-22-33-44-55",
        "a1:b2:c3:d4:e5:f6"
    ]
    for m in valid_macs:
        assert validate_mac(m) is True, f"MAC válida rechazada: {m}"

    invalid_macs = [
        "00:11:22:33:44",        # Muy corta
        "00:11:22:33:44:55:66",   # Muy larga
        "GG:11:22:33:44:55",      # Caracter no hexadecimal
        "'; DROP TABLE devices;--", # Intento de inyección
        "",
        None
    ]
    for m in invalid_macs:
        assert validate_mac(m) is False, f"MAC inválida aceptada: {m}"


def test_normalize_mac():
    """Comprueba la normalización homogénea a minúsculas separadas por dos puntos."""
    assert normalize_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"
    assert normalize_mac("001122334455") == "00:11:22:33:44:55"
    with pytest.raises(ValueError):
        normalize_mac("invalida")


def test_ip_validation():
    """Verifica la validación de direcciones IPv4."""
    assert validate_ip("192.168.1.1") is True
    assert validate_ip("10.0.0.1") is True
    assert validate_ip("224.0.0.1") is False  # Multicast rechazada
    assert validate_ip("999.999.999.999") is False
    assert validate_ip("localhost") is False


def test_secrets_masking():
    """Verifica que las contraseñas nunca se expongan en texto claro al consultar la configuración."""
    cfg = Config()
    cfg.router_password = "SuperPasswordSegura123"
    cfg.router_api_token = "TokenSecreto456"

    exported = cfg.to_dict(hide_secrets=True)
    assert exported["router_password"] == "••••••••"
    assert exported["router_api_token"] == "••••••••"

    # En almacenamiento interno sí se preserva
    assert cfg.router_password == "SuperPasswordSegura123"


def test_update_settings_validates_ranges():
    """Los valores fuera de rango se rechazan con un mensaje claro."""
    cfg = Config()

    ok, message = cfg.update_settings({"scan_interval": 1})
    assert ok is False and "intervalo" in message.lower()

    ok, message = cfg.update_settings({"scan_max_hosts": 99999})
    assert ok is False and "barrido" in message.lower()

    ok, message = cfg.update_settings({"router_type": "inventado"})
    assert ok is False and "router" in message.lower()

    ok, message = cfg.update_settings({"router_port": 70000})
    assert ok is False and "puerto" in message.lower()

    ok, message = cfg.update_settings({"router_timeout": 999})
    assert ok is False and "espera" in message.lower()

    # Los campos desconocidos se ignoran sin provocar errores.
    ok, _message = cfg.update_settings({"campo_desconocido": "valor"})
    assert ok is True


def test_update_settings_accepts_valid_values():
    cfg = Config()
    ok, message = cfg.update_settings({
        "scan_interval": 45,
        "scan_max_hosts": 256,
        "router_timeout": 8,
        "router_type": "ssh",
        "read_only": True,
    })
    assert ok is True, message
    assert cfg.scan_interval == 45
    assert cfg.scan_max_hosts == 256
    assert cfg.router_timeout == 8
    assert cfg.router_type in ALLOWED_ROUTER_TYPES


def test_update_settings_rejects_non_dict():
    cfg = Config()
    ok, message = cfg.update_settings(["no", "es", "dict"])
    assert ok is False
    assert "JSON" in message


def test_interface_name_sanitization():
    """Se aceptan nombres reales de Linux y Windows, y se rechaza travesía."""
    assert sanitize_interface("wlan0") == "wlan0"
    assert sanitize_interface("Wi-Fi") == "Wi-Fi"
    assert sanitize_interface("Ethernet 2") == "Ethernet 2"
    assert sanitize_interface("") == ""

    for bad in ("../../etc/passwd", "con/barra", "con\\barra", "-flag"):
        with pytest.raises(ValueError):
            sanitize_interface(bad)


def test_sanitize_text_rejects_overlong_values():
    assert sanitize_text("ok", 10) == "ok"
    with pytest.raises(ValueError):
        sanitize_text("x" * 100, 10, "campo")


def test_resolve_db_path_is_absolute():
    resolved = resolve_db_path("mangored.db")
    assert os.path.isabs(resolved)
    assert resolved.endswith("mangored.db")


def test_update_settings_rejects_invalid_db_extension():
    cfg = Config()
    ok, message = cfg.update_settings({"db_path": "inventario.txt"})
    assert ok is False
    assert "extensión" in message


def test_malformed_config_file_falls_back_to_safe_defaults(tmp_path, monkeypatch):
    """Un JSON corrupto no debe romper el arranque: se usan valores seguros."""
    import config as config_module

    bad_file = tmp_path / "mangored_config.json"
    bad_file.write_text("{esto no es json valido", encoding="utf-8")

    monkeypatch.setattr(config_module, "CONFIG_FILE", bad_file)
    cfg = Config()

    assert cfg.read_only is True
    assert cfg.scan_interval == 30
    assert cfg.scan_max_hosts == 512
    assert cfg.router_type == "ssh"
    assert cfg.router_host == "192.168.1.1"


def test_config_file_is_created_with_restricted_permissions(tmp_path, monkeypatch):
    """El archivo de credenciales se escribe con permisos restrictivos."""
    import config as config_module

    target = tmp_path / "conf" / "mangored_config.json"
    monkeypatch.setattr(config_module, "CONFIG_FILE", target)

    Config()
    assert target.exists()

    stored = json.loads(target.read_text(encoding="utf-8"))
    assert stored["read_only"] is True
    assert stored["scan_max_hosts"] == 512

    if os.name != "nt":
        assert (target.stat().st_mode & 0o777) == 0o600


# ============================================================================
# Tiempo real, SSH y declaración de autorización
# ============================================================================

def test_authorization_is_disabled_by_default():
    """Nunca se opera sobre un router real sin aceptar la declaración."""
    cfg = Config()
    assert cfg.authorization_confirmed is False
    assert cfg.router_ssh_accept_new_host_key is False


def test_realtime_and_ssh_settings_validation():
    cfg = Config()

    ok, message = cfg.update_settings({"watch_interval": 1})
    assert ok is False and "vigilancia" in message.lower()

    ok, message = cfg.update_settings({"disconnect_grace": 5})
    assert ok is False and "gracia" in message.lower()

    ok, message = cfg.update_settings({"router_ssh_profile": "telnet"})
    assert ok is False and "ssh" in message.lower()

    ok, message = cfg.update_settings({"router_ssh_port": 70000})
    assert ok is False and "ssh" in message.lower()

    ok, message = cfg.update_settings({
        "watch_interval": 5,
        "disconnect_grace": 30,
        "router_ssh_profile": "iptables",
        "router_ssh_port": 2222,
        "router_ssh_accept_new_host_key": True,
        "authorization_confirmed": True,
        "router_type": "ssh",
    })
    assert ok is True, message
    assert cfg.watch_interval == 5
    assert cfg.disconnect_grace == 30
    assert cfg.router_ssh_profile == "iptables"
    assert cfg.router_ssh_port == 2222
    assert cfg.router_ssh_accept_new_host_key is True
    assert cfg.authorization_confirmed is True
    assert cfg.router_type == "ssh"


def test_ssh_router_type_is_allowed():
    cfg = Config()
    ok, message = cfg.update_settings({"router_type": "ssh"})
    assert ok is True, message
    assert cfg.router_type == "ssh"


def test_block_mode_validation():
    """El modo de bloqueo sólo admite 'full' (desconectar) o 'internet'."""
    cfg = Config()
    assert cfg.router_block_mode == "full"  # por defecto: desconectar de la red

    ok, message = cfg.update_settings({"router_block_mode": "internet"})
    assert ok is True, message
    assert cfg.router_block_mode == "internet"

    ok, message = cfg.update_settings({"router_block_mode": "inventado"})
    assert ok is False
    assert "bloqueo" in message.lower()


def test_old_simulator_config_is_migrated_to_ssh(tmp_path, monkeypatch):
    """Un archivo de configuración antiguo con 'simulator' pasa a SSH real."""
    import config as config_module

    legacy = tmp_path / "mangored_config.json"
    legacy.write_text('{"router_type": "simulator", "read_only": true}', encoding="utf-8")
    monkeypatch.setattr(config_module, "CONFIG_FILE", legacy)

    cfg = Config()
    assert cfg.router_type == "ssh"
    assert "simulator" not in config_module.ALLOWED_ROUTER_TYPES

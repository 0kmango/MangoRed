"""
Pruebas unitarias para el módulo de configuración y seguridad de MangoRed.
"""

import os
import pytest
from config import Config, validate_mac, normalize_mac, validate_ip


def test_default_read_only_mode(tmp_path):
    """Verifica que el modo de solo lectura esté estrictamente activado por defecto."""
    cfg = Config()
    assert cfg.read_only is True, "El modo de solo lectura debe estar activo por defecto."


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

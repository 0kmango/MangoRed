"""
Pruebas de los controles de seguridad de la API local (security.py).

Cubre: token efímero, comparación en tiempo constante, limitador de
peticiones, validación de la cabecera Host (anti DNS-rebinding) y política CSP.
"""

import time

from security import (
    CONTENT_SECURITY_POLICY,
    SAFE_METHODS,
    SECURITY_HEADERS,
    ApiToken,
    RateLimiter,
    allowed_hosts_from_environment,
    client_key,
    is_allowed_host,
    is_loopback_bind,
    parse_host_header,
)


def test_api_token_generation_and_comparison(monkeypatch):
    """Sin variable de entorno se genera un token aleatorio robusto."""
    monkeypatch.delenv("MANGORED_TEST_TOKEN", raising=False)
    token = ApiToken(env_var="MANGORED_TEST_TOKEN")

    assert token.from_environment is False
    assert len(token.value) >= 32
    assert token.matches(token.value) is True
    assert token.matches("valor-incorrecto") is False
    assert token.matches("") is False
    assert token.matches(None) is False


def test_api_token_from_environment(monkeypatch):
    """Un token definido por el usuario debe respetarse si tiene longitud suficiente."""
    monkeypatch.setenv("MANGORED_TEST_TOKEN", "token-local-largo-1234567890")
    token = ApiToken(env_var="MANGORED_TEST_TOKEN")

    assert token.from_environment is True
    assert token.value == "token-local-largo-1234567890"

    # Un token demasiado corto se descarta en favor de uno generado.
    monkeypatch.setenv("MANGORED_TEST_TOKEN", "corto")
    weak = ApiToken(env_var="MANGORED_TEST_TOKEN")
    assert weak.from_environment is False
    assert weak.value != "corto"


def test_rate_limiter_blocks_after_limit():
    """El limitador permite N llamadas y bloquea la siguiente con espera."""
    limiter = RateLimiter(max_calls=3, window_seconds=60)

    for _ in range(3):
        allowed, retry = limiter.hit("127.0.0.1:scan")
        assert allowed is True
        assert retry == 0

    allowed, retry = limiter.hit("127.0.0.1:scan")
    assert allowed is False
    assert retry >= 1

    # Otra clave no se ve afectada.
    allowed, _ = limiter.hit("127.0.0.1:router")
    assert allowed is True


def test_rate_limiter_window_expires():
    """Al expirar la ventana, el contador se reinicia."""
    limiter = RateLimiter(max_calls=1, window_seconds=1)
    assert limiter.hit("k")[0] is True
    assert limiter.hit("k")[0] is False

    time.sleep(1.05)
    assert limiter.hit("k")[0] is True


def test_host_header_parsing_and_validation():
    """Se acepta loopback y se rechaza cualquier host externo."""
    assert parse_host_header("127.0.0.1:5000") == "127.0.0.1"
    assert parse_host_header("[::1]:5000") == "::1"
    assert parse_host_header("LOCALHOST") == "localhost"
    assert parse_host_header(None) == ""

    assert is_allowed_host("127.0.0.1:5000") is True
    assert is_allowed_host("localhost") is True
    assert is_allowed_host("[::1]:5000") is True
    assert is_allowed_host("127.0.0.9") is True          # cualquier loopback
    assert is_allowed_host("evil.example.com") is False
    assert is_allowed_host("") is False

    # Hosts extra declarados explícitamente
    assert is_allowed_host("mi-panel.lan", {"mi-panel.lan"}) is True


def test_allowed_hosts_from_environment(monkeypatch):
    """MANGORED_ALLOWED_HOSTS añade hosts sin eliminar loopback."""
    monkeypatch.delenv("MANGORED_ALLOWED_HOSTS", raising=False)
    assert allowed_hosts_from_environment() == {"127.0.0.1", "localhost", "::1"}

    monkeypatch.setenv("MANGORED_ALLOWED_HOSTS", "panel.lan, 10.0.0.5")
    hosts = allowed_hosts_from_environment()
    assert "panel.lan" in hosts
    assert "10.0.0.5" in hosts
    assert "127.0.0.1" in hosts


def test_loopback_bind_detection():
    """La detección de escucha local se usa para exigir confirmación de exposición."""
    assert is_loopback_bind("127.0.0.1") is True
    assert is_loopback_bind("localhost") is True
    assert is_loopback_bind("::1") is True
    assert is_loopback_bind("0.0.0.0") is False
    assert is_loopback_bind("192.168.1.10") is False


def test_client_key_is_stable():
    assert client_key("127.0.0.1", "scan") == "127.0.0.1:scan"
    assert client_key(None, "router") == "local:router"


def test_csp_forbids_inline_scripts():
    """La CSP debe impedir scripts inline (mitigación de XSS)."""
    script_src = CONTENT_SECURITY_POLICY.split("script-src")[1].split(";")[0]
    assert "'self'" in script_src
    assert "unsafe-inline" not in script_src
    assert "frame-ancestors 'none'" in CONTENT_SECURITY_POLICY
    assert "object-src 'none'" in CONTENT_SECURITY_POLICY


def test_security_headers_are_complete():
    for header in (
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Referrer-Policy",
        "Content-Security-Policy",
        "Permissions-Policy",
    ):
        assert header in SECURITY_HEADERS

    assert SAFE_METHODS == {"GET", "HEAD", "OPTIONS"}
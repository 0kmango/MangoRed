"""
Controles de seguridad para la API HTTP local de MangoRed.

El panel se sirve en ``127.0.0.1``, pero un servicio local sigue siendo
accesible por cualquier proceso del equipo y por páginas web maliciosas que
intenten hablar con ``localhost`` (CSRF) o reescribir el DNS (DNS rebinding).
Este módulo aporta las defensas mínimas:

  * **Token de sesión local** exigido en toda petición que modifique estado
    (POST/PUT/PATCH/DELETE). Se genera en cada arranque, salvo que se defina
    ``MANGORED_API_TOKEN``.
  * **Validación estricta de la cabecera Host** para bloquear DNS rebinding.
  * **Limitador de peticiones** en memoria para acciones costosas o sensibles.
  * **Cabeceras de seguridad** (CSP sin scripts inline, no-sniff, no-frame...).
"""

from __future__ import annotations

import hmac
import ipaddress
import os
import secrets
import threading
import time
from collections import deque
from typing import Deque, Dict, Iterable, Optional, Tuple

#: Hosts considerados locales por defecto.
DEFAULT_ALLOWED_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})

#: Política CSP: sólo scripts del propio origen, sin ``unsafe-inline`` para JS.
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "font-src 'self' data:; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "frame-src 'none'; "
    "frame-ancestors 'none'; "
    "base-uri 'none'; "
    "form-action 'self'"
)

#: Cabeceras añadidas a todas las respuestas.
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=(), payment=()",
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
}

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


class ApiToken:
    """
    Token efímero que protege las operaciones de escritura de la API.

    Se puede fijar mediante la variable de entorno ``MANGORED_API_TOKEN``
    (útil para automatización); en caso contrario se genera con
    :func:`secrets.token_urlsafe` en cada arranque.
    """

    def __init__(self, env_var: str = "MANGORED_API_TOKEN", min_length: int = 16):
        configured = (os.environ.get(env_var, "") or "").strip()
        if len(configured) >= min_length:
            self._value = configured
            self.from_environment = True
        else:
            self._value = secrets.token_urlsafe(32)
            self.from_environment = False

    @property
    def value(self) -> str:
        return self._value

    def matches(self, candidate: Optional[str]) -> bool:
        """Compara en tiempo constante para evitar ataques de temporización."""
        if not candidate or not isinstance(candidate, str):
            return False
        return hmac.compare_digest(candidate, self._value)


class RateLimiter:
    """
    Limitador de ventana deslizante en memoria, seguro entre hilos.

    No persiste estado: al reiniciar el proceso se reinician los contadores.
    """

    def __init__(self, max_calls: int = 60, window_seconds: float = 60.0):
        self.max_calls = max(1, int(max_calls))
        self.window_seconds = max(1.0, float(window_seconds))
        self._buckets: Dict[str, Deque[float]] = {}
        self._lock = threading.Lock()

    def hit(self, key: str) -> Tuple[bool, int]:
        """Registra un intento. Devuelve ``(permitido, segundos_de_espera)``."""
        now = time.monotonic()
        with self._lock:
            bucket = self._buckets.setdefault(key, deque())
            while bucket and (now - bucket[0]) > self.window_seconds:
                bucket.popleft()

            if len(bucket) >= self.max_calls:
                retry_after = int(self.window_seconds - (now - bucket[0])) + 1
                return False, max(1, retry_after)

            bucket.append(now)
            if len(self._buckets) > 512:
                self._prune(now)
            return True, 0

    def _prune(self, now: float) -> None:
        """Elimina cubos inactivos para que el diccionario no crezca sin control."""
        stale = [
            key
            for key, bucket in self._buckets.items()
            if not bucket or (now - bucket[-1]) > self.window_seconds
        ]
        for key in stale:
            self._buckets.pop(key, None)

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()


def parse_host_header(host_header: Optional[str]) -> str:
    """
    Extrae el nombre de host de la cabecera ``Host``, soportando IPv6
    (``[::1]:5000``) y puertos (``127.0.0.1:5000``).
    """
    if not host_header:
        return ""
    value = str(host_header).strip().lower()
    if value.startswith("["):
        end = value.find("]")
        return value[1:end] if end > 0 else value
    return value.split(":", 1)[0]


def allowed_hosts_from_environment() -> set:
    """
    Conjunto de hosts permitidos.

    Por defecto sólo loopback. Para exponer el panel en una red de confianza se
    pueden añadir hosts explícitamente con ``MANGORED_ALLOWED_HOSTS``
    (separados por comas). En ese caso el token de API sigue siendo obligatorio
    para cualquier operación de escritura.
    """
    hosts = set(DEFAULT_ALLOWED_HOSTS)
    raw = (os.environ.get("MANGORED_ALLOWED_HOSTS", "") or "").strip()
    if raw:
        for item in raw.split(","):
            candidate = item.strip().lower()
            if candidate:
                hosts.add(candidate)
    return hosts


def is_allowed_host(host_header: Optional[str], extra_hosts: Optional[Iterable[str]] = None) -> bool:
    """Comprueba que la cabecera Host apunte a un destino permitido."""
    hostname = parse_host_header(host_header)
    if not hostname:
        return False

    allowed = set(DEFAULT_ALLOWED_HOSTS)
    if extra_hosts:
        allowed.update(str(h).strip().lower() for h in extra_hosts if str(h).strip())

    if hostname in allowed:
        return True

    # Cualquier dirección de loopback (127.0.0.0/8, ::1) es aceptable.
    try:
        address = ipaddress.ip_address(hostname)
        if address.is_loopback:
            return True
    except ValueError:
        pass

    return hostname in allowed


def is_loopback_bind(host: str) -> bool:
    """Indica si una dirección de escucha es de loopback."""
    if not host:
        return False
    if str(host).lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(str(host)).is_loopback
    except ValueError:
        return False


def client_key(remote_addr: Optional[str], bucket: str) -> str:
    """Clave de limitación por cliente y categoría de endpoint."""
    return f"{remote_addr or 'local'}:{bucket}"
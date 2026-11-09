"""
Módulo de Configuración y Seguridad para MangoRed.

Garantiza el modo de solo lectura por defecto, la protección estricta de
credenciales (permisos ``0600`` en POSIX y ACL equivalente en Windows),
validaciones de red y valores por defecto seguros ante archivos corruptos.

El archivo de configuración puede reubicarse con ``MANGORED_CONFIG_FILE``.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
from pathlib import Path
from typing import Any, Tuple

from platform_compat import PLATFORM_LABEL, secure_file_permissions

BASE_DIR = Path(__file__).resolve().parent
CONFIG_FILE = Path(
    os.environ.get("MANGORED_CONFIG_FILE", str(BASE_DIR / "mangored_config.json"))
).expanduser()
DEFAULT_DB_PATH = BASE_DIR / "mangored.db"

# Expresiones regulares de validación
MAC_REGEX = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")
CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")

ALLOWED_ROUTER_TYPES = ("ssh", "openwrt", "mikrotik", "generic_webhook")
ALLOWED_SSH_PROFILES = ("openwrt", "iptables")
#: Modo de bloqueo: "full" expulsa del Wi-Fi + corta Internet; "internet" sólo corta Internet.
ALLOWED_BLOCK_MODES = ("full", "internet")
DEFAULT_ROUTER_TYPE = "ssh"
ALLOWED_DB_SUFFIXES = (".db", ".sqlite", ".sqlite3")


def validate_mac(mac: str) -> bool:
    """Valida formato estándar de dirección MAC IEEE 802."""
    if not isinstance(mac, str):
        return False
    return bool(MAC_REGEX.match(mac.strip()))


def normalize_mac(mac: str) -> str:
    """Normaliza MAC a minúsculas separadas por dos puntos."""
    cleaned = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(cleaned) != 12:
        raise ValueError(f"Dirección MAC no válida: {mac}")
    return ":".join(cleaned[i:i + 2].lower() for i in range(0, 12, 2))


def validate_ip(ip: str) -> bool:
    """Valida si es una dirección IPv4 válida y no reservada/multicast."""
    try:
        addr = ipaddress.IPv4Address(str(ip).strip())
    except (ValueError, TypeError):
        return False
    return not addr.is_multicast and not addr.is_reserved


def is_local_address(ip: str) -> bool:
    """
    Indica si la IP pertenece a un rango local (privado, loopback, link-local
    o CGNAT). Se usa para impedir que la integración de router actúe como
    proxy hacia Internet (SSRF).
    """
    try:
        addr = ipaddress.IPv4Address(str(ip).strip())
    except (ValueError, TypeError):
        return False
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return True
    return addr in ipaddress.IPv4Network("100.64.0.0/10")


def sanitize_text(value: Any, max_length: int, field: str = "valor") -> str:
    """Elimina caracteres de control y recorta un texto de configuración."""
    text = CONTROL_CHARS.sub("", str(value if value is not None else ""))
    if len(text) > max_length:
        raise ValueError(f"El campo '{field}' supera el máximo de {max_length} caracteres.")
    return text.strip()


def sanitize_interface(value: Any) -> str:
    """
    Valida un nombre de interfaz de red.

    Se aceptan nombres de Linux (``wlan0``, ``enp3s0``) y de Windows
    (``Wi-Fi``, ``Ethernet 2``, ``Conexión de área local``), pero se rechazan
    separadores de ruta y secuencias de travesía.
    """
    text = CONTROL_CHARS.sub("", str(value or "")).strip()
    if not text:
        return ""
    if len(text) > 64:
        raise ValueError("El nombre de interfaz supera los 64 caracteres.")
    if "/" in text or "\\" in text or ".." in text or text.startswith("-"):
        raise ValueError("Nombre de interfaz de red no válido.")
    return text


def resolve_db_path(value: Any) -> str:
    """Resuelve una ruta de base de datos relativa al directorio del proyecto."""
    raw = str(value or "").strip()
    if not raw:
        return str(DEFAULT_DB_PATH)
    expanded = os.path.expandvars(os.path.expanduser(raw))
    path = Path(expanded)
    if not path.is_absolute():
        path = BASE_DIR / path
    try:
        return str(path.resolve())
    except OSError:
        return str(path)


def _as_bool(value: Any, default: bool) -> bool:
    """Convierte de forma tolerante valores JSON/strings a booleano."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "si", "sí", "on"}
    return default


def _as_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    """Convierte y acota un entero; devuelve el valor por defecto si es inválido."""
    try:
        number = int(float(value))
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, number))


class Config:
    """Configuración persistente de MangoRed con valores seguros por defecto."""

    def __init__(self):
        # Modo seguro: por defecto estrictamente SOLO LECTURA
        self.read_only = True

        # Parámetros del escáner
        self.scan_interval = 30      # segundos
        self.scan_max_hosts = 512    # límite de hosts sondeados por barrido
        self.interface = ""          # se autodetecta si está vacío
        self.auto_scan = True
        self.db_path = str(DEFAULT_DB_PATH)

        # Reconocimiento de dispositivos (nombres y tipo)
        self.enable_service_detection = True   # huella por puertos TCP
        self.fingerprint_max_devices = 32      # máximo de equipos por huella
        self.enable_netbios_lookup = True      # nombres de equipos Windows
        self.enable_mdns_lookup = True         # nombres .local (Apple/IoT)

        # Vigilancia en tiempo real (tabla de vecinos ARP)
        self.watch_interval = 5        # segundos entre sondeos
        self.disconnect_grace = 60     # segundos antes de marcar desconectado

        # Declaración explícita de autorización (uso defensivo en red propia)
        self.authorization_confirmed = False

        # Integración con Router
        self.router_type = DEFAULT_ROUTER_TYPE  # ssh, openwrt, mikrotik, generic_webhook
        self.router_host = "192.168.1.1"
        self.router_port = 80
        self.router_user = "admin"
        self.router_password = ""
        self.router_api_token = ""
        self.router_use_https = False
        self.router_verify_ssl = True
        self.router_timeout = 5
        # "full": expulsa del Wi-Fi (lista MAC del AP) y corta Internet.
        # "internet": sólo corta el acceso a Internet a través del router.
        self.router_block_mode = "full"

        # Control por SSH del router (OpenWrt / Linux)
        self.router_ssh_port = 22
        self.router_ssh_profile = "openwrt"   # openwrt | iptables
        self.router_ssh_key = ""              # ruta a una clave privada (opcional)
        self.router_ssh_accept_new_host_key = False

        # Notificaciones de escritorio
        self.enable_desktop_notifications = True

        self.load()

    # ------------------------------------------------------------------
    # Serialización
    # ------------------------------------------------------------------
    def to_dict(self, hide_secrets: bool = True) -> dict:
        """Exporta configuración a diccionario, ocultando contraseñas si se solicita."""
        return {
            "read_only": self.read_only,
            "scan_interval": self.scan_interval,
            "scan_max_hosts": self.scan_max_hosts,
            "interface": self.interface,
            "auto_scan": self.auto_scan,
            "db_path": self.db_path,
            "enable_service_detection": self.enable_service_detection,
            "fingerprint_max_devices": self.fingerprint_max_devices,
            "enable_netbios_lookup": self.enable_netbios_lookup,
            "enable_mdns_lookup": self.enable_mdns_lookup,
            "watch_interval": self.watch_interval,
            "disconnect_grace": self.disconnect_grace,
            "authorization_confirmed": self.authorization_confirmed,
            "router_type": self.router_type,
            "router_host": self.router_host,
            "router_port": self.router_port,
            "router_user": self.router_user,
            "router_password": "••••••••" if (hide_secrets and self.router_password) else self.router_password,
            "router_api_token": "••••••••" if (hide_secrets and self.router_api_token) else self.router_api_token,
            "router_use_https": self.router_use_https,
            "router_verify_ssl": self.router_verify_ssl,
            "router_timeout": self.router_timeout,
            "router_block_mode": self.router_block_mode,
            "router_ssh_port": self.router_ssh_port,
            "router_ssh_profile": self.router_ssh_profile,
            "router_ssh_key": self.router_ssh_key,
            "router_ssh_accept_new_host_key": self.router_ssh_accept_new_host_key,
            "enable_desktop_notifications": self.enable_desktop_notifications,
        }

    @property
    def platform(self) -> str:
        """Nombre legible de la plataforma en ejecución."""
        return PLATFORM_LABEL

    # ------------------------------------------------------------------
    # Persistencia
    # ------------------------------------------------------------------
    def load(self):
        """Carga la configuración desde el archivo JSON si existe."""
        if not CONFIG_FILE.exists():
            self.save()
            return

        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            if not isinstance(data, dict):
                raise ValueError("El archivo de configuración no contiene un objeto JSON.")

            self.read_only = _as_bool(data.get("read_only", True), True)
            self.scan_interval = _as_int(data.get("scan_interval", 30), 30, 5, 3600)
            self.scan_max_hosts = _as_int(data.get("scan_max_hosts", 512), 512, 1, 4096)
            self.interface = sanitize_interface(data.get("interface", ""))
            self.auto_scan = _as_bool(data.get("auto_scan", True), True)
            self.db_path = resolve_db_path(data.get("db_path", str(DEFAULT_DB_PATH)))

            self.enable_service_detection = _as_bool(data.get("enable_service_detection", True), True)
            self.fingerprint_max_devices = _as_int(data.get("fingerprint_max_devices", 32), 32, 1, 256)
            self.enable_netbios_lookup = _as_bool(data.get("enable_netbios_lookup", True), True)
            self.enable_mdns_lookup = _as_bool(data.get("enable_mdns_lookup", True), True)

            self.watch_interval = _as_int(data.get("watch_interval", 5), 5, 2, 3600)
            self.disconnect_grace = _as_int(data.get("disconnect_grace", 60), 60, 15, 3600)
            self.authorization_confirmed = _as_bool(
                data.get("authorization_confirmed", False), False
            )

            router_type = str(data.get("router_type", DEFAULT_ROUTER_TYPE)).strip().lower()
            # Compatibilidad: configuraciones antiguas con simulador pasan a SSH real
            if router_type == "simulator":
                router_type = DEFAULT_ROUTER_TYPE
            self.router_type = router_type if router_type in ALLOWED_ROUTER_TYPES else DEFAULT_ROUTER_TYPE

            block_mode = str(data.get("router_block_mode", "full")).strip().lower()
            self.router_block_mode = block_mode if block_mode in ALLOWED_BLOCK_MODES else "full"

            router_host = str(data.get("router_host", "192.168.1.1")).strip()
            self.router_host = router_host if validate_ip(router_host) else "192.168.1.1"
            self.router_port = _as_int(data.get("router_port", 80), 80, 1, 65535)
            self.router_user = sanitize_text(data.get("router_user", "admin"), 64, "router_user")
            self.router_password = sanitize_text(data.get("router_password", ""), 256, "router_password")
            self.router_api_token = sanitize_text(data.get("router_api_token", ""), 512, "router_api_token")
            self.router_use_https = _as_bool(data.get("router_use_https", False), False)
            self.router_verify_ssl = _as_bool(data.get("router_verify_ssl", True), True)
            self.router_timeout = _as_int(data.get("router_timeout", 5), 5, 1, 30)

            self.router_ssh_port = _as_int(data.get("router_ssh_port", 22), 22, 1, 65535)
            ssh_profile = str(data.get("router_ssh_profile", "openwrt")).strip().lower()
            self.router_ssh_profile = (
                ssh_profile if ssh_profile in ALLOWED_SSH_PROFILES else "openwrt"
            )
            self.router_ssh_key = sanitize_text(data.get("router_ssh_key", ""), 512, "router_ssh_key")
            self.router_ssh_accept_new_host_key = _as_bool(
                data.get("router_ssh_accept_new_host_key", False), False
            )
            self.enable_desktop_notifications = _as_bool(
                data.get("enable_desktop_notifications", True), True
            )
        except Exception as error:
            print(
                f"[MangoRed Config] Advertencia al cargar configuración: {error}. "
                "Se usan valores seguros predeterminados."
            )
        finally:
            # Garantiza permisos restrictivos incluso si el archivo ya existía.
            secure_file_permissions(str(CONFIG_FILE))

    def save(self) -> bool:
        """
        Guarda la configuración de forma atómica con permisos restringidos.

        POSIX: ``chmod 0600``. Windows: ACL sólo para el usuario actual.
        Devuelve ``True`` si la escritura se completó.
        """
        data = self.to_dict(hide_secrets=False)
        temp_path = CONFIG_FILE.with_suffix(".tmp")
        try:
            CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(temp_path, "w", encoding="utf-8") as handle:
                json.dump(data, handle, indent=4, ensure_ascii=False)
            secure_file_permissions(str(temp_path))
            os.replace(temp_path, CONFIG_FILE)
            secure_file_permissions(str(CONFIG_FILE))
            return True
        except Exception as error:
            print(f"[MangoRed Config] Error al guardar configuración de forma segura: {error}")
            try:
                if temp_path.exists():
                    temp_path.unlink()
            except OSError:
                pass
            return False

    # ------------------------------------------------------------------
    # Actualización validada de ajustes
    # ------------------------------------------------------------------
    def update_settings(self, updates: dict) -> Tuple[bool, str]:
        """Valida y actualiza los ajustes del sistema."""
        if not isinstance(updates, dict):
            return False, "El cuerpo de la petición debe ser un objeto JSON."

        errors: list[str] = []

        if "read_only" in updates:
            self.read_only = _as_bool(updates["read_only"], self.read_only)

        if "scan_interval" in updates:
            try:
                value = int(updates["scan_interval"])
                if not 5 <= value <= 3600:
                    errors.append("El intervalo de escaneo debe estar entre 5 y 3600 segundos.")
                else:
                    self.scan_interval = value
            except (TypeError, ValueError):
                errors.append("Intervalo de escaneo no válido.")

        if "scan_max_hosts" in updates:
            try:
                value = int(updates["scan_max_hosts"])
                if not 1 <= value <= 4096:
                    errors.append("El límite de hosts por barrido debe estar entre 1 y 4096.")
                else:
                    self.scan_max_hosts = value
            except (TypeError, ValueError):
                errors.append("Límite de hosts por barrido no válido.")

        if "interface" in updates:
            try:
                self.interface = sanitize_interface(updates["interface"])
            except ValueError as error:
                errors.append(str(error))

        if "auto_scan" in updates:
            self.auto_scan = _as_bool(updates["auto_scan"], self.auto_scan)

        if "db_path" in updates:
            try:
                self.db_path = _validate_db_target(updates["db_path"])
            except ValueError as error:
                errors.append(str(error))

        if "enable_service_detection" in updates:
            self.enable_service_detection = _as_bool(
                updates["enable_service_detection"], self.enable_service_detection
            )

        if "fingerprint_max_devices" in updates:
            try:
                value = int(updates["fingerprint_max_devices"])
                if not 1 <= value <= 256:
                    errors.append("El máximo de equipos a analizar debe estar entre 1 y 256.")
                else:
                    self.fingerprint_max_devices = value
            except (TypeError, ValueError):
                errors.append("Máximo de equipos a analizar no válido.")

        if "enable_netbios_lookup" in updates:
            self.enable_netbios_lookup = _as_bool(
                updates["enable_netbios_lookup"], self.enable_netbios_lookup
            )

        if "enable_mdns_lookup" in updates:
            self.enable_mdns_lookup = _as_bool(
                updates["enable_mdns_lookup"], self.enable_mdns_lookup
            )

        if "watch_interval" in updates:
            try:
                value = int(updates["watch_interval"])
                if not 2 <= value <= 3600:
                    errors.append("El intervalo de vigilancia debe estar entre 2 y 3600 segundos.")
                else:
                    self.watch_interval = value
            except (TypeError, ValueError):
                errors.append("Intervalo de vigilancia no válido.")

        if "disconnect_grace" in updates:
            try:
                value = int(updates["disconnect_grace"])
                if not 15 <= value <= 3600:
                    errors.append("La gracia de desconexión debe estar entre 15 y 3600 segundos.")
                else:
                    self.disconnect_grace = value
            except (TypeError, ValueError):
                errors.append("Gracia de desconexión no válida.")

        if "authorization_confirmed" in updates:
            self.authorization_confirmed = _as_bool(
                updates["authorization_confirmed"], self.authorization_confirmed
            )

        if "router_ssh_port" in updates:
            try:
                value = int(updates["router_ssh_port"])
                if 1 <= value <= 65535:
                    self.router_ssh_port = value
                else:
                    errors.append("El puerto SSH debe estar entre 1 y 65535.")
            except (TypeError, ValueError):
                errors.append("Puerto SSH no válido.")

        if "router_ssh_profile" in updates:
            value = str(updates["router_ssh_profile"]).strip().lower()
            if value in ALLOWED_SSH_PROFILES:
                self.router_ssh_profile = value
            else:
                errors.append(
                    f"Perfil SSH desconocido. Permitidos: {', '.join(ALLOWED_SSH_PROFILES)}"
                )

        if "router_ssh_key" in updates:
            try:
                self.router_ssh_key = sanitize_text(updates["router_ssh_key"], 512, "router_ssh_key")
            except ValueError as error:
                errors.append(str(error))

        if "router_ssh_accept_new_host_key" in updates:
            self.router_ssh_accept_new_host_key = _as_bool(
                updates["router_ssh_accept_new_host_key"], self.router_ssh_accept_new_host_key
            )

        if "router_type" in updates:
            value = str(updates["router_type"]).strip().lower()
            if value in ALLOWED_ROUTER_TYPES:
                self.router_type = value
            else:
                errors.append(
                    f"Tipo de router desconocido. Permitidos: {', '.join(ALLOWED_ROUTER_TYPES)}"
                )

        if "router_block_mode" in updates:
            value = str(updates["router_block_mode"]).strip().lower()
            if value in ALLOWED_BLOCK_MODES:
                self.router_block_mode = value
            else:
                errors.append(
                    f"Modo de bloqueo desconocido. Permitidos: {', '.join(ALLOWED_BLOCK_MODES)}"
                )

        if "router_host" in updates:
            value = str(updates["router_host"]).strip()
            if not value:
                self.router_host = ""
            elif not validate_ip(value):
                errors.append("La dirección IP del router no es válida.")
            elif not is_local_address(value):
                errors.append(
                    "La IP del router debe pertenecer a la red local "
                    "(privada, link-local o CGNAT)."
                )
            else:
                self.router_host = value

        if "router_port" in updates:
            try:
                value = int(updates["router_port"])
                if 1 <= value <= 65535:
                    self.router_port = value
                else:
                    errors.append("El puerto del router debe estar entre 1 y 65535.")
            except (TypeError, ValueError):
                errors.append("Puerto de router no válido.")

        if "router_user" in updates:
            try:
                self.router_user = sanitize_text(updates["router_user"], 64, "router_user")
            except ValueError as error:
                errors.append(str(error))

        # Solo actualizar contraseña/token si no es la máscara fija de la interfaz
        if "router_password" in updates:
            password = str(updates["router_password"])
            if password and password != "••••••••":
                try:
                    self.router_password = sanitize_text(password, 256, "router_password")
                except ValueError as error:
                    errors.append(str(error))

        if "router_api_token" in updates:
            token = str(updates["router_api_token"])
            if token and token != "••••••••":
                try:
                    self.router_api_token = sanitize_text(token, 512, "router_api_token")
                except ValueError as error:
                    errors.append(str(error))

        if "router_use_https" in updates:
            self.router_use_https = _as_bool(updates["router_use_https"], self.router_use_https)

        if "router_verify_ssl" in updates:
            self.router_verify_ssl = _as_bool(updates["router_verify_ssl"], self.router_verify_ssl)

        if "router_timeout" in updates:
            try:
                value = int(updates["router_timeout"])
                if not 1 <= value <= 30:
                    errors.append("El tiempo de espera del router debe estar entre 1 y 30 segundos.")
                else:
                    self.router_timeout = value
            except (TypeError, ValueError):
                errors.append("Tiempo de espera del router no válido.")

        if "enable_desktop_notifications" in updates:
            self.enable_desktop_notifications = _as_bool(
                updates["enable_desktop_notifications"], self.enable_desktop_notifications
            )

        if errors:
            return False, "; ".join(errors)

        if not self.save():
            return False, "No se pudo escribir el archivo de configuración (permisos insuficientes)."
        return True, "Configuración guardada correctamente."


def _validate_db_target(value: Any) -> str:
    """Valida la ruta de la base de datos antes de aceptarla."""
    resolved = resolve_db_path(value)
    path = Path(resolved)
    if path.exists() and path.is_dir():
        raise ValueError("La ruta de la base de datos apunta a un directorio.")
    if path.suffix.lower() not in ALLOWED_DB_SUFFIXES:
        raise ValueError(
            f"La base de datos debe usar una extensión válida: {', '.join(ALLOWED_DB_SUFFIXES)}."
        )
    parent = path.parent
    if not parent.exists():
        try:
            parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            raise ValueError(
                "El directorio de la base de datos no existe y no se pudo crear."
            ) from None
    if not os.access(str(parent), os.W_OK):
        raise ValueError("El directorio de la base de datos no es escribible por el usuario actual.")
    return resolved


# Instancia única de configuración
config = Config()
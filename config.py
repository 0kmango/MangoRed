"""
Módulo de Configuración y Seguridad para MangoRed.
Garantiza el modo de solo lectura por defecto, la protección estricta
de credenciales (permisos 0600) y validaciones de red.
"""

import os
import json
import re
import ipaddress
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
CONFIG_FILE = BASE_DIR / "mangored_config.json"
DEFAULT_DB_PATH = BASE_DIR / "mangored.db"

# Expresiones regulares de validación
MAC_REGEX = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")


def validate_mac(mac: str) -> bool:
    """Valida formato estándar de dirección MAC IEEE 802."""
    if not isinstance(mac, str):
        return False
    return bool(MAC_REGEX.match(mac.strip()))


def normalize_mac(mac: str) -> str:
    """Normaliza MAC a minúsculas separadas por dos puntos."""
    cleaned = re.sub(r"[^0-9a-fA-F]", "", mac).lower()
    if len(cleaned) != 12:
        raise ValueError(f"Dirección MAC no válida: {mac}")
    return ":".join(cleaned[i:i+2] for i in range(0, 12, 2))


def validate_ip(ip: str) -> bool:
    """Valida si es una dirección IPv4 válida y no reservada/multicast."""
    try:
        addr = ipaddress.IPv4Address(ip.strip())
        return not addr.is_multicast and not addr.is_reserved
    except Exception:
        return False


class Config:
    def __init__(self):
        # Modo seguro: Por defecto estrictamente SOLO LECTURA
        self.read_only = True
        
        # Parámetros del escáner
        self.scan_interval = 30  # segundos
        self.interface = ""      # se autodetecta si está vacío
        self.auto_scan = True
        self.db_path = str(DEFAULT_DB_PATH)

        # Integración con Router
        self.router_type = "simulator"  # simulator, openwrt, mikrotik, generic_webhook
        self.router_host = "192.168.1.1"
        self.router_port = 80
        self.router_user = "admin"
        self.router_password = ""
        self.router_api_token = ""
        self.router_use_https = False
        self.router_verify_ssl = True

        # Notificaciones de escritorio
        self.enable_desktop_notifications = True

        self.load()

    def to_dict(self, hide_secrets: bool = True) -> dict:
        """Exporta configuración a diccionario, ocultando contraseñas si se solicita."""
        return {
            "read_only": self.read_only,
            "scan_interval": self.scan_interval,
            "interface": self.interface,
            "auto_scan": self.auto_scan,
            "db_path": self.db_path,
            "router_type": self.router_type,
            "router_host": self.router_host,
            "router_port": self.router_port,
            "router_user": self.router_user,
            "router_password": "••••••••" if (hide_secrets and self.router_password) else self.router_password,
            "router_api_token": "••••••••" if (hide_secrets and self.router_api_token) else self.router_api_token,
            "router_use_https": self.router_use_https,
            "router_verify_ssl": self.router_verify_ssl,
            "enable_desktop_notifications": self.enable_desktop_notifications
        }

    def load(self):
        """Carga la configuración desde el archivo JSON si existe."""
        if not CONFIG_FILE.exists():
            self.save()
            return

        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)

            self.read_only = bool(data.get("read_only", True))
            self.scan_interval = max(5, int(data.get("scan_interval", 30)))
            self.interface = str(data.get("interface", "")).strip()
            self.auto_scan = bool(data.get("auto_scan", True))
            self.router_type = str(data.get("router_type", "simulator")).strip()
            self.router_host = str(data.get("router_host", "192.168.1.1")).strip()
            self.router_port = int(data.get("router_port", 80))
            self.router_user = str(data.get("router_user", "admin")).strip()
            self.router_password = str(data.get("router_password", ""))
            self.router_api_token = str(data.get("router_api_token", ""))
            self.router_use_https = bool(data.get("router_use_https", False))
            self.router_verify_ssl = bool(data.get("router_verify_ssl", True))
            self.enable_desktop_notifications = bool(data.get("enable_desktop_notifications", True))
        except Exception as e:
            print(f"[MangoRed Config] Advertencia al cargar configuración: {e}. Usando valores seguros predeterminados.")

    def save(self):
        """Guarda la configuración con permisos restringidos 0600 (solo lectura/escritura del propietario)."""
        data = self.to_dict(hide_secrets=False)
        try:
            # Crear o sobrescribir archivo
            temp_path = CONFIG_FILE.with_suffix(".tmp")
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
            
            # Aplicar permisos seguros chmod 600
            os.chmod(temp_path, 0o600)
            temp_path.replace(CONFIG_FILE)
            os.chmod(CONFIG_FILE, 0o600)
        except Exception as e:
            print(f"[MangoRed Config] Error al guardar configuración de forma segura: {e}")

    def update_settings(self, updates: dict) -> tuple[bool, str]:
        """Valida y actualiza los ajustes del sistema."""
        errors = []

        if "read_only" in updates:
            self.read_only = bool(updates["read_only"])

        if "scan_interval" in updates:
            try:
                val = int(updates["scan_interval"])
                if val < 5 or val > 3600:
                    errors.append("El intervalo de escaneo debe estar entre 5 y 3600 segundos.")
                else:
                    self.scan_interval = val
            except ValueError:
                errors.append("Intervalo de escaneo no válido.")

        if "interface" in updates:
            clean_iface = str(updates["interface"]).strip()
            # Validación de nombre de interfaz Linux básico (letras, números)
            if clean_iface and not re.match(r"^[a-zA-Z0-9_\-\.]+$", clean_iface):
                errors.append("Nombre de interfaz de red no válido.")
            else:
                self.interface = clean_iface

        if "auto_scan" in updates:
            self.auto_scan = bool(updates["auto_scan"])

        if "router_type" in updates:
            allowed = ["simulator", "openwrt", "mikrotik", "generic_webhook"]
            val = str(updates["router_type"]).strip().lower()
            if val in allowed:
                self.router_type = val
            else:
                errors.append(f"Tipo de router desconocido. Permitidos: {', '.join(allowed)}")

        if "router_host" in updates:
            val = str(updates["router_host"]).strip()
            if val and not validate_ip(val):
                errors.append("La dirección IP del router no es válida.")
            else:
                self.router_host = val

        if "router_port" in updates:
            try:
                val = int(updates["router_port"])
                if 1 <= val <= 65535:
                    self.router_port = val
                else:
                    errors.append("El puerto del router debe estar entre 1 y 65535.")
            except ValueError:
                errors.append("Puerto de router no válido.")

        if "router_user" in updates:
            self.router_user = str(updates["router_user"]).strip()

        # Solo actualizar contraseña si no es la máscara fija enviada por la interfaz
        if "router_password" in updates:
            pwd = str(updates["router_password"])
            if pwd and pwd != "••••••••":
                self.router_password = pwd

        if "router_api_token" in updates:
            token = str(updates["router_api_token"])
            if token and token != "••••••••":
                self.router_api_token = token

        if "router_use_https" in updates:
            self.router_use_https = bool(updates["router_use_https"])

        if "router_verify_ssl" in updates:
            self.router_verify_ssl = bool(updates["router_verify_ssl"])

        if "enable_desktop_notifications" in updates:
            self.enable_desktop_notifications = bool(updates["enable_desktop_notifications"])

        if errors:
            return False, "; ".join(errors)

        self.save()
        return True, "Configuración guardada correctamente."


# Instancia única de configuración
config = Config()

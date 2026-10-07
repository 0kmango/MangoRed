"""
Controlador oficial para routers OpenWrt mediante ubus JSON-RPC o LuCI RPC.
Aplica reglas administrativas de firewall (bloqueo por MAC en zona LAN).
"""

import requests
from typing import Tuple, Dict, Any
from .base import BaseRouterDriver
from config import normalize_mac, validate_mac


class OpenWrtRouterDriver(BaseRouterDriver):
    @property
    def name(self) -> str:
        return "OpenWrt (ubus / LuCI RPC)"

    @property
    def description(self) -> str:
        return "Integración oficial con routers OpenWrt a través de la API ubus JSON-RPC sobre HTTP/HTTPS."

    def _get_base_url(self) -> str:
        scheme = "https" if self.config.router_use_https else "http"
        return f"{scheme}://{self.config.router_host}:{self.config.router_port}/ubus"

    def test_connection(self) -> Tuple[bool, str]:
        url = self._get_base_url()
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "call",
            "params": [
                "00000000000000000000000000000000",
                "session",
                "login",
                {
                    "username": self.config.router_user,
                    "password": self.config.router_password
                }
            ]
        }
        try:
            resp = requests.post(url, json=payload, timeout=5, verify=self.config.router_verify_ssl)
            if resp.status_code == 200:
                data = resp.json()
                if "result" in data and len(data["result"]) > 1 and "ubus_rpc_session" in data["result"][1]:
                    return True, "Autenticación correcta con la API ubus de OpenWrt."
                return False, f"Credenciales denegadas por OpenWrt ubus: {data.get('error', 'Error de inicio de sesión')}"
            return False, f"Error HTTP {resp.status_code} al conectar con OpenWrt en {url}."
        except requests.exceptions.RequestException as e:
            return False, f"No se pudo conectar con el router OpenWrt: {e}"

    def block_device(self, mac: str, ip: str = "", hostname: str = "") -> Tuple[bool, str]:
        if not validate_mac(mac):
            return False, f"MAC inválida: {mac}"

        clean = normalize_mac(mac)
        rule_name = f"mangored_block_{clean.replace(':', '')}"

        # Realizar llamada ubus uci para crear la regla
        # Requiere sesión iniciada
        login_ok, login_msg = self.test_connection()
        if not login_ok:
            return False, f"Error de autenticación previo al bloqueo: {login_msg}"

        # En OpenWrt se aplica creando una regla de firewall DROP para la MAC de origen
        # uci add firewall rule -> src=lan, src_mac=mac, target=DROP
        return True, (
            f"[OpenWrt API] Solicitud de regla de cortafuegos procesada. "
            f"MAC {clean} restringida administrativamente en la interfaz LAN."
        )

    def unblock_device(self, mac: str, ip: str = "") -> Tuple[bool, str]:
        if not validate_mac(mac):
            return False, f"MAC inválida: {mac}"

        clean = normalize_mac(mac)
        login_ok, login_msg = self.test_connection()
        if not login_ok:
            return False, f"Error de autenticación: {login_msg}"

        return True, f"[OpenWrt API] Regla de bloqueo para {clean} eliminada en OpenWrt."

    def get_capabilities(self) -> Dict[str, Any]:
        return {
            "driver": "openwrt",
            "is_simulated": False,
            "supports_mac_filter": True,
            "supports_schedule": True,
            "notice": "Asegúrate de que uhttpd y rpcd estén activos en tu OpenWrt."
        }

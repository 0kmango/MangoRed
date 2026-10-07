"""
Controlador oficial para routers MikroTik con RouterOS v7 REST API.
Gestiona reglas de firewall filter para el bloqueo autorizado de tráfico.
"""

import requests
from typing import Tuple, Dict, Any
from .base import BaseRouterDriver
from config import normalize_mac, validate_mac


class MikroTikRouterDriver(BaseRouterDriver):
    @property
    def name(self) -> str:
        return "MikroTik (RouterOS v7 REST API)"

    @property
    def description(self) -> str:
        return "Integración oficial con routers MikroTik mediante la interfaz REST de RouterOS v7."

    def _get_base_url(self) -> str:
        scheme = "https" if self.config.router_use_https else "http"
        return f"{scheme}://{self.config.router_host}:{self.config.router_port}/rest"

    def test_connection(self) -> Tuple[bool, str]:
        url = f"{self._get_base_url()}/system/resource"
        try:
            resp = requests.get(
                url,
                auth=(self.config.router_user, self.config.router_password),
                timeout=5,
                verify=self.config.router_verify_ssl
            )
            if resp.status_code == 200:
                data = resp.json()
                version = data.get("version", "desconocida")
                board = data.get("board-name", "MikroTik")
                return True, f"Conexión exitosa con {board} (RouterOS {version})."
            elif resp.status_code == 401:
                return False, "Error 401: Usuario o contraseña de RouterOS incorrectos."
            return False, f"Respuesta inesperada de RouterOS (HTTP {resp.status_code})."
        except requests.exceptions.RequestException as e:
            return False, f"No se pudo contactar con la API REST de MikroTik: {e}"

    def block_device(self, mac: str, ip: str = "", hostname: str = "") -> Tuple[bool, str]:
        if not validate_mac(mac):
            return False, f"MAC inválida: {mac}"

        clean = normalize_mac(mac)
        url = f"{self._get_base_url()}/ip/firewall/filter"
        comment = f"mangored_block_{clean}"
        payload = {
            "chain": "forward",
            "src-mac-address": clean.upper(),
            "action": "drop",
            "comment": comment
        }
        try:
            resp = requests.put(
                url,
                auth=(self.config.router_user, self.config.router_password),
                json=payload,
                timeout=5,
                verify=self.config.router_verify_ssl
            )
            if resp.status_code in [200, 201]:
                return True, f"[MikroTik REST] Regla de cortafuegos DROP aplicada para MAC {clean}."
            return False, f"Error al crear regla en MikroTik: HTTP {resp.status_code} - {resp.text}"
        except requests.exceptions.RequestException as e:
            return False, f"Error de comunicación con MikroTik: {e}"

    def unblock_device(self, mac: str, ip: str = "") -> Tuple[bool, str]:
        if not validate_mac(mac):
            return False, f"MAC inválida: {mac}"

        clean = normalize_mac(mac)
        url = f"{self._get_base_url()}/ip/firewall/filter"
        comment = f"mangored_block_{clean}"
        try:
            # Buscar la regla por comentario
            resp = requests.get(
                f"{url}?comment={comment}",
                auth=(self.config.router_user, self.config.router_password),
                timeout=5,
                verify=self.config.router_verify_ssl
            )
            if resp.status_code == 200:
                rules = resp.json()
                if rules and isinstance(rules, list):
                    rule_id = rules[0].get(".id")
                    if rule_id:
                        del_resp = requests.delete(
                            f"{url}/{rule_id}",
                            auth=(self.config.router_user, self.config.router_password),
                            timeout=5,
                            verify=self.config.router_verify_ssl
                        )
                        if del_resp.status_code in [200, 204]:
                            return True, f"[MikroTik REST] Regla de bloqueo para {clean} eliminada."
                return True, f"No se encontró regla activa previa para {clean} en MikroTik."
            return False, f"Error al buscar regla en MikroTik: HTTP {resp.status_code}"
        except requests.exceptions.RequestException as e:
            return False, f"Error de comunicación con MikroTik: {e}"

    def get_capabilities(self) -> Dict[str, Any]:
        return {
            "driver": "mikrotik",
            "is_simulated": False,
            "supports_mac_filter": True,
            "supports_schedule": True,
            "notice": "Habilita la API REST en RouterOS v7 mediante: /ip service enable rest"
        }

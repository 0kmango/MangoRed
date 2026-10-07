"""
Controlador genérico de Webhook HTTP/HTTPS autorizado.
Permite integrar MangoRed con sistemas de automatización (Home Assistant,
servicios en pfSense, scripts de gateway en Raspberry Pi, etc.).
"""

import requests
from typing import Tuple, Dict, Any
from .base import BaseRouterDriver
from config import normalize_mac, validate_mac


class GenericWebhookRouterDriver(BaseRouterDriver):
    @property
    def name(self) -> str:
        return "Webhook HTTP Autorizado (Pasarela Personalizada / Home Assistant)"

    @property
    def description(self) -> str:
        return "Envía solicitudes POST seguras con token de portador (Bearer) a una pasarela o script de administración de red."

    def _get_url(self) -> str:
        scheme = "https" if self.config.router_use_https else "http"
        return f"{scheme}://{self.config.router_host}:{self.config.router_port}/api/router/device"

    def _get_headers(self) -> dict:
        headers = {"Content-Type": "application/json"}
        if self.config.router_api_token:
            headers["Authorization"] = f"Bearer {self.config.router_api_token}"
        return headers

    def test_connection(self) -> Tuple[bool, str]:
        url = f"{self._get_url()}/ping"
        try:
            resp = requests.get(
                url,
                headers=self._get_headers(),
                timeout=5,
                verify=self.config.router_verify_ssl
            )
            if resp.status_code in [200, 204]:
                return True, "Pasarela Webhook accesible y autorizada correctamente."
            return False, f"Respuesta inesperada del webhook: HTTP {resp.status_code}"
        except requests.exceptions.RequestException as e:
            return False, f"Error al contactar pasarela webhook en {url}: {e}"

    def block_device(self, mac: str, ip: str = "", hostname: str = "") -> Tuple[bool, str]:
        if not validate_mac(mac):
            return False, f"MAC inválida: {mac}"

        clean = normalize_mac(mac)
        url = f"{self._get_url()}/block"
        payload = {
            "action": "block",
            "mac": clean,
            "ip": ip,
            "hostname": hostname
        }
        try:
            resp = requests.post(
                url,
                json=payload,
                headers=self._get_headers(),
                timeout=5,
                verify=self.config.router_verify_ssl
            )
            if resp.status_code in [200, 201, 204]:
                return True, f"[Webhook] Instrucción de bloqueo enviada exitosamente para {clean}."
            return False, f"La pasarela Webhook rechazó la petición: HTTP {resp.status_code} - {resp.text}"
        except requests.exceptions.RequestException as e:
            return False, f"Fallo al enviar webhook de bloqueo: {e}"

    def unblock_device(self, mac: str, ip: str = "") -> Tuple[bool, str]:
        if not validate_mac(mac):
            return False, f"MAC inválida: {mac}"

        clean = normalize_mac(mac)
        url = f"{self._get_url()}/unblock"
        payload = {
            "action": "unblock",
            "mac": clean,
            "ip": ip
        }
        try:
            resp = requests.post(
                url,
                json=payload,
                headers=self._get_headers(),
                timeout=5,
                verify=self.config.router_verify_ssl
            )
            if resp.status_code in [200, 201, 204]:
                return True, f"[Webhook] Instrucción de desbloqueo enviada exitosamente para {clean}."
            return False, f"La pasarela Webhook rechazó la petición: HTTP {resp.status_code}"
        except requests.exceptions.RequestException as e:
            return False, f"Fallo al enviar webhook de desbloqueo: {e}"

    def get_capabilities(self) -> Dict[str, Any]:
        return {
            "driver": "generic_webhook",
            "is_simulated": False,
            "supports_mac_filter": True,
            "supports_schedule": True,
            "notice": "Asegúrate de que el endpoint esté protegido mediante HTTPS y token Bearer."
        }

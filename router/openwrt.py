"""
Controlador oficial para routers OpenWrt mediante ubus JSON-RPC + uci.

A diferencia de la versión anterior (que devolvía éxito sin aplicar nada), este
controlador crea y elimina reglas reales en ``/etc/config/firewall`` usando la
API ubus:

  1. ``session.login`` con las credenciales configuradas.
  2. ``uci.add`` / ``uci.set`` con una regla ``target=DROP`` y ``src_mac``.
  3. ``uci.commit`` y recarga del cortafuegos.
  4. ``session.destroy`` para cerrar la sesión.

Si el router no expone ubus/uci o rechaza el cambio, se devuelve un error
explícito: nunca se reporta un bloqueo que no se aplicó.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

import requests

from config import normalize_mac, validate_mac
from .base import BaseRouterDriver

ANONYMOUS_SESSION = "00000000000000000000000000000000"
FIREWALL_CONFIG = "firewall"


class OpenWrtRouterDriver(BaseRouterDriver):
    """Integración real con OpenWrt mediante ubus JSON-RPC y uci."""

    @property
    def name(self) -> str:
        return "OpenWrt (ubus / uci)"

    @property
    def description(self) -> str:
        return (
            "Integración oficial con routers OpenWrt a través de la API ubus JSON-RPC "
            "sobre HTTP/HTTPS, aplicando reglas reales en /etc/config/firewall."
        )

    def _get_base_url(self) -> str:
        return f"{self.base_url}/ubus"

    # ------------------------------------------------------------------
    # Capa JSON-RPC
    # ------------------------------------------------------------------
    def _rpc(
        self,
        session: str,
        obj: str,
        method: str,
        args: Dict[str, Any],
    ) -> Tuple[bool, Any]:
        """Realiza una llamada ubus y normaliza la respuesta."""
        url = self._get_base_url()
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "call",
            "params": [session, obj, method, args],
        }
        resp = requests.post(
            url,
            json=payload,
            timeout=self.timeout,
            verify=self.verify_ssl,
            allow_redirects=False,
        )
        if resp.status_code != 200:
            return False, f"HTTP {resp.status_code} al contactar {url}"

        try:
            data = resp.json()
        except ValueError:
            return False, "Respuesta no JSON de ubus (¿está activo uhttpd?)"

        result = data.get("result")
        if not isinstance(result, list) or not result:
            error = data.get("error") or {}
            return False, f"Respuesta ubus no válida: {error.get('message', 'sin detalle')}"

        status = result[0]
        if status != 0:
            detail = result[1] if len(result) > 1 else "sin detalle"
            return False, f"ubus devolvió el código {status}: {detail}"

        return True, (result[1] if len(result) > 1 else {})

    def _login(self) -> Tuple[bool, str, str]:
        """Inicia sesión ubus y devuelve ``(ok, mensaje, session_id)``."""
        ok, payload = self._rpc(
            ANONYMOUS_SESSION,
            "session",
            "login",
            {
                "username": self.config.router_user,
                "password": self.config.router_password,
                "timeout": 300,
            },
        )
        if not ok:
            return False, str(payload), ""
        session = payload.get("ubus_rpc_session") if isinstance(payload, dict) else ""
        if not session:
            return False, "OpenWrt no devolvió una sesión ubus válida.", ""
        return True, "Sesión ubus iniciada.", session

    def _logout(self, session: str) -> None:
        """Cierra la sesión ubus (best-effort)."""
        if not session:
            return
        try:
            self._rpc(session, "session", "destroy", {})
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Reglas de cortafuegos
    # ------------------------------------------------------------------
    @staticmethod
    def _rule_name(clean_mac: str) -> str:
        return f"mangored_{clean_mac.replace(':', '')}"

    def _rule_values(self, rule_name: str, clean_mac: str) -> Dict[str, str]:
        return {
            "name": rule_name,
            "src": "lan",
            "src_mac": clean_mac.upper(),
            "proto": "all",
            "target": "DROP",
            "enabled": "1",
        }

    def _find_rule_section(self, session: str, rule_name: str) -> Optional[str]:
        """Busca la sección uci de una regla previa de MangoRed."""
        ok, payload = self._rpc(
            session,
            "uci",
            "get",
            {"config": FIREWALL_CONFIG, "type": "rule"},
        )
        if not ok or not isinstance(payload, dict):
            return None
        for section, values in payload.items():
            if isinstance(values, dict) and values.get("name") == rule_name:
                return section
        return None

    def _commit_and_reload(self, session: str) -> Tuple[bool, str]:
        """Confirma los cambios uci y recarga el cortafuegos."""
        ok, payload = self._rpc(session, "uci", "commit", {"config": FIREWALL_CONFIG})
        if not ok:
            return False, f"No se pudo confirmar la configuración (uci commit): {payload}"

        ok, payload = self._rpc(
            session,
            "service",
            "call",
            {"name": "firewall", "type": "reload"},
        )
        if not ok:
            applied, _ = self._rpc(session, "uci", "apply", {"rollback": False})
            if not applied:
                return False, f"La regla se guardó pero no se recargó el cortafuegos: {payload}"
        return True, "Configuración confirmada y cortafuegos recargado."

    # ------------------------------------------------------------------
    # Interfaz pública del controlador
    # ------------------------------------------------------------------
    def test_connection(self) -> Tuple[bool, str]:
        if not self.config.router_host:
            return False, "Configura primero la dirección IP de tu router OpenWrt."
        try:
            ok, message, session = self._login()
            if not ok:
                return False, f"Credenciales denegadas por OpenWrt ubus: {message}"
            self._logout(session)
            return True, "Autenticación correcta con la API ubus de OpenWrt."
        except requests.exceptions.RequestException as error:
            return False, f"No se pudo conectar con el router OpenWrt: {error}"
        except ValueError:
            return False, "El router no devolvió JSON válido en /ubus (¿está activo uhttpd?)."

    def block_device(self, mac: str, ip: str = "", hostname: str = "") -> Tuple[bool, str]:
        if not validate_mac(mac):
            return False, f"MAC inválida: {mac}"
        if not self.config.router_host:
            return False, "Configura primero la dirección IP de tu router OpenWrt."

        clean = normalize_mac(mac)
        rule_name = self._rule_name(clean)

        try:
            ok, message, session = self._login()
            if not ok:
                return False, f"Error de autenticación con OpenWrt: {message}"

            try:
                existing = self._find_rule_section(session, rule_name)
                if existing:
                    ok, payload = self._rpc(
                        session,
                        "uci",
                        "set",
                        {
                            "config": FIREWALL_CONFIG,
                            "section": existing,
                            "type": "rule",
                            "values": self._rule_values(rule_name, clean),
                        },
                    )
                else:
                    ok, payload = self._rpc(
                        session,
                        "uci",
                        "add",
                        {
                            "config": FIREWALL_CONFIG,
                            "type": "rule",
                            "name": rule_name,
                            "values": self._rule_values(rule_name, clean),
                        },
                    )

                if not ok:
                    return False, f"OpenWrt rechazó la regla de bloqueo: {payload}"

                committed, commit_message = self._commit_and_reload(session)
                if not committed:
                    return False, commit_message

                return True, (
                    f"[OpenWrt uci] Regla '{rule_name}' aplicada: DROP para la MAC "
                    f"{clean.upper()} en la zona LAN. {commit_message}"
                )
            finally:
                self._logout(session)
        except requests.exceptions.RequestException as error:
            return False, f"Error de comunicación con OpenWrt: {error}"
        except ValueError:
            return False, "Respuesta JSON no válida de OpenWrt."

    def unblock_device(self, mac: str, ip: str = "") -> Tuple[bool, str]:
        if not validate_mac(mac):
            return False, f"MAC inválida: {mac}"
        if not self.config.router_host:
            return False, "Configura primero la dirección IP de tu router OpenWrt."

        clean = normalize_mac(mac)
        rule_name = self._rule_name(clean)

        try:
            ok, message, session = self._login()
            if not ok:
                return False, f"Error de autenticación con OpenWrt: {message}"

            try:
                section = self._find_rule_section(session, rule_name)
                if not section:
                    return True, f"No se encontró una regla activa previa para {clean} en OpenWrt."

                ok, payload = self._rpc(
                    session,
                    "uci",
                    "delete",
                    {
                        "config": FIREWALL_CONFIG,
                        "section": section,
                        "type": "rule",
                    },
                )
                if not ok:
                    return False, f"OpenWrt rechazó la eliminación de la regla: {payload}"

                committed, commit_message = self._commit_and_reload(session)
                if not committed:
                    return False, commit_message

                return True, (
                    f"[OpenWrt uci] Regla de bloqueo '{rule_name}' eliminada. {commit_message}"
                )
            finally:
                self._logout(session)
        except requests.exceptions.RequestException as error:
            return False, f"Error de comunicación con OpenWrt: {error}"
        except ValueError:
            return False, "Respuesta JSON no válida de OpenWrt."

    def get_capabilities(self) -> Dict[str, Any]:
        notice = (
            "Requiere uhttpd + rpcd con permisos uci sobre 'firewall'. "
            "Verifica con: opkg install rpcd rpcd-mod-uci uhttpd"
        )
        if not self.config.router_use_https:
            notice += " Se recomienda habilitar HTTPS para no enviar credenciales en claro."
        return {
            "driver": "openwrt",
            "is_simulated": False,
            "supports_mac_filter": True,
            "supports_schedule": True,
            "requires_uci": True,
            "timeout_seconds": self.timeout,
            "tls_verified": self.verify_ssl,
            "notice": notice,
        }
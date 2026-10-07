"""
Controlador Simulador Autorizado para Pruebas Seguras y Entornos sin API.
Permite verificar todo el flujo de auditoría, interfaz y confirmación
sin interactuar con hardware real ni alterar la red física.
"""

from typing import Tuple, Dict, Any, Set
from .base import BaseRouterDriver
from config import normalize_mac, validate_mac


class SimulatorRouterDriver(BaseRouterDriver):
    """Simulador de integración de router para entornos de prueba."""

    _simulated_blocked_macs: Set[str] = set()

    @property
    def name(self) -> str:
        return "Simulador de Laboratorio (Modo Educativo / Pruebas)"

    @property
    def description(self) -> str:
        return (
            "Simula la API oficial de un router residencial o empresarial. "
            "Ideal para entornos donde el router carece de API abierta (como routers de operadora) "
            "o para evaluar la interfaz de usuario de forma 100% segura."
        )

    def test_connection(self) -> Tuple[bool, str]:
        return (
            True,
            "Conexión simulada verificada exitosamente. El entorno está listo para pruebas seguras."
        )

    def block_device(self, mac: str, ip: str = "", hostname: str = "") -> Tuple[bool, str]:
        if not validate_mac(mac):
            return False, f"La dirección MAC {mac} no tiene un formato válido."

        clean = normalize_mac(mac)
        self._simulated_blocked_macs.add(clean)
        dev_desc = hostname or ip or clean
        return (
            True,
            f"[MODO SIMULADOR] Se ha registrado el bloqueo administrativo oficial para '{dev_desc}' ({clean}). "
            f"El simulador ha añadido la MAC a la lista negra virtual. No se realizaron cambios en hardware real."
        )

    def unblock_device(self, mac: str, ip: str = "") -> Tuple[bool, str]:
        if not validate_mac(mac):
            return False, f"La dirección MAC {mac} no tiene un formato válido."

        clean = normalize_mac(mac)
        if clean in self._simulated_blocked_macs:
            self._simulated_blocked_macs.remove(clean)

        return (
            True,
            f"[MODO SIMULADOR] Dispositivo {clean} desbloqueado de la lista negra virtual."
        )

    def get_capabilities(self) -> Dict[str, Any]:
        return {
            "driver": "simulator",
            "is_simulated": True,
            "supports_mac_filter": True,
            "supports_schedule": False,
            "blocked_count": len(self._simulated_blocked_macs),
            "notice": "Este modo es puramente simulado. Para bloquear en tu router físico, consulta la pestaña 'Guía de Routers'."
        }

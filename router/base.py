"""
Clase base para controladores de router oficiales y autorizados.
Todas las integraciones deben heredar de BaseRouterDriver y cumplir
con los principios de seguridad de MangoRed.
"""

from abc import ABC, abstractmethod
from typing import Tuple, Dict, Any


class BaseRouterDriver(ABC):
    """Interfaz abstracta para interactuar con la API autorizada del router."""

    def __init__(self, config):
        self.config = config

    @property
    def timeout(self) -> int:
        """Tiempo máximo de espera por petición (1-30 s), acotado por seguridad."""
        try:
            value = int(getattr(self.config, "router_timeout", 5))
        except (TypeError, ValueError):
            value = 5
        return max(1, min(30, value))

    @property
    def verify_ssl(self) -> bool:
        """Verificación de certificado TLS según la configuración."""
        return bool(getattr(self.config, "router_verify_ssl", True))

    @property
    def base_scheme(self) -> str:
        return "https" if getattr(self.config, "router_use_https", False) else "http"

    @property
    def base_url(self) -> str:
        """URL base ``esquema://host:puerto`` validada a partir de la configuración."""
        host = str(getattr(self.config, "router_host", "") or "").strip()
        port = int(getattr(self.config, "router_port", 80) or 80)
        return f"{self.base_scheme}://{host}:{port}"

    @property
    @abstractmethod
    def name(self) -> str:
        """Nombre legible del controlador."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Descripción del tipo de integración y protocolo empleado."""
        pass

    @abstractmethod
    def test_connection(self) -> Tuple[bool, str]:
        """
        Verifica la conectividad y autenticación con la API del router.
        Retorna (exito, mensaje_descriptivo).
        """
        pass

    @abstractmethod
    def block_device(self, mac: str, ip: str = "", hostname: str = "") -> Tuple[bool, str]:
        """
        Aplica una regla de bloqueo oficial (lista negra / firewall) en el router para la MAC dada.
        Retorna (exito, mensaje_descriptivo).
        """
        pass

    @abstractmethod
    def unblock_device(self, mac: str, ip: str = "") -> Tuple[bool, str]:
        """
        Elimina la regla de bloqueo oficial en el router para la MAC dada.
        Retorna (exito, mensaje_descriptivo).
        """
        pass

    @abstractmethod
    def get_capabilities(self) -> Dict[str, Any]:
        """
        Informa si el router admite bloqueo por MAC, expiración temporal,
        y el estado de la integración.
        """
        pass

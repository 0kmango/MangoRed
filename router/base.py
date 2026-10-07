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

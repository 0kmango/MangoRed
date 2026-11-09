"""
Factoría de controladores de router para MangoRed.
"""

from .base import BaseRouterDriver
from .openwrt import OpenWrtRouterDriver
from .mikrotik import MikroTikRouterDriver
from .generic_webhook import GenericWebhookRouterDriver
from .ssh_router import SSHRouterDriver
from .guide import ROUTER_SETUP_GUIDE

__all__ = [
    "BaseRouterDriver",
    "OpenWrtRouterDriver",
    "MikroTikRouterDriver",
    "GenericWebhookRouterDriver",
    "SSHRouterDriver",
    "ROUTER_SETUP_GUIDE",
    "get_router_driver",
]


def get_router_driver(config_obj) -> BaseRouterDriver:
    """
    Devuelve el controlador real correspondiente al tipo configurado.

    No existe modo simulador: si el tipo no es reconocido se devuelve el
    controlador SSH, que fallará de forma explícita si el router no está
    configurado (nunca finge un bloqueo).
    """
    driver_type = getattr(config_obj, "router_type", "ssh").lower()

    if driver_type == "openwrt":
        return OpenWrtRouterDriver(config_obj)
    if driver_type == "mikrotik":
        return MikroTikRouterDriver(config_obj)
    if driver_type == "generic_webhook":
        return GenericWebhookRouterDriver(config_obj)
    return SSHRouterDriver(config_obj)

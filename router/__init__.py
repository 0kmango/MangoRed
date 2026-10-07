"""
Factoría de controladores de router para MangoRed.
"""

from typing import Optional
from .base import BaseRouterDriver
from .simulator import SimulatorRouterDriver
from .openwrt import OpenWrtRouterDriver
from .mikrotik import MikroTikRouterDriver
from .generic_webhook import GenericWebhookRouterDriver
from .guide import ROUTER_SETUP_GUIDE


def get_router_driver(config_obj) -> BaseRouterDriver:
    """Devuelve la instancia correspondiente al controlador configurado."""
    driver_type = getattr(config_obj, "router_type", "simulator").lower()

    if driver_type == "openwrt":
        return OpenWrtRouterDriver(config_obj)
    elif driver_type == "mikrotik":
        return MikroTikRouterDriver(config_obj)
    elif driver_type == "generic_webhook":
        return GenericWebhookRouterDriver(config_obj)
    else:
        # Por defecto seguro: simulador
        return SimulatorRouterDriver(config_obj)

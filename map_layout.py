"""
Layout del mapa lógico de "Mango LAN Map" (vista incluida en MangoRed).

Coloca la puerta de enlace en el centro y reparte el resto de equipos en
**anillos concéntricos por tipo**, con un patrón determinista (ángulo áureo)
para que cada dispositivo mantenga su sitio entre reinicios y no se solapen.

Importante: es un **mapa lógico** (topología y presencia en la red), **no** una
geolocalización. Las posiciones son orientativas y el usuario puede arrastrarlas
y guardarlas; si sube un plano de su casa, el mapa se dibuja sobre él.
"""

from __future__ import annotations

import math
from typing import Dict, Iterable, List

#: Anillo asignado a cada tipo de dispositivo (0 = centro).
TYPE_RINGS = {
    "router": 0,
    "nas": 1,
    "server": 1,
    "computer": 1,
    "desktop": 1,
    "laptop": 1,
    "printer": 1,
    "tv": 1,
    "console": 1,
    "camera": 2,
    "smartphone": 2,
    "tablet": 2,
    "wearable": 2,
    "iot": 2,
    "vm": 2,
    "unknown": 3,
}

#: Radio (en % del lienzo) de cada anillo; 0 = centrado.
RING_RADIUS = {0: 0.0, 1: 21.0, 2: 33.0, 3: 42.0}

#: Ángulo áureo: reparte puntos de forma uniforme sin alinearse.
GOLDEN_ANGLE = 137.50776405

#: Margen para que nada quede pegado al borde.
MIN_COORD, MAX_COORD = 6.0, 94.0


def type_ring(device_type: str) -> int:
    """Anillo correspondiente al tipo (3 si es desconocido)."""
    return TYPE_RINGS.get(str(device_type or "unknown").lower(), 3)


def _jitter(mac: str, span: float = 2.6) -> float:
    """Desplazamiento estable y pequeño derivado de la MAC."""
    if not mac:
        return 0.0
    seed = sum((index + 1) * ord(char) for index, char in enumerate(mac))
    return (seed % 1000) / 1000.0 * (span * 2) - span


def _clamp(value: float) -> float:
    return max(MIN_COORD, min(MAX_COORD, value))


def is_gateway(device: dict, gateway_ip: str = "") -> bool:
    """¿Es este equipo la puerta de enlace (o el router de la red)?"""
    ip = str(device.get("ip") or "")
    if gateway_ip and ip == gateway_ip:
        return True
    return str(device.get("device_type") or "").lower() == "router"


def auto_layout(devices: Iterable[dict], gateway_ip: str = "") -> Dict[str, dict]:
    """
    Calcula posiciones (x, y en 0-100) para todos los dispositivos.

    Devuelve ``{mac: {"x": float, "y": float, "ring": int, "center": bool}}``.
    """
    items: List[dict] = [dict(device) for device in devices]
    layout: Dict[str, dict] = {}
    if not items:
        return layout

    gateway = next((device for device in items if is_gateway(device, gateway_ip)), None)
    if gateway is not None:
        layout[str(gateway.get("mac"))] = {
            "x": 50.0,
            "y": 50.0,
            "ring": 0,
            "center": True,
        }

    others = [device for device in items if str(device.get("mac")) not in layout]
    # Orden estable: primero por anillo y después por tipo y MAC.
    others.sort(key=lambda device: (
        type_ring(device.get("device_type", "")),
        str(device.get("device_type") or ""),
        str(device.get("mac") or ""),
    ))

    counters: Dict[int, int] = {}
    for device in others:
        mac = str(device.get("mac") or "")
        if not mac:
            continue
        ring = type_ring(device.get("device_type", ""))
        if ring == 0:
            # Otros routers/puntos de acceso (no el gateway) van al primer anillo
            # para no quedar apilados sobre el nodo central.
            ring = 1
        index = counters.get(ring, 0)
        counters[ring] = index + 1

        angle = math.radians((index * GOLDEN_ANGLE) + (ring * 41.0))
        radius = RING_RADIUS.get(ring, RING_RADIUS[3]) + _jitter(mac)

        layout[mac] = {
            "x": round(_clamp(50.0 + radius * math.cos(angle)), 2),
            "y": round(_clamp(50.0 + radius * math.sin(angle)), 2),
            "ring": ring,
            "center": False,
        }
    return layout


def apply_layout(devices: Iterable[dict], gateway_ip: str = "") -> List[dict]:
    """
    Devuelve los dispositivos con ``x``/``y``/``ring`` listos para pintar.

    Respeta la posición manual (``map_pinned``) del usuario; el resto recibe la
    posición automática.
    """
    items = [dict(device) for device in devices]
    automatic = auto_layout(items, gateway_ip)

    for device in items:
        mac = str(device.get("mac") or "")
        pinned = bool(device.get("map_pinned"))
        if pinned and device.get("map_x") is not None and device.get("map_y") is not None:
            device["x"] = float(device["map_x"])
            device["y"] = float(device["map_y"])
            device["ring"] = type_ring(device.get("device_type", ""))
            device["center"] = False
            device["pinned"] = True
            continue

        fallback = automatic.get(mac, {"x": 50.0, "y": 50.0, "ring": 3, "center": False})
        device["x"] = fallback["x"]
        device["y"] = fallback["y"]
        device["ring"] = fallback["ring"]
        device["center"] = fallback["center"]
        device["pinned"] = False

    return items
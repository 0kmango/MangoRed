"""
Clasificación (huella) de dispositivos para MangoRed.

Combina tres fuentes de evidencia, en orden de fiabilidad:

  1. **Nombre de host** visible (DNS inverso, NetBIOS o mDNS): el patrón suele
     delatar el modelo (``iPhone``, ``DESKTOP-XXXX``, ``raspberrypi``…).
  2. **Puertos TCP abiertos** (connect scan acotado, sin sockets raw): 62078 en
     un iPhone, 445/3389 en Windows, 9100 en una impresora…
  3. **Fabricante (OUI)**: Espressif suele ser IoT, Raspberry Pi un equipo Linux,
     VMware una máquina virtual, etc.

Todos los resultados son **estimaciones**: el nombre puede ser arbitrario y los
puertos varían con el firewall del equipo. El módulo nunca lanza excepciones y
nunca abre sockets privilegiados.
"""

from __future__ import annotations

import concurrent.futures
import re
import socket
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

#: Etiquetas legibles en español para cada tipo de dispositivo.
DEVICE_TYPE_LABELS = {
    "smartphone": "Móvil",
    "tablet": "Tablet",
    "laptop": "Portátil",
    "desktop": "Ordenador",
    "computer": "Ordenador",
    "server": "Servidor",
    "router": "Router / Punto de acceso",
    "printer": "Impresora",
    "tv": "TV / Streaming",
    "console": "Consola de juegos",
    "camera": "Cámara IP",
    "nas": "NAS / Almacenamiento",
    "iot": "Dispositivo IoT",
    "wearable": "Wearable",
    "vm": "Máquina virtual",
    "unknown": "Desconocido",
}

#: Puertos habituales de servicios que revelan el tipo de dispositivo.
SERVICE_NAMES = {
    22: "SSH",
    23: "Telnet",
    53: "DNS",
    80: "HTTP",
    139: "NetBIOS",
    443: "HTTPS",
    445: "SMB",
    515: "LPD",
    554: "RTSP",
    631: "IPP",
    1883: "MQTT",
    3389: "RDP",
    5000: "AirPlay/UPnP",
    5900: "VNC",
    7000: "AirPlay",
    8008: "Chromecast",
    8009: "Chromecast",
    9100: "Impresora RAW",
    32400: "Plex",
    62078: "Sincronización iPhone",
}

#: Lista de puertos por defecto (acotada y pensada para huella, no para auditoría).
DEFAULT_PORTS = tuple(SERVICE_NAMES.keys())

#: Iconos para la interfaz.
DEVICE_TYPE_ICONS = {
    "smartphone": "📱",
    "tablet": "📲",
    "laptop": "💻",
    "desktop": "🖥️",
    "computer": "💻",
    "server": "🗄️",
    "router": "📡",
    "printer": "🖨️",
    "tv": "📺",
    "console": "🎮",
    "camera": "📷",
    "nas": "💾",
    "iot": "🔌",
    "wearable": "⌚",
    "vm": "🧩",
    "unknown": "❓",
}


def service_names(ports: Iterable[int]) -> List[str]:
    """Traduce una lista de puertos a nombres de servicio legibles."""
    names = []
    for port in sorted({int(p) for p in ports}):
        names.append(f"{port} ({SERVICE_NAMES.get(port, 'desconocido')})")
    return names


def tcp_probe(ip: str, port: int, timeout: float = 0.35) -> bool:
    """Comprueba si un puerto TCP acepta conexión (connect scan no privilegiado)."""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(max(0.05, float(timeout)))
        return sock.connect_ex((ip, int(port))) == 0
    except (OSError, ValueError, OverflowError):
        return False
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def scan_services(
    ip: str,
    ports: Sequence[int] = DEFAULT_PORTS,
    timeout: float = 0.35,
    max_workers: int = 12,
) -> List[int]:
    """
    Escanea una lista acotada de puertos TCP y devuelve los abiertos.

    No se ejecuta ningún barrido de rangos ni de puertos arbitrarios: sólo la
    lista curada de ``SERVICE_NAMES`` (máximo 64 puertos por dispositivo).
    """
    candidates = list(dict.fromkeys(int(p) for p in ports))[:64]
    if not candidates:
        return []

    workers = max(1, min(int(max_workers), len(candidates)))
    open_ports: List[int] = []
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(tcp_probe, ip, port, timeout): port for port in candidates}
            for future in concurrent.futures.as_completed(futures):
                port = futures[future]
                try:
                    if future.result():
                        open_ports.append(port)
                except Exception:
                    continue
    except Exception:
        return sorted(open_ports)
    return sorted(open_ports)


# ============================================================================
# Reglas de clasificación
# ============================================================================

#: (patrón, tipo, sistema operativo estimado, motivo)
HOSTNAME_RULES: List[Tuple[re.Pattern, str, str, str]] = [
    # Televisores y streaming (antes que reglas genéricas de marca)
    (re.compile(r"apple-?tv|appletv|chromecast|googletv|google-?tv|android-?tv|fire-?tv|"
                r"roku|bravia|webos|tizen|smart-?tv|shield|mi-?box|mi-?tv"),
     "tv", "Android TV / tvOS", "El nombre corresponde a un dispositivo de TV/streaming"),
    # Consolas
    (re.compile(r"playstation|ps[45]\b|xbox|nintendo|switch"),
     "console", "", "El nombre corresponde a una consola de juegos"),
    # Infraestructura de red
    (re.compile(r"router|gateway|fritz|openwrt|mikrotik|ubiquiti|unifi|archer|deco\b|orbi|"
                r"eero|amplifi|repeater|extender"),
     "router", "", "El nombre corresponde a un router o punto de acceso"),
    # Almacenamiento en red
    (re.compile(r"synology|diskstation|qnap|truenas|unraid|freenas|openmediavault|nas[-_]"),
     "nas", "", "El nombre corresponde a un NAS/servidor de almacenamiento"),
    # Impresoras
    (re.compile(r"printer|impresora|deskjet|laserjet|officejet|envy|epson|canon|brother|"
                r"lexmark|xerox|zebra|(^|-)hp[0-9a-f]{4}"),
     "printer", "", "El nombre corresponde a una impresora"),
    # Cámaras IP y videovigilancia
    (re.compile(r"camera|camara|ipcam|ip-?cam|hikvision|dahua|reolink|doorbell|timbre|nvr|dvr"),
     "camera", "", "El nombre corresponde a una cámara o grabador IP"),
    # Domótica y wearables
    (re.compile(r"echo\b|alexa|sonos|nest\b|homekit|hue\b|bulb|bombilla|plug|enchufe|shelly|"
                r"tasmota|esphome|esp32|esp8266|tuya|wyze|ring\b|blink|thermostat|termostato"),
     "iot", "", "El nombre corresponde a un dispositivo domótico/IoT"),
    (re.compile(r"apple-?watch|watchos"), "wearable", "watchOS",
     "El nombre corresponde a un Apple Watch"),
    (re.compile(r"airpods"), "wearable", "AirPods",
     "El nombre corresponde a unos AirPods"),
    (re.compile(r"watch|wear|band\b|fitbit|garmin"),
     "wearable", "", "El nombre corresponde a un wearable"),
    # Apple
    (re.compile(r"iphone"), "smartphone", "iOS", "El nombre contiene 'iPhone'"),
    (re.compile(r"ipad"), "tablet", "iPadOS", "El nombre contiene 'iPad'"),
    (re.compile(r"ipod"), "smartphone", "iOS", "El nombre contiene 'iPod'"),
    (re.compile(r"macbook"), "laptop", "macOS", "El nombre contiene 'MacBook'"),
    (re.compile(r"imac|mac-?mini|mac-?pro|mac-?studio"), "desktop", "macOS",
     "El nombre corresponde a un Mac de sobremesa"),
    (re.compile(r"homepod"), "iot", "HomePod", "El nombre corresponde a un HomePod"),
    # Windows (nombres por defecto del sistema)
    (re.compile(r"^desktop-|^win-|-pc$|^pc-"), "desktop", "Windows",
     "El nombre sigue el patrón por defecto de Windows"),
    (re.compile(r"^laptop-"), "laptop", "Windows",
     "El nombre sigue el patrón por defecto de Windows"),
    # Linux embebido
    (re.compile(r"raspberry|raspberrypi|^rpi"), "computer", "Linux",
     "El nombre corresponde a una Raspberry Pi"),
    (re.compile(r"ubuntu|debian|fedora|archlinux|arch-|linux|kali|centos|rocky|almalinux|"
                r"opensuse|manjaro|linuxmint"),
     "computer", "Linux", "El nombre sugiere un equipo con Linux"),
    # Android
    (re.compile(r"galaxy|sm-[gasn]\d|sm-t\d|samsung"), "smartphone", "Android",
     "El nombre corresponde a un Samsung Galaxy"),
    (re.compile(r"redmi|xiaomi|poco|oneplus|pixel|nexus|moto-|motorola|oppo|vivo|realme|"
                r"nothing-?phone|huawei|honor|mate-?\d|p[234]\d-"),
     "smartphone", "Android", "El nombre corresponde a un móvil Android"),
    (re.compile(r"android|tablet|tab-?\d|tab[as]\d"),
     "smartphone", "Android", "El nombre contiene 'Android'"),
]


#: Reglas basadas en puertos: (puertos_requeridos, tipo, SO, motivo, confianza)
PORT_RULES: List[Tuple[frozenset, str, str, str, str]] = [
    (frozenset({62078}), "smartphone", "iOS",
     "Puerto 62078 abierto (sincronización de iPhone)", "high"),
    (frozenset({8008}), "tv", "Google TV / Chromecast",
     "Puerto 8008 abierto (Chromecast)", "high"),
    (frozenset({8009}), "tv", "Google TV / Chromecast",
     "Puerto 8009 abierto (Chromecast)", "high"),
    (frozenset({9100}), "printer", "", "Puerto 9100 abierto (impresión RAW)", "high"),
    (frozenset({631}), "printer", "", "Puerto 631 abierto (IPP)", "high"),
    (frozenset({515}), "printer", "", "Puerto 515 abierto (LPD)", "high"),
    (frozenset({554}), "camera", "", "Puerto 554 abierto (RTSP de cámara IP)", "high"),
    (frozenset({3389}), "desktop", "Windows",
     "Puerto 3389 abierto (Escritorio remoto de Windows)", "high"),
    (frozenset({445}), "desktop", "Windows", "Puerto 445 abierto (SMB de Windows)", "high"),
    (frozenset({139}), "desktop", "Windows", "Puerto 139 abierto (NetBIOS de Windows)", "medium"),
    (frozenset({5900}), "desktop", "", "Puerto 5900 abierto (VNC)", "medium"),
    (frozenset({32400}), "nas", "", "Puerto 32400 abierto (servidor Plex)", "medium"),
    (frozenset({1883}), "iot", "", "Puerto 1883 abierto (MQTT de domótica)", "high"),
    (frozenset({5000, 7000}), "tv", "tvOS / AirPlay",
     "Puertos AirPlay abiertos (Apple TV)", "medium"),
    (frozenset({53, 80}), "router", "", "Puertos 53 y 80 abiertos (servicios de router)", "medium"),
    (frozenset({23}), "iot", "", "Puerto 23 abierto (Telnet embebido)", "medium"),
]

#: Reglas basadas en el fabricante: (patrón, tipo, SO, motivo, confianza)
VENDOR_RULES: List[Tuple[re.Pattern, str, str, str, str]] = [
    (re.compile(r"espressif|tuya|itead|sonoff|shelly"), "iot", "",
     "Fabricante de chips IoT (Espressif/Tuya)", "high"),
    (re.compile(r"raspberry pi"), "computer", "Linux", "Fabricante Raspberry Pi", "high"),
    (re.compile(r"vmware|virtualbox|qemu|parallels|xen"), "vm", "",
     "Fabricante de virtualización", "high"),
    (re.compile(r"hikvision|dahua|reolink|axis communications"), "camera", "",
     "Fabricante de cámaras IP", "high"),
    (re.compile(r"canon|epson|brother industries|lexmark|xerox|zebra technologies"), "printer", "",
     "Fabricante de impresoras", "high"),
    (re.compile(r"synology|qnap|western digital|seagate"), "nas", "",
     "Fabricante de NAS", "high"),
    (re.compile(r"roku|vizio|hisense|tcl|lg electronics|sony corporation|philips"), "tv", "",
     "Fabricante de televisores", "medium"),
    (re.compile(r"sony interactive|nintendo"), "console", "",
     "Fabricante de consolas", "medium"),
    (re.compile(r"tp-link|netgear|d-link|ubiquiti|mikrotik|zyxel|aruba|ruckus|cambium|meraki"),
     "router", "", "Fabricante de equipos de red", "medium"),
    (re.compile(r"sonos"), "iot", "", "Fabricante de altavoces conectados", "medium"),
    (re.compile(r"amazon technologies"), "iot", "",
     "Fabricante Amazon (Alexa / Fire TV / Echo)", "low"),
    (re.compile(r"samsung electronics"), "smartphone", "Android",
     "Fabricante Samsung", "low"),
    (re.compile(r"xiaomi|oneplus|oppo|vivo|realme|motorola|google inc|huawei|honor device"),
     "smartphone", "Android", "Fabricante de móviles Android", "low"),
    (re.compile(r"intel corporate|realtek|qualcomm|broadcom|azurewave|mediatek|liteon|"
                r"dell|lenovo|asustek|micro-star|gigabyte"), "computer", "",
     "Fabricante de equipos informáticos", "low"),
]


#: Reglas basadas en el modelo publicado por mDNS (Apple): máxima fiabilidad.
MODEL_RULES: List[Tuple[re.Pattern, str, str]] = [
    (re.compile(r"^iphone", re.IGNORECASE), "smartphone", "iOS"),
    (re.compile(r"^ipad", re.IGNORECASE), "tablet", "iPadOS"),
    (re.compile(r"^ipod", re.IGNORECASE), "smartphone", "iOS"),
    (re.compile(r"^macbook", re.IGNORECASE), "laptop", "macOS"),
    (re.compile(r"^imac|^macmini|^macpro|^macstudio|^mac-", re.IGNORECASE), "desktop", "macOS"),
    (re.compile(r"^appletv", re.IGNORECASE), "tv", "tvOS"),
    (re.compile(r"^chromecast|^google tv|^android tv|^google inc", re.IGNORECASE),
     "tv", "Google TV / Chromecast"),
    (re.compile(r"^audioaccessory", re.IGNORECASE), "iot", "HomePod"),
    (re.compile(r"^watch", re.IGNORECASE), "wearable", "watchOS"),
    (re.compile(r"^airpods", re.IGNORECASE), "wearable", "AirPods"),
    (re.compile(r"^xbox", re.IGNORECASE), "console", "Xbox"),
]


def _result(device_type: str, os_guess: str, confidence: str, evidence: Iterable[str]) -> Dict[str, object]:
    """Construye el diccionario de resultado homogéneo."""
    return {
        "device_type": device_type,
        "device_type_label": DEVICE_TYPE_LABELS.get(device_type, DEVICE_TYPE_LABELS["unknown"]),
        "device_type_icon": DEVICE_TYPE_ICONS.get(device_type, DEVICE_TYPE_ICONS["unknown"]),
        "os_guess": os_guess,
        "confidence": confidence,
        "evidence": [str(item) for item in evidence if item][:4],
    }


def classify_device(
    hostname: str = "",
    vendor: str = "",
    ports: Optional[Iterable[int]] = None,
    is_gateway: bool = False,
    is_local: bool = False,
    local_os: str = "",
    model: str = "",
    mdns_services: Optional[Iterable[str]] = None,
) -> Dict[str, object]:
    """
    Estima el tipo de dispositivo a partir del modelo mDNS, el nombre, los
    puertos abiertos y el fabricante.

    Devuelve ``device_type``, ``device_type_label``, ``device_type_icon``,
    ``os_guess``, ``confidence`` (``high``/``medium``/``low``) y ``evidence``.
    """
    host = (hostname or "").strip().lower()
    vendor_text = (vendor or "").strip().lower()
    model_text = (model or "").strip()
    port_set = frozenset(int(p) for p in (ports or []))
    service_text = " ".join(str(item).lower() for item in (mdns_services or []))

    if is_local:
        return _result("computer", local_os or "Sistema local", "high",
                       ["Es el propio equipo donde se ejecuta MangoRed"])

    if is_gateway:
        return _result("router", "", "high",
                       ["Es la puerta de enlace predeterminada de la red"])

    # 0. Modelo publicado por mDNS (máxima fiabilidad: iPhone14,2, MacBookPro18,3…)
    if model_text:
        for pattern, device_type, os_guess in MODEL_RULES:
            if pattern.search(model_text):
                return _result(device_type, os_guess, "high",
                               [f"Modelo publicado por el dispositivo: {model_text}"])

    # 0b. Google Cast con modelo => receptor de TV/streaming (Android TV, Chromecast).
    #     Muchos Android TV usan nombres de host «android-xxxx», así que esta
    #     evidencia debe primar sobre la regla genérica de "Android".
    if model_text and ("google cast" in service_text or "googlecast" in service_text):
        return _result("tv", "Google TV / Android TV", "high",
                       [f"Anuncia Google Cast con modelo {model_text}"])

    # 1. Nombre de host (evidencia legible y específica)
    if host and host not in {"_gateway", "localhost"}:
        for pattern, device_type, os_guess, reason in HOSTNAME_RULES:
            if pattern.search(host):
                return _result(device_type, os_guess, "high",
                               [reason, f"Nombre visible: {host}"])

    # 2. Puertos abiertos
    if port_set:
        for required, device_type, os_guess, reason, confidence in PORT_RULES:
            if required.issubset(port_set):
                return _result(device_type, os_guess, confidence,
                               [reason, f"Servicios: {', '.join(service_names(port_set))}"])

    # 3. Servicios mDNS anunciados (específicos de un ecosistema)
    if service_text:
        if "apple mobile device" in service_text or "apple-mobdev2" in service_text:
            return _result("unknown", "iOS / iPadOS", "medium",
                           ["Anuncia el servicio Apple Mobile Device (iPhone/iPad con sincronización Wi-Fi)"])
        if "airplay" in service_text:
            return _result("unknown", "iOS / iPadOS / macOS / tvOS", "low",
                           ["El dispositivo anuncia AirPlay (ecosistema Apple)"])

    # 4. Fabricante (OUI)
    if vendor_text and "desconocido" not in vendor_text and "privado" not in vendor_text:
        for pattern, device_type, os_guess, reason, confidence in VENDOR_RULES:
            if pattern.search(vendor_text):
                return _result(device_type, os_guess, confidence,
                               [reason, f"Fabricante: {vendor}"])

        # Fabricantes ambiguos: se informa el ecosistema sin afirmar el tipo.
        if "apple" in vendor_text:
            return _result("unknown", "iOS / iPadOS / macOS", "low",
                           ["Fabricante Apple (puede ser móvil, tablet o Mac)"])
        if "microsoft" in vendor_text:
            return _result("computer", "Windows", "low", ["Fabricante Microsoft"])

    return _result("unknown", "", "low", [])


def fingerprint_device(
    ip: str,
    hostname: str = "",
    vendor: str = "",
    is_gateway: bool = False,
    is_local: bool = False,
    local_os: str = "",
    model: str = "",
    mdns_services: Optional[Iterable[str]] = None,
    detect_services: bool = True,
    timeout: float = 0.35,
) -> Dict[str, object]:
    """
    Ejecuta la huella completa: escaneo acotado de servicios + clasificación.

    El escaneo de puertos se omite si el modelo mDNS o el nombre de host ya
    identifican el equipo, o si ``detect_services`` es falso.
    """
    ports: List[int] = []
    already_classified = False

    preliminary = classify_device(
        hostname=hostname,
        vendor=vendor,
        model=model,
        mdns_services=mdns_services,
    )
    if preliminary["confidence"] == "high":
        already_classified = True

    if detect_services and ip and not is_local and not already_classified:
        ports = scan_services(ip, timeout=timeout)

    result = classify_device(
        hostname=hostname,
        vendor=vendor,
        ports=ports,
        is_gateway=is_gateway,
        is_local=is_local,
        local_os=local_os,
        model=model,
        mdns_services=mdns_services,
    )
    result["open_ports"] = ports
    result["services"] = service_names(ports)
    return result
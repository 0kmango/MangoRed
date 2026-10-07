"""
Módulo de resolución de fabricantes (OUI) a partir de la dirección MAC.
Utiliza la base de datos local de prefijos IEEE/Nmap en Kali Linux con un
diccionario de reserva para los fabricantes más comunes.
"""

import os
import re

COMMON_OUIs = {
    # Fabricantes comunes y chips de red
    "00:50:56": "VMware",
    "00:0C:29": "VMware",
    "08:00:27": "Oracle VirtualBox",
    "52:54:00": "QEMU/KVM Virtual NIC",
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Trading",
    "E4:5F:01": "Raspberry Pi Trading",
    "28:CD:C1": "Raspberry Pi Trading",
    "F8:9A:25": "Huawei Technologies",
    "00:1E:10": "Huawei Technologies",
    "20:51:F5": "Huawei Technologies",
    "00:E0:4C": "Realtek Semiconductor",
    "00:E8:4C": "Realtek Semiconductor",
    "B0:2E:BA": "TP-Link Corporation",
    "50:C7:BF": "TP-Link Corporation",
    "F4:F2:6D": "TP-Link Corporation",
    "C0:25:67": "TP-Link Corporation",
    "EC:08:6B": "TP-Link Corporation",
    "00:1A:2B": "Ayecom Technology",
    "F0:9F:C2": "Ubiquiti Networks",
    "78:8A:20": "Ubiquiti Networks",
    "AC:8B:A9": "Apple",
    "F0:18:98": "Apple",
    "3C:06:30": "Apple",
    "BC:D0:74": "Apple",
    "60:F8:1D": "Apple",
    "F8:FF:C2": "Apple",
    "A4:83:E7": "Apple",
    "5C:52:1E": "Apple",
    "00:1A:11": "Google",
    "3C:5A:37": "Google",
    "D8:6C:63": "Google",
    "F4:F5:D8": "Google",
    "00:17:88": "Philips Hue",
    "30:FD:38": "Espressif Inc. (ESP8266/ESP32)",
    "24:6F:28": "Espressif Inc. (ESP8266/ESP32)",
    "84:CC:A8": "Espressif Inc. (ESP8266/ESP32)",
    "A4:CF:12": "Espressif Inc. (ESP8266/ESP32)",
    "2C:F4:32": "Espressif Inc. (ESP8266/ESP32)",
    "60:01:94": "Espressif Inc. (ESP8266/ESP32)",
    "48:E7:DA": "Samsung Electronics",
    "84:25:19": "Samsung Electronics",
    "50:01:D9": "Samsung Electronics",
    "00:26:37": "Samsung Electronics",
    "D0:03:DF": "Samsung Electronics",
    "A8:7C:01": "Xiaomi Communications",
    "7C:49:EB": "Xiaomi Communications",
    "64:A2:F9": "Xiaomi Communications",
    "00:24:D7": "Intel Corporate",
    "34:13:E8": "Intel Corporate",
    "80:86:F2": "Intel Corporate",
    "00:1B:21": "Intel Corporate",
    "40:16:9F": "Amazon Technologies",
    "68:54:5A": "Amazon Technologies",
    "FC:65:DE": "Amazon Technologies",
    "00:04:4B": "NVIDIA",
    "00:1E:67": "Intel Corporate",
    "00:19:66": "Asustek Computer",
    "AC:9E:17": "Asustek Computer",
    "04:D4:C4": "Asustek Computer",
    "D8:50:E6": "Asustek Computer",
    "00:0C:42": "MikroTik",
    "48:8F:5A": "MikroTik",
    "64:D1:54": "MikroTik",
    "CC:2D:E0": "MikroTik"
}

_OUI_CACHE = {}
_DATABASE_LOADED = False


def _normalize_prefix(mac_str: str) -> str:
    """Extrae los primeros 3 octetos en formato hexadecimal sin delimitadores."""
    clean = re.sub(r"[^0-9A-Fa-f]", "", mac_str).upper()
    return clean[:6] if len(clean) >= 6 else ""


def _load_system_oui_db():
    """Carga los prefijos OUI desde las bases de datos de Kali Linux."""
    global _OUI_CACHE, _DATABASE_LOADED
    if _DATABASE_LOADED:
        return

    # Primero cargar el diccionario de reserva
    for prefix, vendor in COMMON_OUIs.items():
        clean_prefix = _normalize_prefix(prefix)
        if clean_prefix:
            _OUI_CACHE[clean_prefix] = vendor

    # Buscar bases de datos comunes en Kali Linux
    candidate_paths = [
        "/usr/share/nmap/nmap-mac-prefixes",
        "/usr/share/arp-scan/ieee-oui.txt",
        "/var/lib/ieee-data/oui.txt"
    ]

    for path in candidate_paths:
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        
                        # Formato nmap: 00000C Cisco Systems
                        parts = line.split(None, 1)
                        if len(parts) == 2:
                            prefix = parts[0].strip().upper()
                            vendor = parts[1].strip()
                            clean_prefix = _normalize_prefix(prefix)
                            if len(clean_prefix) == 6 and clean_prefix not in _OUI_CACHE:
                                _OUI_CACHE[clean_prefix] = vendor
                break  # Con una base de datos completa es suficiente
            except Exception:
                continue

    _DATABASE_LOADED = True


def lookup_vendor(mac: str) -> dict:
    """
    Busca el fabricante asociado a una dirección MAC.
    
    Retorna un diccionario:
    {
        "vendor": "Nombre del fabricante o 'Desconocido'",
        "is_confirmed": False, # Siempre estimación basada en prefijo OUI
        "note": "Estimado a partir del prefijo OUI de 24 bits (puede variar con MAC aleatoria)"
    }
    """
    if not mac:
        return {
            "vendor": "Desconocido",
            "is_confirmed": False,
            "note": "Dirección MAC no proporcionada"
        }

    _load_system_oui_db()
    prefix = _normalize_prefix(mac)

    # Detección de MAC privada / aleatoria (bit localmente administrado)
    # Si el segundo dígito hexadecimal tiene el bit 1 activo (2, 6, A, E)
    is_locally_administered = False
    clean_mac = re.sub(r"[^0-9A-Fa-f]", "", mac)
    if len(clean_mac) >= 2:
        try:
            second_char = int(clean_mac[1], 16)
            if second_char & 0b0010:
                is_locally_administered = True
        except ValueError:
            pass

    if is_locally_administered:
        return {
            "vendor": "Dispositivo Privado (MAC Aleatoria)",
            "is_confirmed": False,
            "note": "El dispositivo utiliza una MAC aleatoria o privada (común en iOS, Android y Windows modernos)"
        }

    vendor = _OUI_CACHE.get(prefix, "Fabricante Desconocido")
    return {
        "vendor": vendor,
        "is_confirmed": False,
        "note": "Estimación basada en el registro IEEE OUI del fabricante"
    }

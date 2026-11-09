"""
Descubrimiento de red multiplataforma para MangoRed.

Sustituye las llamadas exclusivas de Linux (``ip route``, ``ip neigh``,
``/proc/net/arp``) por una capa que funciona en:

  * Linux (Kali, Debian, Ubuntu, Arch, Fedora, openSUSE...)
  * Windows 10 / 11 (``route print``, ``ipconfig``, ``arp -a``)
  * macOS (``route``, ``ifconfig``, ``arp``)

El módulo es 100 % defensivo: sólo lee la tabla de vecinos del sistema y, como
mucho, envía un ICMP Echo por host dentro de la subred local detectada. Nunca
modifica la red ni ejecuta comandos con ``shell=True``.
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import re
import socket
import struct
from typing import Dict, List, Optional

from platform_compat import IS_MACOS, IS_WINDOWS, PLATFORM_LABEL, run_command

DEFAULT_SUBNET = "192.168.1.0/24"
DEFAULT_GATEWAY = "192.168.1.1"

NETMASK_LIKE = re.compile(
    r"^(255|254|252|248|240|224|192|128|0)\.(255|254|252|248|240|224|192|128|0)\."
    r"(255|254|252|248|240|224|192|128|0)\.(255|254|252|248|240|224|192|128|0)$"
)
ARP_ENTRY = re.compile(
    r"(\d{1,3}(?:\.\d{1,3}){3})\)?\s+(?:at\s+)?([0-9A-Fa-f:\-]{11,23})(?=\s|$)"
)
IPV4 = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


# ============================================================================
# Utilidades de validación y normalización
# ============================================================================

def is_valid_ipv4(value: object) -> bool:
    """Comprueba que el valor sea una IPv4 en notación decimal."""
    try:
        ipaddress.IPv4Address(str(value).strip())
        return True
    except (ValueError, TypeError):
        return False


def parse_mac_loose(value: object) -> str:
    """
    Normaliza direcciones MAC con separadores ``:`` o ``-`` aceptando octetos
    de uno o dos dígitos (formato que usa ``arp`` en macOS y Windows).
    Devuelve cadena vacía si no es una MAC reconocible.
    """
    if value is None:
        return ""
    text = str(value).strip().strip("()[]")
    if not text:
        return ""

    if ":" in text or "-" in text:
        parts = re.split(r"[:\-]", text)
        if len(parts) == 6 and all(re.fullmatch(r"[0-9A-Fa-f]{1,2}", p) for p in parts):
            return ":".join(p.zfill(2).lower() for p in parts)

    digits = re.sub(r"[^0-9A-Fa-f]", "", text)
    if len(digits) == 12:
        return ":".join(digits[i:i + 2].lower() for i in range(0, 12, 2))
    return ""


def is_unicast_mac(mac: str) -> bool:
    """Descarta MAC nulas, de broadcast y de multicast (no son equipos reales)."""
    normalized = parse_mac_loose(mac)
    if not normalized:
        return False
    if normalized in {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}:
        return False
    try:
        first_octet = int(normalized.split(":")[0], 16)
    except ValueError:
        return False
    return (first_octet & 0x01) == 0


def mask_to_prefix(mask: str) -> int:
    """Convierte una máscara decimal (255.255.255.0) a longitud de prefijo (/24)."""
    if not mask or not is_valid_ipv4(mask):
        return 0
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
    except ValueError:
        return 0


def safe_network(cidr: str) -> Optional[ipaddress.IPv4Network]:
    """Devuelve la red IPv4 o ``None`` si el CIDR no es válido."""
    try:
        net = ipaddress.ip_network(str(cidr).strip(), strict=False)
    except (ValueError, TypeError):
        return None
    return net if net.version == 4 else None


def is_local_network(net: Optional[ipaddress.IPv4Network]) -> bool:
    """
    Determina si una red es privada, de enlace local o CGNAT.

    MangoRed está pensado exclusivamente para redes propias, por lo que el
    barrido activo se desactiva en rangos públicos.
    """
    if net is None or net.version != 4:
        return False
    if net.is_private or net.is_loopback or net.is_link_local:
        return True
    try:
        return net.subnet_of(ipaddress.IPv4Network("100.64.0.0/10"))
    except (ValueError, TypeError):
        return False


# ============================================================================
# Enumeración de interfaces
# ============================================================================

def _load_psutil():
    try:
        import psutil  # type: ignore
        return psutil
    except Exception:
        return None


def psutil_interfaces() -> Dict[str, dict]:
    """Devuelve ``{nombre: {ip, netmask, mac, is_up}}`` usando psutil si existe."""
    psutil = _load_psutil()
    if psutil is None:
        return {}

    result: Dict[str, dict] = {}
    try:
        addresses = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
    except Exception:
        return {}

    af_link = getattr(psutil, "AF_LINK", -1)
    for name, entries in addresses.items():
        info = {"name": name, "ip": "", "netmask": "", "mac": "", "is_up": False}
        try:
            stat = stats.get(name)
            info["is_up"] = bool(stat.isup) if stat else False
        except Exception:
            pass

        for entry in entries:
            family = getattr(entry, "family", None)
            address = getattr(entry, "address", "") or ""
            if family == socket.AF_INET and not info["ip"]:
                if is_valid_ipv4(address):
                    info["ip"] = address
                    info["netmask"] = getattr(entry, "netmask", "") or ""
            elif family == af_link and not info["mac"]:
                info["mac"] = parse_mac_loose(address)
        result[name] = info

    return result


def _first_active_interface(interfaces: Dict[str, dict]) -> str:
    """Elige una interfaz activa con IPv4 distinta de loopback."""
    preferred_prefixes = ("wl", "wi-fi", "wifi", "en", "eth", "eno", "ens", "wlan")
    candidates = [
        (name, info)
        for name, info in interfaces.items()
        if info.get("ip") and not str(info["ip"]).startswith("127.")
    ]
    if not candidates:
        return ""

    def sort_key(item):
        name = item[0].lower()
        up_rank = 0 if item[1].get("is_up") else 1
        name_rank = 0 if any(name.startswith(p) for p in preferred_prefixes) else 1
        return (up_rank, name_rank, name)

    return sorted(candidates, key=sort_key)[0][0]


def list_network_interfaces() -> List[dict]:
    """Lista interfaces disponibles para el desplegable de Ajustes."""
    interfaces = psutil_interfaces()
    rows = [
        {
            "name": name,
            "ip": info.get("ip", ""),
            "mac": info.get("mac", ""),
            "is_up": bool(info.get("is_up")),
        }
        for name, info in interfaces.items()
        if not name.lower().startswith("loopback")
    ]

    if not rows and not IS_MACOS:
        rows = _command_interfaces()

    return sorted(rows, key=lambda r: (not r["ip"], r["name"].lower()))


def _command_interfaces() -> List[dict]:
    """Fallback sin psutil: enumera interfaces con herramientas del sistema."""
    rows: List[dict] = []
    seen = set()

    if IS_WINDOWS:
        for block in _windows_ipconfig_blocks():
            name = block.get("header", "")
            if not name or name.lower() in seen:
                continue
            seen.add(name.lower())
            rows.append({
                "name": name,
                "ip": block.get("ip", ""),
                "mac": block.get("mac", ""),
                "is_up": True,
            })
        return rows

    if IS_MACOS:
        result = run_command(["ifconfig", "-l"], timeout=4)
        if result and result.stdout:
            for name in result.stdout.split():
                ip, _ = _macos_interface_ipv4(name)
                rows.append({
                    "name": name,
                    "ip": ip or "",
                    "mac": _macos_interface_mac(name),
                    "is_up": True,
                })
        return rows

    result = run_command(["ip", "-o", "link", "show"], timeout=4)
    if result and result.stdout:
        for line in result.stdout.splitlines():
            match = re.match(r"\d+:\s+([^:@]+)[:@]", line)
            if not match:
                continue
            name = match.group(1).strip()
            if name == "lo" or name in seen:
                continue
            seen.add(name)
            mac_match = re.search(r"link/ether\s+([0-9a-fA-F:]{17})", line)
            ip, _ = _linux_interface_ipv4(name)
            rows.append({
                "name": name,
                "ip": ip,
                "mac": parse_mac_loose(mac_match.group(1)) if mac_match else "",
                "is_up": "state UP" in line or "<BROADCAST,MULTICAST,UP" in line,
            })
    return rows
# ============================================================================
# Detectores específicos por sistema operativo
# ============================================================================

def _linux_default_route() -> tuple[str, str]:
    """Obtiene ``(gateway, interfaz)`` de la ruta por defecto en Linux."""
    result = run_command(["ip", "route", "show", "default"], timeout=3)
    if result and result.stdout:
        for line in result.stdout.splitlines():
            if not line.startswith("default"):
                continue
            gateway_match = re.search(r"\bvia\s+(\d{1,3}(?:\.\d{1,3}){3})", line)
            device_match = re.search(r"\bdev\s+(\S+)", line)
            if gateway_match:
                return gateway_match.group(1), (device_match.group(1) if device_match else "")

    # Fallback sin iproute2: /proc/net/route (gateway en little-endian)
    try:
        with open("/proc/net/route", "r", encoding="utf-8") as handle:
            for line in handle.readlines()[1:]:
                columns = line.split()
                if len(columns) >= 3 and columns[1] == "00000000":
                    gateway = socket.inet_ntoa(struct.pack("<L", int(columns[2], 16)))
                    if is_valid_ipv4(gateway) and gateway != "0.0.0.0":
                        return gateway, columns[0]
    except (OSError, ValueError):
        pass
    return "", ""


def _linux_interface_ipv4(interface: str) -> tuple[str, int]:
    """Devuelve ``(ip, prefijo)`` de una interfaz Linux."""
    if not interface:
        return "", 0
    result = run_command(["ip", "-o", "-4", "addr", "show", "dev", interface], timeout=3)
    if result and result.stdout:
        match = re.search(r"inet\s+(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})", result.stdout)
        if match:
            return match.group(1), int(match.group(2))
    return "", 0


def _linux_interface_mac(interface: str) -> str:
    """Devuelve la MAC de una interfaz Linux."""
    if not interface:
        return ""
    result = run_command(["ip", "link", "show", "dev", interface], timeout=3)
    if result and result.stdout:
        match = re.search(r"link/ether\s+([0-9a-fA-F:]{17})", result.stdout)
        if match:
            return parse_mac_loose(match.group(1))

    try:
        with open(f"/sys/class/net/{interface}/address", "r", encoding="utf-8") as handle:
            return parse_mac_loose(handle.read())
    except OSError:
        return ""


def _windows_default_route() -> tuple[str, str]:
    """
    Obtiene ``(gateway, ip_local)`` a partir de ``route print -4``.

    La salida está localizada, pero la fila por defecto siempre empieza con
    ``0.0.0.0  0.0.0.0  <gateway>  <ip_interfaz>  <métrica>``.
    """
    result = run_command(["route", "print", "-4"], timeout=8)
    if result and result.stdout:
        for line in result.stdout.splitlines():
            columns = line.split()
            if len(columns) >= 5 and columns[0] == "0.0.0.0" and columns[1] == "0.0.0.0":
                gateway, interface_ip = columns[2], columns[3]
                if is_valid_ipv4(gateway) and gateway != "0.0.0.0":
                    return gateway, interface_ip
    return "", ""


def _looks_like_netmask(value: str) -> bool:
    return bool(NETMASK_LIKE.match(value or ""))


def _windows_ipconfig_blocks() -> List[dict]:
    """
    Analiza ``ipconfig`` en bloques por adaptador.

    No depende del idioma de Windows: cada bloque se inicia en la línea del
    nombre del adaptador (terminada en ``:`` y sin IPv4) e identifica la IPv4
    local, la máscara (por patrón numérico) y la MAC (por patrón hexadecimal).
    """
    result = run_command(["ipconfig"], timeout=8)
    if not result or not result.stdout:
        return []

    header_pattern = re.compile(r"^\s*\S.*:\s*$")
    blocks: List[dict] = []
    current: Optional[dict] = None

    for raw_line in result.stdout.splitlines():
        line = raw_line.rstrip()
        if not line.strip():
            continue

        stripped = line.strip()
        if header_pattern.match(line) and not IPV4.search(stripped):
            # Línea de nombre de adaptador: comienza un bloque nuevo.
            current = {"header": stripped.rstrip(":"), "lines": []}
            blocks.append(current)
            continue

        if current is None:
            current = {"header": stripped.rstrip(":"), "lines": []}
            blocks.append(current)
        current["lines"].append(line)

    parsed: List[dict] = []
    for block in blocks:
        body = "\n".join(block["lines"])
        ipv4_values = [v for v in IPV4.findall(body) if is_valid_ipv4(v)]
        if not ipv4_values:
            continue
        netmask = next((v for v in ipv4_values if _looks_like_netmask(v)), "")
        local_ip = next(
            (v for v in ipv4_values if not _looks_like_netmask(v) and v != "0.0.0.0"),
            "",
        )
        mac_match = re.search(r"(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}", body)
        parsed.append({
            "header": block["header"],
            "ip": local_ip,
            "netmask": netmask,
            "mac": parse_mac_loose(mac_match.group(0)) if mac_match else "",
        })
    return parsed


def _macos_default_route() -> tuple[str, str]:
    """Obtiene ``(gateway, interfaz)`` de la ruta por defecto en macOS."""
    result = run_command(["route", "-n", "get", "default"], timeout=4)
    if not result or not result.stdout:
        return "", ""
    gateway_match = re.search(r"gateway:\s*(\d{1,3}(?:\.\d{1,3}){3})", result.stdout)
    interface_match = re.search(r"interface:\s*(\S+)", result.stdout)
    gateway = gateway_match.group(1) if gateway_match else ""
    interface = interface_match.group(1) if interface_match else ""
    return (gateway if is_valid_ipv4(gateway) else ""), interface


def _macos_interface_ipv4(interface: str) -> tuple[str, int]:
    """Devuelve ``(ip, prefijo)`` de una interfaz macOS."""
    if not interface:
        return "", 0
    result = run_command(["ifconfig", interface], timeout=4)
    if not result or not result.stdout:
        return "", 0
    match = re.search(
        r"inet\s+(\d{1,3}(?:\.\d{1,3}){3})\s+netmask\s+(0x[0-9a-fA-F]{8}|\d{1,3}(?:\.\d{1,3}){3})",
        result.stdout,
    )
    if not match:
        return "", 0
    ip_value, mask_value = match.group(1), match.group(2)
    if mask_value.startswith("0x"):
        try:
            mask_value = socket.inet_ntoa(struct.pack(">L", int(mask_value, 16)))
        except (ValueError, struct.error):
            return ip_value, 0
    return ip_value, mask_to_prefix(mask_value)


def _macos_interface_mac(interface: str) -> str:
    """Devuelve la MAC de una interfaz macOS."""
    if not interface:
        return ""
    result = run_command(["ifconfig", interface], timeout=4)
    if not result or not result.stdout:
        return ""
    match = re.search(r"ether\s+([0-9a-fA-F:]{17})", result.stdout)
    return parse_mac_loose(match.group(1)) if match else ""


def _socket_local_ip() -> str:
    """Obtiene la IP local saliente sin enviar tráfico (socket UDP no conectado)."""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.5)
        sock.connect(("8.8.8.8", 80))
        candidate = sock.getsockname()[0]
        if is_valid_ipv4(candidate) and not candidate.startswith("127."):
            return candidate
    except OSError:
        pass
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    try:
        candidate = socket.gethostbyname(socket.gethostname())
        if is_valid_ipv4(candidate) and not candidate.startswith("127."):
            return candidate
    except OSError:
        pass
    return ""


def _guess_gateway(local_ip: str, prefix: int) -> str:
    """Estima la puerta de enlace como el primer host de la subred local."""
    try:
        network = ipaddress.IPv4Network(f"{local_ip}/{prefix or 24}", strict=False)
        for host in network.hosts():
            return str(host)
    except (ValueError, TypeError):
        pass
    return DEFAULT_GATEWAY


# ============================================================================
# Contexto de red (interfaz, IP, MAC, subred y puerta de enlace)
# ============================================================================

def detect_network_context(preferred_interface: str = "") -> dict:
    """
    Detecta la topología local de forma multiplataforma.

    Estrategia en cascada:
      1. psutil (si está instalado) para IP, máscara y MAC por interfaz.
      2. Comandos nativos del SO para la ruta por defecto (gateway).
      3. Comandos nativos para IP/MAC si psutil no está disponible.
      4. Socket UDP (sin enviar tráfico) como último recurso para la IP local.

    Siempre devuelve un diccionario con claves estables, incluso si la
    detección falla por completo.
    """
    context = {
        "interface": "",
        "local_ip": "",
        "local_mac": "",
        "subnet": DEFAULT_SUBNET,
        "gateway": DEFAULT_GATEWAY,
        "platform": PLATFORM_LABEL,
        "detected": False,
    }

    interfaces = psutil_interfaces()
    preferred = (preferred_interface or "").strip()

    gateway, route_interface = "", ""
    try:
        if IS_WINDOWS:
            gateway, route_interface = _windows_default_route()
        elif IS_MACOS:
            gateway, route_interface = _macos_default_route()
        else:
            gateway, route_interface = _linux_default_route()
    except Exception:
        gateway, route_interface = "", ""

    interface = preferred or route_interface
    if interface and interfaces and interface not in interfaces:
        interface = route_interface if route_interface in interfaces else ""
    if not interface:
        interface = _first_active_interface(interfaces)

    local_ip, prefix, local_mac = "", 0, ""
    if interface and interface in interfaces:
        local_ip = interfaces[interface].get("ip", "") or ""
        local_mac = interfaces[interface].get("mac", "") or ""
        prefix = mask_to_prefix(interfaces[interface].get("netmask", ""))

    if interface and not local_ip:
        if IS_WINDOWS:
            for block in _windows_ipconfig_blocks():
                if local_ip:
                    break
                local_ip = block.get("ip", "")
                prefix = mask_to_prefix(block.get("netmask", ""))
                local_mac = local_mac or block.get("mac", "")
        elif IS_MACOS:
            local_ip, prefix = _macos_interface_ipv4(interface)
        else:
            local_ip, prefix = _linux_interface_ipv4(interface)

    if interface and not local_mac:
        if IS_MACOS:
            local_mac = _macos_interface_mac(interface)
        elif not IS_WINDOWS:
            local_mac = _linux_interface_mac(interface)

    if not local_ip:
        local_ip = _socket_local_ip()
        if local_ip:
            for name, info in interfaces.items():
                if info.get("ip") == local_ip:
                    interface = interface or name
                    prefix = prefix or mask_to_prefix(info.get("netmask", ""))
                    local_mac = local_mac or info.get("mac", "")
                    break

    if local_ip and not prefix:
        prefix = 24

    subnet = DEFAULT_SUBNET
    if local_ip and prefix:
        try:
            subnet = str(ipaddress.IPv4Network(f"{local_ip}/{prefix}", strict=False))
        except ValueError:
            subnet = DEFAULT_SUBNET

    if not gateway:
        gateway = _guess_gateway(local_ip, prefix) if local_ip else DEFAULT_GATEWAY

    context.update({
        "interface": interface,
        "local_ip": local_ip,
        "local_mac": local_mac,
        "subnet": subnet,
        "gateway": gateway,
        "detected": bool(local_ip),
    })
    return context


# ============================================================================
# Tabla de vecinos (ARP) multiplataforma
# ============================================================================

def _parse_arp_text(text: str, default_state: str = "REACHABLE") -> Dict[str, dict]:
    """
    Extrae ``{ip: {mac, state}}`` de la salida de ``arp -a``.

    Soporta los tres formatos habituales:
      * Linux:   ``? (192.168.1.1) at 00:11:22:33:44:55 [ether] on eth0``
      * macOS:   ``? (192.168.1.1) at 0:11:22:33:44:55 on en0 ifscope``
      * Windows: ``192.168.1.1   00-11-22-33-44-55   dynamic``
    """
    entries: Dict[str, dict] = {}
    if not text:
        return entries

    for line in text.splitlines():
        if "(incomplete)" in line.lower():
            continue
        match = ARP_ENTRY.search(line)
        if not match:
            continue
        ip_value, raw_mac = match.group(1), match.group(2)
        mac = parse_mac_loose(raw_mac)
        if not is_valid_ipv4(ip_value) or not is_unicast_mac(mac):
            continue
        state = default_state
        upper_line = line.upper()
        for candidate in ("REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT", "FAILED", "INCOMPLETE"):
            if candidate in upper_line:
                state = candidate
                break
        entries[ip_value] = {"mac": mac, "state": state}
    return entries


def _parse_ip_neigh_text(text: str) -> Dict[str, dict]:
    """Extrae vecinos de la salida de ``ip neigh show``."""
    entries: Dict[str, dict] = {}
    if not text:
        return entries
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4 or "lladdr" not in parts:
            continue
        ip_value = parts[0]
        if not is_valid_ipv4(ip_value):
            continue
        mac_index = parts.index("lladdr")
        if mac_index + 1 >= len(parts):
            continue
        mac = parse_mac_loose(parts[mac_index + 1])
        if not is_unicast_mac(mac):
            continue
        entries[ip_value] = {"mac": mac, "state": parts[-1].upper()}
    return entries


def _proc_net_arp_entries() -> Dict[str, dict]:
    """Lee ``/proc/net/arp`` en Linux (fallback sin net-tools)."""
    entries: Dict[str, dict] = {}
    try:
        with open("/proc/net/arp", "r", encoding="utf-8") as handle:
            for line in handle.readlines()[1:]:
                columns = line.split()
                if len(columns) < 6 or columns[2] == "0x0":
                    continue
                ip_value, mac = columns[0], parse_mac_loose(columns[3])
                if is_valid_ipv4(ip_value) and is_unicast_mac(mac):
                    entries[ip_value] = {"mac": mac, "state": "REACHABLE"}
    except OSError:
        pass
    return entries


def _linux_neighbors(interface: str) -> Dict[str, dict]:
    """Tabla de vecinos en Linux mediante ``ip neigh`` y ``arp -an``."""
    entries: Dict[str, dict] = {}

    command = ["ip", "neigh", "show"]
    if interface:
        command.extend(["dev", interface])
    result = run_command(command, timeout=4)
    if result and result.stdout:
        entries.update(_parse_ip_neigh_text(result.stdout))

    arp_command = ["arp", "-an"]
    if interface:
        arp_command.extend(["-i", interface])
    arp_result = run_command(arp_command, timeout=4)
    if arp_result and arp_result.stdout:
        for ip_value, info in _parse_arp_text(arp_result.stdout).items():
            entries.setdefault(ip_value, info)

    for ip_value, info in _proc_net_arp_entries().items():
        entries.setdefault(ip_value, info)

    return entries


def _windows_neighbors() -> Dict[str, dict]:
    """Tabla ARP en Windows mediante ``arp -a``."""
    result = run_command(["arp", "-a"], timeout=8)
    if result and result.stdout:
        return _parse_arp_text(result.stdout)
    return {}


def _macos_neighbors(interface: str) -> Dict[str, dict]:
    """Tabla ARP en macOS mediante ``arp -an``."""
    command = ["arp", "-an"]
    if interface:
        command.extend(["-i", interface])
    result = run_command(command, timeout=6)
    if result and result.stdout:
        return _parse_arp_text(result.stdout)
    return {}


def read_neighbor_table(interface: str = "", subnet: str = "") -> Dict[str, dict]:
    """
    Devuelve la tabla de vecinos normalizada ``{ip: {mac, state}}``.

    Si se indica ``subnet``, se descartan las entradas de otras redes (útil en
    Windows, donde ``arp -a`` lista todas las interfaces).
    """
    entries: Dict[str, dict] = {}
    try:
        if IS_WINDOWS:
            entries = _windows_neighbors()
        elif IS_MACOS:
            entries = _macos_neighbors(interface)
        else:
            entries = _linux_neighbors(interface)
    except Exception:
        entries = {}

    network = safe_network(subnet) if subnet else None
    clean: Dict[str, dict] = {}
    for ip_value, info in entries.items():
        if not is_valid_ipv4(ip_value):
            continue
        mac = parse_mac_loose(info.get("mac", ""))
        if not is_unicast_mac(mac):
            continue
        if network is not None:
            try:
                if ipaddress.IPv4Address(ip_value) not in network:
                    continue
            except ValueError:
                continue
        clean[ip_value] = {"mac": mac, "state": str(info.get("state", "REACHABLE")).upper()}
    return clean


# ============================================================================
# Ping y barrido controlado
# ============================================================================

def ping_host(ip_value: str, timeout: float = 1.0) -> bool:
    """
    Envía un único ICMP Echo no privilegiado con la sintaxis correcta en cada
    sistema operativo. Devuelve ``False`` si no hay respuesta o falta ``ping``.
    """
    if not is_valid_ipv4(ip_value):
        return False

    seconds = max(1, int(round(timeout)))
    milliseconds = max(200, int(timeout * 1000))

    if IS_WINDOWS:
        command = ["ping", "-n", "1", "-w", str(milliseconds), ip_value]
    elif IS_MACOS:
        # En macOS -W se expresa en milisegundos y -t en segundos.
        command = ["ping", "-c", "1", "-t", str(seconds), ip_value]
    else:
        command = ["ping", "-c", "1", "-W", str(seconds), ip_value]

    result = run_command(command, timeout=timeout + 2.0)
    return result is not None and result.returncode == 0


def iter_hosts(subnet: str, max_hosts: int = 512) -> List[str]:
    """Lista acotada de hosts utilizables de la subred (sin red ni broadcast)."""
    network = safe_network(subnet)
    if network is None:
        return []

    limit = max(1, min(int(max_hosts or 512), 4096))
    hosts: List[str] = []
    for host in network.hosts():
        hosts.append(str(host))
        if len(hosts) >= limit:
            break
    return hosts


def ping_sweep(
    subnet: str,
    max_hosts: int = 512,
    max_workers: int = 50,
    timeout: float = 1.0,
) -> dict:
    """
    Refresca la caché ARP del kernel con pings acotados **sólo** en redes
    locales (privadas, link-local o CGNAT).

    Devuelve un resumen con los hosts sondeados y los que respondieron.
    """
    network = safe_network(subnet)
    summary = {"subnet": subnet or "", "probed": 0, "responded": 0, "skipped": ""}

    if network is None:
        summary["skipped"] = "Subred no válida."
        return summary
    if not is_local_network(network):
        summary["skipped"] = "Subred no local: barrido activo deshabilitado por seguridad."
        return summary

    hosts = iter_hosts(subnet, max_hosts)
    if not hosts:
        summary["skipped"] = "La subred no contiene hosts utilizables."
        return summary

    workers = max(1, min(int(max_workers or 50), len(hosts)))
    responded = 0
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(ping_host, host, timeout) for host in hosts]
            for future in concurrent.futures.as_completed(futures, timeout=len(hosts) + 30):
                try:
                    if future.result(timeout=0):
                        responded += 1
                except Exception:
                    continue
    except Exception:
        pass

    summary["probed"] = len(hosts)
    summary["responded"] = responded
    return summary
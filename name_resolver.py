"""
Resolución de nombres de dispositivos para MangoRed.

Los nombres "visibles" de los equipos de una red local no siempre están en el
DNS. Este módulo los busca en cascada, sin privilegios especiales:

  1. **DNS inverso (PTR)**: la vía clásica, rápida y compatible con todo.
  2. **NetBIOS NBSTAT (UDP 137)**: obtiene el nombre de equipos Windows
     (``DESKTOP-XXXX``, ``LAPTOP-XXXX``) aunque no exista DNS.
  3. **mDNS (UDP 5353)**: consulta PTR inversa a ``in-addr.arpa`` en multicast,
     habitual en Apple (``MacBook-de-Luis.local``), impresoras e IoT.

Cada nombre devuelto incluye su **fuente** para que la interfaz pueda indicar de
dónde proviene. Todo el módulo es tolerante a fallos: sin respuesta, devuelve
diccionarios vacíos.
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import re
import socket
import struct
import time
from typing import Dict, Iterable, List, Tuple

MDNS_GROUP = ("224.0.0.251", 5353)
NETBIOS_PORT = 137
MAX_LOOKUPS = 64
MAX_NAME_LENGTH = 63

#: Servicios mDNS que revelan el tipo/modelo de dispositivo.
MDNS_SERVICE_TYPES = (
    "_device-info._tcp.local",       # Apple: TXT model=iPhone14,2 / MacBookPro18,3
    "_apple-mobdev2._tcp.local",     # iPhone/iPad con sincronización Wi-Fi
    "_airplay._tcp.local",           # AirPlay (Apple TV, HomePod, Mac, iPhone)
    "_raop._tcp.local",              # AirPlay de audio
    "_googlecast._tcp.local",        # Chromecast / Google TV
)

#: Etiquetas legibles de los servicios encontrados.
MDNS_SERVICE_LABELS = {
    "_device-info._tcp.local": "Apple Device Info",
    "_apple-mobdev2._tcp.local": "Apple Mobile Device (Wi-Fi Sync)",
    "_airplay._tcp.local": "AirPlay",
    "_raop._tcp.local": "AirPlay Audio",
    "_googlecast._tcp.local": "Google Cast",
}

#: Nombres que no identifican a ningún equipo.
GENERIC_NAMES = {
    "_gateway",
    "gateway",
    "localhost",
    "localhost.localdomain",
    "unknown",
    "none",
    "android",
    "dhcp",
    "router",
    "modem",
    "wlan",
    "lan",
}

_IP_LIKE = re.compile(r"^\d{1,3}([-.]\d{1,3}){3}$")
_HEX_ONLY = re.compile(r"^[0-9a-f]{12,}$")
_UUID_LIKE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)


def _is_valid_ipv4(value: object) -> bool:
    try:
        ipaddress.IPv4Address(str(value).strip())
        return True
    except (ValueError, TypeError):
        return False


def clean_name(raw: object, ip: str = "") -> str:
    """
    Normaliza y valida un nombre obtenido de la red.

    Descarta nombres genéricos, IPs, MACs y cadenas de relleno. Si el nombre es
    un FQDN, conserva la etiqueta principal (``host.lan`` → ``host``).
    """
    if raw is None:
        return ""
    text = str(raw).strip().strip("\"'. ")
    if not text:
        return ""

    text = text.splitlines()[0].strip()
    if not text:
        return ""

    lowered = text.lower().rstrip(".")

    # Consultas inversas y direcciones IP nunca son nombres de equipo.
    if lowered.endswith("in-addr.arpa") or lowered.endswith(".arpa"):
        return ""
    if _is_valid_ipv4(text):
        return ""
    if ":" in text and len(text) >= 11:  # aspecto de dirección MAC
        return ""

    # FQDN → etiqueta principal (pero conserva nombres con espacios internos)
    if "." in text:
        first_label = text.split(".", 1)[0].strip()
        if first_label:
            text = first_label
            lowered = text.lower()

    if lowered in GENERIC_NAMES:
        return ""
    if _IP_LIKE.match(text) or _HEX_ONLY.match(lowered) or _UUID_LIKE.match(text):
        return ""
    if ip and lowered == str(ip).lower():
        return ""
    if len(text) < 2 or len(text) > MAX_NAME_LENGTH:
        return ""
    if not re.search(r"[A-Za-z0-9]", text):
        return ""
    return text


# ============================================================================
# DNS inverso clásico
# ============================================================================

def _safe_reverse_dns(ip: str) -> str:
    """Resolver DNS inverso sin alterar la configuración global de sockets."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return str(hostname).strip()
    except (OSError, socket.herror, socket.gaierror, UnicodeError):
        return ""


def resolve_dns(ips: Iterable[str], timeout: float = 1.2, max_workers: int = 20) -> Dict[str, str]:
    """Resuelve nombres PTR en paralelo con un límite global de tiempo."""
    results: Dict[str, str] = {}
    candidates = [ip for ip in dict.fromkeys(ips) if _is_valid_ipv4(ip)]
    if not candidates:
        return results

    executor = concurrent.futures.ThreadPoolExecutor(
        max_workers=max(1, min(max_workers, len(candidates))),
        thread_name_prefix="MangoRedDNS",
    )
    try:
        futures = {executor.submit(_safe_reverse_dns, ip): ip for ip in candidates}
        deadline = max(1.5, timeout * 4)
        for future in concurrent.futures.as_completed(futures, timeout=deadline):
            ip = futures[future]
            try:
                results[ip] = future.result() or ""
            except Exception:
                results[ip] = ""
    except concurrent.futures.TimeoutError:
        pass
    except Exception:
        pass
    finally:
        for ip in candidates:
            results.setdefault(ip, "")
        executor.shutdown(wait=False, cancel_futures=True)
    return results


# ============================================================================
# Mensajes DNS (utilizados por NetBIOS y mDNS)
# ============================================================================

def _encode_dns_name(name: str) -> bytes:
    """Codifica un nombre DNS en formato de etiquetas de longitud prefijada."""
    output = bytearray()
    for label in str(name).rstrip(".").split("."):
        if not label:
            continue
        # Los nombres de equipo y las consultas inversas son ASCII; se descarta
        # cualquier carácter no representable en lugar de fallar.
        encoded = label.encode("ascii", "ignore")[:63]
        if not encoded:
            continue
        output.append(len(encoded))
        output.extend(encoded)
    output.append(0)
    return bytes(output)


def build_dns_query(name: str, qtype: int, txid: int = 0, unicast: bool = False) -> bytes:
    """
    Construye una consulta DNS.

    ``qtype`` 12 = PTR, 33 = SRV, 255 = ANY. ``unicast`` activa el bit QU de
    mDNS para pedir respuesta directa al socket consultante.
    """
    header = struct.pack("!HHHHHH", txid & 0xFFFF, 0, 1, 0, 0, 0)
    qclass = 0x8001 if unicast else 0x0001
    return header + _encode_dns_name(name) + struct.pack("!HH", qtype, qclass)


def parse_dns_name(data: bytes, offset: int, max_jumps: int = 16) -> Tuple[str, int]:
    """Lee un nombre DNS soportando compresión de punteros."""
    labels: List[str] = []
    cursor = offset
    jumps = 0
    end_offset = offset

    while True:
        if cursor >= len(data):
            raise ValueError("Nombre DNS truncado")
        length = data[cursor]
        if length == 0:
            cursor += 1
            if jumps == 0:
                end_offset = cursor
            break
        if (length & 0xC0) == 0xC0:
            if cursor + 1 >= len(data):
                raise ValueError("Puntero DNS truncado")
            pointer = ((length & 0x3F) << 8) | data[cursor + 1]
            if jumps == 0:
                end_offset = cursor + 2
            jumps += 1
            if jumps > max_jumps:
                raise ValueError("Bucle de compresión DNS")
            cursor = pointer
            continue
        start = cursor + 1
        end = start + length
        if end > len(data):
            raise ValueError("Etiqueta DNS truncada")
        labels.append(data[start:end].decode("utf-8", "ignore"))
        cursor = end

    return ".".join(labels), end_offset


def parse_dns_response(data: bytes) -> Tuple[List[Tuple[str, int]], List[Tuple[str, int, str]]]:
    """
    Analiza una respuesta DNS.

    Devuelve ``(preguntas, registros)`` donde cada registro es
    ``(nombre_propietario, tipo, valor)``. Sólo se decodifican los valores
    relevantes (PTR, A y TXT).
    """
    questions: List[Tuple[str, int]] = []
    records: List[Tuple[str, int, str]] = []

    if len(data) < 12:
        return questions, records

    try:
        _txid, _flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
    except struct.error:
        return questions, records

    offset = 12
    for _ in range(qdcount):
        try:
            name, offset = parse_dns_name(data, offset)
        except ValueError:
            return questions, records
        if offset + 4 > len(data):
            return questions, records
        qtype, _qclass = struct.unpack("!HH", data[offset:offset + 4])
        offset += 4
        questions.append((name, qtype))

    for _ in range(ancount + nscount + arcount):
        try:
            owner, offset = parse_dns_name(data, offset)
        except ValueError:
            break
        if offset + 10 > len(data):
            break
        rtype, _rclass, _ttl, rdlength = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10
        if offset + rdlength > len(data):
            break

        rdata_offset = offset
        rdata = data[offset:offset + rdlength]
        offset += rdlength

        value = ""
        if rtype == 12:  # PTR
            try:
                value, _ = parse_dns_name(data, rdata_offset)
            except ValueError:
                value = ""
        elif rtype == 1 and rdlength == 4:  # A
            value = socket.inet_ntoa(rdata)
        elif rtype == 16:  # TXT
            value = rdata[:120].decode("utf-8", "ignore").strip("\x00").strip()

        if value:
            records.append((owner, rtype, value))

    return questions, records


# ============================================================================
# NetBIOS NBSTAT (UDP 137)
# ============================================================================

def _encode_netbios_name(name: str = "*", pad: bytes = b"\x00") -> bytes:
    """Codifica un nombre NetBIOS de 16 bytes como 32 letras A-P."""
    raw = str(name).upper().encode("ascii", "ignore")[:16].ljust(16, pad)
    encoded = bytearray()
    for byte in raw:
        encoded.append(ord("A") + (byte >> 4))
        encoded.append(ord("A") + (byte & 0x0F))
    return bytes(encoded)


def build_nbstat_query(txid: int = 0) -> bytes:
    """Construye una consulta NBSTAT (wildcard ``*``) para un equipo concreto."""
    header = struct.pack("!HHHHHH", txid & 0xFFFF, 0, 1, 0, 0, 0)
    return header + b"\x20" + _encode_netbios_name("*") + b"\x00" + struct.pack("!HH", 0x0021, 0x0001)


def _parse_nbstat_rdata(rdata: bytes) -> str:
    """
    Extrae el nombre de equipo de los datos de un NBSTAT.

    Cada entrada ocupa 18 bytes: 15 de nombre + 1 de sufijo + 2 de flags.
    Se prefieren sufijos 0x00 (estación de trabajo), 0x20 (servidor) y 0x03.
    """
    if not rdata:
        return ""
    count = rdata[0]
    if not 1 <= count <= 32:
        return ""

    best_rank = 99
    best_name = ""
    for index in range(count):
        start = 1 + index * 18
        end = start + 18
        if end > len(rdata):
            break
        entry = rdata[start:end]
        raw_name = entry[:15].decode("ascii", "ignore").strip("\x00 \t\r\n")
        suffix = entry[15]
        flags = struct.unpack("!H", entry[16:18])[0]
        is_group = bool(flags & 0x0001)

        if not raw_name or is_group:
            continue
        rank = {0x00: 0, 0x20: 1, 0x03: 2}.get(suffix)
        if rank is None:
            continue
        if rank < best_rank:
            best_rank = rank
            best_name = raw_name
    return best_name


def parse_nbstat_response(data: bytes) -> str:
    """Analiza una respuesta NBSTAT y devuelve el nombre del equipo."""
    if len(data) < 12:
        return ""
    try:
        _txid, _flags, qdcount, ancount, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
    except struct.error:
        return ""

    offset = 12
    for _ in range(qdcount):
        try:
            _name, offset = parse_dns_name(data, offset)
        except ValueError:
            return ""
        offset += 4
        if offset > len(data):
            return ""

    for _ in range(ancount):
        try:
            _owner, offset = parse_dns_name(data, offset)
        except ValueError:
            return ""
        if offset + 10 > len(data):
            return ""
        rtype, _rclass, _ttl, rdlength = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10
        if offset + rdlength > len(data):
            return ""
        rdata = data[offset:offset + rdlength]
        offset += rdlength
        if rtype == 0x0021:
            return _parse_nbstat_rdata(rdata)
    return ""


def netbios_lookup(ips: Iterable[str], timeout: float = 1.2) -> Dict[str, str]:
    """
    Consulta NBSTAT a varios equipos usando un único socket UDP.

    Devuelve ``{ip: nombre}``. Es habitual que equipos que no son Windows no
    respondan: en ese caso simplemente no aparecen en el resultado.
    """
    results: Dict[str, str] = {}
    candidates = [ip for ip in dict.fromkeys(ips) if _is_valid_ipv4(ip)][:MAX_LOOKUPS]
    if not candidates:
        return results

    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(0.15)

        txid_map: Dict[int, str] = {}
        base = int(time.time() * 1000) & 0xFFFF
        for index, ip in enumerate(candidates):
            txid = (base + index) & 0xFFFF
            try:
                sock.sendto(build_nbstat_query(txid), (ip, NETBIOS_PORT))
            except OSError:
                continue
            txid_map[txid] = ip

        deadline = time.monotonic() + max(0.4, float(timeout))
        while time.monotonic() < deadline and len(results) < len(candidates):
            try:
                data, address = sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                break
            if len(data) < 2:
                continue
            txid = struct.unpack("!H", data[:2])[0]
            ip = txid_map.get(txid) or address[0]
            if ip in results:
                continue
            name = parse_nbstat_response(data)
            if name:
                results[ip] = name
    except (OSError, ValueError):
        pass
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    return results


# ============================================================================
# mDNS (UDP 5353) - PTR inversa
# ============================================================================

def reverse_query_name(ip: str) -> str:
    """Construye el nombre de consulta inversa ``x.x.x.x.in-addr.arpa``."""
    return ".".join(reversed(str(ip).split("."))) + ".in-addr.arpa"


def ip_from_reverse_name(name: str) -> str:
    """Extrae la IP de un nombre inverso ``in-addr.arpa`` (o cadena vacía)."""
    text = (name or "").strip().lower().rstrip(".")
    suffix = ".in-addr.arpa"
    if not text.endswith(suffix):
        return ""
    parts = text[:-len(suffix)].split(".")
    if len(parts) != 4:
        return ""
    candidate = ".".join(reversed(parts))
    return candidate if _is_valid_ipv4(candidate) else ""


def mdns_reverse_lookup(ips: Iterable[str], timeout: float = 1.5) -> Dict[str, str]:
    """
    Consulta mDNS la PTR inversa de cada IP y devuelve ``{ip: nombre}``.

    Usa el bit QU (unicast response) para recibir la respuesta en el mismo
    socket, sin necesidad de unirse al grupo multicast ni privilegios extra.
    """
    results: Dict[str, str] = {}
    candidates = [ip for ip in dict.fromkeys(ips) if _is_valid_ipv4(ip)][:MAX_LOOKUPS]
    if not candidates:
        return results

    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        except OSError:
            pass
        sock.settimeout(0.2)

        pending: Dict[str, str] = {}
        base = int(time.time() * 1000) & 0xFFFF
        for index, ip in enumerate(candidates):
            query_name = reverse_query_name(ip)
            packet = build_dns_query(query_name, 12, (base + index) & 0xFFFF, unicast=True)
            try:
                sock.sendto(packet, MDNS_GROUP)
            except OSError:
                continue
            pending[query_name.lower()] = ip

        targets = set(pending.values())
        deadline = time.monotonic() + max(0.5, float(timeout))
        while time.monotonic() < deadline and len(results) < len(candidates):
            try:
                data, _address = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break

            _questions, records = parse_dns_response(data)
            for owner, rtype, value in records:
                if rtype == 12:  # PTR: nombre inverso → nombre .local
                    ip = pending.get(owner.lower().rstrip(".")) or ip_from_reverse_name(owner)
                    if ip and ip in targets and ip not in results:
                        results[ip] = value
                elif rtype == 1 and _is_valid_ipv4(value):  # A: nombre .local → IP
                    if value in targets and value not in results:
                        results[value] = owner
    except (OSError, ValueError):
        pass
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    return results


# ============================================================================
# mDNS: descubrimiento de servicios y modelo del dispositivo
# ============================================================================

def parse_txt_record(rdata: bytes) -> Dict[str, str]:
    """Convierte los pares ``clave=valor`` de un registro TXT en un diccionario."""
    items: Dict[str, str] = {}
    index = 0
    while index < len(rdata):
        length = rdata[index]
        index += 1
        if length == 0:
            continue
        chunk = rdata[index:index + length]
        index += length
        text = chunk.decode("utf-8", "ignore").strip()
        if not text:
            continue
        if "=" in text:
            key, value = text.split("=", 1)
            items[key.strip().lower()] = value.strip()
        else:
            items[text.lower()] = ""
    return items


def parse_mdns_services(data: bytes) -> Dict[str, object]:
    """
    Extrae PTR, SRV, TXT y A de una respuesta mDNS de descubrimiento.

    Devuelve ``{"ptr": [(servicio, instancia)], "srv": {instancia: (host, puerto)},
    "txt": {instancia: {clave: valor}}, "a": {host: ip}}``.
    """
    result: Dict[str, object] = {"ptr": [], "srv": {}, "txt": {}, "a": {}}
    if len(data) < 12:
        return result

    try:
        _txid, _flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
    except struct.error:
        return result

    offset = 12
    for _ in range(qdcount):
        try:
            _name, offset = parse_dns_name(data, offset)
        except ValueError:
            return result
        offset += 4
        if offset > len(data):
            return result

    for _ in range(ancount + nscount + arcount):
        try:
            owner, offset = parse_dns_name(data, offset)
        except ValueError:
            break
        if offset + 10 > len(data):
            break
        rtype, _rclass, _ttl, rdlength = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10
        if offset + rdlength > len(data):
            break

        rdata_offset = offset
        rdata = data[offset:offset + rdlength]
        offset += rdlength

        owner_key = owner.lower().rstrip(".")
        if rtype == 12:  # PTR: servicio → instancia
            try:
                instance, _ = parse_dns_name(data, rdata_offset)
            except ValueError:
                continue
            result["ptr"].append((owner_key, instance.rstrip(".")))
        elif rtype == 33 and rdlength >= 6:  # SRV: instancia → host + puerto
            try:
                _priority, _weight, port = struct.unpack("!HHH", rdata[:6])
                target, _ = parse_dns_name(data, rdata_offset + 6)
            except (ValueError, struct.error):
                continue
            result["srv"][owner_key] = (target.rstrip("."), port)
        elif rtype == 16:  # TXT: atributos (model=, md=, am=…)
            result["txt"][owner_key] = parse_txt_record(rdata)
        elif rtype == 1 and rdlength == 4:  # A: host → IP
            result["a"][owner_key] = socket.inet_ntoa(rdata)

    return result


def join_service_records(
    batches: Iterable[Dict[str, object]],
    targets: Iterable[str],
) -> Dict[str, dict]:
    """
    Combina los registros mDNS recibidos y los asocia a direcciones IP.

    Devuelve ``{ip: {"name", "model", "services"}}`` para las IP de ``targets``.
    """
    target_set = {ip for ip in targets if _is_valid_ipv4(ip)}
    if not target_set:
        return {}

    instances: Dict[str, dict] = {}
    hosts: Dict[str, str] = {}

    def instance_entry(name: str) -> dict:
        return instances.setdefault(name, {"service": "", "host": "", "txt": {}})

    for batch in batches:
        for service, instance in batch.get("ptr", []) or []:
            # La instancia puede llegar con distinta capitalización que el
            # propietario del registro SRV/TXT: se normaliza para unirlos.
            entry = instance_entry(str(instance).lower().rstrip("."))
            if not entry["service"]:
                entry["service"] = str(service)
        for instance, srv in (batch.get("srv", {}) or {}).items():
            entry = instance_entry(str(instance).lower().rstrip("."))
            host, _port = srv
            entry["host"] = str(host)
        for instance, txt in (batch.get("txt", {}) or {}).items():
            instance_entry(str(instance).lower().rstrip("."))["txt"].update(txt or {})
        for host, ip in (batch.get("a", {}) or {}).items():
            hosts[str(host).lower().rstrip(".")] = str(ip)

    grouped: Dict[str, dict] = {}
    for instance, info in instances.items():
        host = str(info["host"]).lower().rstrip(".")
        ip = hosts.get(host) or hosts.get(instance.lower().rstrip("."))
        if not ip or ip not in target_set:
            continue

        entry = grouped.setdefault(
            ip, {"names": [], "models": [], "services": [], "friendly": False}
        )
        service = str(info["service"])
        if service and service not in entry["services"]:
            entry["services"].append(service)

        txt = info["txt"] or {}
        # Apple publica «model=iPhone14,2»; Google Cast publica «md=Chromecast».
        model = str(txt.get("model") or txt.get("md") or "").strip()
        if model and model not in entry["models"]:
            entry["models"].append(model)

        # Nombre: el «fn» de Google Cast es el nombre amigable configurado
        # (p. ej. "TV Salón"); el resto de servicios usan el host .local.
        friendly = clean_name(str(txt.get("fn") or ""), ip)
        if friendly:
            if friendly not in entry["names"]:
                entry["names"].insert(0, friendly)
            entry["friendly"] = True

        label = host.split(".")[0] if host else instance.split("@")[0]
        cleaned = clean_name(label, ip)
        if cleaned and cleaned not in entry["names"]:
            entry["names"].append(cleaned)

    results: Dict[str, dict] = {}
    for ip, entry in grouped.items():
        friendly = bool(entry.get("friendly"))
        results[ip] = {
            "name": entry["names"][0] if entry["names"] else "",
            "model": entry["models"][0] if entry["models"] else "",
            "friendly": friendly,
            "services": [
                MDNS_SERVICE_LABELS.get(service, service) for service in entry["services"]
            ],
        }
    return results


def mdns_service_lookup(
    ips: Iterable[str],
    timeout: float = 1.2,
    services: Tuple[str, ...] = MDNS_SERVICE_TYPES,
) -> Dict[str, dict]:
    """
    Descubre servicios mDNS (y el modelo Apple) de las IP indicadas.

    Es la vía más fiable para reconocer iPhone/iPad: ``_device-info`` publica
    ``model=iPhone14,2`` en su TXT, que sobrevive incluso a la MAC aleatoria.
    """
    results: Dict[str, dict] = {}
    candidates = [ip for ip in dict.fromkeys(ips) if _is_valid_ipv4(ip)][:MAX_LOOKUPS]
    if not candidates:
        return results

    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        except OSError:
            pass
        sock.settimeout(0.2)

        base = int(time.time() * 1000) & 0xFFFF
        for index, service in enumerate(services):
            packet = build_dns_query(service, 12, (base + index) & 0xFFFF, unicast=True)
            try:
                sock.sendto(packet, MDNS_GROUP)
            except OSError:
                continue

        batches: List[Dict[str, object]] = []
        deadline = time.monotonic() + max(0.6, float(timeout))
        while time.monotonic() < deadline:
            try:
                data, _address = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            batches.append(parse_mdns_services(data))

        results = join_service_records(batches, candidates)
    except (OSError, ValueError):
        pass
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    return results


# ============================================================================
# API pública
# ============================================================================

def resolve_names(
    ips: Iterable[str],
    timeout: float = 1.2,
    enable_netbios: bool = True,
    enable_mdns: bool = True,
) -> Dict[str, dict]:
    """
    Resuelve nombres en cascada y devuelve ``{ip: {"name", "source"[, "model",
    "services"]}}``.

    La prioridad es DNS inverso → NetBIOS → mDNS, de modo que nunca se
    sobrescribe un nombre más fiable con uno menos fiable. El descubrimiento de
    servicios mDNS añade el **modelo** (``iPhone14,2``) cuando el dispositivo lo
    publica, lo que permite identificar iOS/iPadOS aunque la MAC sea aleatoria.
    """
    candidates = [ip for ip in dict.fromkeys(ips) if _is_valid_ipv4(ip)][:MAX_LOOKUPS]
    results: Dict[str, dict] = {}
    if not candidates:
        return results

    for ip, name in resolve_dns(candidates, timeout=timeout).items():
        cleaned = clean_name(name, ip)
        if cleaned:
            results[ip] = {"name": cleaned, "source": "dns"}

    pending = [ip for ip in candidates if ip not in results]
    if pending and (enable_netbios or enable_mdns):
        netbios_names: Dict[str, str] = {}
        mdns_names: Dict[str, str] = {}
        service_info: Dict[str, dict] = {}
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                future_netbios = (
                    executor.submit(netbios_lookup, pending, min(timeout, 1.2))
                    if enable_netbios else None
                )
                future_mdns = (
                    executor.submit(mdns_reverse_lookup, pending, min(max(timeout, 0.8), 1.5))
                    if enable_mdns else None
                )
                if future_netbios is not None:
                    try:
                        netbios_names = future_netbios.result() or {}
                    except Exception:
                        netbios_names = {}
                if future_mdns is not None:
                    try:
                        mdns_names = future_mdns.result() or {}
                    except Exception:
                        mdns_names = {}
        except Exception:
            netbios_names = {}
            mdns_names = {}

        for source, mapping in (("netbios", netbios_names), ("mdns", mdns_names)):
            for ip, name in mapping.items():
                if ip in results:
                    continue
                cleaned = clean_name(name, ip)
                if cleaned:
                    results[ip] = {"name": cleaned, "source": source}

        # Servicios y modelo (Apple) para todos los equipos
        if enable_mdns:
            try:
                service_info = mdns_service_lookup(
                    candidates, timeout=min(max(timeout, 0.8), 1.6)
                )
            except Exception:
                service_info = {}

            for ip, info in service_info.items():
                entry = results.setdefault(ip, {"name": "", "source": "mdns"})
                if not entry.get("name") or info.get("friendly"):
                    cleaned = clean_name(info.get("name", ""), ip)
                    if cleaned:
                        entry["name"] = cleaned
                        entry["source"] = "mdns"
                if info.get("model"):
                    entry["model"] = info["model"]
                if info.get("services"):
                    entry["services"] = info["services"]

    return results


def resolve_hostname(ip: str, timeout: float = 1.2) -> str:
    """Compatibilidad: devuelve sólo el nombre de una IP (o cadena vacía)."""
    info = resolve_names([ip], timeout=timeout)
    return info.get(ip, {}).get("name", "")
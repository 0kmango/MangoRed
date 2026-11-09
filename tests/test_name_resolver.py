"""
Pruebas de la resolución de nombres (name_resolver.py).

Se validan la limpieza de nombres, la construcción/parseo de mensajes DNS y
NetBIOS NBSTAT, y la prioridad de la cascada DNS → NetBIOS → mDNS.
"""

import socket
import struct

import name_resolver as nr


# ============================================================================
# Limpieza y validación de nombres
# ============================================================================

def test_clean_name_accepts_real_hostnames():
    assert nr.clean_name("MacBook-de-Luis.local") == "MacBook-de-Luis"
    assert nr.clean_name("DESKTOP-4F2K9L") == "DESKTOP-4F2K9L"
    assert nr.clean_name("  iPhone.de.Luis  ") == "iPhone"
    assert nr.clean_name("impresora-salon.lan") == "impresora-salon"


def test_clean_name_rejects_generic_or_meaningless_values():
    assert nr.clean_name("_gateway") == ""
    assert nr.clean_name("localhost") == ""
    assert nr.clean_name("192-168-1-15") == ""
    assert nr.clean_name("001122334455") == ""
    assert nr.clean_name("192.168.1.15", "192.168.1.15") == ""
    assert nr.clean_name("") == ""
    assert nr.clean_name(None) == ""
    assert nr.clean_name("x") == ""
    assert nr.clean_name("host.in-addr.arpa") == ""


def test_reverse_query_name_and_back():
    assert nr.reverse_query_name("192.168.1.15") == "15.1.168.192.in-addr.arpa"
    assert nr.ip_from_reverse_name("15.1.168.192.in-addr.arpa") == "192.168.1.15"
    assert nr.ip_from_reverse_name("15.1.168.in-addr.arpa") == ""
    assert nr.ip_from_reverse_name("ejemplo.local") == ""


# ============================================================================
# Mensajes DNS
# ============================================================================

def test_encode_and_parse_dns_name_roundtrip():
    encoded = nr._encode_dns_name("impresora.local")
    name, offset = nr.parse_dns_name(encoded, 0)
    assert name == "impresora.local"
    assert offset == len(encoded)


def test_parse_dns_name_supports_compression():
    # Offset 0: etiqueta "macbook" + puntero a offset 10, donde vive "local".
    first = nr._encode_dns_name("macbook")[:-1]      # sin el 0 final
    second = nr._encode_dns_name("local")
    pointer_offset = len(first) + 2
    packet = first + b"\xc0" + bytes([pointer_offset]) + second

    name, end_offset = nr.parse_dns_name(packet, 0)
    assert name == "macbook.local"
    assert end_offset == len(first) + 2


def build_ptr_response(ip: str, target: str, txid: int = 0) -> bytes:
    """Construye una respuesta DNS con un registro PTR (para pruebas)."""
    question_name = nr.reverse_query_name(ip)
    question = nr._encode_dns_name(question_name) + struct.pack("!HH", 12, 0x0001)
    header = struct.pack("!HHHHHH", txid, 0x8400, 1, 1, 0, 0)
    rdata = nr._encode_dns_name(target)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 12, 0x0001, 120, len(rdata)) + rdata
    return header + question + answer


def test_parse_dns_response_extracts_ptr():
    packet = build_ptr_response("192.168.1.15", "MacBook-de-Luis.local")
    questions, records = nr.parse_dns_response(packet)

    assert questions[0][0] == "15.1.168.192.in-addr.arpa"
    assert questions[0][1] == 12
    assert records == [("15.1.168.192.in-addr.arpa", 12, "MacBook-de-Luis.local")]


def test_parse_dns_response_tolerates_truncated_data():
    assert nr.parse_dns_response(b"") == ([], [])
    assert nr.parse_dns_response(b"\x00\x01") == ([], [])
    assert nr.parse_dns_response(b"\x00" * 12) == ([], [])


# ============================================================================
# NetBIOS NBSTAT
# ============================================================================

def build_nbstat_response(hostname: str, txid: int = 0x1234) -> bytes:
    """Construye una respuesta NBSTAT con un nombre de equipo único."""
    question = (
        b"\x20" + nr._encode_netbios_name("*") + b"\x00" + struct.pack("!HH", 0x0021, 0x0001)
    )
    header = struct.pack("!HHHHHH", txid, 0x8400, 1, 1, 0, 0)
    entry = hostname.encode("ascii")[:15].ljust(15, b"\x00") + b"\x00" + struct.pack("!H", 0x0000)
    rdata = bytes([1]) + entry
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 0x0021, 0x0001, 0, len(rdata)) + rdata
    return header + question + answer


def test_build_nbstat_query_structure():
    packet = nr.build_nbstat_query(0xBEEF)
    assert struct.unpack("!H", packet[:2])[0] == 0xBEEF
    assert packet[12] == 0x20
    assert packet[13:15] == b"CK"  # codificación de '*'
    assert packet.endswith(struct.pack("!HH", 0x0021, 0x0001))


def test_parse_nbstat_response_returns_hostname():
    packet = build_nbstat_response("DESKTOP-4F2K9L")
    assert nr.parse_nbstat_response(packet) == "DESKTOP-4F2K9L"


def test_parse_nbstat_response_ignores_group_names():
    """Los nombres de grupo (bit G activo) se descartan."""
    question = (
        b"\x20" + nr._encode_netbios_name("*") + b"\x00" + struct.pack("!HH", 0x0021, 0x0001)
    )
    header = struct.pack("!HHHHHH", 1, 0x8400, 1, 1, 0, 0)
    group = b"WORKGROUP".ljust(15, b"\x00") + b"\x1e" + struct.pack("!H", 0x0001)
    machine = b"MIPC".ljust(15, b"\x00") + b"\x00" + struct.pack("!H", 0x0000)
    rdata = bytes([2]) + group + machine
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 0x0021, 0x0001, 0, len(rdata)) + rdata
    assert nr.parse_nbstat_response(header + question + answer) == "MIPC"


def test_parse_nbstat_response_with_invalid_data():
    assert nr.parse_nbstat_response(b"") == ""
    assert nr.parse_nbstat_response(b"\x00" * 11) == ""
    assert nr.parse_nbstat_response(b"\x00" * 12) == ""


# ============================================================================
# Cascada de resolución y tolerancia a fallos
# ============================================================================

def test_resolve_names_prioritizes_dns_then_netbios_then_mdns(monkeypatch):
    """DNS gana a NetBIOS, y NetBIOS gana a mDNS para la misma IP."""
    monkeypatch.setattr(nr, "resolve_dns", lambda ips, timeout=1.2: {"192.168.1.10": "equipo-dns.local"})
    monkeypatch.setattr(nr, "mdns_service_lookup", lambda *args, **kwargs: {})
    monkeypatch.setattr(nr, "netbios_lookup", lambda ips, timeout=1.2: {
        "192.168.1.10": "EQUIPO-NB",
        "192.168.1.11": "DESKTOP-NB",
    })
    monkeypatch.setattr(nr, "mdns_reverse_lookup", lambda ips, timeout=1.5: {
        "192.168.1.10": "equipo-mdns.local",
        "192.168.1.11": "equipo-mdns.local",
        "192.168.1.12": "impresora.local",
    })

    result = nr.resolve_names(["192.168.1.10", "192.168.1.11", "192.168.1.12"])

    assert result["192.168.1.10"] == {"name": "equipo-dns", "source": "dns"}
    assert result["192.168.1.11"] == {"name": "DESKTOP-NB", "source": "netbios"}
    assert result["192.168.1.12"] == {"name": "impresora", "source": "mdns"}


def test_resolve_names_can_disable_protocols(monkeypatch):
    monkeypatch.setattr(nr, "resolve_dns", lambda ips, timeout=1.2: {})
    called = {"netbios": False, "mdns": False}
    monkeypatch.setattr(nr, "netbios_lookup", lambda ips, timeout=1.2: called.__setitem__("netbios", True) or {})
    monkeypatch.setattr(nr, "mdns_reverse_lookup", lambda ips, timeout=1.5: called.__setitem__("mdns", True) or {})

    nr.resolve_names(["192.168.1.10"], enable_netbios=False, enable_mdns=False)
    assert called == {"netbios": False, "mdns": False}


def test_resolve_names_ignores_invalid_ips_and_empty_results():
    assert nr.resolve_names([]) == {}
    assert nr.resolve_names(["no-es-ip", "", None, "999.999.999.999"]) == {}


def test_lookup_helpers_return_empty_without_targets():
    assert nr.netbios_lookup([]) == {}
    assert nr.mdns_reverse_lookup([]) == {}
    assert nr.netbios_lookup(["no-es-ip"]) == {}
    assert nr.mdns_reverse_lookup(["no-es-ip"]) == {}


def test_resolve_hostname_compatibility(monkeypatch):
    monkeypatch.setattr(nr, "resolve_dns", lambda ips, timeout=1.2: {"10.0.0.5": "mi-pc.lan"})
    monkeypatch.setattr(nr, "netbios_lookup", lambda ips, timeout=1.2: {})
    monkeypatch.setattr(nr, "mdns_reverse_lookup", lambda ips, timeout=1.5: {})
    monkeypatch.setattr(nr, "mdns_service_lookup", lambda *args, **kwargs: {})
    assert nr.resolve_hostname("10.0.0.5") == "mi-pc"
    assert nr.resolve_hostname("no-es-ip") == ""


# ============================================================================
# Descubrimiento de servicios mDNS y modelo Apple (iOS/iPadOS)
# ============================================================================

def build_mdns_service_response(instance, host, ip, model=None, service="_device-info._tcp.local",
                                txt=None):
    """Respuesta mDNS con PTR + SRV + TXT + A, como la de un iPhone o un Chromecast."""
    question = nr._encode_dns_name(service) + struct.pack("!HH", 12, 0x0001)
    header = struct.pack("!HHHHHH", 0, 0x8400, 1, 3, 0, 1)

    instance_name = f"{instance}.{service}"
    instance_enc = nr._encode_dns_name(instance_name)
    host_enc = nr._encode_dns_name(host)

    pairs = dict(txt or {})
    if model:
        pairs["model"] = model
    chunks = b""
    for key, value in pairs.items():
        item = f"{key}={value}".encode("ascii")
        chunks += bytes([len(item)]) + item

    ptr = b"\xc0\x0c" + struct.pack("!HHIH", 12, 1, 4500, len(instance_enc)) + instance_enc
    srv_rdata = struct.pack("!HHH", 0, 0, 5000) + host_enc
    srv = instance_enc + struct.pack("!HHIH", 33, 1, 120, len(srv_rdata)) + srv_rdata
    txt_record = instance_enc + struct.pack("!HHIH", 16, 1, 4500, len(chunks)) + chunks
    additional = host_enc + struct.pack("!HHIH", 1, 1, 120, 4) + socket.inet_aton(ip)
    return header + question + ptr + srv + txt_record + additional


def test_parse_txt_record():
    value = b"model=iPhone14,2"
    assert nr.parse_txt_record(bytes([len(value)]) + value) == {"model": "iPhone14,2"}

    rdata = bytes([5]) + b"model" + bytes([3]) + b"abc"   # claves sin '='
    assert nr.parse_txt_record(rdata) == {"model": "", "abc": ""}


def test_parse_mdns_services_extracts_apple_model():
    packet = build_mdns_service_response(
        "Luis-iPhone", "luis-iphone.local", "192.168.1.40", "iPhone14,2"
    )
    parsed = nr.parse_mdns_services(packet)

    assert ("_device-info._tcp.local", "Luis-iPhone._device-info._tcp.local") in parsed["ptr"]
    assert parsed["srv"]["luis-iphone._device-info._tcp.local"] == ("luis-iphone.local", 5000)
    assert parsed["txt"]["luis-iphone._device-info._tcp.local"]["model"] == "iPhone14,2"
    assert parsed["a"]["luis-iphone.local"] == "192.168.1.40"


def test_join_service_records_maps_ip_to_model():
    packet = build_mdns_service_response(
        "Luis-iPhone", "luis-iphone.local", "192.168.1.40", "iPhone14,2"
    )
    joined = nr.join_service_records([nr.parse_mdns_services(packet)], ["192.168.1.40"])

    assert joined["192.168.1.40"]["name"] == "luis-iphone"
    assert joined["192.168.1.40"]["model"] == "iPhone14,2"
    assert joined["192.168.1.40"]["services"] == ["Apple Device Info"]


def test_clean_name_rejects_uuids():
    """Google Cast usa UUIDs como instancia: no son un nombre útil."""
    assert nr.clean_name("b2b90f8a-3fac-e99b-d16e-c5a2863bb9f6") == ""


def test_join_service_records_ignores_other_networks():
    packet = build_mdns_service_response(
        "Otro-iPad", "otro-ipad.local", "10.9.9.9", "iPad13,4"
    )
    assert nr.join_service_records([nr.parse_mdns_services(packet)], ["192.168.1.40"]) == {}


def test_join_service_records_prefers_friendly_name():
    """El TXT fn= de Google Cast es el nombre amigable configurado por el usuario."""
    packet = build_mdns_service_response(
        "b2b90f8a-3fac-e99b-d16e-c5a2863bb9f6",
        "b2b90f8a-3fac-e99b-d16e-c5a2863bb9f6.local",
        "192.168.1.7",
        txt={"fn": "TV Salon", "md": "Chromecast"},
        service="_googlecast._tcp.local",
    )
    joined = nr.join_service_records([nr.parse_mdns_services(packet)], ["192.168.1.7"])

    assert joined["192.168.1.7"]["name"] == "TV Salon"
    assert joined["192.168.1.7"]["model"] == "Chromecast"
    assert joined["192.168.1.7"]["services"] == ["Google Cast"]
    assert joined["192.168.1.7"]["friendly"] is True


def test_join_service_records_ignores_uuid_as_name():
    """Sin nombre amigable, un UUID no se propaga como nombre del equipo."""
    packet = build_mdns_service_response(
        "b2b90f8a-3fac-e99b-d16e-c5a2863bb9f6",
        "b2b90f8a-3fac-e99b-d16e-c5a2863bb9f6.local",
        "192.168.1.7",
        txt={"md": "Chromecast"},
        service="_googlecast._tcp.local",
    )
    joined = nr.join_service_records([nr.parse_mdns_services(packet)], ["192.168.1.7"])
    assert joined["192.168.1.7"]["name"] == ""
    assert joined["192.168.1.7"]["model"] == "Chromecast"


def test_parse_mdns_services_with_invalid_data():
    assert nr.parse_mdns_services(b"") == {"ptr": [], "srv": {}, "txt": {}, "a": {}}
    assert nr.parse_mdns_services(b"\x00" * 11) == {"ptr": [], "srv": {}, "txt": {}, "a": {}}


def test_resolve_names_merges_mdns_model(monkeypatch):
    """El modelo mDNS se adjunta al resultado aunque el nombre venga de otra vía."""
    monkeypatch.setattr(nr, "resolve_dns", lambda ips, timeout=1.2: {})
    monkeypatch.setattr(nr, "netbios_lookup", lambda ips, timeout=1.2: {})
    monkeypatch.setattr(nr, "mdns_reverse_lookup", lambda ips, timeout=1.5: {
        "192.168.1.40": "luis-iphone.local"
    })
    monkeypatch.setattr(nr, "mdns_service_lookup", lambda *args, **kwargs: {
        "192.168.1.40": {
            "name": "luis-iphone",
            "model": "iPhone14,2",
            "services": ["Apple Device Info"],
        }
    })

    result = nr.resolve_names(["192.168.1.40"])
    assert result["192.168.1.40"]["name"] == "luis-iphone"
    assert result["192.168.1.40"]["source"] == "mdns"
    assert result["192.168.1.40"]["model"] == "iPhone14,2"
    assert result["192.168.1.40"]["services"] == ["Apple Device Info"]


def test_resolve_names_prefers_friendly_name_over_reverse_dns(monkeypatch):
    """El nombre amigable de Google Cast ("My TV") gana al hostname android-2."""
    monkeypatch.setattr(nr, "resolve_dns", lambda ips, timeout=1.2: {})
    monkeypatch.setattr(nr, "netbios_lookup", lambda ips, timeout=1.2: {})
    monkeypatch.setattr(nr, "mdns_reverse_lookup", lambda ips, timeout=1.5: {
        "192.168.1.7": "android-2.local"
    })
    monkeypatch.setattr(nr, "mdns_service_lookup", lambda *args, **kwargs: {
        "192.168.1.7": {
            "name": "My TV",
            "model": "FUSE 4K",
            "services": ["Google Cast"],
            "friendly": True,
        }
    })

    result = nr.resolve_names(["192.168.1.7"])
    assert result["192.168.1.7"]["name"] == "My TV"
    assert result["192.168.1.7"]["source"] == "mdns"
    assert result["192.168.1.7"]["model"] == "FUSE 4K"
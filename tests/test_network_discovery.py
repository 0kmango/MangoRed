"""
Pruebas del descubrimiento de red multiplataforma (network_discovery.py).

Se validan los analizadores de salidas reales de ``ip neigh``, ``arp -a``
(Windows, Linux y macOS), ``ipconfig`` y ``route print``, junto con las
salvaguardas que impiden el barrido de redes públicas.
"""

import ipaddress

import network_discovery as nd


# ============================================================================
# Normalización de MAC
# ============================================================================

def test_parse_mac_loose_supports_all_separators():
    """Se aceptan formatos Linux (dos dígitos) y macOS/Windows (uno o dos)."""
    assert nd.parse_mac_loose("00:11:22:33:44:55") == "00:11:22:33:44:55"
    assert nd.parse_mac_loose("00-11-22-33-44-55") == "00:11:22:33:44:55"
    assert nd.parse_mac_loose("0:11:22:33:44:55") == "00:11:22:33:44:55"   # macOS
    assert nd.parse_mac_loose("001122334455") == "00:11:22:33:44:55"
    assert nd.parse_mac_loose("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"
    assert nd.parse_mac_loose("(incomplete)") == ""
    assert nd.parse_mac_loose(None) == ""
    assert nd.parse_mac_loose("no-es-mac") == ""


def test_is_unicast_mac_filters_broadcast_and_multicast():
    assert nd.is_unicast_mac("00:11:22:33:44:55") is True
    assert nd.is_unicast_mac("ff:ff:ff:ff:ff:ff") is False
    assert nd.is_unicast_mac("00:00:00:00:00:00") is False
    assert nd.is_unicast_mac("01:00:5e:00:00:01") is False  # multicast IPv4
    assert nd.is_unicast_mac("") is False


# ============================================================================
# Cálculos de red
# ============================================================================

def test_mask_to_prefix():
    assert nd.mask_to_prefix("255.255.255.0") == 24
    assert nd.mask_to_prefix("255.255.0.0") == 16
    assert nd.mask_to_prefix("255.255.255.252") == 30
    assert nd.mask_to_prefix("no-es-mascara") == 0
    assert nd.mask_to_prefix("") == 0


def test_safe_network():
    assert str(nd.safe_network("192.168.1.42/24")) == "192.168.1.0/24"
    assert nd.safe_network("no-es-cidr") is None
    assert nd.safe_network("2001:db8::/32") is None  # sólo IPv4


def test_is_local_network_allows_only_local_ranges():
    """Los rangos públicos no deben considerarse locales (evita escaneos indebidos)."""
    assert nd.is_local_network(ipaddress.IPv4Network("192.168.1.0/24")) is True
    assert nd.is_local_network(ipaddress.IPv4Network("10.0.0.0/8")) is True
    assert nd.is_local_network(ipaddress.IPv4Network("172.16.0.0/12")) is True
    assert nd.is_local_network(ipaddress.IPv4Network("100.64.0.0/10")) is True  # CGNAT
    assert nd.is_local_network(ipaddress.IPv4Network("8.8.8.0/24")) is False
    assert nd.is_local_network(ipaddress.IPv4Network("1.1.1.0/24")) is False
    assert nd.is_local_network(None) is False


def test_iter_hosts_respects_limit():
    hosts = nd.iter_hosts("192.168.1.0/24", max_hosts=10)
    assert len(hosts) == 10
    assert hosts[0] == "192.168.1.1"
    assert nd.iter_hosts("no-valido") == []


def test_ping_sweep_skips_non_local_subnet():
    """El barrido activo se desactiva en rangos públicos por seguridad."""
    summary = nd.ping_sweep("8.8.8.0/24", max_hosts=4)
    assert summary["probed"] == 0
    assert summary["responded"] == 0
    assert summary["skipped"] != ""


def test_ping_host_rejects_invalid_addresses():
    assert nd.ping_host("no-es-ip") is False
    assert nd.ping_host("999.999.999.999") is False
    assert nd.ping_host("") is False


# ============================================================================
# Analizadores de la tabla de vecinos
# ============================================================================

LINUX_ARP = """
? (192.168.1.1) at 00:11:22:33:44:55 [ether] on wlan0
? (192.168.1.20) at b8:27:eb:11:22:33 [ether] on wlan0
? (192.168.1.99) at <incomplete> on wlan0
"""

MACOS_ARP = """
? (192.168.1.1) at 0:11:22:33:44:55 on en0 ifscope [ethernet]
? (192.168.1.30) at a4:83:e7:1:2:3 on en0 ifscope [ethernet]
? (192.168.1.77) at (incomplete) on en0 ifscope [ethernet]
"""

WINDOWS_ARP = """
Interfaz: 192.168.1.50 --- 0x9
  Direccion de Internet          Direccion fisica      Tipo
  192.168.1.1           00-11-22-33-44-55     dinamico
  192.168.1.25          f8-9a-25-b8-55-14     dinamico
  192.168.1.255         ff-ff-ff-ff-ff-ff     estatico
  224.0.0.22            01-00-5e-00-00-16     estatico
"""

IP_NEIGH = """
192.168.1.1 dev wlan0 lladdr 00:11:22:33:44:55 REACHABLE
192.168.1.40 dev wlan0 lladdr 3c:06:30:aa:bb:cc STALE
192.168.1.80 dev wlan0  FAILED
"""


def test_parse_arp_text_linux_format():
    entries = nd._parse_arp_text(LINUX_ARP)
    assert entries["192.168.1.1"]["mac"] == "00:11:22:33:44:55"
    assert entries["192.168.1.20"]["mac"] == "b8:27:eb:11:22:33"
    assert "192.168.1.99" not in entries  # incomplete se descarta


def test_parse_arp_text_macos_format():
    entries = nd._parse_arp_text(MACOS_ARP)
    assert entries["192.168.1.1"]["mac"] == "00:11:22:33:44:55"
    assert entries["192.168.1.30"]["mac"] == "a4:83:e7:01:02:03"
    assert "192.168.1.77" not in entries


def test_parse_arp_text_windows_format():
    entries = nd._parse_arp_text(WINDOWS_ARP)
    assert entries["192.168.1.1"]["mac"] == "00:11:22:33:44:55"
    assert entries["192.168.1.25"]["mac"] == "f8:9a:25:b8:55:14"
    # Broadcast y multicast se filtran
    assert "192.168.1.255" not in entries
    assert "224.0.0.22" not in entries


def test_parse_ip_neigh_text():
    entries = nd._parse_ip_neigh_text(IP_NEIGH)
    assert entries["192.168.1.1"]["state"] == "REACHABLE"
    assert entries["192.168.1.40"]["state"] == "STALE"
    assert "192.168.1.80" not in entries  # sin lladdr


def test_read_neighbor_table_filters_by_subnet(monkeypatch):
    """Las entradas de otras redes se descartan (necesario en Windows)."""
    monkeypatch.setattr(
        nd,
        "_windows_neighbors",
        lambda: nd._parse_arp_text(WINDOWS_ARP + "\n  10.9.9.9   00-aa-bb-cc-dd-ee   dinamico\n"),
    )
    monkeypatch.setattr(nd, "IS_WINDOWS", True)

    entries = nd.read_neighbor_table(interface="", subnet="192.168.1.0/24")
    assert "192.168.1.1" in entries
    assert "10.9.9.9" not in entries


# ============================================================================
# Analizadores de Windows (ipconfig / route print)
# ============================================================================

IPCONFIG_SAMPLE = """
Configuracion IP de Windows


Adaptador de LAN inalambrica Wi-Fi:

   Sufijo DNS especifico para la conexion. . : lan
   Direccion IPv4. . . . . . . . . . . . . . : 192.168.1.50
   Mascara de subred . . . . . . . . . . . . : 255.255.255.0
   Puerta de enlace predeterminada . . . . . : 192.168.1.1
   Direccion fisica. . . . . . . . . . . . . : B8-27-EB-11-22-33

Adaptador de Ethernet Ethernet 2:

   Direccion IPv4. . . . . . . . . . . . . . : 10.0.0.7
   Mascara de subred . . . . . . . . . . . . : 255.255.0.0
   Direccion fisica. . . . . . . . . . . . . : 00-1E-67-AA-BB-CC
"""

ROUTE_SAMPLE = """
===========================================================================
Lista de interfaces
  9...b8 27 eb 11 22 33 ......Realtek PCIe GbE Family Controller

===========================================================================
Rutas IPv4 activas
Destino de red        Mascara de red      Puerta de enlace    Interfaz  Metrica
          0.0.0.0          0.0.0.0      192.168.1.1     192.168.1.50     25
        127.0.0.0        255.0.0.0     En vinculo         127.0.0.1    331
"""


class _FakeResult:
    """Resultado simulado de subprocess para aislar el analizador de la red real."""

    def __init__(self, stdout: str):
        self.stdout = stdout
        self.stderr = ""
        self.returncode = 0


def test_windows_ipconfig_blocks_parser(monkeypatch):
    """El analizador de ipconfig no depende del idioma de Windows."""
    monkeypatch.setattr(nd, "run_command", lambda *args, **kwargs: _FakeResult(IPCONFIG_SAMPLE))

    blocks = nd._windows_ipconfig_blocks()
    assert len(blocks) == 2

    wifi = next(b for b in blocks if "Wi-Fi" in b["header"])
    assert wifi["ip"] == "192.168.1.50"
    assert wifi["netmask"] == "255.255.255.0"
    assert wifi["mac"] == "b8:27:eb:11:22:33"

    ethernet = next(b for b in blocks if "Ethernet 2" in b["header"])
    assert ethernet["ip"] == "10.0.0.7"
    assert nd.mask_to_prefix(ethernet["netmask"]) == 16


def test_windows_default_route_parser(monkeypatch):
    """La ruta por defecto se extrae de 'route print -4'."""
    monkeypatch.setattr(nd, "run_command", lambda *args, **kwargs: _FakeResult(ROUTE_SAMPLE))
    gateway, interface_ip = nd._windows_default_route()
    assert gateway == "192.168.1.1"
    assert interface_ip == "192.168.1.50"


def test_windows_default_route_without_output(monkeypatch):
    monkeypatch.setattr(nd, "run_command", lambda *args, **kwargs: None)
    assert nd._windows_default_route() == ("", "")


# ============================================================================
# Detección de contexto y tolerancia a fallos
# ============================================================================

def test_detect_network_context_returns_stable_keys(monkeypatch):
    """La detección nunca falla: siempre devuelve un contexto coherente."""
    monkeypatch.setattr(nd, "run_command", lambda *args, **kwargs: None)
    monkeypatch.setattr(nd, "_load_psutil", lambda: None)

    context = nd.detect_network_context()
    for key in ("interface", "local_ip", "local_mac", "subnet", "gateway", "platform", "detected"):
        assert key in context
    assert nd.safe_network(context["subnet"]) is not None


def test_detect_network_context_uses_preferred_interface(monkeypatch):
    """La interfaz indicada por el usuario tiene prioridad."""
    monkeypatch.setattr(nd, "_load_psutil", lambda: None)
    monkeypatch.setattr(nd, "run_command", lambda *args, **kwargs: None)
    monkeypatch.setattr(nd, "psutil_interfaces", lambda: {
        "wlan0": {"name": "wlan0", "ip": "192.168.1.50", "netmask": "255.255.255.0", "mac": "b8:27:eb:11:22:33", "is_up": True},
        "eth0": {"name": "eth0", "ip": "10.0.0.7", "netmask": "255.255.0.0", "mac": "00:1e:67:aa:bb:cc", "is_up": True},
    })
    monkeypatch.setattr(nd, "_linux_default_route", lambda: ("192.168.1.1", "wlan0"))

    context = nd.detect_network_context("eth0")
    assert context["interface"] == "eth0"
    assert context["local_ip"] == "10.0.0.7"
    assert context["subnet"] == "10.0.0.0/16"
    assert context["gateway"] == "192.168.1.1"


def test_list_network_interfaces_returns_list(monkeypatch):
    monkeypatch.setattr(nd, "run_command", lambda *args, **kwargs: None)
    monkeypatch.setattr(nd, "_load_psutil", lambda: None)
    assert isinstance(nd.list_network_interfaces(), list)


def test_guess_gateway_uses_first_host():
    assert nd._guess_gateway("192.168.1.50", 24) == "192.168.1.1"
    assert nd._guess_gateway("10.0.0.7", 16) == "10.0.0.1"
    assert nd._guess_gateway("no-es-ip", 24) == nd.DEFAULT_GATEWAY
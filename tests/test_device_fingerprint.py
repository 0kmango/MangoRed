"""
Pruebas de la clasificación de dispositivos (device_fingerprint.py).

Se valida el reconocimiento de móviles, ordenadores, impresoras, TVs, cámaras y
routers a partir del nombre visible, los puertos abiertos y el fabricante.
"""

import pytest

import device_fingerprint as df


# ============================================================================
# Clasificación por nombre de host
# ============================================================================

@pytest.mark.parametrize("hostname, expected_type, expected_os", [
    ("iPhone-de-Luis", "smartphone", "iOS"),
    ("ipad-air", "tablet", "iPadOS"),
    ("MacBook-Pro-de-Ana", "laptop", "macOS"),
    ("iMac-de-casa", "desktop", "macOS"),
    ("AppleTV-salon", "tv", "Android TV / tvOS"),
    ("DESKTOP-4F2K9L", "desktop", "Windows"),
    ("LAPTOP-9ABC123", "laptop", "Windows"),
    ("Galaxy-S21", "smartphone", "Android"),
    ("Redmi-Note-12", "smartphone", "Android"),
    ("raspberrypi", "computer", "Linux"),
    ("ubuntu-server", "computer", "Linux"),
    ("HP-LaserJet-Pro", "printer", ""),
    ("Chromecast-Ultra", "tv", "Android TV / tvOS"),
    ("PlayStation-5", "console", ""),
    ("Hikvision-Cam-01", "camera", ""),
    ("Synology-DS220", "nas", ""),
    ("FRITZ!Box-7530", "router", ""),
    ("shellyplug-s-ABC", "iot", ""),
    ("mi-band-7", "wearable", ""),
])
def test_classify_by_hostname(hostname, expected_type, expected_os):
    result = df.classify_device(hostname=hostname)
    assert result["device_type"] == expected_type
    assert result["os_guess"] == expected_os
    assert result["confidence"] == "high"
    assert result["device_type_label"] == df.DEVICE_TYPE_LABELS[expected_type]
    assert result["evidence"]


def test_hostname_rule_has_priority_over_vendor():
    """Un nombre explícito (iPhone) gana al fabricante genérico (Apple)."""
    result = df.classify_device(hostname="iPhone-de-Luis", vendor="Apple, Inc.")
    assert result["device_type"] == "smartphone"
    assert result["os_guess"] == "iOS"


# ============================================================================
# Clasificación por puertos
# ============================================================================

@pytest.mark.parametrize("ports, expected_type", [
    ((62078,), "smartphone"),
    ((445,), "desktop"),
    ((3389, 445), "desktop"),
    ((9100,), "printer"),
    ((631,), "printer"),
    ((554,), "camera"),
    ((8008, 8009), "tv"),
    ((1883,), "iot"),
    ((32400,), "nas"),
    ((53, 80), "router"),
    ((5900,), "desktop"),
])
def test_classify_by_ports(ports, expected_type):
    result = df.classify_device(ports=ports)
    assert result["device_type"] == expected_type
    assert "Servicios:" in " ".join(result["evidence"])


def test_iphone_port_is_high_confidence():
    result = df.classify_device(ports=[62078], vendor="Apple")
    assert result["device_type"] == "smartphone"
    assert result["os_guess"] == "iOS"
    assert result["confidence"] == "high"


# ============================================================================
# Clasificación por fabricante y casos límite
# ============================================================================

def test_classify_by_vendor():
    assert df.classify_device(vendor="Espressif Inc. (ESP8266/ESP32)")["device_type"] == "iot"
    assert df.classify_device(vendor="Raspberry Pi Foundation")["device_type"] == "computer"
    assert df.classify_device(vendor="VMware")["device_type"] == "vm"
    assert df.classify_device(vendor="Hikvision")["device_type"] == "camera"
    assert df.classify_device(vendor="Canon Inc.")["device_type"] == "printer"


def test_ambiguous_vendor_is_marked_low_confidence():
    """Apple sin más datos no se etiqueta como móvil: se informa el ecosistema."""
    result = df.classify_device(vendor="Apple, Inc.")
    assert result["device_type"] == "unknown"
    assert "iOS" in result["os_guess"]
    assert result["confidence"] == "low"


def test_gateway_and_local_device():
    gateway = df.classify_device(hostname="cualquiera", is_gateway=True)
    assert gateway["device_type"] == "router"
    assert gateway["confidence"] == "high"

    local = df.classify_device(is_local=True, local_os="Linux")
    assert local["device_type"] == "computer"
    assert local["os_guess"] == "Linux"


def test_unknown_device():
    result = df.classify_device(hostname="x1", vendor="Fabricante Desconocido")
    assert result["device_type"] == "unknown"
    assert result["device_type_label"] == "Desconocido"
    assert result["confidence"] == "low"
    assert result["evidence"] == []


def test_result_contains_all_required_keys():
    result = df.classify_device(hostname="iPhone")
    for key in ("device_type", "device_type_label", "device_type_icon", "os_guess",
                "confidence", "evidence"):
        assert key in result


# ============================================================================
# Huella completa y utilidades
# ============================================================================

def test_scan_services_uses_probe(monkeypatch):
    """Sólo se devuelven los puertos que aceptan conexión."""
    monkeypatch.setattr(df, "tcp_probe", lambda ip, port, timeout=0.35: port in {22, 445})
    assert df.scan_services("192.168.1.10", ports=(22, 80, 445)) == [22, 445]


def test_scan_services_limits_port_list(monkeypatch):
    calls = []

    def fake_probe(ip, port, timeout=0.35):
        calls.append(port)
        return False

    monkeypatch.setattr(df, "tcp_probe", fake_probe)
    df.scan_services("192.168.1.10", ports=tuple(range(1, 200)))
    assert len(calls) <= 64


def test_tcp_probe_rejects_invalid_input():
    assert df.tcp_probe("no-es-ip", 80, timeout=0.1) is False
    assert df.tcp_probe("127.0.0.1", -1, timeout=0.1) is False


def test_fingerprint_device_skips_scan_when_hostname_is_conclusive(monkeypatch):
    """Si el nombre ya identifica el equipo, no se escanean puertos."""
    called = {"scan": False}

    def fake_scan(ip, timeout=0.35):
        called["scan"] = True
        return [445]

    monkeypatch.setattr(df, "scan_services", fake_scan)
    result = df.fingerprint_device("192.168.1.20", hostname="iPhone-de-Luis")

    assert called["scan"] is False
    assert result["device_type"] == "smartphone"
    assert result["open_ports"] == []


def test_fingerprint_device_scans_when_needed(monkeypatch):
    monkeypatch.setattr(df, "scan_services", lambda ip, timeout=0.35: [9100])
    result = df.fingerprint_device("192.168.1.30", hostname="", vendor="Desconocido")

    assert result["device_type"] == "printer"
    assert result["open_ports"] == [9100]
    assert any("9100" in service for service in result["services"])


def test_service_names():
    assert df.service_names([445]) == ["445 (SMB)"]
    assert df.service_names([]) == []


# ============================================================================
# Reconocimiento de dispositivos Apple (iOS / iPadOS / macOS)
# ============================================================================

@pytest.mark.parametrize("model, expected_type, expected_os", [
    ("iPhone14,2", "smartphone", "iOS"),
    ("iPhone17,1", "smartphone", "iOS"),
    ("iPad13,4", "tablet", "iPadOS"),
    ("iPod9,1", "smartphone", "iOS"),
    ("MacBookPro18,3", "laptop", "macOS"),
    ("Macmini9,1", "desktop", "macOS"),
    ("iMac21,1", "desktop", "macOS"),
    ("AppleTV6,2", "tv", "tvOS"),
    ("AudioAccessory5,1", "iot", "HomePod"),
    ("Watch6,1", "wearable", "watchOS"),
    ("AirPodsPro1,1", "wearable", "AirPods"),
])
def test_classify_by_apple_model(model, expected_type, expected_os):
    """El modelo publicado por mDNS identifica iPhone/iPad con total precisión."""
    result = df.classify_device(model=model)
    assert result["device_type"] == expected_type
    assert result["os_guess"] == expected_os
    assert result["confidence"] == "high"
    assert model in result["evidence"][0]


def test_model_has_priority_over_generic_hostname_and_ports():
    result = df.classify_device(
        hostname="dispositivo-privado",
        vendor="Dispositivo Privado (MAC Aleatoria)",
        ports=[445],
        model="iPhone14,2",
    )
    assert result["device_type"] == "smartphone"
    assert result["os_guess"] == "iOS"


def test_ios_detected_with_randomized_mac_and_unknown_name():
    """Caso habitual: iOS con MAC aleatoria, sin nombre y sin puertos, pero con modelo."""
    result = df.classify_device(
        hostname="",
        vendor="Dispositivo Privado (MAC Aleatoria)",
        model="iPhone15,3",
    )
    assert result["device_type"] == "smartphone"
    assert result["os_guess"] == "iOS"


def test_classify_by_apple_mdns_services():
    """Sin modelo, el servicio Apple Mobile Device ya delata un iOS/iPadOS."""
    result = df.classify_device(mdns_services=["Apple Mobile Device (Wi-Fi Sync)"])
    assert result["os_guess"] == "iOS / iPadOS"
    assert result["confidence"] == "medium"

    # El modelo 'md' de Google Cast identifica un Chromecast/Google TV
    cast = df.classify_device(model="Chromecast Ultra")
    assert cast["device_type"] == "tv"
    assert cast["os_guess"] == "Google TV / Chromecast"


def test_google_cast_service_alone_does_not_misclassify_a_phone():
    """Muchos móviles anuncian Google Cast: el nombre Android debe prevalecer."""
    phone = df.classify_device(hostname="android-2", mdns_services=["Google Cast"])
    assert phone["device_type"] == "smartphone"
    assert phone["os_guess"] == "Android"


def test_android_tv_with_google_cast_model_is_tv():
    """Android TV también usa nombres 'android-xxxx'; el modelo mDNS lo corrige."""
    result = df.classify_device(
        hostname="android-2",
        model="FUSE 4K",
        mdns_services=["Google Cast"],
    )
    assert result["device_type"] == "tv"
    assert "Android TV" in result["os_guess"]
    assert result["confidence"] == "high"
    assert "FUSE 4K" in result["evidence"][0]


def test_apple_watch_and_airpods_by_hostname():
    assert df.classify_device(hostname="Apple-Watch-de-Luis")["os_guess"] == "watchOS"
    assert df.classify_device(hostname="AirPods-de-Luis")["device_type"] == "wearable"


def test_fingerprint_device_skips_scan_with_apple_model(monkeypatch):
    called = {"scan": False}

    def fake_scan(ip, timeout=0.35):
        called["scan"] = True
        return [62078]

    monkeypatch.setattr(df, "scan_services", fake_scan)
    result = df.fingerprint_device("192.168.1.41", model="iPhone14,2")

    assert called["scan"] is False
    assert result["device_type"] == "smartphone"
    assert result["os_guess"] == "iOS"
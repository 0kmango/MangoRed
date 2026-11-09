"""
Pruebas del vigilante en tiempo real (event_watcher.py).

Se simula la tabla de vecinos para verificar la línea base, los eventos de
conexión/desconexión, la gracia anti-falsos-positivos y el búfer de eventos.
"""

import pytest

import database
import event_watcher
from config import config as global_config
from event_watcher import DeviceEventWatcher

MAC = "aa:bb:cc:dd:ee:01"
MAC2 = "aa:bb:cc:dd:ee:02"
IP = "192.168.1.50"
IP2 = "192.168.1.51"


@pytest.fixture
def watcher(tmp_path, monkeypatch):
    db_file = str(tmp_path / "watch.db")
    database.init_db(db_file)
    monkeypatch.setattr(global_config, "db_path", db_file)
    monkeypatch.setattr(global_config, "enable_desktop_notifications", False)
    monkeypatch.setattr(global_config, "disconnect_grace", 60)
    monkeypatch.setattr(event_watcher, "send_desktop_notification", lambda *a, **k: True)
    return DeviceEventWatcher()


@pytest.fixture
def neighbors(monkeypatch):
    """Permite cambiar la tabla de vecinos entre sondeos."""
    holder = {"data": {}, "alive": False}
    monkeypatch.setattr(
        event_watcher.network_discovery, "detect_network_context",
        lambda preferred="": {"interface": "wlan0", "subnet": "192.168.1.0/24"},
    )
    monkeypatch.setattr(
        event_watcher.network_discovery, "read_neighbor_table",
        lambda interface="", subnet="": dict(holder["data"]),
    )
    # La confirmación por ICMP se simula: por defecto el equipo no responde
    monkeypatch.setattr(
        event_watcher.network_discovery, "ping_host",
        lambda ip, timeout=0.6: bool(holder["alive"]),
    )
    return holder


# ============================================================================
# Línea base
# ============================================================================

def test_first_poll_is_only_baseline(watcher, neighbors):
    """La primera pasada inventaría pero no notifica (evita spam al arrancar)."""
    neighbors["data"] = {IP: {"mac": MAC, "state": "REACHABLE"}}
    summary = watcher.poll_once()

    events, latest = watcher.events_since(0)
    assert events == []
    assert latest == 0
    assert summary["baseline"] is True
    assert watcher.status()["known_devices"] == 1


def test_empty_network_poll(watcher, neighbors):
    summary = watcher.poll_once()
    assert summary["seen"] == 0
    assert watcher.status()["running"] is False  # no se ha arrancado el hilo


# ============================================================================
# Conexión / desconexión
# ============================================================================

def test_new_device_emits_event_and_persists(watcher, neighbors):
    watcher.poll_once()  # baseline vacío

    neighbors["data"] = {IP: {"mac": MAC, "state": "REACHABLE"}}
    watcher.poll_once()

    events, latest = watcher.events_since(0)
    assert latest == 1
    assert len(events) == 1
    assert events[0]["type"] == "new_device"
    assert events[0]["mac"] == MAC
    assert events[0]["ip"] == IP
    assert "Nuevo dispositivo conectado" in events[0]["message"]
    assert events[0]["severity"] == "warning"

    device = database.get_device_by_mac(global_config.db_path, MAC)
    assert device is not None
    assert device["status"] == "online"


def test_disconnect_and_reconnect_events(watcher, neighbors):
    database.upsert_device(global_config.db_path, {"mac": MAC, "ip": IP, "status": "online"})

    neighbors["data"] = {IP: {"mac": MAC, "state": "REACHABLE"}}
    watcher.poll_once()  # baseline
    assert watcher.events_since(0)[0] == []

    # El equipo desaparece y ya ha superado la gracia
    neighbors["data"] = {}
    watcher._known[MAC]["last_seen"] -= 120
    watcher.poll_once()

    events, _ = watcher.events_since(0)
    assert len(events) == 1
    assert events[0]["type"] == "disconnected"
    assert events[0]["severity"] == "danger"
    assert "se ha desconectado" in events[0]["message"]
    assert database.get_device_by_mac(global_config.db_path, MAC)["status"] == "offline"

    # Vuelve a la red
    neighbors["data"] = {IP: {"mac": MAC, "state": "REACHABLE"}}
    watcher.poll_once()

    events, _ = watcher.events_since(1)
    assert len(events) == 1
    assert events[0]["type"] == "connected"
    assert events[0]["severity"] == "success"
    assert database.get_device_by_mac(global_config.db_path, MAC)["status"] == "online"


def test_disconnect_respects_grace_period(watcher, neighbors):
    """Una ausencia breve no genera un 'desconectado' (entradas ARP caducadas)."""
    database.upsert_device(global_config.db_path, {"mac": MAC, "ip": IP, "status": "online"})
    neighbors["data"] = {IP: {"mac": MAC, "state": "REACHABLE"}}
    watcher.poll_once()

    neighbors["data"] = {}
    watcher.poll_once()  # sólo 1 ausencia, dentro de la gracia

    assert watcher.events_since(0)[0] == []
    assert database.get_device_by_mac(global_config.db_path, MAC)["status"] == "online"


def test_device_missing_from_arp_but_answering_ping_stays_online(watcher, neighbors):
    """
    El kernel caduca entradas ARP de equipos inactivos: un ping puntual evita
    declarar 'desconectado' a un equipo que sigue en la red.
    """
    database.upsert_device(global_config.db_path, {"mac": MAC, "ip": IP, "status": "online"})
    neighbors["data"] = {IP: {"mac": MAC, "state": "REACHABLE"}}
    watcher.poll_once()  # baseline

    neighbors["data"] = {}
    neighbors["alive"] = True           # responde al ICMP de confirmación
    watcher._known[MAC]["last_seen"] -= 120
    watcher.poll_once()

    assert watcher.events_since(0)[0] == []
    assert database.get_device_by_mac(global_config.db_path, MAC)["status"] == "online"
    assert watcher.status()["known_devices"] == 1


def test_effective_grace_covers_two_scan_intervals(watcher, monkeypatch):
    """La gracia nunca es menor que dos intervalos de escaneo."""
    monkeypatch.setattr(global_config, "disconnect_grace", 20)
    monkeypatch.setattr(global_config, "scan_interval", 300)
    assert watcher._effective_grace() == 600

    monkeypatch.setattr(global_config, "scan_interval", 5)
    assert watcher._effective_grace() == 20


def test_blocked_device_is_not_reported_as_disconnected(watcher, neighbors):
    database.upsert_device(global_config.db_path, {"mac": MAC, "ip": IP, "status": "online"})
    database.set_device_blocked_state(global_config.db_path, MAC, is_blocked=True, reason="manual")

    neighbors["data"] = {IP: {"mac": MAC, "state": "REACHABLE"}}
    watcher.poll_once()

    neighbors["data"] = {}
    watcher._known[MAC]["last_seen"] -= 120
    watcher.poll_once()

    assert watcher.events_since(0)[0] == []
    assert database.get_device_by_mac(global_config.db_path, MAC)["status"] == "blocked"


def test_two_devices_generate_independent_events(watcher, neighbors):
    watcher.poll_once()
    neighbors["data"] = {
        IP: {"mac": MAC, "state": "REACHABLE"},
        IP2: {"mac": MAC2, "state": "REACHABLE"},
    }
    watcher.poll_once()

    events, latest = watcher.events_since(0)
    assert latest == 2
    assert {event["mac"] for event in events} == {MAC, MAC2}


# ============================================================================
# Búfer de eventos
# ============================================================================

def test_events_since_filters_by_id(watcher):
    watcher.push("connected", {"mac": MAC, "ip": IP, "hostname": "equipo"}, "uno")
    watcher.push("disconnected", {"mac": MAC2, "ip": IP2, "hostname": "otro"}, "dos")

    all_events, latest = watcher.events_since(0)
    assert latest == 2 and len(all_events) == 2

    pending, _ = watcher.events_since(1)
    assert len(pending) == 1
    assert pending[0]["type"] == "disconnected"

    assert watcher.events_since(99)[0] == []


def test_events_since_tolerates_invalid_value(watcher):
    watcher.push("new_device", {"mac": MAC}, "x")
    events, _ = watcher.events_since("no-es-numero")
    assert len(events) == 1


def test_event_contains_display_fields(watcher):
    event = watcher.push(
        "connected",
        {"mac": MAC, "ip": IP, "custom_name": "Mi Móvil", "device_type": "smartphone",
         "device_type_label": "Móvil"},
        "mensaje",
        "success",
    )
    assert event["name"] == "Mi Móvil"
    assert event["device_type"] == "smartphone"
    assert event["device_type_label"] == "Móvil"
    assert event["timestamp"].endswith("+00:00")


def test_status_reports_watcher_state(watcher, neighbors):
    neighbors["data"] = {IP: {"mac": MAC, "state": "REACHABLE"}}
    watcher.poll_once()
    status = watcher.status()

    assert status["baseline_done"] is True
    assert status["known_devices"] == 1
    assert status["seen_last_poll"] == 1
    assert status["poll_count"] == 1
    assert status["interval"] >= 2
    assert status["running"] is False
    assert status["last_error"] == ""
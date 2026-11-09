"""
Pruebas del layout del mapa lógico (map_layout.py).

Verifica que el gateway queda centrado, que las posiciones son deterministas,
que respetan los límites del lienzo y que las posiciones manuales (pinned) se
conservan.
"""

import map_layout


def device(mac, device_type="unknown", ip="", **extra):
    data = {"mac": mac, "device_type": device_type, "ip": ip}
    data.update(extra)
    return data


def test_gateway_is_centered():
    devices = [
        device("aa:bb:cc:dd:ee:01", "router", "192.168.1.1"),
        device("aa:bb:cc:dd:ee:02", "smartphone", "192.168.1.20"),
    ]
    layout = map_layout.auto_layout(devices, "192.168.1.1")

    gateway = layout["aa:bb:cc:dd:ee:01"]
    assert gateway["x"] == 50.0 and gateway["y"] == 50.0
    assert gateway["center"] is True
    assert layout["aa:bb:cc:dd:ee:02"]["center"] is False


def test_gateway_detected_by_type_without_ip():
    devices = [device("aa:bb:cc:dd:ee:01", "router")]
    layout = map_layout.auto_layout(devices, "")
    assert layout["aa:bb:cc:dd:ee:01"]["center"] is True


def test_positions_are_within_bounds_and_unique():
    devices = [device(f"aa:bb:cc:dd:ee:{index:02x}", "smartphone") for index in range(30)]
    layout = map_layout.auto_layout(devices)

    points = set()
    for position in layout.values():
        assert map_layout.MIN_COORD <= position["x"] <= map_layout.MAX_COORD
        assert map_layout.MIN_COORD <= position["y"] <= map_layout.MAX_COORD
        points.add((position["x"], position["y"]))
    assert len(points) == len(layout), "no debería haber dos equipos en el mismo punto"


def test_layout_is_deterministic():
    devices = [
        device("aa:bb:cc:dd:ee:01", "laptop"),
        device("aa:bb:cc:dd:ee:02", "printer"),
        device("aa:bb:cc:dd:ee:03", "iot"),
    ]
    first = map_layout.auto_layout(devices)
    second = map_layout.auto_layout(list(reversed(devices)))
    assert first == second


def test_type_rings():
    assert map_layout.type_ring("router") == 0
    assert map_layout.type_ring("printer") == 1
    assert map_layout.type_ring("smartphone") == 2
    assert map_layout.type_ring("desconocido") == 3
    assert map_layout.type_ring(None) == 3


def test_ring_radius_increases_with_type():
    infrastructure = map_layout.auto_layout([device("aa:bb:cc:dd:ee:01", "printer")])
    mobile = map_layout.auto_layout([device("aa:bb:cc:dd:ee:02", "smartphone")])
    unknown = map_layout.auto_layout([device("aa:bb:cc:dd:ee:03", "unknown")])

    def distance(position):
        return ((position["x"] - 50) ** 2 + (position["y"] - 50) ** 2) ** 0.5

    assert distance(infrastructure["aa:bb:cc:dd:ee:01"]) < \
        distance(mobile["aa:bb:cc:dd:ee:02"]) < \
        distance(unknown["aa:bb:cc:dd:ee:03"])


def test_second_router_is_not_stacked_on_the_gateway():
    """Un AP/router extra debe ir al primer anillo, no encima del gateway."""
    devices = [
        device("aa:bb:cc:dd:ee:01", "router", "192.168.1.1"),
        device("aa:bb:cc:dd:ee:02", "router", "192.168.1.8"),
    ]
    layout = map_layout.auto_layout(devices, "192.168.1.1")

    gateway = layout["aa:bb:cc:dd:ee:01"]
    access_point = layout["aa:bb:cc:dd:ee:02"]
    assert (gateway["x"], gateway["y"]) == (50.0, 50.0)
    assert access_point["ring"] == 1

    distance = ((access_point["x"] - 50) ** 2 + (access_point["y"] - 50) ** 2) ** 0.5
    assert distance > 10, "el segundo router no debe quedar pegado al centro"


def test_pinned_position_is_respected():
    devices = [
        device("aa:bb:cc:dd:ee:01", "router", "192.168.1.1", map_x=12.5, map_y=80.0,
               map_pinned=1),
        device("aa:bb:cc:dd:ee:02", "laptop", "192.168.1.20"),
    ]
    nodes = map_layout.apply_layout(devices, "192.168.1.1")
    by_mac = {node["mac"]: node for node in nodes}

    assert by_mac["aa:bb:cc:dd:ee:01"]["x"] == 12.5
    assert by_mac["aa:bb:cc:dd:ee:01"]["y"] == 80.0
    assert by_mac["aa:bb:cc:dd:ee:01"]["pinned"] is True

    # El que no está fijado usa el layout automático
    assert by_mac["aa:bb:cc:dd:ee:02"]["pinned"] is False
    assert map_layout.MIN_COORD <= by_mac["aa:bb:cc:dd:ee:02"]["x"] <= map_layout.MAX_COORD


def test_pinned_without_coordinates_falls_back_to_auto():
    devices = [device("aa:bb:cc:dd:ee:01", "laptop", map_pinned=1)]
    nodes = map_layout.apply_layout(devices)
    assert nodes[0]["pinned"] is False
    assert map_layout.MIN_COORD <= nodes[0]["x"] <= map_layout.MAX_COORD


def test_empty_input_returns_empty_layout():
    assert map_layout.auto_layout([]) == {}
    assert map_layout.apply_layout([]) == []


def test_apply_layout_does_not_mutate_input():
    devices = [device("aa:bb:cc:dd:ee:01", "router", "192.168.1.1")]
    original = dict(devices[0])
    map_layout.apply_layout(devices, "192.168.1.1")
    assert devices[0] == original
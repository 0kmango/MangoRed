"""
Servidor Web Flask y API REST para MangoRed.

Proporciona el panel de control local para la supervisión de red doméstica
autorizada en Linux (Kali y otras distribuciones), Windows y macOS.

Defensas activas de la API:
  * Escucha sólo en loopback por defecto.
  * Token local obligatorio en toda operación de escritura (anti-CSRF).
  * Validación de la cabecera ``Host`` (anti DNS-rebinding).
  * Limitación de peticiones y tamaño máximo de cuerpo.
  * Cabeceras de seguridad y CSP sin scripts inline.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import threading
import time
import webbrowser
from pathlib import Path
from typing import Optional

from flask import Flask, Response, jsonify, render_template, request, send_file

import database
import map_layout
import network_discovery
import scanner
from config import config, validate_mac
from event_watcher import device_watcher
from platform_compat import PLATFORM_LABEL, list_platform_tools, secure_file_permissions
from router import ROUTER_SETUP_GUIDE, get_router_driver
from router.ssh_router import describe_open_ports, probe_router_ports, suggest_router_action
from security import (
    SAFE_METHODS,
    SECURITY_HEADERS,
    ApiToken,
    RateLimiter,
    allowed_hosts_from_environment,
    client_key,
    is_allowed_host,
    is_loopback_bind,
)

APP_VERSION = "1.0.0"
MAX_REQUEST_BYTES = 64 * 1024

#: "Mango LAN Map": plano de planta opcional (imagen) subido por el usuario.
MAX_MAP_UPLOAD_BYTES = 2 * 1024 * 1024
MAP_ASSETS_DIR = Path(__file__).resolve().parent / "map_assets"
FLOORPLAN_META_KEY = "floorplan"
ALLOWED_FLOORPLAN = {
    "png": ("image/png", b"\x89PNG\r\n\x1a\n"),
    "jpg": ("image/jpeg", b"\xff\xd8\xff"),
    "jpeg": ("image/jpeg", b"\xff\xd8\xff"),
}

app = Flask(__name__)
app.config.update(
    JSON_SORT_KEYS=False,
    MAX_CONTENT_LENGTH=MAX_MAP_UPLOAD_BYTES,
    SECRET_KEY=os.urandom(32),
)

#: Token efímero exigido en las operaciones de escritura.
api_token = ApiToken()

#: Hosts aceptados en la cabecera Host (loopback + MANGORED_ALLOWED_HOSTS).
ALLOWED_HOSTS = allowed_hosts_from_environment()

#: Limitadores por categoría de endpoint.
scan_limiter = RateLimiter(max_calls=12, window_seconds=60)
action_limiter = RateLimiter(max_calls=30, window_seconds=60)
config_limiter = RateLimiter(max_calls=20, window_seconds=60)

logger = logging.getLogger("MangoRed")


# ============================================================================
# PROTECCIONES TRANSVERSALES
# ============================================================================

def _json_error(message: str, status: int, retry_after: int = 0) -> Response:
    """Construye una respuesta JSON de error homogénea."""
    response = jsonify({"success": False, "error": message})
    response.status_code = status
    if retry_after:
        response.headers["Retry-After"] = str(retry_after)
    return response


def _rate_bucket(path: str):
    """Selecciona el limitador adecuado según el endpoint solicitado."""
    if path == "/api/scan":
        return "scan", scan_limiter
    if path == "/api/config":
        return "config", config_limiter
    if path.startswith("/api/router/"):
        return "router", action_limiter
    return "action", action_limiter


@app.before_request
def _security_guard():
    """Valida Host, token de escritura y límite de peticiones."""
    # 1. Anti DNS-rebinding: sólo se aceptan hosts locales autorizados.
    if not is_allowed_host(request.host, ALLOWED_HOSTS):
        return _json_error(
            "Host no permitido. Abre el panel mediante http://127.0.0.1:5000 "
            "o configura MANGORED_ALLOWED_HOSTS si usas otro nombre.",
            403,
        )

    # 2. Token obligatorio para cualquier método que modifique estado.
    if request.method not in SAFE_METHODS:
        provided = request.headers.get("X-MangoRed-Token", "")
        if not api_token.matches(provided):
            return _json_error(
                "Token de API ausente o inválido. Recarga el panel desde el navegador local.",
                403,
            )

        # 2b. Límite estricto de cuerpo para las API JSON: la única subida
        #     permitida (el plano del mapa) tiene su propio tope de 2 MB.
        if (
            request.path != "/api/map/floorplan"
            and (request.content_length or 0) > MAX_REQUEST_BYTES
        ):
            return _json_error("El cuerpo de la petición es demasiado grande.", 413)

        # 3. Límite de peticiones (desactivado en la suite de pruebas).
        if not app.config.get("TESTING"):
            bucket, limiter = _rate_bucket(request.path)
            allowed, retry_after = limiter.hit(client_key(request.remote_addr, bucket))
            if not allowed:
                return _json_error(
                    "Demasiadas peticiones en poco tiempo. Espera unos segundos.",
                    429,
                    retry_after=retry_after,
                )

    return None


@app.after_request
def _security_headers(response: Response) -> Response:
    """Añade cabeceras de seguridad y evita el almacenamiento en caché."""
    for header, value in SECURITY_HEADERS.items():
        response.headers.setdefault(header, value)
    response.headers["Server"] = "MangoRed"

    if request.path == "/" or request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store, max-age=0"
        response.headers["Pragma"] = "no-cache"
    return response


@app.errorhandler(404)
def _handle_not_found(_error):
    if request.path.startswith("/api/"):
        return _json_error("Recurso no encontrado.", 404)
    return "No encontrado", 404


@app.errorhandler(405)
def _handle_method_not_allowed(_error):
    return _json_error("Método HTTP no permitido.", 405)


@app.errorhandler(413)
def _handle_payload_too_large(_error):
    return _json_error("El cuerpo de la petición es demasiado grande.", 413)


@app.errorhandler(500)
def _handle_internal_error(error):
    logger.exception("Error interno del servidor: %s", error)
    return _json_error("Error interno del servidor. Revisa el log de MangoRed.", 500)


# ============================================================================
# RUTAS DE INTERFAZ Y VISTAS
# ============================================================================

@app.route("/")
def index():
    """Página principal del panel interactivo (incluye el token de sesión)."""
    return render_template(
        "index.html",
        api_token=api_token.value,
        app_version=APP_VERSION,
        platform_label=PLATFORM_LABEL,
    )


@app.route("/map")
def map_view():
    """Vista "Mango LAN Map": mapa lógico en vivo de la red local."""
    return render_template(
        "map.html",
        api_token=api_token.value,
        app_version=APP_VERSION,
        platform_label=PLATFORM_LABEL,
    )


@app.route("/api/health", methods=["GET"])
def api_health():
    """Comprobación de estado sin datos sensibles (útil para automatización)."""
    return jsonify({
        "success": True,
        "status": "ok",
        "version": APP_VERSION,
        "platform": PLATFORM_LABEL,
        "read_only": config.read_only,
        "scan_in_progress": bool(scanner.scanner_service.is_scanning),
        "watcher": device_watcher.status(),
        "system": list_platform_tools(),
    })


# ============================================================================
# API DE DISPOSITIVOS Y ESTADO DE RED
# ============================================================================

@app.route("/api/devices", methods=["GET"])
def api_get_devices():
    """Obtiene el listado de dispositivos con filtros opcionales."""
    search = request.args.get("search", "").strip()
    status_filter = request.args.get("status", "").strip()
    tag_filter = request.args.get("tag", "").strip()
    type_filter = request.args.get("type", "").strip()

    devices = database.get_all_devices(
        config.db_path, search, status_filter, tag_filter, type_filter
    )
    return jsonify({
        "success": True,
        "count": len(devices),
        "devices": devices,
    })


@app.route("/api/devices/<mac>", methods=["GET"])
def api_get_device(mac):
    """Detalles de un dispositivo específico por su MAC."""
    if not validate_mac(mac):
        return _json_error("Formato de MAC no válido.", 400)

    device = database.get_device_by_mac(config.db_path, mac)
    if not device:
        return _json_error("Dispositivo no encontrado.", 404)

    return jsonify({"success": True, "device": device})


@app.route("/api/devices/<mac>/custom", methods=["POST"])
def api_update_device_custom(mac):
    """Actualiza el nombre personalizado, etiquetas o notas de un dispositivo."""
    if not validate_mac(mac):
        return _json_error("Formato de MAC no válido.", 400)

    data = request.get_json(silent=True) or {}
    custom_name = str(data.get("custom_name", ""))
    custom_tags = str(data.get("custom_tags", ""))
    notes = str(data.get("notes", ""))

    ok = database.update_device_custom_info(config.db_path, mac, custom_name, custom_tags, notes)
    if ok:
        return jsonify({
            "success": True,
            "message": "Datos personalizados guardados correctamente.",
        })
    return _json_error("No se pudo actualizar el dispositivo.", 400)


@app.route("/api/devices/<mac>/acknowledge", methods=["POST"])
def api_acknowledge_device(mac):
    """Marca un nuevo dispositivo como reconocido/leído."""
    if not validate_mac(mac):
        return _json_error("Formato de MAC no válido.", 400)

    ok = database.acknowledge_device(config.db_path, mac)
    return jsonify({"success": ok})


@app.route("/api/devices/acknowledge-all", methods=["POST"])
def api_acknowledge_all():
    """Marca todos los dispositivos nuevos como reconocidos."""
    count = database.acknowledge_all_devices(config.db_path)
    return jsonify({"success": True, "acknowledged_count": count})


# ============================================================================
# API DE ESCANEO, MÉTRICAS E INTERFACES
# ============================================================================

@app.route("/api/scan", methods=["POST"])
def api_trigger_scan():
    """Lanza un escaneo inmediato de la red."""
    if scanner.scanner_service.is_scanning:
        return _json_error("Ya hay un escaneo en curso.", 409)

    result = scanner.scanner_service.trigger_scan_now()
    if result.get("status") == "busy":
        return _json_error(result.get("message", "Escaneo en curso."), 409)
    return jsonify({"success": result.get("status") == "success", "result": result})


@app.route("/api/scan/status", methods=["GET"])
def api_scan_status():
    """Consulta el estado del motor de escaneo."""
    net_context = scanner.detect_network_context()
    return jsonify({
        "success": True,
        "is_scanning": scanner.scanner_service.is_scanning,
        "last_scan_time": scanner.scanner_service.last_scan_time,
        "last_duration": scanner.scanner_service.last_scan_duration,
        "last_count": scanner.scanner_service.last_found_count,
        "last_sweep": scanner.scanner_service.last_sweep,
        "network_context": net_context,
        "platform": PLATFORM_LABEL,
    })


@app.route("/api/interfaces", methods=["GET"])
def api_list_interfaces():
    """Lista las interfaces de red disponibles en el sistema."""
    return jsonify({
        "success": True,
        "interfaces": network_discovery.list_network_interfaces(),
        "active": scanner.detect_network_context(),
    })


@app.route("/api/stats", methods=["GET"])
def api_get_stats():
    """Retorna métricas globales de la red y estado del sistema."""
    stats = database.get_stats(config.db_path)
    net_context = scanner.detect_network_context()
    router_driver = get_router_driver(config)

    return jsonify({
        "success": True,
        "stats": stats,
        "network": net_context,
        "read_only": config.read_only,
        "platform": PLATFORM_LABEL,
        "version": APP_VERSION,
        "watcher": device_watcher.status(),
        "router_driver": {
            "name": router_driver.name,
            "capabilities": router_driver.get_capabilities(),
        },
    })


@app.route("/api/events", methods=["GET"])
def api_get_events():
    """
    Eventos de conexión/desconexión en tiempo real.

    El panel consulta ``?since=<último_id>`` cada 2 segundos y muestra un aviso
    en el momento en que un equipo aparece o desaparece de la red.
    """
    try:
        since = int(request.args.get("since", 0))
    except (TypeError, ValueError):
        return _json_error("El parámetro 'since' debe ser un número entero.", 400)

    events, latest = device_watcher.events_since(since)
    return jsonify({
        "success": True,
        "events": events,
        "latest": latest,
        "watcher": device_watcher.status(),
    })


# ============================================================================
# MANGO LAN MAP: mapa lógico en vivo (dispositivos, posiciones y plano)
# ============================================================================

#: Campos que el mapa expone de cada dispositivo (payload compacto y estable).
MAP_DEVICE_FIELDS = (
    "mac", "ip", "hostname", "custom_name", "custom_tags", "vendor", "model",
    "device_type", "device_type_label", "os_guess", "services", "name_source",
    "status", "is_blocked", "is_new", "first_seen", "last_seen",
)


def _map_payload(since_id: int = 0) -> dict:
    """Construye el estado completo que consume la vista del mapa."""
    context = scanner.detect_network_context()
    gateway_ip = context.get("gateway", "")

    nodes = map_layout.apply_layout(database.get_all_devices(config.db_path), gateway_ip)
    trimmed = []
    for node in nodes:
        item = {key: node.get(key) for key in MAP_DEVICE_FIELDS}
        item.update({
            "display_name": node.get("custom_name") or node.get("hostname") or node.get("mac"),
            "x": node.get("x"),
            "y": node.get("y"),
            "ring": node.get("ring"),
            "center": bool(node.get("center")),
            "pinned": bool(node.get("pinned")),
        })
        trimmed.append(item)

    events, latest = device_watcher.events_since(since_id)
    return {
        "success": True,
        "nodes": trimmed,
        "events": events,
        "latest": latest,
        "stats": database.get_stats(config.db_path),
        "network": context,
        "gateway_ip": gateway_ip,
        "watcher": device_watcher.status(),
        "floorplan": bool(database.get_meta(config.db_path, FLOORPLAN_META_KEY, "")),
        "pinned_count": sum(1 for item in trimmed if item["pinned"]),
    }


@app.route("/api/map", methods=["GET"])
def api_map():
    """Estado del mapa: dispositivos con posición, eventos nuevos y métricas."""
    try:
        since = int(request.args.get("since", 0))
    except (TypeError, ValueError):
        return _json_error("El parámetro 'since' debe ser un número entero.", 400)
    return jsonify(_map_payload(since))


@app.route("/api/map/positions", methods=["POST"])
def api_map_positions():
    """Guarda las posiciones que el usuario ha arrastrado (0-100 % del lienzo)."""
    data = request.get_json(silent=True) or {}
    positions = data.get("positions")
    if not isinstance(positions, dict) or not positions:
        return _json_error("Se espera un objeto 'positions' con {mac: [x, y]}.", 400)
    if len(positions) > 512:
        return _json_error("Demasiadas posiciones en una sola petición.", 400)

    saved = 0
    for mac, point in positions.items():
        if not isinstance(point, (list, tuple)) or len(point) != 2:
            continue
        if database.set_device_map_position(config.db_path, mac, point[0], point[1]):
            saved += 1

    return jsonify({"success": True, "saved": saved})


@app.route("/api/map/positions/reset", methods=["POST"])
def api_map_positions_reset():
    """Devuelve uno o todos los dispositivos al layout automático."""
    data = request.get_json(silent=True) or {}
    mac = str(data.get("mac", "")).strip()
    if mac and not validate_mac(mac):
        return _json_error("Dirección MAC no válida.", 400)
    count = database.reset_map_positions(config.db_path, mac or None)
    return jsonify({"success": True, "reset": count})


@app.route("/api/map/floorplan", methods=["POST"])
def api_map_floorplan_upload():
    """Sube un plano de planta (PNG/JPEG, máx. 2 MB) como fondo del mapa."""
    upload = request.files.get("file")
    if upload is None or not upload.filename:
        return _json_error("No se recibió ningún archivo (campo 'file').", 400)

    extension = upload.filename.rsplit(".", 1)[-1].lower() if "." in upload.filename else ""
    if extension not in ALLOWED_FLOORPLAN:
        return _json_error("Formato no admitido. Usa una imagen PNG o JPEG.", 400)

    payload = upload.read(MAX_MAP_UPLOAD_BYTES + 1)
    if len(payload) > MAX_MAP_UPLOAD_BYTES:
        return _json_error("La imagen supera el límite de 2 MB.", 413)

    mimetype, magic = ALLOWED_FLOORPLAN[extension]
    if not payload.startswith(magic):
        return _json_error("El archivo no es una imagen PNG/JPEG válida.", 400)

    try:
        MAP_ASSETS_DIR.mkdir(parents=True, exist_ok=True)
        secure_file_permissions(str(MAP_ASSETS_DIR), 0o700)
        for previous in MAP_ASSETS_DIR.glob("floorplan.*"):
            previous.unlink(missing_ok=True)
        target = MAP_ASSETS_DIR / f"floorplan.{extension}"
        target.write_bytes(payload)
        secure_file_permissions(str(target), 0o600)
    except OSError as error:
        return _json_error(f"No se pudo guardar el plano: {error}", 500)

    database.set_meta(config.db_path, FLOORPLAN_META_KEY, target.name)
    return jsonify({"success": True, "floorplan": target.name, "mimetype": mimetype})


@app.route("/api/map/floorplan", methods=["GET"])
def api_map_floorplan_get():
    """Sirve el plano de planta subido (404 si no hay ninguno)."""
    filename = database.get_meta(config.db_path, FLOORPLAN_META_KEY, "")
    if not filename:
        return _json_error("No hay plano configurado.", 404)
    path = MAP_ASSETS_DIR / filename
    if not path.is_file():
        return _json_error("El plano ya no está disponible.", 404)
    extension = path.suffix.lstrip(".").lower()
    mimetype = ALLOWED_FLOORPLAN.get(extension, ("image/png", b""))[0]
    response = send_file(path, mimetype=mimetype, conditional=True)
    response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/api/map/floorplan", methods=["DELETE"])
def api_map_floorplan_delete():
    """Elimina el plano de planta del mapa."""
    filename = database.get_meta(config.db_path, FLOORPLAN_META_KEY, "")
    if filename:
        (MAP_ASSETS_DIR / filename).unlink(missing_ok=True)
    database.delete_meta(config.db_path, FLOORPLAN_META_KEY)
    return jsonify({"success": True})


@app.route("/api/history", methods=["GET"])
def api_get_history():
    """Obtiene el historial de eventos con filtros opcionales."""
    mac = request.args.get("mac", "").strip() or None
    event_type = request.args.get("event_type", "").strip() or None

    try:
        limit = int(request.args.get("limit", 100))
    except (TypeError, ValueError):
        return _json_error("El parámetro 'limit' debe ser un número entero.", 400)

    history_records = database.get_history(config.db_path, limit, mac, event_type)
    return jsonify({
        "success": True,
        "count": len(history_records),
        "history": history_records,
    })


# ============================================================================
# API DE GESTIÓN Y BLOQUEO AUTORIZADO DEL ROUTER
# ============================================================================

@app.route("/api/router/test", methods=["POST"])
def api_router_test():
    """Prueba la conexión con el router y, si falla, diagnostica sus servicios."""
    driver = get_router_driver(config)
    ok, message = driver.test_connection()

    payload = {
        "success": ok,
        "message": message,
        "driver_name": driver.name,
        "capabilities": driver.get_capabilities(),
    }

    if not ok and "Servicios detectados" not in message:
        # Diagnóstico rápido de los servicios de administración del router.
        # (El controlador SSH ya incluye este diagnóstico en su propio mensaje.)
        try:
            ports = probe_router_ports(config.router_host)
        except Exception:
            ports = {}
        payload["diagnostics"] = {
            "host": config.router_host,
            "ports": ports,
            "open_services": describe_open_ports(ports),
            "suggestion": suggest_router_action(ports),
        }

    return jsonify(payload)


@app.route("/api/router/block", methods=["POST"])
def api_router_block():
    """
    Aplica una regla de bloqueo autorizada mediante la API del router.

    Requiere confirmación explícita, valida el modo de solo lectura y exige el
    token local (comprobado de forma global en ``before_request``).
    """
    # 1. Validación de seguridad: Modo de Solo Lectura por defecto
    if config.read_only:
        return _json_error(
            "Operación denegada: MangoRed está configurado en 'Modo Solo Lectura' por seguridad. "
            "Para autorizar cambios en el router, desactiva el modo de solo lectura en la pestaña de Ajustes.",
            403,
        )

    data = request.get_json(silent=True) or {}
    mac = str(data.get("mac", "")).strip()
    confirmed = bool(data.get("confirmed", False))
    reason = str(data.get("reason", "Bloqueo administrativo autorizado por el usuario"))

    # 1b. Declaración explícita de autorización (uso defensivo en red propia)
    if not config.authorization_confirmed:
        return _json_error(
            "Antes de bloquear debes aceptar la declaración de autorización en Ajustes "
            "(Administración autorizada de la red).",
            403,
        )

    # 2. Validación de confirmación explícita
    if not confirmed:
        return _json_error(
            "Se requiere confirmación explícita del usuario para ejecutar el bloqueo administrativo.",
            400,
        )

    # 3. Validación de dirección MAC
    if not validate_mac(mac):
        return _json_error("Dirección MAC no válida.", 400)

    device = database.get_device_by_mac(config.db_path, mac)
    if not device:
        return _json_error("Dispositivo no encontrado en el inventario.", 404)

    ip = device.get("ip", "")
    hostname = device.get("custom_name") or device.get("hostname") or mac

    # 4. Ejecución mediante el controlador oficial del router
    driver = get_router_driver(config)
    ok, message = driver.block_device(mac, ip, hostname)

    if ok:
        database.set_device_blocked_state(config.db_path, mac, is_blocked=True, reason=reason)
        database.log_event(
            config.db_path, "blocked", mac, ip,
            f"Bloqueo administrativo aplicado en router ({driver.name}). "
            f"Motivo: {reason}. Detalle: {message}",
            severity="danger",
        )
        return jsonify({
            "success": True,
            "message": message,
            "device": database.get_device_by_mac(config.db_path, mac),
        })

    return _json_error(f"Fallo al aplicar el bloqueo en el router: {message}", 502)


@app.route("/api/router/unblock", methods=["POST"])
def api_router_unblock():
    """Elimina la regla de bloqueo en el router."""
    if config.read_only:
        return _json_error(
            "Operación denegada: MangoRed está en 'Modo Solo Lectura'.",
            403,
        )

    data = request.get_json(silent=True) or {}
    mac = str(data.get("mac", "")).strip()

    if not validate_mac(mac):
        return _json_error("Dirección MAC no válida.", 400)

    if not config.authorization_confirmed:
        return _json_error(
            "Antes de desbloquear debes aceptar la declaración de autorización en Ajustes "
            "(Administración autorizada de la red).",
            403,
        )

    device = database.get_device_by_mac(config.db_path, mac)
    if not device:
        return _json_error("Dispositivo no encontrado.", 404)

    driver = get_router_driver(config)
    ok, message = driver.unblock_device(mac, device.get("ip", ""))

    if ok:
        database.set_device_blocked_state(config.db_path, mac, is_blocked=False, reason="")
        database.log_event(
            config.db_path, "unblocked", mac, device.get("ip", ""),
            f"Desbloqueo administrativo aplicado en router ({driver.name}). Detalle: {message}",
            severity="success",
        )
        return jsonify({
            "success": True,
            "message": message,
            "device": database.get_device_by_mac(config.db_path, mac),
        })

    return _json_error(f"Fallo al desbloquear en el router: {message}", 502)


@app.route("/api/guide", methods=["GET"])
def api_get_guide():
    """Retorna la guía de configuración y buenas prácticas."""
    return jsonify({"success": True, "guide": ROUTER_SETUP_GUIDE})


# ============================================================================
# API DE CONFIGURACIÓN DEL SISTEMA
# ============================================================================

@app.route("/api/config", methods=["GET"])
def api_get_config():
    """Retorna la configuración actual (con contraseñas enmascaradas)."""
    payload = config.to_dict(hide_secrets=True)
    payload["platform"] = PLATFORM_LABEL
    payload["version"] = APP_VERSION
    return jsonify({"success": True, "config": payload})


@app.route("/api/config", methods=["POST"])
def api_update_config():
    """Actualiza la configuración del sistema con validación estricta."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return _json_error("El cuerpo de la petición debe ser un objeto JSON.", 400)

    previous_db_path = config.db_path
    ok, message = config.update_settings(data)

    if ok:
        # Si cambió la base de datos, se inicializa el nuevo esquema.
        if config.db_path != previous_db_path:
            try:
                database.init_db(config.db_path)
            except Exception as error:
                logger.exception("No se pudo inicializar la nueva base de datos")
                return _json_error(
                    f"Configuración guardada, pero la base de datos no se pudo inicializar: {error}",
                    500,
                )

        payload = config.to_dict(hide_secrets=True)
        payload["platform"] = PLATFORM_LABEL
        payload["version"] = APP_VERSION
        return jsonify({
            "success": True,
            "message": message,
            "config": payload,
        })

    return _json_error(message, 400)


# ============================================================================
# INICIALIZACIÓN Y ARRANQUE
# ============================================================================

def init_app(start_scanner: bool = True, start_watcher: bool = True):
    """
    Inicializa la base de datos y arranca el escáner y la vigilancia en tiempo real.

    El vigilante espera al primer escaneo completo para tomar su línea base: así
    no se notifica toda la red como "nueva" al arrancar por primera vez.
    """
    database.init_db(config.db_path)
    if start_scanner:
        scanner.scanner_service.start()
    if start_watcher:
        if start_scanner:
            threading.Thread(
                target=_start_watcher_after_first_scan,
                daemon=True,
                name="MangoRedWatcherBootstrap",
            ).start()
        else:
            device_watcher.start()


def _start_watcher_after_first_scan(timeout: float = 45.0) -> None:
    """Arranca el vigilante cuando el escáner ya tiene una foto de la red."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if scanner.scanner_service.last_scan_time is not None:
            break
        time.sleep(0.5)
    device_watcher.start()


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mangored",
        description="MangoRed - Monitor doméstico de red local (Linux, Windows y macOS).",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Dirección de escucha (por defecto 127.0.0.1).")
    parser.add_argument("--port", type=int, default=5000, help="Puerto de escucha (por defecto 5000).")
    parser.add_argument("--no-browser", action="store_true", help="No abrir el navegador al arrancar.")
    parser.add_argument("--no-scan", action="store_true", help="No iniciar el escáner periódico.")
    parser.add_argument("--no-watch", action="store_true",
                        help="No iniciar la vigilancia en tiempo real (conexión/desconexión).")
    parser.add_argument("--version", action="version", version=f"MangoRed {APP_VERSION}")
    return parser


def _serve(host: str, port: int) -> None:
    """Sirve la aplicación con waitress si está disponible; si no, con Flask."""
    try:
        from waitress import serve as waitress_serve  # type: ignore
    except ImportError:
        waitress_serve = None

    if waitress_serve is not None:
        print("[MangoRed] Servidor WSGI waitress activo.")
        waitress_serve(app, host=host, port=port, threads=8, ident="MangoRed")
        return

    print("[MangoRed] waitress no está instalado; usando el servidor de desarrollo de Flask.")
    app.run(host=host, port=port, debug=False, threaded=True, use_reloader=False)


def main(argv: Optional[list] = None) -> int:
    """Punto de entrada CLI multiplataforma."""
    args = _build_parser().parse_args(argv)

    if not 1 <= args.port <= 65535:
        print("[MangoRed] Error: el puerto debe estar entre 1 y 65535.", file=sys.stderr)
        return 2

    if not is_loopback_bind(args.host):
        if os.environ.get("MANGORED_ALLOW_REMOTE", "") != "1":
            print(
                "[MangoRed] Error de seguridad: exponer el panel fuera de loopback requiere "
                "MANGORED_ALLOW_REMOTE=1 y una entrada en MANGORED_ALLOWED_HOSTS.",
                file=sys.stderr,
            )
            return 2
        print(
            "[MangoRed] AVISO: el panel está expuesto en la red. El token local sigue siendo "
            "obligatorio para escribir, pero cualquiera con acceso puede leer el inventario.",
            file=sys.stderr,
        )

    display_host = "127.0.0.1" if args.host in {"0.0.0.0", "::", ""} else args.host
    url = f"http://{display_host}:{args.port}"

    print("==================================================================")
    print(f" MangoRed {APP_VERSION} - Monitor Doméstico de Red Local")
    print(f" Plataforma: {PLATFORM_LABEL}")
    print(f" Servidor web activo en: {url}")
    print(f" Modo Solo Lectura: {'ACTIVADO' if config.read_only else 'DESACTIVADO'}")
    print(f" Base de datos: {config.db_path}")
    print(" Token de escritura: generado para esta sesión (incluido en el panel).")
    print(" Presiona Ctrl+C para detener el servicio.")
    print("==================================================================")

    init_app(start_scanner=not args.no_scan, start_watcher=not args.no_watch)

    if not args.no_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()

    try:
        _serve(args.host, args.port)
    except KeyboardInterrupt:
        print("\n[MangoRed] Deteniendo servicio...")
    finally:
        scanner.scanner_service.stop()
        device_watcher.stop()
    return 0


if __name__ == "__main__":
    logging.basicConfig(
        level=os.environ.get("MANGORED_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    sys.exit(main())
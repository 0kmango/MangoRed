"""
Servidor Web Flask y API REST para MangoRed.
Proporciona el panel de control local (http://127.0.0.1:5000)
para la supervisión de red doméstica autorizada.
"""

import os
import sys
from flask import Flask, render_template, jsonify, request
from config import config, validate_mac, normalize_mac, validate_ip
import database
import scanner
from router import get_router_driver, ROUTER_SETUP_GUIDE

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False


# ============================================================================
# RUTAS DE INTERFAZ Y VISTAS
# ============================================================================

@app.route("/")
def index():
    """Página principal del panel interactivo."""
    return render_template("index.html")


# ============================================================================
# API DE DISPOSITIVOS Y ESTADO DE RED
# ============================================================================

@app.route("/api/devices", methods=["GET"])
def api_get_devices():
    """Obtiene el listado de dispositivos con filtros opcionales."""
    search = request.args.get("search", "").strip()
    status_filter = request.args.get("status", "").strip()
    tag_filter = request.args.get("tag", "").strip()

    devices = database.get_all_devices(config.db_path, search, status_filter, tag_filter)
    return jsonify({
        "success": True,
        "count": len(devices),
        "devices": devices
    })


@app.route("/api/devices/<mac>", methods=["GET"])
def api_get_device(mac):
    """Detalles de un dispositivo específico por su MAC."""
    if not validate_mac(mac):
        return jsonify({"success": False, "error": "Formato de MAC no válido"}), 400

    dev = database.get_device_by_mac(config.db_path, mac)
    if not dev:
        return jsonify({"success": False, "error": "Dispositivo no encontrado"}), 404

    return jsonify({"success": True, "device": dev})


@app.route("/api/devices/<mac>/custom", methods=["POST"])
def api_update_device_custom(mac):
    """Actualiza el nombre personalizado, etiquetas o notas asignadas a un dispositivo."""
    if not validate_mac(mac):
        return jsonify({"success": False, "error": "Formato de MAC no válido"}), 400

    data = request.get_json(silent=True) or {}
    custom_name = str(data.get("custom_name", "")).strip()
    custom_tags = str(data.get("custom_tags", "")).strip()
    notes = str(data.get("notes", "")).strip()

    ok = database.update_device_custom_info(config.db_path, mac, custom_name, custom_tags, notes)
    if ok:
        return jsonify({"success": True, "message": "Datos personalizados guardados correctamente."})
    return jsonify({"success": False, "error": "No se pudo actualizar el dispositivo."}), 400


@app.route("/api/devices/<mac>/acknowledge", methods=["POST"])
def api_acknowledge_device(mac):
    """Marca un nuevo dispositivo como reconocido/leído."""
    if not validate_mac(mac):
        return jsonify({"success": False, "error": "Formato de MAC no válido"}), 400

    ok = database.acknowledge_device(config.db_path, mac)
    return jsonify({"success": ok})


@app.route("/api/devices/acknowledge-all", methods=["POST"])
def api_acknowledge_all():
    """Marca todos los dispositivos nuevos como reconocidos."""
    count = database.acknowledge_all_devices(config.db_path)
    return jsonify({"success": True, "acknowledged_count": count})


# ============================================================================
# API DE ESCANEO Y MÉTRICAS
# ============================================================================

@app.route("/api/scan", methods=["POST"])
def api_trigger_scan():
    """Lanza un escaneo inmediato de la red."""
    if scanner.scanner_service.is_scanning:
        return jsonify({"success": False, "error": "Ya hay un escaneo en curso."}), 409

    result = scanner.scanner_service.trigger_scan_now()
    return jsonify({"success": result.get("status") == "success", "result": result})


@app.route("/api/scan/status", methods=["GET"])
def api_scan_status():
    """Consulta el estado del motor de escaneo."""
    net_ctx = scanner.detect_network_context()
    return jsonify({
        "success": True,
        "is_scanning": scanner.scanner_service.is_scanning,
        "last_scan_time": scanner.scanner_service.last_scan_time,
        "last_duration": scanner.scanner_service.last_scan_duration,
        "last_count": scanner.scanner_service.last_found_count,
        "network_context": net_ctx
    })


@app.route("/api/stats", methods=["GET"])
def api_get_stats():
    """Retorna métricas globales de la red y estado del sistema."""
    stats = database.get_stats(config.db_path)
    net_ctx = scanner.detect_network_context()
    router_driver = get_router_driver(config)
    
    return jsonify({
        "success": True,
        "stats": stats,
        "network": net_ctx,
        "read_only": config.read_only,
        "router_driver": {
            "name": router_driver.name,
            "capabilities": router_driver.get_capabilities()
        }
    })


@app.route("/api/history", methods=["GET"])
def api_get_history():
    """Obtiene el historial de eventos con filtros opcionales."""
    mac = request.args.get("mac", "").strip() or None
    event_type = request.args.get("event_type", "").strip() or None
    limit = int(request.args.get("limit", 100))

    history_records = database.get_history(config.db_path, limit, mac, event_type)
    return jsonify({
        "success": True,
        "count": len(history_records),
        "history": history_records
    })


# ============================================================================
# API DE GESTIÓN Y BLOQUEO AUTORIZADO DEL ROUTER
# ============================================================================

@app.route("/api/router/test", methods=["POST"])
def api_router_test():
    """Prueba la conexión y autenticación con la API del router configurado."""
    driver = get_router_driver(config)
    ok, msg = driver.test_connection()
    return jsonify({
        "success": ok,
        "message": msg,
        "driver_name": driver.name
    })


@app.route("/api/router/block", methods=["POST"])
def api_router_block():
    """
    Aplica una regla de bloqueo autorizada mediante la API del router.
    Requiere confirmación explícita y valida el modo de solo lectura.
    """
    # 1. Validación de seguridad: Modo de Solo Lectura por defecto
    if config.read_only:
        return jsonify({
            "success": False,
            "error": "Operación denegada: MangoRed está configurado en 'Modo Solo Lectura' por seguridad. "
                     "Para autorizar cambios en el router, desactiva el modo de solo lectura en la pestaña de Ajustes."
        }), 403

    data = request.get_json(silent=True) or {}
    mac = str(data.get("mac", "")).strip()
    confirmed = bool(data.get("confirmed", False))
    reason = str(data.get("reason", "Bloqueo administrativo autorizado por el usuario")).strip()

    # 2. Validación de confirmación explícita
    if not confirmed:
        return jsonify({
            "success": False,
            "error": "Se requiere confirmación explícita del usuario para ejecutar el bloqueo administrativo."
        }), 400

    # 3. Validación de dirección MAC
    if not validate_mac(mac):
        return jsonify({"success": False, "error": "Dirección MAC no válida."}), 400

    dev = database.get_device_by_mac(config.db_path, mac)
    if not dev:
        return jsonify({"success": False, "error": "Dispositivo no encontrado en el inventario."}), 404

    ip = dev.get("ip", "")
    hostname = dev.get("custom_name") or dev.get("hostname") or mac

    # 4. Ejecución mediante el controlador oficial del router
    driver = get_router_driver(config)
    ok, msg = driver.block_device(mac, ip, hostname)

    if ok:
        # Actualizar estado en la base de datos y registrar en auditoría
        database.set_device_blocked_state(config.db_path, mac, is_blocked=True, reason=reason)
        database.log_event(
            config.db_path, "blocked", mac, ip,
            f"Bloqueo administrativo aplicado en router ({driver.name}). Motivo: {reason}. Detalle: {msg}",
            severity="danger"
        )
        return jsonify({
            "success": True,
            "message": msg,
            "device": database.get_device_by_mac(config.db_path, mac)
        })
    else:
        return jsonify({
            "success": False,
            "error": f"Fallo al aplicar el bloqueo en el router: {msg}"
        }), 502


@app.route("/api/router/unblock", methods=["POST"])
def api_router_unblock():
    """Elimina la regla de bloqueo en el router."""
    if config.read_only:
        return jsonify({
            "success": False,
            "error": "Operación denegada: MangoRed está en 'Modo Solo Lectura'."
        }), 403

    data = request.get_json(silent=True) or {}
    mac = str(data.get("mac", "")).strip()

    if not validate_mac(mac):
        return jsonify({"success": False, "error": "Dirección MAC no válida."}), 400

    dev = database.get_device_by_mac(config.db_path, mac)
    if not dev:
        return jsonify({"success": False, "error": "Dispositivo no encontrado."}), 404

    driver = get_router_driver(config)
    ok, msg = driver.unblock_device(mac, dev.get("ip", ""))

    if ok:
        database.set_device_blocked_state(config.db_path, mac, is_blocked=False, reason="")
        database.log_event(
            config.db_path, "unblocked", mac, dev.get("ip", ""),
            f"Desbloqueo administrativo aplicado en router ({driver.name}). Detalle: {msg}",
            severity="success"
        )
        return jsonify({
            "success": True,
            "message": msg,
            "device": database.get_device_by_mac(config.db_path, mac)
        })
    else:
        return jsonify({
            "success": False,
            "error": f"Fallo al desbloquear en el router: {msg}"
        }), 502


@app.route("/api/guide", methods=["GET"])
def api_get_guide():
    """Retorna la guía de configuración y buenas prácticas."""
    return jsonify({
        "success": True,
        "guide": ROUTER_SETUP_GUIDE
    })


# ============================================================================
# API DE CONFIGURACIÓN DEL SISTEMA
# ============================================================================

@app.route("/api/config", methods=["GET"])
def api_get_config():
    """Retorna la configuración actual (con contraseñas enmascaradas)."""
    return jsonify({
        "success": True,
        "config": config.to_dict(hide_secrets=True)
    })


@app.route("/api/config", methods=["POST"])
def api_update_config():
    """Actualiza la configuración del sistema."""
    data = request.get_json(silent=True) or {}
    ok, msg = config.update_settings(data)
    if ok:
        return jsonify({
            "success": True,
            "message": msg,
            "config": config.to_dict(hide_secrets=True)
        })
    return jsonify({"success": False, "error": msg}), 400


# ============================================================================
# INICIALIZACIÓN
# ============================================================================

def init_app():
    """Inicializa la base de datos y arranca el servicio de escaneo de fondo."""
    database.init_db(config.db_path)
    scanner.scanner_service.start()


if __name__ == "__main__":
    init_app()
    # Ejecución local segura en 127.0.0.1
    print("==================================================================")
    print(" MangoRed - Monitor Doméstico de Red Local para Kali Linux")
    print(" Servidor web activo en: http://127.0.0.1:5000")
    print(" Modo Solo Lectura:", "ACTIVADO" if config.read_only else "DESACTIVADO")
    print("==================================================================")
    app.run(host="127.0.0.1", port=5000, debug=False)

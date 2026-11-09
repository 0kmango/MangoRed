"""
Motor de Escaneo y Descubrimiento de Red para MangoRed.

Descubre dispositivos conectados de forma no invasiva, pasiva y mediante
lectura de la tabla de vecinos ARP del sistema, complementada con un barrido
ICMP acotado únicamente dentro de la subred local.

Funciona en Linux, Windows y macOS gracias a :mod:`network_discovery`.
Garantiza la estricta distinción entre datos confirmados y estimados.
"""

from __future__ import annotations

import threading
import time
from typing import Dict, List, Optional

import database
import device_fingerprint
import name_resolver
import network_discovery
import oui_lookup
from config import config, validate_ip, validate_mac
from platform_compat import PLATFORM_LABEL, send_desktop_notification

#: Estados de la tabla de vecinos que confirman presencia en capa 2.
CONFIRMED_STATES = frozenset({"REACHABLE", "PERMANENT", "LOCAL_HOST", "STALE", "DELAY"})
SKIPPED_STATES = frozenset({"FAILED", "INCOMPLETE", "NOARP"})


def detect_network_context(preferred_interface: str = "") -> Dict[str, str]:
    """
    Detecta automáticamente la interfaz, IP local, máscara de subred,
    puerta de enlace y MAC local de forma multiplataforma.
    """
    interface = (preferred_interface or config.interface or "").strip()
    context = network_discovery.detect_network_context(interface)
    context["platform"] = PLATFORM_LABEL
    return context


def resolve_names(ips: List[str], timeout: float = 1.2) -> Dict[str, dict]:
    """
    Resuelve los nombres visibles de los equipos.

    Cascada DNS inverso → NetBIOS → mDNS (configurable en Ajustes). Devuelve
    ``{ip: {"name": str, "source": "dns"|"netbios"|"mdns"}}``.
    Siempre es un dato ESTIMADO: el nombre lo declara el propio dispositivo.
    """
    return name_resolver.resolve_names(
        ips,
        timeout=timeout,
        enable_netbios=config.enable_netbios_lookup,
        enable_mdns=config.enable_mdns_lookup,
    )


def resolve_hostnames(
    ips: List[str],
    timeout: float = 1.2,
    max_workers: int = 20,
) -> Dict[str, str]:
    """Compatibilidad: devuelve ``{ip: nombre}`` para una lista de IPs."""
    resolved = resolve_names(ips, timeout=timeout)
    return {ip: info.get("name", "") for ip, info in resolved.items()}


def resolve_hostname(ip: str, timeout: float = 1.2) -> str:
    """Compatibilidad: nombre visible de una única IP (o cadena vacía)."""
    if not validate_ip(ip):
        return ""
    return resolve_hostnames([ip], timeout=timeout).get(ip, "")


def send_new_device_notification(ip: str, mac: str, vendor: str, device_label: str = "") -> bool:
    """Notifica un dispositivo nuevo en el escritorio (Linux, Windows o macOS)."""
    details = f"IP: {ip}\nMAC: {mac}\nFabricante est.: {vendor}"
    if device_label:
        details += f"\nTipo est.: {device_label}"
    return send_desktop_notification(
        "MangoRed: ¡Nuevo dispositivo detectado!",
        details,
        enabled=config.enable_desktop_notifications,
    )


class NetworkScannerService:
    """Servicio de gestión del ciclo de vida del escaneo periódico."""

    def __init__(self):
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._scan_lock = threading.Lock()
        self.is_scanning = False
        self.last_scan_time: Optional[float] = None
        self.last_scan_duration: float = 0.0
        self.last_found_count: int = 0
        self.last_sweep: Dict[str, object] = {}

    def start(self):
        """Inicia el hilo de escaneo en segundo plano."""
        with self._lock:
            if self._running:
                return
            self._running = True
            self._thread = threading.Thread(
                target=self._worker_loop,
                daemon=True,
                name="MangoRedScannerThread",
            )
            self._thread.start()
            print(f"[Scanner Service] Hilo de supervisión iniciado ({PLATFORM_LABEL}).")

    def stop(self):
        """Detiene el hilo de escaneo."""
        with self._lock:
            self._running = False
            print("[Scanner Service] Señal de parada enviada.")

    def trigger_scan_now(self) -> dict:
        """Dispara un escaneo inmediato bajo demanda."""
        return self.execute_scan()

    def _worker_loop(self):
        """Bucle periódico en segundo plano."""
        # Escaneo inicial al arrancar
        try:
            self.execute_scan()
        except Exception as error:
            print(f"[Scanner Service] Error en el escaneo inicial: {error}")

        while self._running:
            interval = max(5, int(config.scan_interval))
            for _ in range(interval):
                if not self._running:
                    break
                time.sleep(1)

            if self._running and config.auto_scan:
                try:
                    self.execute_scan()
                except Exception as error:
                    print(f"[Scanner Service] Error en escaneo periódico: {error}")

    def execute_scan(self) -> dict:
        """
        Ejecuta una ronda completa de descubrimiento y actualización de la red.

        El acceso se serializa con un cerrojo no bloqueante para que dos
        peticiones simultáneas (botón manual + temporizador) no dupliquen
        trabajo ni corrompan el inventario.
        """
        if not self._scan_lock.acquire(blocking=False):
            return {"status": "busy", "message": "Ya hay un escaneo en curso."}

        self.is_scanning = True
        start_time = time.time()
        discovered_devices: List[dict] = []
        new_devices_found: List[dict] = []
        seen_macs: List[str] = []

        try:
            # 1. Contexto de red multiplataforma
            net_ctx = detect_network_context()
            interface = net_ctx.get("interface", "")
            subnet = net_ctx.get("subnet", "")
            gateway_ip = net_ctx.get("gateway", "")
            local_ip = net_ctx.get("local_ip", "")
            local_mac = net_ctx.get("local_mac", "")

            # 2. Barrido ICMP acotado (sólo en redes locales) para refrescar ARP
            sweep = network_discovery.ping_sweep(
                subnet,
                max_hosts=config.scan_max_hosts,
                timeout=1.0,
            )
            self.last_sweep = dict(sweep)

            # 3. Tabla de vecinos del sistema operativo
            neighbors = network_discovery.read_neighbor_table(interface, subnet)

            # 4. Incluir el propio equipo anfitrión si se conoce su IP y MAC
            if local_ip and validate_mac(local_mac):
                neighbors[local_ip] = {"mac": local_mac.lower(), "state": "LOCAL_HOST"}

            # 5. Nombres visibles (DNS → NetBIOS → mDNS) e inventario conocido
            names_map = resolve_names(list(neighbors.keys()))
            known_fingerprints = database.get_device_fingerprints(config.db_path)
            fingerprint_budget = max(0, int(config.fingerprint_max_devices))

            # 6. Procesar, identificar y clasificar cada dispositivo
            for ip, info in neighbors.items():
                mac = info.get("mac", "")
                state = str(info.get("state", "REACHABLE")).upper()

                if state in SKIPPED_STATES or not validate_mac(mac):
                    continue

                seen_macs.append(mac)
                name_info = names_map.get(ip, {}) or {}
                hostname = name_info.get("name", "") or ""
                name_source = name_info.get("source", "") or ""
                model = name_info.get("model", "") or ""
                mdns_services = name_info.get("services", []) or []
                oui_info = oui_lookup.lookup_vendor(mac)
                vendor_name = oui_info["vendor"]

                # Certeza de datos:
                #  - IP y MAC: confirmadas por la tabla de vecinos del kernel
                #  - Hostname, fabricante y tipo: estimaciones heurísticas
                is_confirmed_link = state in CONFIRMED_STATES

                # Huella del dispositivo: se repite sólo para equipos nuevos o
                # aún sin clasificar, y con un presupuesto máximo por escaneo.
                known = known_fingerprints.get(mac, {})
                needs_fingerprint = (
                    fingerprint_budget > 0
                    and known.get("device_type") in (None, "", "unknown")
                )
                if needs_fingerprint:
                    fingerprint = device_fingerprint.fingerprint_device(
                        ip,
                        hostname=hostname,
                        vendor=vendor_name,
                        is_gateway=(ip == gateway_ip),
                        is_local=(ip == local_ip),
                        local_os=PLATFORM_LABEL,
                        model=model,
                        mdns_services=mdns_services,
                        detect_services=config.enable_service_detection,
                    )
                    fingerprint_budget -= 1
                else:
                    fingerprint = device_fingerprint.classify_device(
                        hostname=hostname,
                        vendor=vendor_name,
                        is_gateway=(ip == gateway_ip),
                        is_local=(ip == local_ip),
                        local_os=PLATFORM_LABEL,
                        model=model,
                        mdns_services=mdns_services,
                    )

                custom_name_hint = ""
                custom_tags_hint = ""
                notes_hint = ""

                if ip == gateway_ip:
                    custom_name_hint = "Router / Puerta de Enlace"
                    custom_tags_hint = "Router,Infraestructura"
                    notes_hint = "Dispositivo de administración de red local (Gateway predeterminado)"
                elif ip == local_ip:
                    custom_name_hint = "Mi Equipo (MangoRed)"
                    custom_tags_hint = "Administrador,Local"
                    notes_hint = "Equipo actual desde donde se ejecuta MangoRed"

                device_payload = {
                    "mac": mac,
                    "ip": ip,
                    "hostname": hostname,
                    "vendor": vendor_name,
                    "status": "online" if is_confirmed_link else "stale",
                    "ip_confirmed": is_confirmed_link,
                    "mac_confirmed": is_confirmed_link,
                    "hostname_confirmed": False,   # Estimación (DNS/NetBIOS/mDNS)
                    "vendor_confirmed": False,     # Estimación OUI
                    "device_type": fingerprint["device_type"],
                    "device_type_confidence": fingerprint["confidence"],
                    "device_evidence": fingerprint["evidence"],
                    "os_guess": fingerprint["os_guess"],
                    "services": ", ".join(fingerprint.get("services", [])),
                    "name_source": name_source,
                    "model": model,
                }

                dev_record, is_first_seen = database.upsert_device(config.db_path, device_payload)

                if is_first_seen and (custom_name_hint or custom_tags_hint):
                    database.update_device_custom_info(
                        config.db_path, mac, custom_name_hint, custom_tags_hint, notes_hint
                    )
                    dev_record["custom_name"] = custom_name_hint
                    dev_record["custom_tags"] = custom_tags_hint

                discovered_devices.append(dev_record)

                if is_first_seen:
                    new_devices_found.append(dev_record)
                    send_new_device_notification(
                        ip, mac, vendor_name, fingerprint.get("device_type_label", "")
                    )

            # 7. Actualizar estado offline de los dispositivos ausentes
            database.mark_offline_unseen(
                config.db_path,
                seen_macs,
                timeout_seconds=max(60, int(config.scan_interval) * 2),
            )

            elapsed = round(time.time() - start_time, 2)
            self.last_scan_time = time.time()
            self.last_scan_duration = elapsed
            self.last_found_count = len(discovered_devices)

            return {
                "status": "success",
                "devices_found": len(discovered_devices),
                "new_devices_count": len(new_devices_found),
                "duration_seconds": elapsed,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.last_scan_time)),
                "platform": PLATFORM_LABEL,
                "sweep": dict(sweep),
            }

        except Exception as error:
            print(f"[Scanner Service] Error durante la ejecución del escaneo: {error}")
            return {
                "status": "error",
                "message": f"Fallo al ejecutar el escaneo: {error}",
            }
        finally:
            self.is_scanning = False
            self._scan_lock.release()


# Instancia global del servicio
scanner_service = NetworkScannerService()
"""
Motor de Escaneo y Descubrimiento de Red para MangoRed.
Descubre dispositivos conectados de forma no invasiva, pasiva y
mediante barrido ARP/ICMP no privilegiado o Scapy.
Garantiza la estricta distinción entre datos confirmados y estimados.
"""

import os
import re
import socket
import subprocess
import threading
import time
import ipaddress
import concurrent.futures
from typing import Dict, List, Optional, Tuple

import database
import oui_lookup
from config import config, validate_ip, validate_mac, normalize_mac


def detect_network_context() -> Dict[str, str]:
    """
    Detecta automáticamente la interfaz predeterminada, IP local,
    máscara de subred, puerta de enlace y MAC local.
    """
    context = {
        "interface": "wlan0",
        "local_ip": "",
        "local_mac": "",
        "subnet": "192.168.1.0/24",
        "gateway": "192.168.1.1"
    }

    # 1. Obtener interfaz y gateway predeterminados
    try:
        route_out = subprocess.run(["ip", "route"], capture_output=True, text=True, timeout=3)
        for line in route_out.stdout.splitlines():
            if line.startswith("default via"):
                parts = line.split()
                if len(parts) >= 5:
                    context["gateway"] = parts[2]
                    context["interface"] = parts[4]
                break
    except Exception as e:
        print(f"[Scanner Context] Advertencia al obtener ruta: {e}")

    # Si el usuario configuró una interfaz explícita, respetarla
    if config.interface:
        context["interface"] = config.interface

    # 2. Obtener IP local y subred de la interfaz
    try:
        addr_out = subprocess.run(
            ["ip", "-o", "-4", "addr", "show", "dev", context["interface"]],
            capture_output=True, text=True, timeout=3
        )
        for line in addr_out.stdout.splitlines():
            match = re.search(r"inet\s+([0-9\.]+/[0-9]+)", line)
            if match:
                cidr_str = match.group(1)
                net = ipaddress.ip_network(cidr_str, strict=False)
                context["subnet"] = str(net)
                context["local_ip"] = cidr_str.split("/")[0]
                break
    except Exception as e:
        print(f"[Scanner Context] Advertencia al obtener subred: {e}")

    # 3. Obtener MAC local
    try:
        link_out = subprocess.run(
            ["ip", "link", "show", "dev", context["interface"]],
            capture_output=True, text=True, timeout=3
        )
        match = re.search(r"link/ether\s+([0-9a-fA-F:]{17})", link_out.stdout)
        if match:
            context["local_mac"] = normalize_mac(match.group(1))
    except Exception as e:
        print(f"[Scanner Context] Advertencia al obtener MAC local: {e}")

    return context


def resolve_hostname(ip: str, timeout: float = 0.5) -> str:
    """
    Intenta resolver el nombre de host mediante DNS inverso / mDNS.
    Se clasifica SIEMPRE como dato estimado.
    """
    if not validate_ip(ip):
        return ""

    try:
        # socket.getnameinfo o gethostbyaddr con timeout
        orig_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        hostname, _, _ = socket.gethostbyaddr(ip)
        socket.setdefaulttimeout(orig_timeout)
        return hostname.strip()
    except Exception:
        return ""


def _ping_single_ip(ip_str: str) -> bool:
    """Envía un ping ICMP único (no privilegiado) con tiempo límite de 1 segundo."""
    try:
        res = subprocess.run(
            ["ping", "-c", "1", "-W", "1", ip_str],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=1.5
        )
        return res.returncode == 0
    except Exception:
        return False


def _trigger_arp_cache_refresh(subnet_cidr: str, max_workers: int = 50):
    """
    Realiza un barrido ligero de ping no intrusivo a través de la subred
    para forzar al kernel a resolver ARP en hosts activos.
    """
    try:
        network = ipaddress.ip_network(subnet_cidr, strict=False)
        # Limitar barrido a subredes /24 para no sobrecargar
        hosts = [str(ip) for ip in network.hosts()]
        if len(hosts) > 512:
            hosts = hosts[:512]

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            list(executor.map(_ping_single_ip, hosts))
    except Exception as e:
        print(f"[Scanner] Error en barrido de caché: {e}")


def _parse_kernel_neighbors(interface: str) -> Dict[str, Dict[str, str]]:
    """
    Lee las entradas de la tabla de vecinos del kernel (ip neigh y /proc/net/arp).
    Retorna un diccionario mapeado por IP: {ip: {mac, state}}
    """
    neighbors = {}

    # 1. Leer 'ip neigh show dev <interface>'
    try:
        cmd = ["ip", "neigh", "show"]
        if interface:
            cmd.extend(["dev", interface])
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=4)
        for line in out.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            # Formato: 192.168.1.12 dev wlan0 lladdr 00:e0:4c:68:2f:f6 REACHABLE
            if len(parts) >= 4 and "lladdr" in parts:
                ip = parts[0]
                lladdr_idx = parts.index("lladdr")
                if lladdr_idx + 1 < len(parts):
                    mac = parts[lladdr_idx + 1]
                    state = parts[-1]
                    if validate_ip(ip) and validate_mac(mac):
                        neighbors[ip] = {
                            "mac": normalize_mac(mac),
                            "state": state.upper()
                        }
    except Exception as e:
        print(f"[Scanner] Error leyendo ip neigh: {e}")

    # 2. Complementar con /proc/net/arp si no estaba presente
    try:
        if os.path.exists("/proc/net/arp"):
            with open("/proc/net/arp", "r", encoding="utf-8") as f:
                lines = f.readlines()[1:]  # Omitir cabecera
                for line in lines:
                    cols = line.split()
                    if len(cols) >= 6:
                        ip = cols[0]
                        flags = cols[2]
                        mac = cols[3]
                        if flags != "0x0" and validate_ip(ip) and validate_mac(mac):
                            clean_mac = normalize_mac(mac)
                            if ip not in neighbors:
                                neighbors[ip] = {
                                    "mac": clean_mac,
                                    "state": "REACHABLE"
                                }
    except Exception as e:
        print(f"[Scanner] Error leyendo /proc/net/arp: {e}")

    return neighbors


def _send_desktop_notification(title: str, message: str):
    """Emite una notificación de escritorio en Kali Linux mediante notify-send."""
    if not config.enable_desktop_notifications:
        return
    try:
        subprocess.Popen(
            ["notify-send", "-a", "MangoRed", "-u", "critical", "-i", "network-wireless", title, message],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
    except Exception:
        pass


class NetworkScannerService:
    """Servicio de gestión del ciclo de vida del escaneo periódico."""

    def __init__(self):
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self.is_scanning = False
        self.last_scan_time: Optional[float] = None
        self.last_scan_duration: float = 0.0
        self.last_found_count: int = 0

    def start(self):
        """Inicia el hilo de escaneo en segundo plano."""
        with self._lock:
            if self._running:
                return
            self._running = True
            self._thread = threading.Thread(target=self._worker_loop, daemon=True, name="MangoRedScannerThread")
            self._thread.start()
            print("[Scanner Service] Hilo de supervisión de red iniciado.")

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
        self.execute_scan()

        while self._running:
            interval = max(5, config.scan_interval)
            for _ in range(interval):
                if not self._running:
                    break
                time.sleep(1)

            if self._running and config.auto_scan:
                self.execute_scan()

    def execute_scan(self) -> dict:
        """
        Ejecuta una ronda completa de descubrimiento y actualización de la red.
        """
        if self.is_scanning:
            return {"status": "busy", "message": "Ya hay un escaneo en curso."}

        self.is_scanning = True
        start_time = time.time()
        discovered_devices = []
        new_devices_found = []
        seen_macs = []

        try:
            # 1. Obtener contexto de red
            net_ctx = detect_network_context()
            interface = net_ctx["interface"]
            subnet = net_ctx["subnet"]
            gateway_ip = net_ctx["gateway"]
            local_ip = net_ctx["local_ip"]
            local_mac = net_ctx["local_mac"]

            # 2. Refrescar tabla ARP del kernel mediante barrido
            _trigger_arp_cache_refresh(subnet)

            # 3. Leer vecinos identificados por el kernel
            neighbors = _parse_kernel_neighbors(interface)

            # 4. Incluir el propio equipo anfitrión si se conoce su IP y MAC
            if local_ip and local_mac:
                neighbors[local_ip] = {
                    "mac": local_mac,
                    "state": "LOCAL_HOST"
                }

            # 5. Resolver nombres de host en paralelo
            hostnames_map = {}
            ips_to_resolve = list(neighbors.keys())
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                resolved = list(executor.map(resolve_hostname, ips_to_resolve))
                for ip, hname in zip(ips_to_resolve, resolved):
                    hostnames_map[ip] = hname

            # 6. Procesar y clasificar cada dispositivo
            for ip, info in neighbors.items():
                mac = info["mac"]
                state = info["state"]

                # Omitir entradas fallidas del kernel
                if state in ["FAILED", "INCOMPLETE"]:
                    continue

                seen_macs.append(mac)
                hostname = hostnames_map.get(ip, "")
                oui_info = oui_lookup.lookup_vendor(mac)
                vendor_name = oui_info["vendor"]

                # Clasificación de certeza de datos:
                # - IP y MAC confirmadas por respuesta ARP/ICMP a nivel de enlace de datos
                # - Hostname y Fabricante son estimaciones heurísticas
                is_confirmed_link = state in ["REACHABLE", "PERMANENT", "LOCAL_HOST"]

                # Etiquetado descriptivo por defecto para router y host local
                custom_name_hint = ""
                custom_tags_hint = ""
                notes_hint = ""

                if ip == gateway_ip:
                    custom_name_hint = "Router / Puerta de Enlace"
                    custom_tags_hint = "Router,Infraestructura"
                    notes_hint = "Dispositivo de administración de red local (Gateway predeterminado)"
                elif ip == local_ip:
                    custom_name_hint = "Mi Equipo (Kali Linux)"
                    custom_tags_hint = "Administrador,Local"
                    notes_hint = "Equipo actual desde donde se ejecuta MangoRed"

                status_val = "online" if is_confirmed_link else "stale"

                device_payload = {
                    "mac": mac,
                    "ip": ip,
                    "hostname": hostname,
                    "vendor": vendor_name,
                    "status": status_val,
                    "ip_confirmed": is_confirmed_link,
                    "mac_confirmed": is_confirmed_link,
                    "hostname_confirmed": False,   # Estimación DNS
                    "vendor_confirmed": False      # Estimación OUI
                }

                # Guardar en base de datos
                dev_record, is_first_seen = database.upsert_device(config.db_path, device_payload)

                # Si es un dispositivo nuevo y tiene sugerencias de nombre (ej. Gateway o Local Host), asignarlas
                if is_first_seen and (custom_name_hint or custom_tags_hint):
                    database.update_device_custom_info(
                        config.db_path, mac, custom_name_hint, custom_tags_hint, notes_hint
                    )
                    dev_record["custom_name"] = custom_name_hint
                    dev_record["custom_tags"] = custom_tags_hint

                discovered_devices.append(dev_record)

                if is_first_seen:
                    new_devices_found.append(dev_record)
                    # Notificación de escritorio si está habilitada
                    _send_desktop_notification(
                        "MangoRed: ¡Nuevo dispositivo detectado!",
                        f"IP: {ip}\nMAC: {mac}\nFabricante est.: {vendor_name}"
                    )

            # 7. Actualizar estado offline de los dispositivos ausentes
            database.mark_offline_unseen(config.db_path, seen_macs, timeout_seconds=max(60, config.scan_interval * 2))

            elapsed = round(time.time() - start_time, 2)
            self.last_scan_time = time.time()
            self.last_scan_duration = elapsed
            self.last_found_count = len(discovered_devices)

            return {
                "status": "success",
                "devices_found": len(discovered_devices),
                "new_devices_count": len(new_devices_found),
                "duration_seconds": elapsed,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.last_scan_time))
            }

        except Exception as e:
            print(f"[Scanner Service] Error durante la ejecución del escaneo: {e}")
            return {
                "status": "error",
                "message": f"Fallo al ejecutar el escaneo: {str(e)}"
            }
        finally:
            self.is_scanning = False


# Instancia global del servicio
scanner_service = NetworkScannerService()

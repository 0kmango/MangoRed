"""
Vigilancia en tiempo real de conexiones y desconexiones en MangoRed.

Complementa al escáner periódico: en lugar de esperar al siguiente escaneo
completo, lee la **tabla de vecinos ARP** cada pocos segundos (sin ping ni
barridos) y emite un evento en el momento en que un equipo aparece o desaparece.

Diseño:
  * La primera pasada es sólo de referencia (*baseline*): no notifica nada.
  * Sólo se escribe en la base de datos y se notifica cuando hay un **cambio de
    estado**, no en cada sondeo.
  * La desconexión requiere superar una **gracia** configurable, porque el
    kernel expira entradas ARP de equipos inactivos (evita falsos positivos).
  * Los eventos se guardan en un búfer circular en memoria con un ``id``
    incremental para que el panel los pida con ``?since=<id>``.

Este módulo es 100 % defensivo: no envía tráfico a los equipos, no modifica la
red y no usa sockets privilegiados.
"""

from __future__ import annotations

import concurrent.futures
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

import database
import network_discovery
import oui_lookup
from config import config
from platform_compat import send_desktop_notification

#: Máximo de eventos conservados en memoria para el panel.
MAX_EVENTS = 200

#: Intervalo mínimo de sondeo (segundos).
MIN_INTERVAL = 2


class DeviceEventWatcher:
    """Sondea la tabla de vecinos y emite eventos de conexión/desconexión."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._events: deque = deque(maxlen=MAX_EVENTS)
        self._seq = 0
        self._known: Dict[str, dict] = {}
        self._baseline = False
        self.last_poll: Optional[float] = None
        self.last_error = ""
        self.poll_count = 0
        self.last_seen_count = 0

    # ------------------------------------------------------------------
    # Ciclo de vida
    # ------------------------------------------------------------------
    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        """Inicia el hilo de vigilancia (idempotente)."""
        with self._lock:
            if self.running:
                return
            self._stop.clear()
            self._thread = threading.Thread(
                target=self._loop, daemon=True, name="MangoRedWatcher"
            )
            self._thread.start()
            print("[Watcher] Vigilancia en tiempo real iniciada.")

    def stop(self) -> None:
        """Detiene el hilo de vigilancia."""
        self._stop.set()
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=3)

    def reset(self) -> None:
        """Olvida el estado observado (útil al cambiar de interfaz de red)."""
        with self._lock:
            self._known.clear()
            self._baseline = False

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.poll_once()
            except Exception as error:  # nunca debe tumbar el hilo
                self.last_error = str(error)
                print(f"[Watcher] Error en el sondeo: {error}")
            interval = max(MIN_INTERVAL, int(getattr(config, "watch_interval", 5)))
            self._stop.wait(interval)

    # ------------------------------------------------------------------
    # Sondeo
    # ------------------------------------------------------------------
    def poll_once(self) -> dict:
        """
        Lee la tabla de vecinos y genera eventos para los cambios detectados.

        Devuelve un resumen del sondeo (equipos vistos, conocidos, baseline).
        """
        context = network_discovery.detect_network_context(config.interface)
        neighbors = network_discovery.read_neighbor_table(
            context.get("interface", ""), context.get("subnet", "")
        )

        now = time.time()
        seen = set()
        appear: List[Tuple[str, str]] = []
        stale: List[Tuple[str, str]] = []
        already_baselined = self._baseline

        with self._lock:
            # La primera pasada sólo inventaría: los eventos se emiten a partir
            # del segundo sondeo para no notificar toda la red al arrancar.
            for ip, info in neighbors.items():
                mac = info.get("mac", "")
                if not mac:
                    continue
                seen.add(mac)
                record = self._known.get(mac)
                if record is None:
                    self._known[mac] = {"ip": ip, "last_seen": now, "online": True}
                    if already_baselined:
                        appear.append((mac, ip))
                else:
                    record["ip"] = ip
                    record["last_seen"] = now
                    if not record["online"]:
                        record["online"] = True
                        if already_baselined:
                            appear.append((mac, ip))

            grace = self._effective_grace()
            for mac, record in self._known.items():
                if mac in seen or not record["online"]:
                    continue
                if now - record["last_seen"] >= grace:
                    # Candidato a desconexión: se confirmará con un ICMP puntual
                    stale.append((mac, record.get("ip", "")))

            self._baseline = True
            self.last_poll = now
            self.poll_count += 1
            self.last_seen_count = len(seen)

        # I/O fuera del cerrojo (no bloquea al panel)
        gone = self._confirm_missing(stale)

        for mac, ip in appear:
            self._handle_appear(mac, ip)
        if already_baselined:
            for mac, ip in gone:
                self._handle_disappear(mac, ip)

        return {
            "seen": len(seen),
            "known": len(self._known),
            "baseline": self._baseline,
            "interval": max(MIN_INTERVAL, int(getattr(config, "watch_interval", 5))),
            "confirmed_offline": len(gone),
        }

    def _effective_grace(self) -> int:
        """
        Gracia efectiva antes de declarar una desconexión.

        Se toma el mayor de: valor configurado y dos intervalos de escaneo. Así
        el barrido periódico (que refresca las entradas ARP) siempre llega antes
        de que caduque una entrada del kernel.
        """
        configured = int(getattr(config, "disconnect_grace", 60))
        scan_interval = int(getattr(config, "scan_interval", 30))
        return max(15, configured, scan_interval * 2)

    def _confirm_missing(self, candidates: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
        """
        Confirma con un único ICMP por equipo si realmente ha desaparecido.

        La tabla ARP del kernel caduca entradas de equipos inactivos, por lo que
        la ausencia en ARP **no** implica desconexión. Sólo se declara
        desconectado el equipo que tampoco responde a un ping puntual.
        """
        if not candidates:
            return []

        def probe(item: Tuple[str, str]) -> Tuple[str, str, bool]:
            mac, ip = item
            alive = bool(ip) and network_discovery.ping_host(ip, timeout=0.6)
            return mac, ip, alive

        gone: List[Tuple[str, str]] = []
        workers = max(1, min(8, len(candidates)))
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
                for mac, ip, alive in executor.map(probe, candidates):
                    with self._lock:
                        record = self._known.get(mac)
                        if record is None:
                            continue
                        if alive:
                            record["last_seen"] = time.time()
                            record["online"] = True
                        else:
                            record["online"] = False
                            gone.append((mac, ip))
        except Exception as error:
            self.last_error = str(error)
        return gone

    # ------------------------------------------------------------------
    # Manejadores de estado
    # ------------------------------------------------------------------
    def _handle_appear(self, mac: str, ip: str) -> None:
        """Procesa un equipo que acaba de aparecer en la red."""
        try:
            existing = database.get_device_by_mac(config.db_path, mac)
            was_online = bool(existing and existing.get("status") in ("online", "stale"))
            vendor = oui_lookup.lookup_vendor(mac)["vendor"]

            device, is_new = database.upsert_device(config.db_path, {
                "mac": mac,
                "ip": ip,
                "status": "online",
                "vendor": vendor,
            })
        except Exception as error:
            self.last_error = str(error)
            return

        # Si ya estaba en línea no se genera ruido (el escáner mantiene el estado)
        if not is_new and was_online:
            return

        name = device.get("custom_name") or device.get("hostname") or mac
        label = device.get("device_type_label") or ""
        suffix = f" · {label}" if label and label != "Desconocido" else ""

        if is_new:
            self.push("new_device", device,
                      f"Nuevo dispositivo conectado: {name} ({ip}){suffix}", "warning")
            send_desktop_notification(
                "MangoRed: nuevo dispositivo",
                f"{name}\nIP: {ip}\nMAC: {mac}\nTipo: {label or 'Desconocido'}",
                enabled=config.enable_desktop_notifications,
            )
        else:
            self.push("connected", device,
                      f"El dispositivo '{name}' se ha vuelto a conectar ({ip}){suffix}", "success")
            send_desktop_notification(
                "MangoRed: dispositivo conectado",
                f"{name}\nIP: {ip}\nMAC: {mac}",
                enabled=config.enable_desktop_notifications,
            )

    def _handle_disappear(self, mac: str, ip: str) -> None:
        """Procesa un equipo que ha dejado de estar presente."""
        try:
            device = database.set_device_offline(config.db_path, mac)
        except Exception as error:
            self.last_error = str(error)
            return
        if not device:
            return

        name = device.get("custom_name") or device.get("hostname") or mac
        self.push("disconnected", device,
                  f"El dispositivo '{name}' se ha desconectado ({ip or device.get('ip', '')})",
                  "danger")
        send_desktop_notification(
            "MangoRed: dispositivo desconectado",
            f"{name}\nIP: {ip or device.get('ip', '')}\nMAC: {mac}",
            enabled=config.enable_desktop_notifications,
        )

    # ------------------------------------------------------------------
    # Búfer de eventos
    # ------------------------------------------------------------------
    def push(self, event_type: str, device: dict, message: str, severity: str = "info") -> dict:
        """Añade un evento al búfer circular y devuelve el evento creado."""
        with self._lock:
            self._seq += 1
            event = {
                "id": self._seq,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": event_type,
                "mac": device.get("mac", ""),
                "ip": device.get("ip", ""),
                "name": (device.get("custom_name") or device.get("hostname")
                         or device.get("mac", "")),
                "device_type": device.get("device_type", "unknown"),
                "device_type_label": device.get("device_type_label", ""),
                "severity": severity,
                "message": message,
            }
            self._events.append(event)
            return event

    def events_since(self, since_id: int = 0) -> Tuple[List[dict], int]:
        """Devuelve los eventos con ``id`` mayor que ``since_id`` y el último id."""
        try:
            threshold = int(since_id)
        except (TypeError, ValueError):
            threshold = 0
        with self._lock:
            pending = [event for event in self._events if event["id"] > threshold]
            return pending, self._seq

    def status(self) -> dict:
        """Estado del vigilante para el panel y ``/api/health``."""
        with self._lock:
            return {
                "running": self.running,
                "baseline_done": self._baseline,
                "known_devices": len(self._known),
                "last_poll": self.last_poll,
                "poll_count": self.poll_count,
                "seen_last_poll": self.last_seen_count,
                "latest_event_id": self._seq,
                "interval": max(MIN_INTERVAL, int(getattr(config, "watch_interval", 5))),
                "grace_seconds": self._effective_grace(),
                "last_error": self.last_error,
            }


#: Instancia global del vigilante.
device_watcher = DeviceEventWatcher()
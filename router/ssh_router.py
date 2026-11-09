"""
Controlador real por SSH para routers OpenWrt y routers Linux genéricos.

Es la vía de bloqueo más universal: no necesita la API REST de MikroTik ni
ubus/LuCI, sólo un servidor SSH accesible y un usuario con permisos de
administración (en OpenWrt, ``root``).

Perfiles soportados:
  * ``openwrt``  → crea una regla en ``/etc/config/firewall`` con ``uci``
    (``src_mac`` + ``target=DROP``) y recarga el cortafuegos.
  * ``iptables`` → crea la cadena ``MANGORED`` y añade un ``DROP`` por MAC.
    Compatible con cualquier router Linux (Debian, Alpine, DD-WRT…).

Efecto real: el tráfico del equipo **que pasa por el router** (Internet y otras
redes) deja de reenviarse. No se desconecta al equipo del Wi-Fi a nivel de radio
(para eso hace falta el filtro MAC del AP) ni se le envía tráfico alguno.

Seguridad: la MAC se valida y se normaliza antes de construir el comando, los
comandos son plantillas fijas (sin interpolar texto libre) y la clave de host SSH
se verifica salvo que se autorice explícitamente lo contrario.
"""

from __future__ import annotations

import os
import concurrent.futures
import socket
from typing import Any, Dict, List, Tuple

from config import normalize_mac, validate_mac
from platform_compat import run_command, which
from .base import BaseRouterDriver

#: Perfiles de comandos disponibles.
SSH_PROFILES = ("openwrt", "iptables")

#: Puertos de administración que se comprueban en el diagnóstico del router.
ROUTER_ADMIN_PORTS = (
    (22, "ssh"),
    (80, "http"),
    (443, "https"),
    (8728, "mikrotik_api"),
    (8291, "winbox"),
)

#: Nombres legibles para el panel.
ROUTER_PORT_LABELS = {
    "ssh": "SSH (22)",
    "http": "Interfaz web HTTP (80)",
    "https": "Interfaz web HTTPS (443)",
    "mikrotik_api": "API MikroTik (8728)",
    "winbox": "Winbox (8291)",
}


def tcp_port_open(host: str, port: int, timeout: float = 0.8) -> bool:
    """Comprueba si un puerto TCP acepta conexión (sin enviar datos)."""
    if not host:
        return False
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(max(0.2, float(timeout)))
        return sock.connect_ex((str(host).strip(), int(port))) == 0
    except (OSError, ValueError):
        return False
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def probe_router_ports(host: str, timeout: float = 0.8) -> Dict[str, bool]:
    """Devuelve qué servicios de administración responde el router (en paralelo)."""
    if not host:
        return {}

    results: Dict[str, bool] = {name: False for _port, name in ROUTER_ADMIN_PORTS}
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(ROUTER_ADMIN_PORTS)) as pool:
            futures = {
                pool.submit(tcp_port_open, host, port, timeout): name
                for port, name in ROUTER_ADMIN_PORTS
            }
            for future in concurrent.futures.as_completed(futures, timeout=timeout + 2):
                name = futures[future]
                try:
                    results[name] = bool(future.result())
                except Exception:
                    results[name] = False
    except Exception:
        pass
    return results


def describe_open_ports(ports: Dict[str, bool]) -> str:
    """Lista legible de los servicios detectados (o aviso si no hay ninguno)."""
    detected = [ROUTER_PORT_LABELS.get(name, name) for name, is_open in ports.items() if is_open]
    return ", ".join(detected) if detected else "ninguno"


def suggest_router_action(ports: Dict[str, bool]) -> str:
    """Recomendación según los puertos accesibles en el router."""
    if not ports:
        return "Indica la IP del router en Ajustes y comprueba que estás en su red."
    if ports.get("ssh"):
        return (
            "El SSH responde: revisa usuario, contraseña/clave y la clave de host. "
            "Si falla el login, el controlador SSH es el adecuado."
        )
    if ports.get("mikrotik_api"):
        return "La API de MikroTik responde en 8728: usa el controlador MikroTik (REST)."
    if ports.get("http") or ports.get("https"):
        return (
            "El router sólo responde en su interfaz web (sin SSH/API). Usa el bloqueo "
            "manual desde la pestaña Guía (filtro MAC del AP) o un webhook local."
        )
    return (
        "No se detectan servicios de administración. Verifica la IP del router, que "
        "estés conectado a su red y que no haya aislamiento de clientes."
    )


class SSHRouterDriver(BaseRouterDriver):
    """Bloqueo real de Internet ejecutando reglas de firewall vía SSH."""

    @property
    def name(self) -> str:
        return "SSH del Router (OpenWrt / Linux) — corta Internet"

    @property
    def description(self) -> str:
        return (
            "Ejecuta reglas de cortafuegos en el router mediante SSH (uci en OpenWrt o "
            "iptables en routers Linux). Es un bloqueo administrativo real: el equipo "
            "afectado pierde el acceso a Internet a través del router."
        )

    # ------------------------------------------------------------------
    # Configuración derivada
    # ------------------------------------------------------------------
    @property
    def ssh_port(self) -> int:
        try:
            value = int(getattr(self.config, "router_ssh_port", 22))
        except (TypeError, ValueError):
            value = 22
        return max(1, min(65535, value))

    @property
    def profile(self) -> str:
        value = str(getattr(self.config, "router_ssh_profile", "openwrt")).strip().lower()
        return value if value in SSH_PROFILES else "openwrt"

    @property
    def private_key(self) -> str:
        path = str(getattr(self.config, "router_ssh_key", "") or "").strip()
        if not path:
            return ""
        return os.path.expanduser(path)

    @property
    def accept_new_host_key(self) -> bool:
        return bool(getattr(self.config, "router_ssh_accept_new_host_key", False))

    @property
    def block_mode(self) -> str:
        """``full`` = expulsa del Wi-Fi + corta Internet; ``internet`` = sólo Internet."""
        value = str(getattr(self.config, "router_block_mode", "full")).strip().lower()
        return value if value in ("full", "internet") else "full"

    @staticmethod
    def rule_name(clean_mac: str) -> str:
        """Nombre de sección/regla derivado de la MAC (sólo ``[a-z0-9_]``)."""
        return "mangored_" + clean_mac.replace(":", "")

    @staticmethod
    def _marker(output: str, key: str) -> str:
        """Extrae un marcador ``CLAVE=valor`` de la salida del router."""
        for line in (output or "").splitlines():
            line = line.strip()
            if line.startswith(key + "="):
                return line.split("=", 1)[1].strip()
        return ""

    def _marker_count(self, output: str, key: str) -> int:
        try:
            return max(0, int(self._marker(output, key) or 0))
        except ValueError:
            return 0

    # ------------------------------------------------------------------
    # Construcción de comandos (funciones puras y testables)
    # ------------------------------------------------------------------
    def build_commands(self, action: str, clean_mac: str = "") -> List[str]:
        """
        Devuelve la lista de comandos para ``test``, ``block`` o ``unblock``.

        La MAC debe llegar ya normalizada; aun así se revalida para impedir
        cualquier intento de inyección de comandos.
        """
        if action not in {"test", "block", "unblock"}:
            raise ValueError(f"Acción SSH no soportada: {action}")

        if action == "test":
            if self.profile == "openwrt":
                return [
                    "uname -sr",
                    "uci -q get system.@system[0].hostname || true",
                    "command -v hostapd_cli || true",
                    "command -v iw || true",
                ]
            return [
                "uname -sr",
                "id -un",
                "command -v iptables || true",
                "command -v hostapd_cli || true",
            ]

        if not validate_mac(clean_mac):
            raise ValueError(f"MAC inválida para SSH: {clean_mac}")

        mac = normalize_mac(clean_mac).upper()
        section = self.rule_name(mac.lower())

        if self.profile == "openwrt":
            return self._openwrt_commands(action, mac, section)
        return self._iptables_commands(action, mac)

    def build_script(self, action: str, clean_mac: str = "") -> str:
        """Une los comandos en un script de shell para una única sesión SSH."""
        return "\n".join(self.build_commands(action, clean_mac))

    def _openwrt_wifi_commands(self, mac: str, add: bool) -> List[str]:
        """
        Lista negra Wi-Fi del AP gestionada por OpenWrt.

        Añade o quita la MAC de ``maclist`` en cada ``wifi-iface`` y, al bloquear,
        ordena a hostapd que expulse al cliente en el acto. Es la función
        administrativa oficial del punto de acceso, no un ataque de deauth.
        """
        if add:
            mutate = (
                "uci set $s.macfilter='deny'; "
                f"uci add_list $s.maclist='{mac}' 2>/dev/null || true; "
            )
        else:
            mutate = f"uci del_list $s.maclist='{mac}' 2>/dev/null || true; "

        commands = [
            "for s in $(uci show wireless 2>/dev/null "
            "| sed -n \"s/^\\(wireless\\.[^=]*\\)=wifi-iface$/\\1/p\"); do "
            + mutate
            + "done; uci commit wireless >/dev/null 2>&1; "
            "wifi reload >/dev/null 2>&1 || true",
        ]
        if add:
            commands.append(
                "for i in $(iw dev 2>/dev/null | awk '/Interface/{{print $2}}'); do "
                f"hostapd_cli -i $i deauthenticate {mac} >/dev/null 2>&1 || true; done"
            )
        return commands

    def _openwrt_commands(self, action: str, mac: str, section: str) -> List[str]:
        if action == "block":
            commands = [
                f"uci -q delete firewall.{section} >/dev/null 2>&1 || true",
                f"uci set firewall.{section}=rule",
                f"uci set firewall.{section}.name='{section}'",
                f"uci set firewall.{section}.src='lan'",
                f"uci set firewall.{section}.src_mac='{mac}'",
                f"uci set firewall.{section}.proto='all'",
                f"uci set firewall.{section}.target='DROP'",
                f"uci set firewall.{section}.enabled='1'",
                "uci commit firewall",
                "/etc/init.d/firewall reload >/dev/null 2>&1 || true",
            ]
            if self.block_mode == "full":
                commands.extend(self._openwrt_wifi_commands(mac, add=True))
            commands.append(f"echo MANGORED_FIREWALL=$(uci -q get firewall.{section}.target)")
            if self.block_mode == "full":
                commands.append(
                    "echo MANGORED_WIFI=$(uci show wireless 2>/dev/null "
                    f"| grep -c \"maclist='{mac}'\" || true)"
                )
            else:
                commands.append("echo MANGORED_WIFI=0")
            return commands

        commands = [
            f"uci -q delete firewall.{section} >/dev/null 2>&1 || true",
            "uci commit firewall",
            "/etc/init.d/firewall reload >/dev/null 2>&1 || true",
        ]
        commands.extend(self._openwrt_wifi_commands(mac, add=False))
        commands.extend([
            f"echo MANGORED_FIREWALL=$(uci -q get firewall.{section} "
            ">/dev/null 2>&1 && echo PRESENT || echo REMOVED)",
            "echo MANGORED_WIFI=$(uci show wireless 2>/dev/null "
            f"| grep -c \"maclist='{mac}'\" || true)",
        ])
        return commands

    def _iptables_commands(self, action: str, mac: str) -> List[str]:
        """
        Perfil ``iptables``: cadena dedicada ``MANGORED`` (FORWARD) y, en modo
        completo, ``MANGORED_IN`` (INPUT) para que el equipo tampoco alcance los
        servicios del router (DHCP/DNS). El Wi-Fi se intenta con hostapd si está.
        """
        if action == "block":
            commands = [
                "iptables -N MANGORED 2>/dev/null || true",
                "iptables -C FORWARD -j MANGORED 2>/dev/null || iptables -I FORWARD 1 -j MANGORED",
                f"iptables -C MANGORED -m mac --mac-source {mac} -j DROP 2>/dev/null || "
                f"iptables -A MANGORED -m mac --mac-source {mac} -j DROP",
            ]
            if self.block_mode == "full":
                commands.extend([
                    "iptables -N MANGORED_IN 2>/dev/null || true",
                    "iptables -C INPUT -j MANGORED_IN 2>/dev/null "
                    "|| iptables -I INPUT 1 -j MANGORED_IN",
                    f"iptables -C MANGORED_IN -m mac --mac-source {mac} -j DROP 2>/dev/null || "
                    f"iptables -A MANGORED_IN -m mac --mac-source {mac} -j DROP",
                    # Expulsión inmediata si el propio equipo es el punto de acceso
                    "w=0; for i in $(iw dev 2>/dev/null | awk '/Interface/{{print $2}}'); do "
                    f"if hostapd_cli -i $i deauthenticate {mac} >/dev/null 2>&1; "
                    "then w=$((w+1)); fi; done; echo MANGORED_WIFI=$w",
                ])
            commands.append(
                "echo MANGORED_FIREWALL=$(iptables -S MANGORED 2>/dev/null "
                f"| grep -qi -- '--mac-source {mac}' && echo DROP || echo MISSING)"
            )
            if self.block_mode != "full":
                commands.append("echo MANGORED_WIFI=0")
            return commands

        return [
            f"while iptables -D MANGORED -m mac --mac-source {mac} -j DROP 2>/dev/null; do :; done",
            f"while iptables -D MANGORED_IN -m mac --mac-source {mac} -j DROP 2>/dev/null; do :; done",
            "echo MANGORED_FIREWALL=$(iptables -C MANGORED "
            f"-m mac --mac-source {mac} -j DROP 2>/dev/null && echo PRESENT || echo REMOVED)",
            "echo MANGORED_WIFI=0",
        ]

    # ------------------------------------------------------------------
    # Transporte SSH
    # ------------------------------------------------------------------
    def _connect(self):
        """Crea un cliente paramiko (si está instalado) o devuelve ``None``."""
        try:
            import paramiko  # type: ignore
        except ImportError:
            return None

        client = paramiko.SSHClient()
        try:
            client.load_system_host_keys()
        except Exception:
            pass

        if self.accept_new_host_key:
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        else:
            client.set_missing_host_key_policy(paramiko.RejectPolicy())

        client.connect(
            str(self.config.router_host).strip(),
            port=self.ssh_port,
            username=str(self.config.router_user or "root"),
            password=str(self.config.router_password or "") or None,
            key_filename=self.private_key or None,
            timeout=self.timeout,
            banner_timeout=self.timeout,
            auth_timeout=self.timeout,
            allow_agent=False,
            look_for_keys=False,
        )
        return client

    def _describe_connection_error(self, error: Exception) -> str:
        """Traduce los errores típicos de SSH a mensajes accionables."""
        text = str(error)
        lowered = text.lower()

        if "not found in known_hosts" in lowered or "unknown server" in lowered:
            return (
                "Clave de host SSH desconocida. Añádela a ~/.ssh/known_hosts "
                "(ssh-keyscan) o activa 'Aceptar clave de host nueva' en Ajustes."
            )
        if "authentication" in lowered or "auth fail" in lowered:
            return "Autenticación SSH fallida: revisa usuario, contraseña o clave privada."
        if "timed out" in lowered or isinstance(error, (socket.timeout, TimeoutError)):
            return self._unreachable_message()
        if "refused" in lowered:
            return (
                f"El router rechazó la conexión SSH en el puerto {self.ssh_port} "
                "(servicio deshabilitado o puerto incorrecto). "
                + self._unreachable_message()
            )
        if isinstance(error, OSError):
            return f"No se pudo conectar por SSH con el router: {text[:200]}"
        return f"Error de SSH: {text[:200]}"

    def _ssh_reachable(self) -> bool:
        """Comprueba el puerto SSH antes de intentar el handshake completo."""
        return tcp_port_open(
            str(self.config.router_host).strip(),
            self.ssh_port,
            timeout=min(1.5, float(self.timeout)),
        )

    def _unreachable_message(self) -> str:
        """Mensaje de diagnóstico cuando el router no acepta SSH."""
        host = str(self.config.router_host).strip()
        try:
            ports = probe_router_ports(host)
        except Exception:
            ports = {}

        return (
            f"No se puede conectar por SSH a {host}:{self.ssh_port} "
            f"(puerto cerrado o filtrado). Servicios detectados en el router: "
            f"{describe_open_ports(ports)}. "
            f"{suggest_router_action(ports)} "
            "Si el router no tiene SSH (habitual en ONT de operadora), el bloqueo "
            "real se aplica desde su interfaz web con el filtro MAC (pestaña Guía)."
        )

    def _run(self, script: str) -> Tuple[bool, str]:
        """Ejecuta un script en el router y devuelve ``(ok, salida)``."""
        if not self.config.router_host:
            return False, "Configura primero la dirección IP de tu router (SSH)."

        # Comprobación previa del puerto: falla en ~1 s con un motivo claro en
        # lugar de esperar al timeout de SSH cuando está cerrado o filtrado.
        if not self._ssh_reachable():
            return False, self._unreachable_message()

        try:
            client = self._connect()
        except Exception as error:  # incluye BadHostKey / Authentication
            return False, self._describe_connection_error(error)

        if client is not None:
            try:
                _stdin, stdout, stderr = client.exec_command(script, timeout=self.timeout)
                output = stdout.read().decode("utf-8", "ignore").strip()
                error_output = stderr.read().decode("utf-8", "ignore").strip()
                code = stdout.channel.recv_exit_status()
                if code != 0:
                    return False, (error_output or output or f"SSH devolvió el código {code}")[:300]
                return True, output[:300]
            except Exception as error:
                return False, f"Error ejecutando comandos por SSH: {error}"
            finally:
                try:
                    client.close()
                except Exception:
                    pass

        # Sin paramiko: se usa el cliente OpenSSH del sistema (sólo clave)
        if not which("ssh"):
            return False, (
                "No hay cliente SSH disponible. Instala paramiko (pip install paramiko) "
                "o el cliente OpenSSH."
            )
        if self.config.router_password and not self.private_key:
            return False, (
                "La autenticación por contraseña requiere paramiko "
                "(pip install paramiko). Alternativamente, configura una clave SSH privada."
            )

        command = ["ssh", "-p", str(self.ssh_port), "-o", "BatchMode=yes",
                   "-o", f"ConnectTimeout={self.timeout}", "-o", "StrictHostKeyChecking=yes"]
        if self.private_key:
            command.extend(["-i", self.private_key])
        command.extend([
            f"{self.config.router_user or 'root'}@{str(self.config.router_host).strip()}",
            script,
        ])
        result = run_command(command, timeout=self.timeout + 10)
        if result is None:
            return False, "No se pudo ejecutar ssh (¿está instalado el cliente OpenSSH?)."
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip()
            return False, (detail or f"ssh devolvió el código {result.returncode}")[:300]
        return True, (result.stdout or "").strip()[:300]

    # ------------------------------------------------------------------
    # Interfaz pública del controlador
    # ------------------------------------------------------------------
    def test_connection(self) -> Tuple[bool, str]:
        if not self.config.router_host:
            return False, "Configura primero la dirección IP de tu router (SSH)."

        ok, output = self._run(self.build_script("test"))
        if not ok:
            return False, output

        lowered = output.lower()
        if self.profile == "iptables" and "iptables" not in lowered:
            return False, (
                "Conexión SSH correcta, pero el router no tiene 'iptables' disponible. "
                "Usa el perfil OpenWrt (uci) o instala iptables en el router."
            )

        wifi = "hostapd_cli" in lowered
        first_line = output.splitlines()[0] if output else "sin salida"
        mode = "expulsión Wi-Fi + Internet" if self.block_mode == "full" else "sólo Internet"
        return True, (
            f"Conexión SSH correcta ({first_line}). Perfil: {self.profile}. "
            f"Modo de bloqueo: {mode}. Control Wi-Fi (hostapd): {'sí' if wifi else 'no detectado'}."
        )

    def block_device(self, mac: str, ip: str = "", hostname: str = "") -> Tuple[bool, str]:
        if not validate_mac(mac):
            return False, f"MAC inválida: {mac}"
        if not self.config.router_host:
            return False, "Configura primero la dirección IP de tu router (SSH)."

        clean = normalize_mac(mac)
        ok, output = self._run(self.build_script("block", clean))
        if not ok:
            return False, f"El router rechazó el bloqueo por SSH: {output}"

        firewall = self._marker(output, "MANGORED_FIREWALL").upper()
        wifi_count = self._marker_count(output, "MANGORED_WIFI")

        if firewall != "DROP":
            return False, (
                "La regla de cortafuegos no se pudo verificar (target != DROP). "
                f"Salida del router: {output or 'vacía'}"
            )

        if self.block_mode == "full":
            if wifi_count:
                detail = (
                    f"Equipo desconectado de la red: expulsado del Wi-Fi (lista MAC en "
                    f"{wifi_count} interfaz(es) del AP) y sin acceso a Internet."
                )
            else:
                detail = (
                    "Equipo sin acceso a Internet (regla de cortafuegos aplicada). "
                    "No se pudo añadir la lista MAC del Wi-Fi: router sin hostapd/iw o "
                    "equipo conectado por cable. Para un corte de radio usa el filtro MAC del AP."
                )
        else:
            detail = (
                "Acceso a Internet cortado a través del router (el equipo sigue "
                "conectado al Wi-Fi)."
            )

        return True, (
            f"[SSH {self.profile}] {detail} MAC {clean.upper()} "
            f"(regla '{self.rule_name(clean)}')."
        )

    def unblock_device(self, mac: str, ip: str = "") -> Tuple[bool, str]:
        if not validate_mac(mac):
            return False, f"MAC inválida: {mac}"
        if not self.config.router_host:
            return False, "Configura primero la dirección IP de tu router (SSH)."

        clean = normalize_mac(mac)
        ok, output = self._run(self.build_script("unblock", clean))
        if not ok:
            return False, f"No se pudo eliminar la regla por SSH: {output}"

        firewall = self._marker(output, "MANGORED_FIREWALL").upper()
        wifi_count = self._marker_count(output, "MANGORED_WIFI")

        if firewall != "REMOVED":
            return False, (
                "No se pudo verificar la retirada de la regla de cortafuegos. "
                f"Salida del router: {output or 'vacía'}"
            )

        if wifi_count:
            return True, (
                f"[SSH {self.profile}] Regla de cortafuegos eliminada para {clean.upper()}, "
                f"pero quedan {wifi_count} entrada(s) en la lista MAC del Wi-Fi. "
                "Revisa la configuración wireless del router."
            )

        return True, (
            f"[SSH {self.profile}] Equipo {clean.upper()} desbloqueado: regla de cortafuegos "
            f"eliminada y retirado de la lista negra Wi-Fi. Acceso a la red restaurado."
        )

    def get_capabilities(self) -> Dict[str, Any]:
        full = self.block_mode == "full"
        return {
            "driver": "ssh",
            "is_simulated": False,
            "supports_mac_filter": True,
            "supports_schedule": False,
            "blocks_internet": True,
            "blocks_network": full,
            "block_mode": self.block_mode,
            "profile": self.profile,
            "ssh_port": self.ssh_port,
            "timeout_seconds": self.timeout,
            "notice": (
                "Modo completo: expulsa al equipo del Wi-Fi (lista MAC del AP + expulsión "
                "inmediata) y corta su acceso a Internet. En equipos por cable no existe "
                "expulsión de radio: se aísla con el cortafuegos del router."
                if full else
                "Modo Internet: sólo corta el acceso a Internet a través del router; "
                "el equipo permanece conectado al Wi-Fi."
            ),
        }
"""
Capa de compatibilidad multiplataforma de MangoRed.

Centraliza todo lo que depende del sistema operativo para que el resto de
módulos (escáner, configuración, base de datos y servidor web) funcione igual
en Linux (Kali, Debian, Ubuntu, Arch, Fedora...), Windows 10/11 y macOS.

Principios:
  * Nunca lanzar excepciones por falta de una herramienta del sistema.
  * Nunca ejecutar comandos con ``shell=True`` (evita inyección de comandos).
  * Sanear cualquier texto que se envíe a notificaciones del escritorio.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from typing import List, Optional, Sequence

IS_WINDOWS = os.name == "nt"
IS_LINUX = sys.platform.startswith("linux") and not IS_WINDOWS
IS_MACOS = sys.platform == "darwin"

PLATFORM_LABEL = "Windows" if IS_WINDOWS else ("macOS" if IS_MACOS else "Linux")

#: Caracteres de control que nunca deben llegar a una notificación o log.
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def sanitize_text(value: object, max_length: int = 256) -> str:
    """Elimina caracteres de control y recorta un texto no confiable."""
    if value is None:
        return ""
    text = _CONTROL_CHARS.sub("", str(value)).replace("\r", " ").replace("\n", " ")
    return text.strip()[:max_length]


def which(command: str) -> Optional[str]:
    """Devuelve la ruta del ejecutable o ``None`` si no está instalado."""
    return shutil.which(command)


def run_command(
    args: Sequence[str],
    timeout: float = 5.0,
    encoding: str = "utf-8",
) -> Optional[subprocess.CompletedProcess]:
    """
    Ejecuta un comando sin shell y devuelve el resultado, o ``None`` si la
    herramienta no existe, tarda demasiado o falla de forma inesperada.
    """
    if not args or not which(str(args[0])):
        return None
    try:
        return subprocess.run(
            [str(a) for a in args],
            capture_output=True,
            text=True,
            encoding=encoding,
            errors="ignore",
            timeout=timeout,
            shell=False,
            check=False,
        )
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def _windows_current_user() -> str:
    """Cuenta de Windows en formato ``DOMINIO\\usuario`` para icacls."""
    domain = os.environ.get("USERDOMAIN", "").strip()
    user = os.environ.get("USERNAME", "").strip()
    if not user:
        return ""
    return f"{domain}\\{user}" if domain else user


def secure_file_permissions(path: str, mode: int = 0o600) -> bool:
    """
    Restringe un archivo sensible al usuario propietario.

    * POSIX (Linux/macOS): ``chmod 0600``.
    * Windows: retira la herencia de ACL y concede control total sólo a la
      cuenta actual mediante ``icacls`` (equivalente funcional a 0600).

    Devuelve ``True`` si se aplicó (o ya era correcto) y ``False`` si no se
    pudo aplicar; nunca lanza excepción.
    """
    if not path or not os.path.exists(path):
        return False

    if not IS_WINDOWS:
        try:
            os.chmod(path, mode)
            return True
        except OSError:
            return False

    user = _windows_current_user()
    if not user:
        return False
    try:
        result = run_command(
            ["icacls", path, "/inheritance:r", "/grant:r", f"{user}:F", "/quiet"],
            timeout=10,
        )
        return result is not None and result.returncode == 0
    except Exception:
        return False


def secure_directory_permissions(path: str, mode: int = 0o700) -> bool:
    """Restringe un directorio al usuario propietario (POSIX; best-effort en Windows)."""
    if not path or not os.path.isdir(path):
        return False
    if IS_WINDOWS:
        user = _windows_current_user()
        if not user:
            return False
        try:
            result = run_command(
                ["icacls", path, "/inheritance:r", "/grant:r", f"{user}:(OI)(CI)F", "/quiet"],
                timeout=10,
            )
            return result is not None and result.returncode == 0
        except Exception:
            return False
    try:
        os.chmod(path, mode)
        return True
    except OSError:
        return False


def ensure_private_directory(path: str) -> bool:
    """Crea (si falta) un directorio privado para datos sensibles."""
    if not path:
        return False
    try:
        os.makedirs(path, exist_ok=True)
    except OSError:
        return False
    return secure_directory_permissions(path)


def _powershell_available() -> bool:
    return which("powershell") is not None or which("pwsh") is not None


def _powershell_executable() -> str:
    return which("powershell") or which("pwsh") or "powershell"


def _windows_toast(title: str, message: str) -> bool:
    """Muestra una notificación toast nativa en Windows 10/11 (best-effort)."""
    if not _powershell_available():
        return False

    safe_title = title.replace("'", "''")
    safe_message = message.replace("'", "''")
    script = (
        "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null;"
        "[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] > $null;"
        "$xml = New-Object Windows.Data.Xml.Dom.XmlDocument;"
        "$xml.LoadXml('<toast><visual><binding template=\"ToastGeneric\"><text>"
        + safe_title
        + "</text><text>"
        + safe_message
        + "</text></binding></visual></toast>');"
        "$toast = New-Object Windows.UI.Notifications.ToastNotification $xml;"
        "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('MangoRed').Show($toast);"
    )
    result = run_command(
        [
            _powershell_executable(),
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ],
        timeout=15,
    )
    return result is not None and result.returncode == 0


def send_desktop_notification(
    title: str,
    message: str,
    enabled: bool = True,
    icon: str = "network-wireless",
) -> bool:
    """
    Envía una notificación de escritorio nativa según el sistema operativo.

    * Linux: ``notify-send`` (libnotify) si está instalado.
    * Windows: toast de Windows 10/11 mediante PowerShell.
    * macOS: ``osascript`` (Centro de notificaciones).

    Nunca lanza excepciones: si no hay soporte disponible devuelve ``False``.
    """
    if not enabled:
        return False

    safe_title = sanitize_text(title, 120) or "MangoRed"
    safe_message = sanitize_text(message, 400)

    try:
        if IS_MACOS:
            script = f'display notification "{safe_message}" with title "{safe_title}"'
            result = run_command(["osascript", "-e", script], timeout=8)
            return result is not None and result.returncode == 0

        if IS_WINDOWS:
            return _windows_toast(safe_title, safe_message)

        if which("notify-send"):
            result = run_command(
                [
                    "notify-send",
                    "-a",
                    "MangoRed",
                    "-u",
                    "critical",
                    "-i",
                    icon,
                    safe_title,
                    safe_message,
                ],
                timeout=8,
            )
            return result is not None and result.returncode == 0
        return False
    except Exception:
        return False


def list_platform_tools() -> dict:
    """Informe de herramientas del sistema relevantes (para /api/health)."""
    return {
        "platform": PLATFORM_LABEL,
        "is_windows": IS_WINDOWS,
        "is_linux": IS_LINUX,
        "is_macos": IS_MACOS,
        "tools": {
            "ip": bool(which("ip")),
            "ipconfig": bool(which("ipconfig")),
            "route": bool(which("route")),
            "arp": bool(which("arp")),
            "ping": bool(which("ping")),
            "notify-send": bool(which("notify-send")),
            "osascript": bool(which("osascript")),
            "powershell": _powershell_available(),
        },
    }


def python_requirements_hint() -> List[str]:
    """Comandos sugeridos para preparar el entorno según la plataforma."""
    if IS_WINDOWS:
        return [
            "py -m venv .venv",
            r".venv\Scripts\activate",
            "py -m pip install -r requirements.txt",
        ]
    return [
        "python3 -m venv .venv",
        "source .venv/bin/activate",
        "python3 -m pip install -r requirements.txt",
    ]
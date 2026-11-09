"""
Pruebas de la capa de compatibilidad multiplataforma (platform_compat.py).

Verifican la limpieza de texto no confiable, los permisos seguros de archivos
y que las notificaciones nunca lancen excepciones, incluso sin herramientas
del sistema disponibles.
"""

import os
import stat

import pytest

import platform_compat as pc


def test_platform_flags_are_consistent():
    """Exactamente una plataforma debe estar activa."""
    flags = [pc.IS_WINDOWS, pc.IS_LINUX, pc.IS_MACOS]
    assert flags.count(True) == 1
    assert pc.PLATFORM_LABEL in {"Linux", "Windows", "macOS"}


def test_sanitize_text_removes_control_characters():
    """Los caracteres de control se eliminan y el texto se recorta."""
    assert pc.sanitize_text("Normal") == "Normal"
    assert pc.sanitize_text("Hola\x00Mundo\x07!") == "HolaMundo!"
    assert "\n" not in pc.sanitize_text("linea1\nlinea2")
    assert len(pc.sanitize_text("x" * 500, 10)) == 10
    assert pc.sanitize_text(None) == ""


def test_which_and_run_command_are_safe():
    """Los comandos inexistentes no lanzan excepciones."""
    assert pc.which("herramienta-que-no-existe-12345") is None
    assert pc.run_command(["herramienta-que-no-existe-12345"]) is None
    assert pc.run_command([]) is None


def test_run_command_executes_without_shell():
    """Se ejecuta un comando real capturando la salida."""
    if pc.IS_WINDOWS:
        result = pc.run_command(["cmd", "/c", "echo", "hola"], timeout=10)
    else:
        result = pc.run_command(["echo", "hola"])
    assert result is not None
    assert "hola" in (result.stdout or "")


@pytest.mark.skipif(pc.IS_WINDOWS, reason="Los permisos POSIX sólo aplican a Linux/macOS")
def test_secure_file_permissions_chmod_0600(tmp_path):
    """El archivo de credenciales queda restringido al propietario."""
    target = tmp_path / "credenciales.json"
    target.write_text("{}", encoding="utf-8")
    os.chmod(target, 0o644)

    assert pc.secure_file_permissions(str(target)) is True
    mode = stat.S_IMODE(target.stat().st_mode)
    assert mode == 0o600


def test_secure_file_permissions_missing_file():
    """Un archivo inexistente devuelve False sin lanzar excepción."""
    assert pc.secure_file_permissions("/ruta/que/no/existe/mangored.json") is False


def test_ensure_private_directory(tmp_path):
    """Se crea un directorio privado para datos sensibles."""
    target = tmp_path / "datos" / "privados"
    assert pc.ensure_private_directory(str(target)) is True
    assert target.is_dir()


def test_notifications_are_no_ops_when_disabled():
    """Con las notificaciones desactivadas no se ejecuta ningún proceso."""
    assert pc.send_desktop_notification("Título", "Mensaje", enabled=False) is False


def test_notifications_never_raise():
    """Sin herramientas gráficas la llamada devuelve False en lugar de fallar."""
    result = pc.send_desktop_notification("MangoRed", "Prueba automatizada", enabled=True)
    assert result in (True, False)


def test_list_platform_tools_reports_required_keys():
    report = pc.list_platform_tools()
    assert report["platform"] == pc.PLATFORM_LABEL
    for tool in ("ping", "arp", "ip", "ipconfig", "route"):
        assert tool in report["tools"]


def test_python_requirements_hint_matches_platform():
    hint = pc.python_requirements_hint()
    assert any("requirements.txt" in entry for entry in hint)
    if pc.IS_WINDOWS:
        assert any(".venv\\Scripts" in entry for entry in hint)
    else:
        assert any(".venv/bin" in entry for entry in hint)
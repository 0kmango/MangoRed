#!/usr/bin/env bash
# ==============================================================================
# MangoRed - Lanzador para Linux y macOS
# Supervisión de Red Local Autorizada
# ==============================================================================

set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
cd "$DIR"

echo "=========================================================================="
echo " 🥭 MANGORED - MONITOR DOMÉSTICO DE RED LOCAL"
echo "=========================================================================="
echo " [i] Directorio de trabajo: $DIR"

# 1. Localizar un intérprete de Python 3.9+
PYTHON_BIN=""
for candidate in "$DIR/.venv/bin/python" python3 python; do
    if command -v "$candidate" >/dev/null 2>&1 || [ -x "$candidate" ]; then
        if "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)' 2>/dev/null; then
            PYTHON_BIN="$candidate"
            break
        fi
    fi
done

if [ -z "$PYTHON_BIN" ]; then
    echo " [!] Error: no se encontró Python 3.9 o superior."
    echo "     Linux:  sudo apt install python3 python3-venv    (Debian/Kali/Ubuntu)"
    echo "     macOS:  brew install python3"
    exit 1
fi
echo " [i] Intérprete: $("$PYTHON_BIN" --version 2>&1)"

# 2. Comprobar dependencias de Python
if ! "$PYTHON_BIN" -c 'import flask, requests' >/dev/null 2>&1; then
    echo " [!] Faltan dependencias de Python. Instálalas con:"
    echo "     $PYTHON_BIN -m venv .venv && source .venv/bin/activate"
    echo "     python3 -m pip install -r requirements.txt"
    exit 1
fi

if ! "$PYTHON_BIN" -c 'import psutil' >/dev/null 2>&1; then
    echo " [!] Nota: psutil no está instalado; la detección de interfaces será menos precisa."
fi

# 3. Dependencias opcionales del sistema
if [ "$(uname -s)" = "Linux" ]; then
    if ! command -v notify-send >/dev/null 2>&1; then
        echo " [!] Nota: libnotify-bin no está instalado. Alertas de escritorio desactivadas."
        echo "     Debian/Kali/Ubuntu: sudo apt install libnotify-bin"
    fi
    if ! command -v ip >/dev/null 2>&1; then
        echo " [!] Nota: iproute2 no está instalado. Se usará un método alternativo de detección."
    fi
    if ! command -v ping >/dev/null 2>&1; then
        echo " [!] Nota: ping no está disponible; el descubrimiento usará sólo la tabla ARP."
    fi
fi

# 4. Aplicar permisos restrictivos a los archivos sensibles
if [ -f "$DIR/mangored_config.json" ]; then
    chmod 600 "$DIR/mangored_config.json" 2>/dev/null || true
fi
for db_file in "$DIR"/*.db; do
    [ -e "$db_file" ] && chmod 600 "$db_file" 2>/dev/null || true
done

echo " [✓] Entorno verificado."
echo " [✓] Modo de seguridad: Solo Lectura activo por defecto."
echo " [✓] Token de API local obligatorio para operaciones de escritura."
echo " [✓] Iniciando servidor en http://127.0.0.1:5000 ..."
echo "--------------------------------------------------------------------------"
echo " Presiona Ctrl+C para detener el servicio."
echo "=========================================================================="

exec "$PYTHON_BIN" "$DIR/app.py" "$@"

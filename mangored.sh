#!/usr/bin/env bash
# ==============================================================================
# MangoRed - Lanzador Oficial para Kali Linux
# Supervisión de Red Local Autorizada
# ==============================================================================

set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
cd "$DIR"

echo "=========================================================================="
echo " 🥭 MANRED - MONITOR DOMÉSTICO DE RED LOCAL (KALI LINUX)"
echo "=========================================================================="
echo " [i] Directorio de trabajo: $DIR"
echo " [i] Verificando dependencias..."

# Verificar Python 3
if ! command -v python3 &>/dev/null; then
    echo " [!] Error: python3 no está instalado. Ejecuta: sudo apt install python3"
    exit 1
fi

# Verificar paquetes de sistema recomendados
if ! command -v notify-send &>/dev/null; then
    echo " [!] Nota: libnotify-bin no está instalado. Las alertas de escritorio no se emitirán."
    echo "     Para habilitarlas: sudo apt install libnotify-bin"
fi

# Comprobar permisos del archivo de configuración si existe
if [ -f "$DIR/mangored_config.json" ]; then
    chmod 600 "$DIR/mangored_config.json" 2>/dev/null || true
fi

echo " [✓] Entorno verificado."
echo " [✓] Modo de seguridad: Solo Lectura activo por defecto."
echo " [✓] Iniciando servidor en http://127.0.0.1:5000 ..."
echo "--------------------------------------------------------------------------"
echo " Presiona Ctrl+C para detener el servicio."
echo "=========================================================================="

exec python3 "$DIR/app.py"

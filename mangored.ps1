# ==============================================================================
# MangoRed - Lanzador para Windows 10 / 11 (PowerShell)
# Supervisión de Red Local Autorizada
# ==============================================================================

$ErrorActionPreference = "Stop"
$ProjectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjectDir

Write-Host "==========================================================================" -ForegroundColor Yellow
Write-Host " MANGORED - MONITOR DOMESTICO DE RED LOCAL (WINDOWS)" -ForegroundColor Yellow
Write-Host "==========================================================================" -ForegroundColor Yellow
Write-Host " [i] Directorio de trabajo: $ProjectDir"

function Find-Python {
    $candidates = @()
    if (Test-Path "$ProjectDir\.venv\Scripts\python.exe") {
        $candidates += "$ProjectDir\.venv\Scripts\python.exe"
    }
    $candidates += "py", "python"

    foreach ($candidate in $candidates) {
        try {
            $command = Get-Command $candidate -ErrorAction SilentlyContinue
            if ($null -eq $command) { continue }
            $ok = & $candidate -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)" 2>$null
            if ($LASTEXITCODE -eq 0) { return $candidate }
        } catch {
            continue
        }
    }
    return $null
}

$PythonBin = Find-Python
if (-not $PythonBin) {
    Write-Host " [!] Error: no se encontro Python 3.9 o superior." -ForegroundColor Red
    Write-Host "     Instalalo desde https://www.python.org/downloads/windows/"
    Write-Host "     (marca la casilla 'Add python.exe to PATH' durante la instalacion)"
    exit 1
}
Write-Host " [i] Interprete: $PythonBin"

# 1. Dependencias de Python
& $PythonBin -c "import flask, requests" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host " [!] Faltan dependencias. Ejecuta:" -ForegroundColor Red
    Write-Host "     py -m venv .venv"
    Write-Host "     .venv\Scripts\activate"
    Write-Host "     py -m pip install -r requirements.txt"
    exit 1
}

# 2. Avisos sobre herramientas del sistema
if (-not (Get-Command ping -ErrorAction SilentlyContinue)) {
    Write-Host " [!] Nota: 'ping' no esta disponible; el descubrimiento usara solo la tabla ARP."
}
if (-not (Get-Command powershell -ErrorAction SilentlyContinue)) {
    Write-Host " [!] Nota: PowerShell no disponible; las notificaciones toast se desactivan."
}

# 3. Restringir permisos de los archivos sensibles (equivalente a chmod 0600)
$secureFiles = @()
if (Test-Path "$ProjectDir\mangored_config.json") { $secureFiles += "$ProjectDir\mangored_config.json" }
$secureFiles += Get-ChildItem -Path $ProjectDir -Filter *.db -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName }

foreach ($file in $secureFiles) {
    try {
        & icacls "$file" /inheritance:r /grant:r "$($env:USERDOMAIN)\$($env:USERNAME):F" /quiet | Out-Null
    } catch {
        Write-Host " [!] Aviso: no se pudieron ajustar los permisos de $file"
    }
}

Write-Host " [OK] Entorno verificado." -ForegroundColor Green
Write-Host " [OK] Modo de seguridad: Solo Lectura activo por defecto."
Write-Host " [OK] Token de API local obligatorio para operaciones de escritura."
Write-Host " [OK] Iniciando servidor en http://127.0.0.1:5000 ..."
Write-Host "--------------------------------------------------------------------------"
Write-Host " Presiona Ctrl+C para detener el servicio."
Write-Host "=========================================================================="

& $PythonBin "$ProjectDir\app.py" @args

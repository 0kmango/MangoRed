@echo off
REM ============================================================================
REM MangoRed - Lanzador para Windows 10 / 11 (Símbolo del sistema)
REM Delega en el script de PowerShell mangored.ps1
REM ============================================================================

setlocal enabledelayedexpansion
set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

where powershell >nul 2>&1
if !ERRORLEVEL! EQU 0 (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%mangored.ps1" %*
    exit /b !ERRORLEVEL!
)

echo ==========================================================================
echo  MANGORED - MONITOR DOMESTICO DE RED LOCAL (WINDOWS)
echo ==========================================================================

where py >nul 2>&1
if !ERRORLEVEL! EQU 0 (
    py -c "import flask, requests" >nul 2>&1
    if !ERRORLEVEL! NEQ 0 (
        echo  [!] Faltan dependencias de Python. Ejecuta:
        echo      py -m pip install -r requirements.txt
        pause
        exit /b 1
    )
    py "%SCRIPT_DIR%app.py" %*
    exit /b !ERRORLEVEL!
)

where python >nul 2>&1
if !ERRORLEVEL! EQU 0 (
    python -c "import flask, requests" >nul 2>&1
    if !ERRORLEVEL! NEQ 0 (
        echo  [!] Faltan dependencias de Python. Ejecuta:
        echo      python -m pip install -r requirements.txt
        pause
        exit /b 1
    )
    python "%SCRIPT_DIR%app.py" %*
    exit /b !ERRORLEVEL!
)

echo  [!] Error: no se encontro Python 3.9 o superior.
echo      Instalalo desde https://www.python.org/downloads/windows/
pause
exit /b 1

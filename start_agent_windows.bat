@echo off
title Prompt Sanitizer — Windows Desktop Agent
echo ====================================================================
echo   PROMPT SANITIZER — INICIANDO AGENTE DESKTOP GLOBAL (WINDOWS)
echo ====================================================================

cd /d "%~dp0"

if exist ".venv\Scripts\pythonw.exe" (
    echo [+] Usando ambiente virtual .venv...
    start "" ".venv\Scripts\pythonw.exe" run_desktop_agent.py
    exit /b 0
)

where pythonw >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    echo [+] Iniciando Agente em background via pythonw...
    start "" pythonw run_desktop_agent.py
) else (
    echo [+] Iniciando Agente via python...
    python run_desktop_agent.py
)


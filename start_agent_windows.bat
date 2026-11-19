@echo off
setlocal
chcp 65001 >nul
title Prompt Sanitizer - Windows Desktop Agent
cd /d "%~dp0"

echo ====================================================================
echo   PROMPT SANITIZER - AGENTE DESKTOP GLOBAL (WINDOWS)
echo ====================================================================

rem --- 1. Localizar Python (py launcher ou python no PATH) ---
set "PY="
where py >nul 2>nul && set "PY=py -3"
if not defined PY (
    where python >nul 2>nul && set "PY=python"
)
if not defined PY (
    echo [ERRO] Python 3.10+ nao encontrado. Instale em https://www.python.org/downloads/
    echo        e marque "Add python.exe to PATH" durante a instalacao.
    pause
    exit /b 1
)

rem --- 2. Criar o ambiente virtual na primeira execucao ---
if not exist ".venv\Scripts\python.exe" (
    echo [+] Criando ambiente virtual .venv ...
    %PY% -m venv .venv
    if errorlevel 1 (
        echo [ERRO] Falha ao criar o ambiente virtual.
        pause
        exit /b 1
    )
)

rem --- 3. Instalar/atualizar dependencias apenas quando requirements.txt mudar ---
set "STAMP=.venv\.requirements.stamp"
set "NEEDS_INSTALL=1"
if exist "%STAMP%" (
    fc /b requirements.txt "%STAMP%" >nul 2>nul && set "NEEDS_INSTALL=0"
)
if "%NEEDS_INSTALL%"=="1" (
    echo [+] Instalando dependencias ...
    ".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -r requirements.txt
    if errorlevel 1 (
        echo [ERRO] Falha ao instalar dependencias. Verifique sua conexao com a internet.
        pause
        exit /b 1
    )
    copy /y requirements.txt "%STAMP%" >nul
)

rem --- 4. Iniciar o agente ---
if /i "%~1"=="--install" (
    ".venv\Scripts\python.exe" run_desktop_agent.py --enable-autostart
    if errorlevel 1 (
        pause
        exit /b 1
    )
)
if /i "%~1"=="--uninstall" (
    ".venv\Scripts\python.exe" run_desktop_agent.py --disable-autostart
    pause
    exit /b %errorlevel%
)
if "%~1"=="--console" (
    echo [+] Iniciando em modo console ^(logs visiveis^) ...
    ".venv\Scripts\python.exe" run_desktop_agent.py
    pause
    exit /b %errorlevel%
)

if exist ".venv\Scripts\pythonw.exe" (
    echo [+] Iniciando Agente em segundo plano ^(icone na bandeja perto do relogio^) ...
    start "" ".venv\Scripts\pythonw.exe" run_desktop_agent.py --background
) else (
    ".venv\Scripts\python.exe" run_desktop_agent.py
)
endlocal
exit /b 0

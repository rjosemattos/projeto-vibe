@echo off
setlocal
chcp 65001 >nul
title Prompt Sanitizer - Servidor Web
cd /d "%~dp0"

set "PY="
where py >nul 2>nul && set "PY=py -3"
if not defined PY (
    where python >nul 2>nul && set "PY=python"
)
if not defined PY (
    echo [ERRO] Python 3.10+ nao encontrado. Instale em https://www.python.org/downloads/
    pause
    exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
    echo [+] Criando ambiente virtual .venv ...
    %PY% -m venv .venv || (pause & exit /b 1)
)

set "STAMP=.venv\.requirements.stamp"
set "NEEDS_INSTALL=1"
if exist "%STAMP%" (
    fc /b requirements.txt "%STAMP%" >nul 2>nul && set "NEEDS_INSTALL=0"
)
if "%NEEDS_INSTALL%"=="1" (
    echo [+] Instalando dependencias ...
    ".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -r requirements.txt || (pause & exit /b 1)
    copy /y requirements.txt "%STAMP%" >nul
)

".venv\Scripts\python.exe" run_server.py %*
pause
endlocal

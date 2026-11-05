@echo off
setlocal
chcp 65001 >nul
title Prompt Sanitizer - Build Windows Executable
cd /d "%~dp0"

echo ====================================================================
echo   GERANDO EXECUTAVEL NATIVO WINDOWS (PromptSanitizerAgent.exe)
echo ====================================================================

set "PY="
where py >nul 2>nul && set "PY=py -3"
if not defined PY (
    where python >nul 2>nul && set "PY=python"
)
if not defined PY (
    echo [ERRO] Python 3.10+ nao encontrado no PATH.
    pause
    exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
    echo [+] Criando ambiente virtual .venv ...
    %PY% -m venv .venv || goto :fail
)

echo [+] Instalando dependencias de build ...
".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -r requirements-dev.txt || goto :fail

echo [+] Compilando com PyInstaller ...
".venv\Scripts\python.exe" -m PyInstaller --noconfirm --clean --onefile --windowed ^
    --name "PromptSanitizerAgent" ^
    --collect-submodules pystray ^
    --hidden-import PIL._tkinter_finder ^
    run_desktop_agent.py || goto :fail

echo.
echo ====================================================================
echo   CONCLUIDO! Executavel gerado em: dist\PromptSanitizerAgent.exe
echo ====================================================================
pause
exit /b 0

:fail
echo.
echo [ERRO] O build falhou. Veja as mensagens acima.
pause
exit /b 1

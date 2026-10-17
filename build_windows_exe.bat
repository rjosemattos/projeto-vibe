@echo off
title Prompt Sanitizer — Build Windows Executable (.exe)
echo ====================================================================
echo   GERANDO EXECUTAVEL NATIVO WINDOWS (PromptSanitizerAgent.exe)
echo ====================================================================

cd /d "%~dp0"

python -m pip install --upgrade pip pyinstaller pystray Pillow cryptography pydantic pydantic-settings

python -m PyInstaller ^
    --noconfirm ^
    --onefile ^
    --windowed ^
    --name "PromptSanitizerAgent" ^
    run_desktop_agent.py

echo.
echo ====================================================================
echo   CONCLUIDO! Executavel gerado em: dist\PromptSanitizerAgent.exe
echo ====================================================================
pause


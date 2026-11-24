"""Registro do início automático do agente junto com o Windows.

O agente precisa do clipboard, da janela em primeiro plano e dos atalhos globais do usuário
logado, por isso não pode rodar como um Windows Service clássico (serviços ficam isolados na
Sessão 0). Em vez disso, ele é registrado por usuário em
``HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run`` e inicia silenciosamente na
bandeja a cada logon. Não precisa de permissão de administrador.
"""

import subprocess
import sys
from pathlib import Path
from typing import Optional

from app.core.logging import get_logger

logger = get_logger(__name__)

IS_WINDOWS = sys.platform == "win32"
RUN_KEY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"
VALUE_NAME = "PromptSanitizer"
BACKGROUND_FLAG = "--background"

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


def build_launch_command() -> str:
    """Retorna a linha de comando que inicia o agente silenciosamente na bandeja."""
    if getattr(sys, "frozen", False):  # Executável gerado pelo PyInstaller
        return subprocess.list2cmdline([sys.executable, BACKGROUND_FLAG])

    interpreter = Path(sys.executable)
    pythonw = interpreter.with_name("pythonw.exe")
    if pythonw.exists():
        interpreter = pythonw  # sem janela de console
    script = _PROJECT_ROOT / "run_desktop_agent.py"
    return subprocess.list2cmdline([str(interpreter), str(script), BACKGROUND_FLAG])


def _open_run_key(write: bool):
    import winreg

    access = winreg.KEY_SET_VALUE | winreg.KEY_QUERY_VALUE if write else winreg.KEY_QUERY_VALUE
    return winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, RUN_KEY_PATH, 0, access)


def get_registered_command() -> Optional[str]:
    """Retorna o comando de inicialização registrado, ou None se não houver registro."""
    if not IS_WINDOWS:
        return None
    import winreg

    try:
        with _open_run_key(write=False) as key:
            value, _ = winreg.QueryValueEx(key, VALUE_NAME)
            return str(value)
    except OSError:
        return None


def is_enabled() -> bool:
    """True quando o agente está registrado para iniciar com o Windows."""
    return get_registered_command() is not None


def enable() -> str:
    """Registra o agente para iniciar em segundo plano no logon. Retorna o comando registrado."""
    if not IS_WINDOWS:
        raise OSError("O início automático só está disponível no Windows.")
    import winreg

    command = build_launch_command()
    with _open_run_key(write=True) as key:
        winreg.SetValueEx(key, VALUE_NAME, 0, winreg.REG_SZ, command)
    logger.info("Início automático com o Windows ativado.")
    return command


def disable() -> bool:
    """Remove o registro de inicialização. Retorna True se havia um registro."""
    if not IS_WINDOWS:
        return False
    import winreg

    try:
        with _open_run_key(write=True) as key:
            winreg.DeleteValue(key, VALUE_NAME)
    except FileNotFoundError:
        return False
    logger.info("Início automático com o Windows desativado.")
    return True


def set_enabled(enabled: bool) -> None:
    """Liga ou desliga o início automático com o Windows."""
    if enabled:
        enable()
    else:
        disable()


__all__ = [
    "BACKGROUND_FLAG",
    "build_launch_command",
    "disable",
    "enable",
    "get_registered_command",
    "is_enabled",
    "set_enabled",
]

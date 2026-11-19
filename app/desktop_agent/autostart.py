"""Start-with-Windows registration for the background agent.

The agent needs the interactive user's clipboard, foreground window and global hotkeys, so it
cannot run as a classic Windows Service (services live in the isolated Session 0). Instead it is
registered per user under ``HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run`` and starts
silently in the system tray at every logon. No administrator rights are required.
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
    """Returns the command line that starts the agent silently in the tray."""
    if getattr(sys, "frozen", False):  # PyInstaller executable
        return subprocess.list2cmdline([sys.executable, BACKGROUND_FLAG])

    interpreter = Path(sys.executable)
    pythonw = interpreter.with_name("pythonw.exe")
    if pythonw.exists():
        interpreter = pythonw  # no console window
    script = _PROJECT_ROOT / "run_desktop_agent.py"
    return subprocess.list2cmdline([str(interpreter), str(script), BACKGROUND_FLAG])


def _open_run_key(write: bool):
    import winreg

    access = winreg.KEY_SET_VALUE | winreg.KEY_QUERY_VALUE if write else winreg.KEY_QUERY_VALUE
    return winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, RUN_KEY_PATH, 0, access)


def get_registered_command() -> Optional[str]:
    """Returns the registered start-up command, or None when not registered."""
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
    """True when the agent is registered to start with Windows."""
    return get_registered_command() is not None


def enable() -> str:
    """Registers the agent to start in the background at logon. Returns the registered command."""
    if not IS_WINDOWS:
        raise OSError("O início automático só está disponível no Windows.")
    import winreg

    command = build_launch_command()
    with _open_run_key(write=True) as key:
        winreg.SetValueEx(key, VALUE_NAME, 0, winreg.REG_SZ, command)
    logger.info("Start-with-Windows enabled.")
    return command


def disable() -> bool:
    """Removes the start-up registration. Returns True if an entry was removed."""
    if not IS_WINDOWS:
        return False
    import winreg

    try:
        with _open_run_key(write=True) as key:
            winreg.DeleteValue(key, VALUE_NAME)
    except FileNotFoundError:
        return False
    logger.info("Start-with-Windows disabled.")
    return True


def set_enabled(enabled: bool) -> None:
    """Enables or disables the start-up registration."""
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

"""Platform-specific application data directory resolution."""

import os
import sys
from pathlib import Path


def get_data_dir() -> Path:
    """Returns (and creates) the per-user data directory, with a portable `.data` fallback.

    The `PROMPT_SANITIZER_DATA_DIR` environment variable overrides the default location.
    """
    override = os.getenv("PROMPT_SANITIZER_DATA_DIR")
    if override:
        base_dir = Path(override)
    elif sys.platform == "win32":
        appdata = os.getenv("APPDATA")
        base_dir = (
            Path(appdata) / "PromptSanitizer"
            if appdata
            else Path.home() / "AppData" / "Roaming" / "PromptSanitizer"
        )
    else:
        xdg = os.getenv("XDG_CONFIG_HOME")
        base_dir = (Path(xdg) if xdg else Path.home() / ".config") / "prompt-sanitizer"

    try:
        base_dir.mkdir(parents=True, exist_ok=True)
        return base_dir
    except OSError:
        portable_dir = Path(__file__).resolve().parent.parent.parent / ".data"
        portable_dir.mkdir(parents=True, exist_ok=True)
        return portable_dir

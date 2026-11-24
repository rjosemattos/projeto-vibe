"""Resolve a pasta de dados da aplicação conforme o sistema operacional."""

import os
import sys
import tempfile
from pathlib import Path


def get_data_dir() -> Path:
    """Retorna (e cria) a pasta de dados do usuário, com alternativas em `.data` ou na pasta temporária.

    A variável de ambiente `PROMPT_SANITIZER_DATA_DIR` substitui o local padrão.
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

    for candidate in (
        base_dir,
        Path(__file__).resolve().parent.parent.parent / ".data",
        Path(tempfile.gettempdir()) / "prompt-sanitizer",
    ):
        try:
            candidate.mkdir(parents=True, exist_ok=True)
            return candidate
        except OSError:
            continue
    return base_dir

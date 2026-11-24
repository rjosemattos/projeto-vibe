"""Testes da geração de chaves por instalação, da recuperação do cofre e do sanitizador de linha de comando."""

import os
import stat
import sys

import pytest

from app.core.crypto import RuleCryptoService
from app.desktop_agent.service import DesktopSanitizerService


def test_local_keys_are_random_per_install(tmp_path, monkeypatch):
    monkeypatch.setenv("PROMPT_SANITIZER_DATA_DIR", str(tmp_path / "a"))
    a = RuleCryptoService()
    monkeypatch.setenv("PROMPT_SANITIZER_DATA_DIR", str(tmp_path / "b"))
    b = RuleCryptoService()
    assert a._aes_key != b._aes_key

    # Gravada e estável entre instâncias na mesma pasta
    monkeypatch.setenv("PROMPT_SANITIZER_DATA_DIR", str(tmp_path / "a"))
    assert RuleCryptoService()._aes_key == a._aes_key
    if sys.platform != "win32":
        mode = stat.S_IMODE(os.stat(tmp_path / "a" / ".aes.key").st_mode)
        assert mode == 0o600


def test_legacy_store_keeps_legacy_key(tmp_path, monkeypatch):
    monkeypatch.setenv("PROMPT_SANITIZER_DATA_DIR", str(tmp_path))
    (tmp_path / "rules.enc.json").write_text("[]", encoding="utf-8")
    import hashlib

    legacy = hashlib.sha256(b"prompt-sanitizer-dev-aes-key-change-in-prod").digest()
    assert RuleCryptoService()._aes_key == legacy


def test_corrupt_store_is_preserved(tmp_path):
    store = tmp_path / "rules.enc.json"
    store.write_text("{not json", encoding="utf-8")
    service = DesktopSanitizerService(storage_path=store)
    assert service.list_rules() == []
    assert (tmp_path / "rules.enc.corrupt").exists()


def test_cli_sanitize_exit_codes(capsys, monkeypatch, tmp_path):
    import run_desktop_agent

    monkeypatch.setenv("PROMPT_SANITIZER_DATA_DIR", str(tmp_path))
    assert run_desktop_agent.run_cli_sanitize("CPF 123.456.789-09", False) == 10
    assert "[CPF_USUARIO]" in capsys.readouterr().out
    assert run_desktop_agent.run_cli_sanitize("nada sensível aqui", False) == 0

"""Testes dos handlers da janela de regras, sem abrir janelas de verdade."""

from pathlib import Path
from types import SimpleNamespace
from typing import List, Tuple

import pytest

ui_hud = pytest.importorskip("app.desktop_agent.ui_hud")

from app.desktop_agent.service import DesktopSanitizerService  # noqa: E402

PASSWORD = "senha-forte-123"


def _fake_window(service: DesktopSanitizerService) -> SimpleNamespace:
    """Objeto com o mínimo que os handlers usam, no lugar da janela Tk."""
    return SimpleNamespace(
        service=service,
        BACKUP_FILETYPES=ui_hud.RulesManagerWindow.BACKUP_FILETYPES,
        _refresh_table=lambda: None,
        on_rules_changed=lambda: None,
    )


def _patch_dialogs(monkeypatch, backup: Path, password: str) -> List[Tuple[str, str]]:
    """Substitui os diálogos do Tk: escolhe o arquivo, informa a senha e registra as mensagens."""
    shown: List[Tuple[str, str]] = []
    monkeypatch.setattr(ui_hud.filedialog, "askopenfilename", lambda **_: str(backup))
    monkeypatch.setattr(ui_hud.simpledialog, "askstring", lambda *_, **__: password)
    monkeypatch.setattr(ui_hud.messagebox, "showerror", lambda title, msg, **_: shown.append(("erro", msg)))
    monkeypatch.setattr(ui_hud.messagebox, "showinfo", lambda title, msg, **_: shown.append(("info", msg)))
    return shown


def _backup_with_one_rule(tmp_path: Path) -> Path:
    origem = DesktopSanitizerService(storage_path=tmp_path / "origem" / "rules.enc.json")
    origem.create_rule("CESAR", "[COMPANY_SENSITIVE]")
    backup = tmp_path / "regras.psbackup"
    origem.export_rules(backup, PASSWORD)
    return backup


def test_import_with_wrong_password_shows_error_message(tmp_path: Path, monkeypatch):
    backup = _backup_with_one_rule(tmp_path)
    destino = DesktopSanitizerService(storage_path=tmp_path / "destino" / "rules.enc.json")
    shown = _patch_dialogs(monkeypatch, backup, "senha-errada-000")

    ui_hud.RulesManagerWindow._on_import_clicked(_fake_window(destino))

    assert shown == [("erro", "Senha incorreta ou arquivo de backup corrompido.")]
    assert destino.list_rules() == []


def test_import_with_correct_password_reports_result(tmp_path: Path, monkeypatch):
    backup = _backup_with_one_rule(tmp_path)
    destino = DesktopSanitizerService(storage_path=tmp_path / "destino" / "rules.enc.json")
    shown = _patch_dialogs(monkeypatch, backup, PASSWORD)

    ui_hud.RulesManagerWindow._on_import_clicked(_fake_window(destino))

    assert shown[0][0] == "info"
    assert shown[0][1].startswith("1 regra(s) importada(s)")
    assert [rule.masked_term for rule in destino.list_rules()] == ["C***R"]

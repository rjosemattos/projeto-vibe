"""Tests for exporting and importing the confidential rules vault."""

from pathlib import Path

import pytest

from app.desktop_agent.service import DesktopSanitizerService

PASSWORD = "senha-forte-123"


def _service(tmp_path: Path, name: str) -> DesktopSanitizerService:
    return DesktopSanitizerService(storage_path=tmp_path / name / "rules.enc.json")


def test_export_and_import_rules_between_vaults(tmp_path: Path):
    origem = _service(tmp_path, "origem")
    origem.create_rule("CESAR", "[COMPANY_SENSITIVE]")
    origem.create_rule("Projeto Vibe", "[PROJETO_SECRETO]", case_sensitive=True)

    backup = tmp_path / "regras.psbackup"
    assert origem.export_rules(backup, PASSWORD) == 2
    assert "CESAR" not in backup.read_text(encoding="utf-8")

    destino = _service(tmp_path, "destino")
    destino.create_rule("CESAR", "[COMPANY_SENSITIVE]")  # já existe: deve ser ignorada
    assert destino.import_rules(backup, PASSWORD) == (1, 1)

    tags = sorted(rule.replacement_tag for rule in destino.list_rules())
    assert tags == ["[COMPANY_SENSITIVE]", "[PROJETO_SECRETO]"]


def test_import_rejects_wrong_password_without_changes(tmp_path: Path):
    origem = _service(tmp_path, "origem")
    origem.create_rule("CESAR", "[COMPANY_SENSITIVE]")
    backup = tmp_path / "regras.psbackup"
    origem.export_rules(backup, PASSWORD)

    destino = _service(tmp_path, "destino")
    with pytest.raises(ValueError, match="Senha incorreta"):
        destino.import_rules(backup, "senha-errada-000")
    assert destino.list_rules() == []


def test_export_requires_minimum_password_length(tmp_path: Path):
    service = _service(tmp_path, "origem")
    with pytest.raises(ValueError, match="pelo menos 8"):
        service.export_rules(tmp_path / "regras.psbackup", "curta")

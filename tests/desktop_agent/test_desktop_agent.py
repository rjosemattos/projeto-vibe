"""Testes unitários e de integração do agente desktop para Windows."""
import json 

from pathlib import Path
from typing import List, Tuple
import pytest

from app.desktop_agent.clipboard_monitor import ClipboardGuardMonitor
from app.desktop_agent.service import DesktopSanitizeResult, DesktopSanitizerService
from app.desktop_agent.win32_bridge import IS_WINDOWS, Win32Bridge
from app.models.response import SeverityLevel

uses_real_clipboard = pytest.mark.skipif(
    IS_WINDOWS,
    reason=(
        "No Windows o Win32Bridge usa o clipboard real e simula teclas; "
        "fluxo validado manualmente."
    ),
)

class FakeClipboard:
    """Simulador de clipboard em memória, para testes determinísticos."""

    def __init__(self, initial: str = ""):
        self.content = initial

    def get(self) -> str:
        return self.content

    def set(self, text: str) -> None:
        self.content = text


def test_encrypted_disk_persistence_zero_plaintext(tmp_path: Path):
    """Verifica que as regras são gravadas cifradas em disco, sem nenhum texto claro."""
    store_file = tmp_path / "rules.enc.json"
    service = DesktopSanitizerService(storage_path=store_file)

    created = service.create_rule(
        term="Projeto Ultra Secreto",
        replacement_tag="[PROJETO_CONFIDENCIAL]",
        case_sensitive=False,
        match_whole_word=True,
    )
    assert created.masked_term == "P***o"
    assert store_file.exists()

    raw_disk_content = store_file.read_text(encoding="utf-8")
    assert "Projeto Ultra Secreto" not in raw_disk_content
    assert "[PROJETO_CONFIDENCIAL]" in raw_disk_content

    # Recarrega numa nova instância do serviço para verificar que as regras sobrevivem a reinícios
    reloaded_service = DesktopSanitizerService(storage_path=store_file)
    rules = reloaded_service.list_rules()
    assert len(rules) == 1
    assert rules[0].id == created.id
    assert rules[0].replacement_tag == "[PROJETO_CONFIDENCIAL]"

    # Verifica a recusa de duplicados pelo índice cego
    with pytest.raises(ValueError, match="já está cadastrado"):
        reloaded_service.create_rule(
            term="projeto ultra secreto",
            replacement_tag="[OUTRA_TAG]",
        )


def test_desktop_crud_update_and_delete(tmp_path: Path):
    """Verifica a edição e a exclusão de regras no DesktopSanitizerService."""
    store_file = tmp_path / "rules.enc.json"
    service = DesktopSanitizerService(storage_path=store_file)

    rule = service.create_rule("CESAR", "COMPANY_SENSITIVE")
    assert rule.replacement_tag == "[COMPANY_SENSITIVE]"

    updated = service.update_rule(
        rule.id,
        term="CESAR School",
        replacement_tag="[INSTITUICAO_CONFIDENCIAL]",
        case_sensitive=True,
    )
    assert updated.replacement_tag == "[INSTITUICAO_CONFIDENCIAL]"
    assert updated.case_sensitive is True

    res = service.sanitize_prompt("Bem-vindo à CESAR School!")
    assert res.sanitized_text == "Bem-vindo à [INSTITUICAO_CONFIDENCIAL]!"

    assert service.delete_rule(rule.id) is True
    assert len(service.list_rules()) == 0


@uses_real_clipboard
def test_clipboard_auto_sanitization_and_loop_prevention(tmp_path: Path):
    """Verifica que o monitor do clipboard sanitiza o prompt uma única vez, sem entrar em loop."""
    store_file = tmp_path / "rules.enc.json"
    service = DesktopSanitizerService(storage_path=store_file)
    service.create_rule("CESAR", "[COMPANY_SENSITIVE]")

    fake_clip = FakeClipboard()
    bridge = Win32Bridge(
        fallback_get_clipboard=fake_clip.get,
        fallback_set_clipboard=fake_clip.set,
    )

    events: List[Tuple[DesktopSanitizeResult, str]] = []
    monitor = ClipboardGuardMonitor(
        service=service,
        bridge=bridge,
        on_sanitized_event=lambda r, src: events.append((r, src)),
    )

    # O usuário copia um prompt com termo confidencial + CPF válido + e-mail
    fake_clip.set("Analise o projeto da CESAR do cliente CPF 123.456.789-09 e email dev@cesar.org.br")

    result = monitor.inspect_clipboard_once()
    assert result is not None
    assert result.changed is True
    assert "[COMPANY_SENSITIVE]" in fake_clip.get()
    assert "123.456.789-09" not in fake_clip.get()
    assert "dev@cesar.org.br" not in fake_clip.get()
    assert len(events) == 1
    assert events[0][1] == "AUTO_CLIPBOARD"
    assert result.risk_level in (SeverityLevel.HIGH, SeverityLevel.CRITICAL)

    # Uma nova verificação do clipboard já sanitizado não deve fazer nada
    second_result = monitor.inspect_clipboard_once()
    assert second_result is None
    assert len(events) == 1


@uses_real_clipboard
def test_active_chat_hotkey_in_place_sanitization(tmp_path: Path):
    """Verifica o fluxo de sanitização do chat ativo (Ctrl+Shift+S)."""
    store_file = tmp_path / "rules.enc.json"
    service = DesktopSanitizerService(storage_path=store_file)
    service.create_rule("Projeto Vibe", "[PROJETO_SECRETO]")

    fake_clip = FakeClipboard("Explique a arquitetura do Projeto Vibe usando a chave sk-proj-1234567890abcdefghijklmnop")
    bridge = Win32Bridge(
        fallback_get_clipboard=fake_clip.get,
        fallback_set_clipboard=fake_clip.set,
    )

    events: List[Tuple[DesktopSanitizeResult, str]] = []
    monitor = ClipboardGuardMonitor(
        service=service,
        bridge=bridge,
        on_sanitized_event=lambda r, src: events.append((r, src)),
    )

    res = monitor.sanitize_active_chat_now()
    assert res is not None
    assert res.changed is True
    assert "[PROJETO_SECRETO]" in fake_clip.get()
    assert "Projeto Vibe" not in fake_clip.get()
    assert "sk-proj-" not in fake_clip.get()
    assert len(events) == 1
    assert events[0][1] == "ACTIVE_CHAT_HOTKEY"


def test_ai_window_context_detection():
    """Verifica a detecção de janelas de chat de IA pelo título."""
    assert Win32Bridge.is_ai_context("ChatGPT - Google Chrome") is True
    assert Win32Bridge.is_ai_context("Claude - Mozilla Firefox") is True
    assert Win32Bridge.is_ai_context("Microsoft Copilot") is True
    assert Win32Bridge.is_ai_context("projeto-vibe - Visual Studio Code") is True
    assert Win32Bridge.is_ai_context("Calculadora") is False


def test_reads_legacy_store_with_user_id_and_drops_it_on_save(tmp_path: Path):
    store_file = tmp_path / "rules.enc.json"
    DesktopSanitizerService(storage_path=store_file).create_rule("CESAR", "[COMPANY_SENSITIVE]")

    # Simula um cofre gravado pela versão antiga, com o campo user_id
    data = json.loads(store_file.read_text(encoding="utf-8"))
    data[0]["user_id"] = "windows-desktop-user"
    store_file.write_text(json.dumps(data), encoding="utf-8")

    service = DesktopSanitizerService(storage_path=store_file)
    assert [rule.masked_term for rule in service.list_rules()] == ["C***R"]

    service.create_rule("Projeto Vibe", "[PROJETO_SECRETO]")  # força uma nova gravação
    assert "user_id" not in store_file.read_text(encoding="utf-8")

from app.desktop_agent.service import (
    DesktopSanitizeResult,
    DesktopSanitizerService,
    RulesStoreError,
)

def _blocked_store_path(tmp_path: Path) -> Path:
    """Caminho cuja pasta é na verdade um arquivo: a gravação falha em qualquer sistema."""
    blocker = tmp_path / "bloqueio"
    blocker.write_text("x", encoding="utf-8")
    return blocker / "rules.enc.json"

def test_create_rule_rolls_back_when_store_cannot_be_saved(tmp_path: Path):
    service = DesktopSanitizerService(storage_path=_blocked_store_path(tmp_path))
    with pytest.raises(RulesStoreError):
        service.create_rule("CESAR", "[COMPANY_SENSITIVE]")
        assert service.list_rules() == []

def test_update_and_delete_roll_back_when_store_cannot_be_saved(tmp_path: Path):
    service = DesktopSanitizerService(storage_path=tmp_path / "rules.enc.json")
    rule = service.create_rule("CESAR", "[COMPANY_SENSITIVE]")
    service.storage_path = _blocked_store_path(tmp_path)
    with pytest.raises(RulesStoreError):
        service.update_rule(rule.id, replacement_tag="[OUTRA_TAG]")
    assert service.list_rules()[0].replacement_tag == "[COMPANY_SENSITIVE]"
    with pytest.raises(RulesStoreError):
        service.delete_rule(rule.id)
        assert len(service.list_rules()) == 1
"""Unit and integration tests for the Windows Global Desktop Agent."""

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
    """In-memory clipboard simulator for deterministic testing."""

    def __init__(self, initial: str = ""):
        self.content = initial

    def get(self) -> str:
        return self.content

    def set(self, text: str) -> None:
        self.content = text


def test_encrypted_disk_persistence_zero_plaintext(tmp_path: Path):
    """Verifies that custom rules are persisted encrypted on disk with zero plaintext leakage."""
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

    # Reload in a fresh service instance to verify persistence across restarts
    reloaded_service = DesktopSanitizerService(storage_path=store_file)
    rules = reloaded_service.list_rules()
    assert len(rules) == 1
    assert rules[0].id == created.id
    assert rules[0].replacement_tag == "[PROJETO_CONFIDENCIAL]"

    # Verify duplicate rejection via blind index
    with pytest.raises(ValueError, match="já está cadastrado"):
        reloaded_service.create_rule(
            term="projeto ultra secreto",
            replacement_tag="[OUTRA_TAG]",
        )


def test_desktop_crud_update_and_delete(tmp_path: Path):
    """Verifies updating and deleting rules in the DesktopSanitizerService."""
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
    """Verifies real-time clipboard monitoring sanitizes sensitive prompts once without looping."""
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

    # User copies a prompt with custom confidential term + valid CPF + email
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

    # Subsequent poll on already sanitized clipboard must be a no-op
    second_result = monitor.inspect_clipboard_once()
    assert second_result is None
    assert len(events) == 1


@uses_real_clipboard
def test_active_chat_hotkey_in_place_sanitization(tmp_path: Path):
    """Verifies Ctrl+Shift+S active chat sanitization flow."""
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
    """Verifies AI chat window title detection."""
    assert Win32Bridge.is_ai_context("ChatGPT - Google Chrome") is True
    assert Win32Bridge.is_ai_context("Claude - Mozilla Firefox") is True
    assert Win32Bridge.is_ai_context("Microsoft Copilot") is True
    assert Win32Bridge.is_ai_context("projeto-vibe - Visual Studio Code") is True
    assert Win32Bridge.is_ai_context("Calculadora") is False


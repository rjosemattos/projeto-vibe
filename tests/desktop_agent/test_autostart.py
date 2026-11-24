"""Testes do registro de início automático com o Windows."""

import sys

import pytest

from app.desktop_agent import autostart


def test_launch_command_runs_agent_in_background():
    command = autostart.build_launch_command()
    assert command.endswith(autostart.BACKGROUND_FLAG)
    assert "run_desktop_agent.py" in command


def test_launch_command_uses_frozen_executable(monkeypatch):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", r"C:\Apps\PromptSanitizerAgent.exe")
    assert autostart.build_launch_command() == r"C:\Apps\PromptSanitizerAgent.exe --background"


@pytest.mark.skipif(autostart.IS_WINDOWS, reason="non-Windows fallback behaviour")
def test_non_windows_reports_disabled_and_refuses_enable():
    assert autostart.is_enabled() is False
    assert autostart.disable() is False
    with pytest.raises(OSError):
        autostart.enable()

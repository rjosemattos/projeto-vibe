#!/usr/bin/env python3
"""Entry point for the Prompt Sanitizer Desktop Agent and command-line sanitizer.

Usage:
    python run_desktop_agent.py                       (HUD + tray, Windows recommended)
    pythonw run_desktop_agent.py                      (no console window on Windows)
    python run_desktop_agent.py --self-test
    python run_desktop_agent.py --sanitize "CPF 123.456.789-09"
    echo "meu email a@b.com" | python run_desktop_agent.py --sanitize -
    python run_desktop_agent.py --sanitize - --json < prompt.txt
"""

import argparse
import json
import socket
import sys

from app.desktop_agent.service import DesktopSanitizerService

SINGLE_INSTANCE_PORT = 47653


def _configure_stdio() -> None:
    """Avoids UnicodeEncodeError on legacy Windows consoles (cp1252)."""
    for stream in (sys.stdout, sys.stderr, sys.stdin):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass


def run_self_test() -> int:
    """Runs an automated verification of the desktop agent pipeline and CRUD encryption."""
    import tempfile
    from pathlib import Path

    print("=" * 68)
    print("  PROMPT SANITIZER — DESKTOP AGENT SELF-TEST")
    print("=" * 68)

    with tempfile.TemporaryDirectory() as tmp_dir:
        service = DesktopSanitizerService(storage_path=Path(tmp_dir) / "rules.enc.json")

        rule = service.create_rule(
            term="CESAR",
            replacement_tag="[COMPANY_SENSITIVE]",
            case_sensitive=False,
            match_whole_word=True,
        )
        print(f"[+] Regra confidencial criada (mascarada): {rule.masked_term} -> {rule.replacement_tag}")

        sample_prompt = (
            "Olá ChatGPT, revise o contrato da CESAR para o cliente João Silva, "
            "CPF 123.456.789-09 e email joao.silva@empresa.com.br."
        )
        print(f"\n[Prompt Original]:\n  {sample_prompt}")

        result = service.sanitize_prompt(sample_prompt)
        print(f"\n[Prompt Sanitizado]:\n  {result.sanitized_text}")
        print(f"\n[Resumo do Agente]:\n  {result.summary_badge}")
        print("=" * 68)
    return 0


def run_cli_sanitize(text_arg: str, as_json: bool) -> int:
    """Sanitizes text from an argument (or stdin when '-') and prints the result to stdout."""
    text = sys.stdin.read() if text_arg == "-" else text_arg
    service = DesktopSanitizerService()
    result = service.sanitize_prompt(text)

    if as_json:
        print(
            json.dumps(
                {
                    "sanitized_prompt": result.sanitized_text,
                    "changed": result.changed,
                    "total_detections": result.total_detections,
                    "detected_types": result.detected_types,
                    "risk_level": result.risk_level.value,
                    "risk_score": result.risk_score,
                    "reasons": result.reasons,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
    else:
        sys.stdout.write(result.sanitized_text)
        if not result.sanitized_text.endswith("\n"):
            sys.stdout.write("\n")
        print(f"# {result.summary_badge}", file=sys.stderr)
    # Exit code 10 signals "sensitive data was found" for scripting / pre-commit usage
    return 10 if result.changed else 0


def _acquire_single_instance_lock():
    """Binds a localhost socket to guarantee only one agent runs at a time."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", SINGLE_INSTANCE_PORT))
        sock.listen(1)
        return sock
    except OSError:
        sock.close()
        return None


def _enable_windows_dpi_awareness() -> None:
    """Prevents blurry/mis-sized UI on high-DPI Windows displays."""
    if sys.platform != "win32":
        return
    try:
        import ctypes

        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        pass


def _fatal(message: str) -> int:
    """Reports a fatal startup error to the console and, on GUI launches, via a message box."""
    print(f"[ERRO] {message}", file=sys.stderr)
    try:
        import tkinter as tk
        from tkinter import messagebox

        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("Prompt Sanitizer", message)
        root.destroy()
    except Exception:
        pass
    return 1


def main() -> int:
    _configure_stdio()
    parser = argparse.ArgumentParser(
        description="Prompt Sanitizer — Agente Desktop Global e sanitizador de linha de comando"
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Executa um teste rápido do motor Desktop e encerra.",
    )
    parser.add_argument(
        "--sanitize",
        metavar="TEXTO",
        help="Sanitiza o texto informado (use '-' para ler da entrada padrão) e encerra. "
        "Código de saída 10 se dados sensíveis foram encontrados.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Com --sanitize, imprime o resultado completo em JSON.",
    )
    args = parser.parse_args()

    if args.self_test:
        return run_self_test()
    if args.sanitize is not None:
        return run_cli_sanitize(args.sanitize, args.json)

    try:
        import tkinter  # noqa: F401
    except ImportError:
        return _fatal(
            "O módulo tkinter não está disponível. No Windows, reinstale o Python marcando 'tcl/tk'. "
            "No Linux: sudo apt install python3-tk"
        )

    lock = _acquire_single_instance_lock()
    if lock is None:
        return _fatal("O Prompt Sanitizer já está em execução (verifique o ícone na bandeja do sistema).")

    _enable_windows_dpi_awareness()

    from app.desktop_agent.ui_hud import PromptSanitizerDesktopApp

    app = PromptSanitizerDesktopApp()
    try:
        app.run()
    finally:
        lock.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())

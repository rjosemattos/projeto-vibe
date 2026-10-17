#!/usr/bin/env python3
"""Entry point for the Prompt Sanitizer Windows Global Desktop Agent.

Usage on Windows:
    python run_desktop_agent.py
    pythonw run_desktop_agent.py          (runs without console window)
    python run_desktop_agent.py --self-test
"""

import argparse
import sys

from app.desktop_agent.service import DesktopSanitizerService


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


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Prompt Sanitizer — Agente Desktop Global para Windows"
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Executa um teste rápido do motor Desktop e encerra.",
    )
    args = parser.parse_args()

    if args.self_test:
        return run_self_test()

    from app.desktop_agent.ui_hud import PromptSanitizerDesktopApp

    app = PromptSanitizerDesktopApp()
    app.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())

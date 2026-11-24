"""Testes que garantem que as regex são imunes a ReDoS (negação de serviço por expressão regular)."""

import time
from app.detection.engine import DetectionEngine


def test_redos_adversarial_email_pattern():
    engine = DetectionEngine()
    # Gatilho típico de ReDoS: prefixos alfanuméricos longos e repetitivos sem domínio no final
    adversarial_text = ("a" * 2000) + "@" + ("b" * 2000) + "!@#$%^&*"

    start = time.perf_counter()
    results = engine.analyze(adversarial_text)
    duration = time.perf_counter() - start

    # Precisa terminar rápido (< 0,2 s), provando que não há backtracking catastrófico
    assert duration < 0.2
    assert isinstance(results, list)


def test_redos_adversarial_cpf_spaces():
    engine = DetectionEngine()
    # Sequências longas de espaços e dígitos
    adversarial_text = "c - p - f : " + (" " * 1000) + ("9" * 1000) + " - 00"

    start = time.perf_counter()
    results = engine.analyze(adversarial_text)
    duration = time.perf_counter() - start

    assert duration < 0.2


def test_redos_adversarial_credentials_pattern():
    engine = DetectionEngine()
    # Aspas aninhadas e atribuições repetitivas
    adversarial_text = 'password="' + ("a=" * 1000) + '" secret="' + ("b:" * 1000)

    start = time.perf_counter()
    results = engine.analyze(adversarial_text)
    duration = time.perf_counter() - start

    assert duration < 0.2


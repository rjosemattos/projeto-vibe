"""Tests ensuring regexes are immune to ReDoS (Regular Expression Denial of Service)."""

import time
from app.detection.engine import DetectionEngine


def test_redos_adversarial_email_pattern():
    engine = DetectionEngine()
    # Typical ReDoS trigger: long repetitive alphanumeric prefixes without final domain match
    adversarial_text = ("a" * 2000) + "@" + ("b" * 2000) + "!@#$%^&*"

    start = time.perf_counter()
    results = engine.analyze(adversarial_text)
    duration = time.perf_counter() - start

    # Must finish rapidly (< 0.2s), proving absence of catastrophic backtracking
    assert duration < 0.2
    assert isinstance(results, list)


def test_redos_adversarial_cpf_spaces():
    engine = DetectionEngine()
    # Long sequences of spaces and digits
    adversarial_text = "c - p - f : " + (" " * 1000) + ("9" * 1000) + " - 00"

    start = time.perf_counter()
    results = engine.analyze(adversarial_text)
    duration = time.perf_counter() - start

    assert duration < 0.2


def test_redos_adversarial_credentials_pattern():
    engine = DetectionEngine()
    # Nested quotes, repetitive assignments
    adversarial_text = 'password="' + ("a=" * 1000) + '" secret="' + ("b:" * 1000)

    start = time.perf_counter()
    results = engine.analyze(adversarial_text)
    duration = time.perf_counter() - start

    assert duration < 0.2


"""Testes do SanitizationEngine e da consistência das entidades."""

from app.detection.engine import DetectionEngine
from app.sanitization.engine import SanitizationEngine


def test_sanitization_single_entity():
    engine = DetectionEngine()
    sanitizer = SanitizationEngine()
    text = "Analise este cliente: João da Silva, CPF 123.456.789-09, e me diga se ele pode contratar o serviço."

    detections = engine.analyze(text)
    sanitized = sanitizer.sanitize(text, detections)

    assert "123.456.789-09" not in sanitized
    assert "[CPF_USUARIO]" in sanitized
    assert "Analise este cliente: João da Silva, CPF [CPF_USUARIO], e me diga se ele pode contratar o serviço." == sanitized


def test_sanitization_multiple_different_types():
    engine = DetectionEngine()
    sanitizer = SanitizationEngine()
    text = "Meu CPF é 123.456.789-09 e meu email é teste@email.com"

    detections = engine.analyze(text)
    sanitized = sanitizer.sanitize(text, detections)

    assert "[CPF_USUARIO]" in sanitized
    assert "[EMAIL_USUARIO]" in sanitized
    assert "123.456.789-09" not in sanitized
    assert "teste@email.com" not in sanitized


def test_sanitization_entity_consistency_same_entity_repeated():
    engine = DetectionEngine()
    sanitizer = SanitizationEngine()
    # O mesmo CPF duas vezes: uma formatada e outra sem formatação
    text = "O CPF 123.456.789-09 pertence ao cliente. Verifique novamente o CPF 12345678909."

    detections = engine.analyze(text)
    sanitized = sanitizer.sanitize(text, detections)

    # As duas ocorrências viram [CPF_USUARIO_1], porque são exatamente a mesma entidade!
    assert "[CPF_USUARIO_1]" in sanitized
    assert "[CPF_USUARIO_2]" not in sanitized
    assert sanitized.count("[CPF_USUARIO_1]") == 2
    assert "123.456.789-09" not in sanitized
    assert "12345678909" not in sanitized


def test_sanitization_distinct_entities_same_type():
    engine = DetectionEngine()
    sanitizer = SanitizationEngine()
    # Dois CPFs diferentes
    text = "Compare os CPFs 123.456.789-09 e 529.982.247-25 para validação."

    detections = engine.analyze(text)
    sanitized = sanitizer.sanitize(text, detections)

    assert "[CPF_USUARIO_1]" in sanitized
    assert "[CPF_USUARIO_2]" in sanitized
    assert "123.456.789-09" not in sanitized
    assert "529.982.247-25" not in sanitized


def test_sanitization_clean_text_unchanged():
    engine = DetectionEngine()
    sanitizer = SanitizationEngine()
    text = "Este é um prompt normal sobre culinária e programação sem dados sensíveis."

    detections = engine.analyze(text)
    sanitized = sanitizer.sanitize(text, detections)

    assert sanitized == text


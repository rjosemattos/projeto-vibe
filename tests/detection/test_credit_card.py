"""Testes da detecção de cartão de crédito e da validação pelo algoritmo de Luhn."""

from app.detection.detectors.credit_card import CreditCardDetector
from app.detection.validators import validate_luhn


def test_luhn_validator():
    # Cartões válidos
    assert validate_luhn("4532123456789014") is True  # Visa
    assert validate_luhn("4111111111111111") is True  # Visa de teste
    assert validate_luhn("378282246310005") is True   # Amex de 15 dígitos
    assert validate_luhn("5555555555554444") is True  # Mastercard

    # Cartões inválidos
    assert validate_luhn("4532123456789010") is False
    assert validate_luhn("1234567812345678") is False
    assert validate_luhn("0000000000000000") is True  # Passa na conta, mas o detector rejeita só zeros
    assert validate_luhn("123") is False


def test_credit_card_detector_blocks():
    detector = CreditCardDetector()
    text = "Cartão de crédito Visa: 4532 1234 5678 9014 para cobrança."
    detections = detector.detect(text)

    assert len(detections) == 1
    det = detections[0]
    assert det.type == "CARTAO_CREDITO"
    assert det.masked_value == "****-****-****-9014"
    assert det.normalized_key == "card:4532123456789014"
    assert det.severity.value == "HIGH"


def test_credit_card_detector_amex():
    detector = CreditCardDetector()
    text = "Pagamento Amex: 3782-822463-10005 confirmado."
    detections = detector.detect(text)

    assert len(detections) == 1
    assert detections[0].type == "CARTAO_CREDITO"


def test_credit_card_detector_rejects_false_positives():
    detector = CreditCardDetector()
    # Sequência de dígitos iguais (0000 0000 0000 0000)
    text = "Número 0000 0000 0000 0000 deve ser rejeitado."
    assert len(detector.detect(text)) == 0

    # Números de pedido ou IDs que não passam em Luhn
    text2 = "Pedido 1234 5678 9012 3456 e protocolo 9876-5432-1098-7654."
    assert len(detector.detect(text2)) == 0


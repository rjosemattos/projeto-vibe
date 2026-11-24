"""Testes da detecção de CPF e da validação pelo módulo 11."""

from app.detection.detectors.cpf import CPFDetector
from app.detection.validators import validate_cpf


def test_cpf_validator_valid():
    # 12345678909 é matematicamente válido
    assert validate_cpf("123.456.789-09") is True
    assert validate_cpf("12345678909") is True


def test_cpf_validator_invalid():
    # Dígitos verificadores inválidos
    assert validate_cpf("123.456.789-00") is False
    assert validate_cpf("12345678999") is False
    # Sequência de dígitos iguais (padrão inválido conhecido)
    assert validate_cpf("000.000.000-00") is False
    assert validate_cpf("111.111.111-11") is False
    assert validate_cpf("99999999999") is False
    # Tamanhos errados
    assert validate_cpf("123456789") is False
    assert validate_cpf("123456789012") is False


def test_cpf_detector_formatted():
    detector = CPFDetector()
    text = "O cliente João tem o CPF 123.456.789-09 cadastrado."
    detections = detector.detect(text)

    assert len(detections) == 1
    det = detections[0]
    assert det.type == "CPF"
    assert det.raw_value == "123.456.789-09"
    assert det.normalized_key == "cpf:12345678909"
    assert det.masked_value == "123.***.***-09"
    assert det.severity.value == "HIGH"
    assert det.confidence >= 0.95


def test_cpf_detector_unformatted():
    detector = CPFDetector()
    text = "Documento informado: 12345678909 em anexo."
    detections = detector.detect(text)

    assert len(detections) == 1
    assert detections[0].raw_value == "12345678909"
    assert detections[0].normalized_key == "cpf:12345678909"


def test_cpf_detector_adversarial_spaces():
    detector = CPFDetector()
    # Variação com espaços: 123 . 456 . 789 - 09
    text = "Meu doc é 123 . 456 . 789 - 09 verifique."
    detections = detector.detect(text)

    assert len(detections) == 1
    assert detections[0].normalized_key == "cpf:12345678909"

    # Dígitos separados por espaço: 123 456 789 09
    text2 = "Registro 123 456 789 09 ok."
    detections2 = detector.detect(text2)
    assert len(detections2) == 1
    assert detections2[0].normalized_key == "cpf:12345678909"


def test_cpf_detector_adversarial_labels():
    detector = CPFDetector()
    text = "c-p-f: 123.456.789-09 e CPF: 12345678909"
    detections = detector.detect(text)

    assert len(detections) == 2
    assert detections[0].normalized_key == detections[1].normalized_key


def test_cpf_detector_rejects_false_positives():
    detector = CPFDetector()
    # Números de pedido e sequências aleatórias de 11 dígitos que não passam no módulo 11
    text = "Pedido 98765432101, protocolo 11111111111, timestamp 17163000000."
    detections = detector.detect(text)
    assert len(detections) == 0

"""Tests for CNPJ detection and semantic Modulo 11 validation."""

from app.detection.detectors.cnpj import CNPJDetector
from app.detection.validators import validate_cnpj


def test_cnpj_validator_valid():
    # Banco do Brasil: 00.000.000/0001-91
    assert validate_cnpj("00.000.000/0001-91") is True
    assert validate_cnpj("00000000000191") is True


def test_cnpj_validator_invalid():
    # Invalid check digits
    assert validate_cnpj("00.000.000/0001-00") is False
    assert validate_cnpj("12345678000199") is False
    # All identical digits
    assert validate_cnpj("00000000000000") is False
    assert validate_cnpj("11.111.111/1111-11") is False
    # Wrong length
    assert validate_cnpj("123456780001") is False


def test_cnpj_detector_formatted():
    detector = CNPJDetector()
    text = "Faturamento da empresa CNPJ: 00.000.000/0001-91 com sucesso."
    detections = detector.detect(text)

    assert len(detections) == 1
    det = detections[0]
    assert det.type == "CNPJ"
    assert det.raw_value == "00.000.000/0001-91"
    assert det.normalized_key == "cnpj:00000000000191"
    assert det.masked_value == "00.***.***/0001-91"
    assert det.severity.value == "HIGH"


def test_cnpj_detector_unformatted():
    detector = CNPJDetector()
    text = "Empresa código 00000000000191 aprovada."
    detections = detector.detect(text)

    assert len(detections) == 1
    assert detections[0].normalized_key == "cnpj:00000000000191"


def test_cnpj_detector_spaced():
    detector = CNPJDetector()
    text = "CNPJ 00 . 000 . 000 / 0001 - 91 registrado."
    detections = detector.detect(text)

    assert len(detections) == 1
    assert detections[0].normalized_key == "cnpj:00000000000191"


def test_cnpj_rejects_false_positives():
    detector = CNPJDetector()
    # Random 14-digit number that fails Modulo 11
    text = "Código de rastreamento internacional: 98765432109876."
    detections = detector.detect(text)
    assert len(detections) == 0


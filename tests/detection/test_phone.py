"""Testes do detector de telefone."""

from app.detection.detectors.phone import PhoneDetector


def test_phone_detector_br_mobile():
    detector = PhoneDetector()
    text = "Fale comigo no WhatsApp: (11) 98765-4321 para detalhes."
    detections = detector.detect(text)

    assert len(detections) == 1
    det = detections[0]
    assert det.type == "TELEFONE"
    assert "987654321" in det.normalized_key
    assert det.severity.value == "MEDIUM"


def test_phone_detector_br_landline():
    detector = PhoneDetector()
    text = "Telefone fixo da central: (21) 3456-7890 ligue agora."
    detections = detector.detect(text)

    assert len(detections) == 1
    assert detections[0].type == "TELEFONE"


def test_phone_detector_international():
    detector = PhoneDetector()
    text = "Call support at +1 415 555 2671."
    detections = detector.detect(text)

    assert len(detections) == 1
    assert detections[0].type == "TELEFONE"


def test_phone_detector_rejects_dates_and_math():
    detector = PhoneDetector()
    text = "Data de hoje 2026-09-18 e cálculo 5000 - 2000 = 3000."
    detections = detector.detect(text)
    assert len(detections) == 0


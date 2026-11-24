"""Testes do detector de e-mail."""

from app.detection.detectors.email import EmailDetector


def test_email_detector_standard():
    detector = EmailDetector()
    text = "Envie os relatórios para rodrigo.silva@empresa.com.br até o fim do dia."
    detections = detector.detect(text)

    assert len(detections) == 1
    det = detections[0]
    assert det.type == "EMAIL"
    assert det.raw_value == "rodrigo.silva@empresa.com.br"
    assert det.normalized_key == "email:rodrigo.silva@empresa.com.br"
    assert det.masked_value == "ro***@empresa.com.br"
    assert det.severity.value == "MEDIUM"


def test_email_detector_multiple():
    detector = EmailDetector()
    text = "Emails: suporte@servico.com e financeiro@servico.com."
    detections = detector.detect(text)

    assert len(detections) == 2
    assert detections[0].normalized_key == "email:suporte@servico.com"
    assert detections[1].normalized_key == "email:financeiro@servico.com"


def test_email_detector_rejects_invalid():
    detector = EmailDetector()
    # Formatos de e-mail inválidos
    text = "Texto comum com @arroba solto, teste@invalido sem tld e teste..duplo@invalido.com"
    detections = detector.detect(text)
    assert len(detections) == 0


"""Tests for DetectionEngine orchestration and span overlap resolution."""

from app.detection.engine import DetectionEngine


def test_engine_multiple_distinct_entities():
    engine = DetectionEngine()
    text = (
        "Cliente João Silva, CPF 123.456.789-09, email joao@empresa.com, "
        "com chave sk-proj-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6 cadastrada."
    )
    detections = engine.analyze(text)

    types = [d.type for d in detections]
    assert "CPF" in types
    assert "EMAIL" in types
    assert "API_KEY" in types
    assert len(detections) == 3

    # Detections should be in ascending start offset order
    for i in range(len(detections) - 1):
        assert detections[i].start < detections[i + 1].start
        assert detections[i].end <= detections[i + 1].start


def test_engine_overlap_resolution():
    engine = DetectionEngine()
    # A text where credentials detector might match "token=eyJ..." while JWT detector matches "eyJ..."
    text = 'token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozGzT_WwtqP_ErQDhbP_Wtc8qEkWk7_8b5wB2uF01g"'
    detections = engine.analyze(text)

    # Must resolve overlap to exactly one detection without broken bounds
    assert len(detections) == 1
    det = detections[0]
    assert det.type in ("JWT", "SENHA", "CREDENTIAL")


def test_engine_no_false_overlap():
    engine = DetectionEngine()
    # Card and phone on separate lines
    text = "Cartão: 4532 1234 5678 9014\nTel: (11) 98765-4321"
    detections = engine.analyze(text)

    assert len(detections) == 2
    types = {d.type for d in detections}
    assert "CARTAO_CREDITO" in types
    assert "TELEFONE" in types


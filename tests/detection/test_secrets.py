"""Tests for API keys, JWTs, Bearer tokens, passwords, and credential detectors."""

from app.detection.detectors.api_key import APIKeyDetector
from app.detection.detectors.credentials import CredentialsDetector
from app.detection.detectors.jwt import JWTDetector


def test_openai_api_key_detector():
    detector = APIKeyDetector()
    text = "Use key: sk-proj-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6 to run."
    detections = detector.detect(text)

    assert len(detections) == 1
    det = detections[0]
    assert det.type == "API_KEY"
    assert det.severity.value == "CRITICAL"
    assert "sk-proj-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6" not in det.masked_value
    assert "************" in det.masked_value


def test_aws_access_key_detector():
    detector = APIKeyDetector()
    text = "Config AWS: AKIAIOSFODNN7EXAMPLE para o bucket s3."
    detections = detector.detect(text)

    assert len(detections) == 1
    det = detections[0]
    assert det.type == "API_KEY"
    assert det.severity.value == "CRITICAL"
    assert "AKIAIOSFODNN7EXAMPLE" not in det.masked_value


def test_github_token_detector():
    detector = APIKeyDetector()
    text = "Token: ghp_1234567890abcdefghijklmnopqrstuvwxyz"
    detections = detector.detect(text)

    assert len(detections) == 1
    assert detections[0].type == "API_KEY"


def test_jwt_detector():
    detector = JWTDetector()
    text = (
        "Token JWT recebido: "
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozGzT_WwtqP_ErQDhbP_Wtc8qEkWk7_8b5wB2uF01g"
    )
    detections = detector.detect(text)

    assert len(detections) == 1
    det = detections[0]
    assert det.type == "JWT"
    assert det.severity.value == "CRITICAL"
    assert "eyJ" in det.masked_value


def test_bearer_and_password_detector():
    detector = CredentialsDetector()
    text = 'Bearer abcdef1234567890xyz! e password="MinhaSenhaSuperSecreta!"'
    detections = detector.detect(text)

    assert len(detections) == 2
    types = {d.type for d in detections}
    assert "BEARER_TOKEN" in types
    assert "SENHA" in types
    for d in detections:
        assert d.severity.value == "CRITICAL"
        assert "MinhaSenhaSuperSecreta" not in d.masked_value


def test_url_embedded_credentials():
    detector = CredentialsDetector()
    text = "Conecte no banco: postgres://admin:SuperSecretPass@db.internal.net:5432/main"
    detections = detector.detect(text)

    assert len(detections) == 1
    det = detections[0]
    assert det.type == "URL_PASSWORD"
    assert det.raw_value == "SuperSecretPass"
    assert "SuperSecretPass" not in det.masked_value


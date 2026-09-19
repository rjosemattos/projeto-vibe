"""Tests for RiskAnalyzer risk assessment logic and transparent scoring."""

from app.detection.base import Detection
from app.models.response import SeverityLevel
from app.risk.analyzer import RiskAnalyzer


def make_mock_detection(ent_type: str, severity: SeverityLevel) -> Detection:
    return Detection(
        type=ent_type,
        start=0,
        end=10,
        confidence=0.99,
        severity=severity,
        strategy="mock_strategy",
        raw_value="mock_value",
        normalized_key=f"{ent_type.lower()}:mock",
        masked_value="m***k",
    )


def test_risk_analyzer_empty():
    analyzer = RiskAnalyzer()
    report = analyzer.evaluate([])

    assert report.risk_level == SeverityLevel.LOW
    assert report.score == 0
    assert len(report.reasons) > 0


def test_risk_analyzer_critical_credentials():
    analyzer = RiskAnalyzer()
    detections = [make_mock_detection("API_KEY", SeverityLevel.CRITICAL)]
    report = analyzer.evaluate(detections)

    assert report.risk_level == SeverityLevel.CRITICAL
    assert report.score >= 85
    assert any("credenciais" in r.lower() or "chaves" in r.lower() for r in report.reasons)


def test_risk_analyzer_high_gov_id():
    analyzer = RiskAnalyzer()
    detections = [make_mock_detection("CPF", SeverityLevel.HIGH)]
    report = analyzer.evaluate(detections)

    assert report.risk_level == SeverityLevel.HIGH
    assert report.score >= 65


def test_risk_analyzer_pii_correlation():
    analyzer = RiskAnalyzer()
    detections = [
        make_mock_detection("CPF", SeverityLevel.HIGH),
        make_mock_detection("EMAIL", SeverityLevel.MEDIUM),
    ]
    report = analyzer.evaluate(detections)

    assert report.risk_level == SeverityLevel.HIGH
    assert report.score >= 75
    assert any("combinação" in r.lower() or "engenharia social" in r.lower() for r in report.reasons)


def test_risk_analyzer_medium_contact():
    analyzer = RiskAnalyzer()
    detections = [make_mock_detection("EMAIL", SeverityLevel.MEDIUM)]
    report = analyzer.evaluate(detections)

    assert report.risk_level == SeverityLevel.MEDIUM
    assert 30 <= report.score <= 60


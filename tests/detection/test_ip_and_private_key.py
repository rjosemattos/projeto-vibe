"""Tests for the IPv4 and PEM private key detectors."""

from app.detection.detectors.ip_address import IPAddressDetector
from app.detection.detectors.private_key import PrivateKeyDetector
from app.detection.engine import DetectionEngine
from app.sanitization.engine import SanitizationEngine


def test_ip_detects_private_and_public():
    dets = IPAddressDetector().detect("DB em 192.168.0.15 e gateway 8.8.8.8 ok")
    assert [d.raw_value for d in dets] == ["192.168.0.15", "8.8.8.8"]
    assert dets[0].masked_value == "192.***.***.15"


def test_ip_ignores_invalid_versions_and_loopback():
    text = "versão 1.2.3.4.5, ip 999.1.1.1, local 127.0.0.1, any 0.0.0.0"
    assert IPAddressDetector().detect(text) == []


def test_private_key_full_block():
    text = (
        "chave:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAabc123+/==\nxyz987\n"
        "-----END RSA PRIVATE KEY-----\nfim"
    )
    dets = PrivateKeyDetector().detect(text)
    assert len(dets) == 1
    assert dets[0].type == "PRIVATE_KEY"
    clean = SanitizationEngine().sanitize(text, dets)
    assert "MIIEow" not in clean and "[CHAVE_PRIVADA]" in clean and clean.endswith("fim")


def test_private_key_without_end_marker_is_still_redacted():
    text = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\nAAAAB3NzaC1yc2E"
    clean = SanitizationEngine().sanitize(text, DetectionEngine().analyze(text))
    assert "b3BlbnNzaC1" not in clean


def test_engine_integration_ip_placeholder():
    text = "Servidor 10.0.0.5 caiu"
    clean = SanitizationEngine().sanitize(text, DetectionEngine().analyze(text))
    assert clean == "Servidor [IP_USUARIO] caiu"

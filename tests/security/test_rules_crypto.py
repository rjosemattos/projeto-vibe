"""Tests for RuleCryptoService (AES-256-GCM and Blind Indexing)."""

import pytest
from app.core.crypto import RuleCryptoService


def test_encryption_and_decryption_roundtrip():
    crypto = RuleCryptoService()
    secret_term = "CESAR Inovação & Tecnologia"
    encrypted = crypto.encrypt(secret_term)

    assert encrypted != secret_term
    assert len(encrypted) > 28

    decrypted = crypto.decrypt(encrypted)
    assert decrypted == secret_term


def test_unique_nonce_generates_different_ciphertexts():
    crypto = RuleCryptoService()
    secret_term = "MesmoTermo"
    enc1 = crypto.encrypt(secret_term)
    enc2 = crypto.encrypt(secret_term)

    # In AES-GCM, each encryption uses a fresh 12-byte random nonce
    assert enc1 != enc2
    # Both decrypt back to the same plain text
    assert crypto.decrypt(enc1) == secret_term
    assert crypto.decrypt(enc2) == secret_term


def test_tampered_ciphertext_fails_authentication():
    crypto = RuleCryptoService()
    secret_term = "TopSecretProject"
    encrypted = crypto.encrypt(secret_term)

    # Tamper with base64 payload
    tampered = encrypted[:-2] + ("AA" if encrypted[-2:] != "AA" else "BB")

    try:
        crypto.decrypt(tampered)
        assert False, "Deveria ter lançado ValueError devido à falha de integridade do GCM."
    except ValueError as e:
        assert "Falha ao decifrar termo" in str(e)


def test_blind_index_deterministic_and_normalized():
    crypto = RuleCryptoService()
    h1 = crypto.compute_blind_index("CESAR")
    h2 = crypto.compute_blind_index("cesar")
    h3 = crypto.compute_blind_index("  CESAR  ")
    h4 = crypto.compute_blind_index("OutroTermo")

    # Blind index is casefolded and stripped
    assert h1 == h2
    assert h1 == h3
    assert h1 != h4


def test_mask_term_security():
    assert RuleCryptoService.mask_term("A") == "**"
    assert RuleCryptoService.mask_term("AB") == "**"
    assert RuleCryptoService.mask_term("ABC") == "A**C"
    assert RuleCryptoService.mask_term("CESAR") == "C***R"
    assert RuleCryptoService.mask_term("ProjetoConfidencial") == "P***l"

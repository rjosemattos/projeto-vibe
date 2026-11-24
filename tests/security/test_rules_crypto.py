"""Testes do RuleCryptoService (AES-256-GCM e índice cego)."""

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

    # No AES-GCM, cada cifragem usa um nonce aleatório novo de 12 bytes
    assert enc1 != enc2
    # As duas decifram de volta para o mesmo texto
    assert crypto.decrypt(enc1) == secret_term
    assert crypto.decrypt(enc2) == secret_term


def test_tampered_ciphertext_fails_authentication():
    crypto = RuleCryptoService()
    secret_term = "TopSecretProject"
    encrypted = crypto.encrypt(secret_term)

    # Altera o payload em base64
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

    # O índice cego ignora maiúsculas e espaços nas pontas
    assert h1 == h2
    assert h1 == h3
    assert h1 != h4


def test_mask_term_security():
    assert RuleCryptoService.mask_term("A") == "**"
    assert RuleCryptoService.mask_term("AB") == "**"
    assert RuleCryptoService.mask_term("ABC") == "A**C"
    assert RuleCryptoService.mask_term("CESAR") == "C***R"
    assert RuleCryptoService.mask_term("ProjetoConfidencial") == "P***l"

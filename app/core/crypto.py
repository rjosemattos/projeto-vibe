"""Application Cryptography Service (AEAD with AES-256-GCM and Blind Indexing).

Guarantees:
1. Confidential terms are encrypted at rest with AES-256-GCM using unique random 96-bit nonces.
2. Integrity and authenticity are strictly verified via GCM authentication tags.
3. Blind indexing uses HMAC-SHA256 to allow duplicate term detection without decrypting.
4. Masking utilities prevent raw sensitive terms from appearing in listings or the UI.
"""

import base64
import hashlib
import hmac
import os
import secrets
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

try:
    from app.core.logging import get_logger
    logger = get_logger(__name__)
except ImportError:
    import logging
    logger = logging.getLogger(__name__)


def _read_key_setting(name: str) -> str:
    """Reads a key from the environment, falling back to a `.env` file in the working directory.

    Mirrors the previous settings loader so keys configured in `.env` keep decrypting existing vaults.
    """
    value = os.getenv(name, "")
    if value:
        return value
    try:
        with open(".env", encoding="utf-8") as env_file:
            for line in env_file:
                key, sep, raw = line.strip().partition("=")
                if sep and key.strip() == name:
                    return raw.strip().strip("'\"")
    except OSError:
        pass
    return ""


class RuleCryptoService:
    """Manages authenticated encryption at rest and blind indexing for confidential terms."""

    def __init__(self, master_key: Optional[bytes] = None, hmac_key: Optional[bytes] = None):
        enc_key_str = _read_key_setting("PROMPT_SANITIZER_ENCRYPTION_KEY")
        blind_key_str = _read_key_setting("PROMPT_SANITIZER_BLIND_INDEX_KEY")

        if master_key:
            self._aes_key = master_key
        elif enc_key_str:
            try:
                decoded = base64.b64decode(enc_key_str)
                if len(decoded) != 32:
                    self._aes_key = hashlib.sha256(decoded).digest()
                else:
                    self._aes_key = decoded
            except Exception:
                self._aes_key = hashlib.sha256(enc_key_str.encode("utf-8")).digest()
        else:
            self._aes_key = self._local_key("aes", legacy=b"prompt-sanitizer-dev-aes-key-change-in-prod")

        if hmac_key:
            self._hmac_key = hmac_key
        elif blind_key_str:
            try:
                decoded = base64.b64decode(blind_key_str)
                if len(decoded) != 32:
                    self._hmac_key = hashlib.sha256(decoded).digest()
                else:
                    self._hmac_key = decoded
            except Exception:
                self._hmac_key = hashlib.sha256(blind_key_str.encode("utf-8")).digest()
        else:
            self._hmac_key = self._local_key("blind", legacy=b"prompt-sanitizer-dev-blind-index-key-change-in-prod")

        self._aesgcm = AESGCM(self._aes_key)

    @staticmethod
    def _local_key(name: str, legacy: bytes) -> bytes:
        """Returns a random per-installation key persisted in the user data dir (file mode 0600).

        Previously a hardcoded, publicly known key was used. To keep existing encrypted stores
        readable, the legacy key is still used when a rules store already exists but no local
        key file has been generated yet.
        """
        try:
            from app.core.paths import get_data_dir

            data_dir = get_data_dir()
            key_path = data_dir / f".{name}.key"
            if key_path.exists():
                raw = base64.b64decode(key_path.read_text(encoding="ascii").strip())
                if len(raw) == 32:
                    return raw
            elif (data_dir / "rules.enc.json").exists():
                return hashlib.sha256(legacy).digest()

            key = secrets.token_bytes(32)
            tmp_path = key_path.with_suffix(".tmp")
            fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="ascii") as fh:
                fh.write(base64.b64encode(key).decode("ascii"))
            os.replace(tmp_path, key_path)
            return key
        except Exception as exc:
            logger.error("Could not persist local key (%s); using legacy dev key.", type(exc).__name__)
            return hashlib.sha256(legacy).digest()

    def encrypt(self, plain_text: str) -> str:
        """Encrypts a plain text term using AES-256-GCM with a unique 12-byte random nonce.

        Returns a Base64-encoded string: nonce (12 bytes) + ciphertext + tag (16 bytes).
        """
        if not plain_text or not plain_text.strip():
            raise ValueError("O termo para cifragem não pode ser vazio.")

        nonce = secrets.token_bytes(12)
        data = plain_text.strip().encode("utf-8")
        ciphertext = self._aesgcm.encrypt(nonce, data, None)
        return base64.b64encode(nonce + ciphertext).decode("ascii")

    def decrypt(self, encrypted_payload: str) -> str:
        """Decrypts payload, validating integrity and authenticity tag."""
        if not encrypted_payload:
            raise ValueError("Payload de cifragem vazio.")

        try:
            raw_bytes = base64.b64decode(encrypted_payload.encode("ascii"))
            if len(raw_bytes) < 28:  # 12 bytes nonce + 16 bytes auth tag
                raise ValueError("Payload criptográfico menor que o tamanho mínimo.")

            nonce = raw_bytes[:12]
            ciphertext_with_tag = raw_bytes[12:]
            decrypted = self._aesgcm.decrypt(nonce, ciphertext_with_tag, None)
            return decrypted.decode("utf-8")
        except Exception as exc:
            raise ValueError("Falha ao decifrar termo: integridade inválida ou chave incorreta.") from exc

    def compute_blind_index(self, term: str) -> str:
        """Generates deterministic HMAC-SHA256 for duplicate lookup without decryption."""
        normalized = term.strip().casefold().encode("utf-8")
        return hmac.new(self._hmac_key, normalized, hashlib.sha256).hexdigest()

    @staticmethod
    def mask_term(term: str) -> str:
        """Masks a sensitive term for safe UI display (e.g., 'CESAR' -> 'C***R')."""
        clean = term.strip()
        length = len(clean)
        if length <= 2:
            return "**"
        if length <= 4:
            return f"{clean[0]}**{clean[-1]}"
        return f"{clean[0]}***{clean[-1]}"

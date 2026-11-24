"""Serviço de criptografia das regras confidenciais (AES-256-GCM + índice cego).

Garantias:
1. Os termos confidenciais são cifrados em repouso com AES-256-GCM, usando um nonce aleatório de 96 bits por cifragem.
2. A integridade e a autenticidade são verificadas pela tag de autenticação do GCM.
3. O índice cego (HMAC-SHA256) permite detectar termos duplicados sem decifrar nada.
4. A máscara (ex.: 'C***R') impede que o termo original apareça em listagens ou na interface.

Também contém as funções do backup do cofre, protegido por uma senha escolhida pelo usuário.
"""

import base64
import hashlib
import hmac
import os
import secrets
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

try:
    from app.core.logging import get_logger
    logger = get_logger(__name__)
except ImportError:
    import logging
    logger = logging.getLogger(__name__)


def _read_key_setting(name: str) -> str:
    """Lê uma chave do ambiente e, se não houver, de um arquivo `.env` na pasta atual.

    Mantém o comportamento do antigo carregador de configurações: chaves definidas no `.env`
    continuam decifrando os cofres já existentes.
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
    """Cifra os termos confidenciais em repouso e calcula o índice cego usado contra duplicidade."""

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

        # Instância reutilizada para cifrar e decifrar todos os termos com a mesma chave.
        self._aesgcm = AESGCM(self._aes_key)

    @staticmethod
    def _local_key(name: str, legacy: bytes) -> bytes:
        """Devolve a chave aleatória desta instalação, salva na pasta de dados (permissão 0600).

        Antigamente era usada uma chave fixa e pública. Para que cofres antigos continuem legíveis,
        a chave legada ainda é usada quando já existe um cofre de regras, mas nenhum arquivo de
        chave local foi gerado.
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
            logger.error("Não foi possível salvar a chave local (%s); usando a chave legada de desenvolvimento.", type(exc).__name__)
            return hashlib.sha256(legacy).digest()

    def encrypt(self, plain_text: str) -> str:
        """Cifra um termo com AES-256-GCM, usando um nonce aleatório de 12 bytes.

        Retorna uma string Base64 com: nonce (12 bytes) + texto cifrado + tag (16 bytes).
        """
        if not plain_text or not plain_text.strip():
            raise ValueError("O termo para cifragem não pode ser vazio.")

        nonce = secrets.token_bytes(12)
        data = plain_text.strip().encode("utf-8")
        ciphertext = self._aesgcm.encrypt(nonce, data, None)
        return base64.b64encode(nonce + ciphertext).decode("ascii")

    def decrypt(self, encrypted_payload: str) -> str:
        """Decifra o conteúdo, validando a integridade e a tag de autenticação."""
        if not encrypted_payload:
            raise ValueError("Payload de cifragem vazio.")

        try:
            raw_bytes = base64.b64decode(encrypted_payload.encode("ascii"))
            if len(raw_bytes) < 28:  # 12 bytes de nonce + 16 bytes da tag de autenticação
                raise ValueError("Payload criptográfico menor que o tamanho mínimo.")

            nonce = raw_bytes[:12]
            ciphertext_with_tag = raw_bytes[12:]
            decrypted = self._aesgcm.decrypt(nonce, ciphertext_with_tag, None)
            return decrypted.decode("utf-8")
        except Exception as exc:
            raise ValueError("Falha ao decifrar termo: integridade inválida ou chave incorreta.") from exc

    def compute_blind_index(self, term: str) -> str:
        """Gera o HMAC-SHA256 determinístico do termo, usado para achar duplicados sem decifrar."""
        # Normaliza o termo (sem espaços nas pontas e sem diferença de maiúsculas) para que
        # 'CESAR' e 'cesar' gerem o mesmo índice e sejam tratados como o mesmo termo.
        normalized = term.strip().casefold().encode("utf-8")
        return hmac.new(self._hmac_key, normalized, hashlib.sha256).hexdigest()

    @staticmethod
    def mask_term(term: str) -> str:
        """Mascara um termo sensível para exibição segura (ex.: 'CESAR' -> 'C***R')."""
        clean = term.strip()
        length = len(clean)
        if length <= 2:
            return "**"
        if length <= 4:
            return f"{clean[0]}**{clean[-1]}"
        return f"{clean[0]}***{clean[-1]}"

BACKUP_FORMAT = "prompt-sanitizer-rules-backup"
MIN_BACKUP_PASSWORD_LENGTH = 8


def _password_key(password: str, salt: bytes) -> bytes:
    """Deriva uma chave de 256 bits a partir da senha do backup, com scrypt."""
    return Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(password.encode("utf-8"))


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def encrypt_backup(data: bytes, password: str) -> dict:
    """Cifra o backup das regras com uma chave derivada da senha do usuário."""
    if len(password) < MIN_BACKUP_PASSWORD_LENGTH:
        raise ValueError(
            f"A senha do backup precisa ter pelo menos {MIN_BACKUP_PASSWORD_LENGTH} caracteres."
        )
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(_password_key(password, salt)).encrypt(nonce, data, None)
    return {
        "format": BACKUP_FORMAT,
        "version": 1,
        "kdf": "scrypt",
        "salt": _b64(salt),
        "nonce": _b64(nonce),
        "ciphertext": _b64(ciphertext),
    }


def decrypt_backup(payload: dict, password: str) -> bytes:
    """Decifra o backup das regras; lança ValueError se a senha estiver errada ou o arquivo tiver sido alterado."""
    if payload.get("format") != BACKUP_FORMAT or payload.get("version") != 1:
        raise ValueError("Arquivo de backup inválido.")
    try:
        salt = base64.b64decode(payload["salt"])
        nonce = base64.b64decode(payload["nonce"])
        ciphertext = base64.b64decode(payload["ciphertext"])
        return AESGCM(_password_key(password, salt)).decrypt(nonce, ciphertext, None)
    except Exception as exc:
        raise ValueError("Senha incorreta ou arquivo de backup corrompido.") from exc

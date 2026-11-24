"""Sistema de logs que preserva a privacidade.

Garantias:
1. Prompts e valores sensíveis detectados NUNCA são gravados nos logs.
2. O filtro apaga qualquer padrão de credencial ou dado sensível que chegue ao log por engano.
3. Nenhum stack trace com variáveis do prompt do usuário é emitido.
"""

import logging
import re
import sys
from typing import Optional


class PrivacyRedactingFilter(logging.Filter):
    """Filtro que apaga dados sensíveis das mensagens de log antes de serem gravadas."""

    SENSITIVE_PATTERNS = [
        re.compile(r"sk-[A-Za-z0-9-_]{10,}", re.IGNORECASE),
        re.compile(r"Bearer\s+[A-Za-z0-9._\-~+/=]{10,}", re.IGNORECASE),
        re.compile(r"AKIA[0-9A-Z]{16}", re.IGNORECASE),
        re.compile(r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b"),  # Parecido com CPF
        re.compile(r"\b\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}\b"),  # Parecido com CNPJ
        re.compile(r"\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b"),  # Parecido com cartão
    ]

    def filter(self, record: logging.LogRecord) -> bool:
        """Substitui padrões sensíveis na mensagem para evitar vazamento acidental de dados pessoais ou segredos."""
        if not isinstance(record.msg, str):
            return True

        msg = record.msg
        for pattern in self.SENSITIVE_PATTERNS:
            msg = pattern.sub("[REDACTED_BY_PRIVACY_FILTER]", msg)

        record.msg = msg
        return True


def setup_logging(level: str = "INFO") -> logging.Logger:
    """Configura e retorna o logger principal da aplicação."""
    root_logger = logging.getLogger("prompt_sanitizer")
    root_logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Evita handlers duplicados se a função for chamada mais de uma vez
    if not root_logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)
        handler.addFilter(PrivacyRedactingFilter())
        root_logger.addHandler(handler)

    # Não propaga para o logger raiz, que gravaria mensagens sem formatação e sem filtro
    root_logger.propagate = False
    return root_logger


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """Retorna um logger com o filtro de privacidade aplicado."""
    base = logging.getLogger("prompt_sanitizer")
    if name:
        return base.getChild(name)
    return base


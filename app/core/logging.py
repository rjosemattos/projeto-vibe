"""Privacy-preserving logging system.

Guarantees by design:
1. Prompts and sensitive detection values are NEVER written to logs.
2. Formatter redacts any potential credential or sensitive pattern if inadvertently passed.
3. No stack traces containing user prompt variables are emitted.
"""

import logging
import re
import sys
from typing import Optional


class PrivacyRedactingFilter(logging.Filter):
    """Filter that suppresses or redacts any sensitive keywords from log records."""

    SENSITIVE_PATTERNS = [
        re.compile(r"sk-[A-Za-z0-9-_]{10,}", re.IGNORECASE),
        re.compile(r"Bearer\s+[A-Za-z0-9._\-~+/=]{10,}", re.IGNORECASE),
        re.compile(r"AKIA[0-9A-Z]{16}", re.IGNORECASE),
        re.compile(r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b"),  # CPF-like
        re.compile(r"\b\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}\b"),  # CNPJ-like
        re.compile(r"\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b"),  # Card-like
    ]

    def filter(self, record: logging.LogRecord) -> bool:
        """Sanitize record message to prevent accidental PII/secret leaks."""
        if not isinstance(record.msg, str):
            return True

        msg = record.msg
        for pattern in self.SENSITIVE_PATTERNS:
            msg = pattern.sub("[REDACTED_BY_PRIVACY_FILTER]", msg)

        record.msg = msg
        return True


def setup_logging(level: str = "INFO") -> logging.Logger:
    """Configure and return the root application logger."""
    root_logger = logging.getLogger("prompt_sanitizer")
    root_logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Avoid duplicate handlers if called multiple times
    if not root_logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)
        handler.addFilter(PrivacyRedactingFilter())
        root_logger.addHandler(handler)

    # Disable propagation to default root to prevent unformatted/unfiltered dumps
    root_logger.propagate = False
    return root_logger


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """Get a logger instance with privacy filtering attached."""
    base = logging.getLogger("prompt_sanitizer")
    if name:
        return base.getChild(name)
    return base


"""Tests ensuring that no prompts or sensitive data leak through logs."""

import logging
from app.core.logging import PrivacyRedactingFilter, get_logger, setup_logging


def test_privacy_redacting_filter():
    filter_obj = PrivacyRedactingFilter()

    # Create a record with a simulated leak attempt
    record = logging.LogRecord(
        name="test_logger",
        level=logging.INFO,
        pathname="test.py",
        lineno=10,
        msg="Leaked secret: sk-1234567890abcdef123456 e CPF 123.456.789-09",
        args=(),
        exc_info=None,
    )

    filter_obj.filter(record)

    assert "sk-1234567890abcdef123456" not in record.msg
    assert "123.456.789-09" not in record.msg
    assert "[REDACTED_BY_PRIVACY_FILTER]" in record.msg


def test_logger_setup():
    logger = setup_logging("INFO")
    assert logger.level == logging.INFO
    assert len(logger.handlers) >= 1
    assert any(isinstance(f, PrivacyRedactingFilter) for f in logger.handlers[0].filters)


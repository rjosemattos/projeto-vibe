"""Detector for Credit and Debit Card numbers with Luhn semantic validation."""

import re
from typing import List
from app.detection.base import BaseDetector, Detection
from app.detection.validators import validate_luhn
from app.models.response import SeverityLevel


class CreditCardDetector(BaseDetector):
    """Detects credit/debit card numbers in groups of digits or contiguous streams with Luhn check."""

    name = "credit_card_detector"
    entity_type = "CARTAO_CREDITO"

    # Matches card formats:
    # 4x4: 1234 5678 9012 3456 or 1234-5678-9012-3456
    # Amex: 4-6-5 (3412 345678 90123)
    # Contiguous 13 to 19 digits
    PATTERN = re.compile(
        r"(?:\b|\b(?=\d))("
        r"\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{1,4}"  # 4-block format
        r"|\d{4}[ -]\d{6}[ -]\d{5}"             # Amex 15-digit format
        r"|\b\d{13,19}\b"                       # Raw continuous sequence
        r")(?:\b|(?<=\d)\b)",
        re.IGNORECASE,
    )

    # Common BIN patterns (Visa, Mastercard, Amex, Discover, Elo, Diners, Hipercard)
    BIN_PREFIXES = (
        "4",       # Visa
        "51", "52", "53", "54", "55", # Mastercard
        "22", "23", "24", "25", "26", "27", # Mastercard
        "34", "37", # Amex
        "6011", "65", # Discover
        "300", "301", "302", "303", "304", "305", "36", "38", # Diners
        "606282", # Hipercard
        "4011", "4389", "4514", "4576", "5041", "5066", "5090", "6277", "6362", "6363", # Elo
    )

    def detect(self, text: str) -> List[Detection]:
        detections: List[Detection] = []
        for match in self.PATTERN.finditer(text):
            candidate_raw = match.group(1)
            start, end = match.span(1)

            digits = re.sub(r"\D", "", candidate_raw)
            if not (13 <= len(digits) <= 19):
                continue

            # Check if all digits are identical (e.g., 0000000000000000)
            if digits == digits[0] * len(digits):
                continue

            # Must satisfy Luhn algorithm
            if not validate_luhn(digits):
                continue

            # Confidence assessment: higher if known IIN/BIN prefix or separated by spaces/hyphens
            has_separators = (" " in candidate_raw) or ("-" in candidate_raw)
            matches_known_bin = any(digits.startswith(prefix) for prefix in self.BIN_PREFIXES)

            if matches_known_bin and has_separators:
                confidence = 0.99
            elif matches_known_bin or has_separators:
                confidence = 0.92
            else:
                confidence = 0.85

            masked = f"****-****-****-{digits[-4:]}"

            detections.append(
                Detection(
                    type=self.entity_type,
                    start=start,
                    end=end,
                    confidence=confidence,
                    severity=SeverityLevel.HIGH,
                    strategy="luhn_algorithm",
                    raw_value=candidate_raw,
                    normalized_key=f"card:{digits}",
                    masked_value=masked,
                )
            )

        return detections


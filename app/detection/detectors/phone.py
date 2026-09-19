"""Detector for Brazilian and International phone numbers."""

import re
from typing import List
from app.detection.base import BaseDetector, Detection
from app.models.response import SeverityLevel


class PhoneDetector(BaseDetector):
    """Detects Brazilian mobile and landline phones, plus E.164 international numbers."""

    name = "phone_detector"
    entity_type = "TELEFONE"

    # Valid Brazilian Area Codes (DDDs)
    VALID_DDDS = {
        11, 12, 13, 14, 15, 16, 17, 18, 19,
        21, 22, 24, 27, 28,
        31, 32, 33, 34, 35, 37, 38,
        41, 42, 43, 44, 45, 46, 47, 48, 49,
        51, 53, 54, 55,
        61, 62, 63, 64, 65, 66, 67, 68, 69,
        71, 73, 74, 75, 77, 79,
        81, 82, 83, 84, 85, 86, 87, 88, 89,
        91, 92, 93, 94, 95, 96, 97, 98, 99,
    }

    # Matches BR phones:
    # Optional country code: (+55 or 55)
    # Area code: (11) or 11
    # Mobile: 9XXXX-XXXX or 9XXXXXXXX
    # Landline: [2-5]XXX-XXXX or [2-5]XXXXXXX
    BR_PATTERN = re.compile(
        r"(?:(?<!\+)(?<!\d))"
        r"(?:(?:\+?55\s*)?(?:\(?([1-9]{2})\)?\s*))?"
        r"(?:(?:tel(?:efone)?|cel(?:ular)?|whatsapp|contato)[:\s]*)?"
        r"(?:(?:\+?55\s*)?(?:\(?([1-9]{2})\)?\s*))"
        r"(9\d{4}[ -]?\d{4}|[2-5]\d{3}[ -]?\d{4})"
        r"(?:\b|(?=[^\w\d]))",
        re.IGNORECASE,
    )

    # Simplified international format: +[1-9]\d{1,2}\s*[\(]?\d{1,4}[\)]?[ -]?\d{3,4}[ -]?\d{3,4}
    INTL_PATTERN = re.compile(
        r"(?:\b|(?<=[^\w\d]))"
        r"(\+[1-9]\d{0,2}[ -]?\(?\d{1,4}\)?[ -]?\d{3,4}[ -]?\d{3,4})"
        r"(?:\b|(?=[^\w\d]))"
    )

    def detect(self, text: str) -> List[Detection]:
        detections: List[Detection] = []
        spans_seen = set()

        # 1. Brazilian phone detection with DDD semantic check
        for match in self.BR_PATTERN.finditer(text):
            full_match = match.group(0)
            start, end = match.span()

            # Discard date-like strings (e.g. 2026-09-18)
            if re.search(r"\d{4}[-/]\d{2}[-/]\d{2}", full_match):
                continue

            # Extract DDD from group 1 or 2
            ddd_str = match.group(1) or match.group(2)
            if not ddd_str:
                continue

            try:
                ddd = int(ddd_str)
            except ValueError:
                continue

            if ddd not in self.VALID_DDDS:
                continue

            raw_digits = re.sub(r"\D", "", full_match)
            # BR phone with DDD is 10 or 11 digits (or 12-13 with +55)
            if len(raw_digits) < 10 or len(raw_digits) > 13:
                continue

            # Masking
            clean_digits = raw_digits[-11:] if len(raw_digits) >= 11 else raw_digits[-10:]
            masked = f"({clean_digits[:2]}) *****-{clean_digits[-4:]}"

            detections.append(
                Detection(
                    type=self.entity_type,
                    start=start,
                    end=end,
                    confidence=0.95,
                    severity=SeverityLevel.MEDIUM,
                    strategy="brazilian_phone_ddd_validation",
                    raw_value=full_match,
                    normalized_key=f"phone:{clean_digits}",
                    masked_value=masked,
                )
            )
            spans_seen.add((start, end))

        # 2. International phone detection
        for match in self.INTL_PATTERN.finditer(text):
            start, end = match.span(1)
            if any(s <= start and end <= e for s, e in spans_seen):
                continue

            candidate = match.group(1)
            raw_digits = re.sub(r"\D", "", candidate)
            if not (8 <= len(raw_digits) <= 15):
                continue

            masked = f"+{raw_digits[:2]} ***-***-{raw_digits[-4:]}"

            detections.append(
                Detection(
                    type=self.entity_type,
                    start=start,
                    end=end,
                    confidence=0.88,
                    severity=SeverityLevel.MEDIUM,
                    strategy="e164_international_phone",
                    raw_value=candidate,
                    normalized_key=f"phone:{raw_digits}",
                    masked_value=masked,
                )
            )

        return detections


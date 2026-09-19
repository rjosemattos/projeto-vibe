"""Detector for Brazilian CPF (Cadastro de Pessoas Físicas) with semantic validation."""

import re
from typing import List
from app.detection.base import BaseDetector, Detection
from app.detection.validators import validate_cpf
from app.models.response import SeverityLevel


class CPFDetector(BaseDetector):
    """Detects CPFs in various formats (standard, spaced, unlabeled, adversarial) with Modulo 11 validation."""

    name = "cpf_detector"
    entity_type = "CPF"

    # 1. Standard formatted: 123.456.789-09 with optional spaces around delimiters: 123 . 456 . 789 - 09
    # 2. Spaced digits: 123 456 789 09
    # 3. Unformatted 11 digits: bounded by non-digits
    PATTERN = re.compile(
        r"(?:(?:c\s*[-.]?\s*p\s*[-.]?\s*f|cpf)[:\s=]*)?"
        r"(?:\b|\b(?=\d))"
        r"(\d{3}\s*\.\s*\d{3}\s*\.\s*\d{3}\s*[-]\s*\d{2}|\d{3}\s+\d{3}\s+\d{3}\s+\d{2}|\b\d{11}\b)",
        re.IGNORECASE,
    )

    def detect(self, text: str) -> List[Detection]:
        detections: List[Detection] = []
        for match in self.PATTERN.finditer(text):
            # Target group 1 contains the candidate digits/separators
            candidate_raw = match.group(1)
            start, end = match.span(1)

            # Strip non-digits and validate
            digits = re.sub(r"\D", "", candidate_raw)
            if len(digits) != 11:
                continue

            if not validate_cpf(digits):
                # Mathematically invalid or fake/repeated sequence -> reject false positive!
                continue

            # Check if preceded by "cpf" or explicit punctuation
            has_label = bool(re.search(r"c\s*[-.]?\s*p\s*[-.]?\s*f", text[max(0, start - 15):start], re.IGNORECASE))
            has_punctuation = "." in candidate_raw or "-" in candidate_raw

            confidence = 0.99 if (has_punctuation or has_label) else 0.88
            masked = f"{digits[:3]}.***.***-{digits[9:]}"

            detections.append(
                Detection(
                    type=self.entity_type,
                    start=start,
                    end=end,
                    confidence=confidence,
                    severity=SeverityLevel.HIGH,
                    strategy="regex_semantic_mod11",
                    raw_value=candidate_raw,
                    normalized_key=f"cpf:{digits}",
                    masked_value=masked,
                )
            )

        return detections


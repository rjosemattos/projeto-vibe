"""Detector for Brazilian CNPJ (Cadastro Nacional da Pessoa Jurídica) with semantic validation."""

import re
from typing import List
from app.detection.base import BaseDetector, Detection
from app.detection.validators import validate_cnpj
from app.models.response import SeverityLevel


class CNPJDetector(BaseDetector):
    """Detects CNPJs in standard formatted, unformatted, and spaced variations with Modulo 11 validation."""

    name = "cnpj_detector"
    entity_type = "CNPJ"

    # 1. Standard formatted: 12.345.678/0001-90 (with optional spaces around separators)
    # 2. Raw unformatted 14 digits
    PATTERN = re.compile(
        r"(?:(?:c\s*[-.]?\s*n\s*[-.]?\s*p\s*[-.]?\s*j|cnpj)[:\s=]*)?"
        r"(?:\b|\b(?=\d))"
        r"(\d{2}\s*\.\s*\d{3}\s*\.\s*\d{3}\s*/\s*\d{4}\s*-\s*\d{2}|\b\d{14}\b)",
        re.IGNORECASE,
    )

    def detect(self, text: str) -> List[Detection]:
        detections: List[Detection] = []
        for match in self.PATTERN.finditer(text):
            candidate_raw = match.group(1)
            start, end = match.span(1)

            digits = re.sub(r"\D", "", candidate_raw)
            if len(digits) != 14:
                continue

            if not validate_cnpj(digits):
                continue

            has_label = bool(re.search(r"c\s*[-.]?\s*n\s*[-.]?\s*p\s*[-.]?\s*j", text[max(0, start - 15):start], re.IGNORECASE))
            has_punctuation = "/" in candidate_raw or "." in candidate_raw

            confidence = 0.99 if (has_punctuation or has_label) else 0.90
            masked = f"{digits[:2]}.***.***/{digits[8:12]}-{digits[12:]}"

            detections.append(
                Detection(
                    type=self.entity_type,
                    start=start,
                    end=end,
                    confidence=confidence,
                    severity=SeverityLevel.HIGH,
                    strategy="regex_semantic_mod11",
                    raw_value=candidate_raw,
                    normalized_key=f"cnpj:{digits}",
                    masked_value=masked,
                )
            )

        return detections


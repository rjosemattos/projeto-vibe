"""Detector de endereços de e-mail com padrões seguros contra ReDoS."""

import re
from typing import List
from app.detection.base import BaseDetector, Detection
from app.models.response import SeverityLevel


class EmailDetector(BaseDetector):
    """Detecta endereços de e-mail com uma expressão regular limitada, segura contra ReDoS."""

    name = "email_detector"
    entity_type = "EMAIL"

    # Regex de e-mail segura contra ReDoS: conjuntos de caracteres limitados, sem repetições aninhadas
    PATTERN = re.compile(
        r"\b[a-zA-Z0-9._%+-]{1,64}@[a-zA-Z0-9.-]{1,255}\.[a-zA-Z]{2,24}\b",
        re.IGNORECASE,
    )

    def detect(self, text: str) -> List[Detection]:
        detections: List[Detection] = []
        for match in self.PATTERN.finditer(text):
            candidate = match.group(0)
            start, end = match.span()

            # Verificações de sanidade
            if ".." in candidate or candidate.startswith(".") or candidate.endswith("."):
                continue

            parts = candidate.split("@", 1)
            if len(parts) != 2:
                continue

            user_part, domain_part = parts
            if not domain_part or "." not in domain_part:
                continue

            # Máscara segura: ex. jo***@dominio.com
            if len(user_part) <= 2:
                masked_user = user_part[0] + "***" if user_part else "***"
            else:
                masked_user = user_part[:2] + "***"

            masked = f"{masked_user}@{domain_part}"

            detections.append(
                Detection(
                    type=self.entity_type,
                    start=start,
                    end=end,
                    confidence=0.98,
                    severity=SeverityLevel.MEDIUM,
                    strategy="safe_rfc_email_regex",
                    raw_value=candidate,
                    normalized_key=f"email:{candidate.lower()}",
                    masked_value=masked,
                )
            )

        return detections


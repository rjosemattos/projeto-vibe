"""Detector for Email addresses with ReDoS-safe patterns."""

import re
from typing import List
from app.detection.base import BaseDetector, Detection
from app.models.response import SeverityLevel


class EmailDetector(BaseDetector):
    """Detects email addresses using a ReDoS-safe bounded regular expression."""

    name = "email_detector"
    entity_type = "EMAIL"

    # ReDoS-safe email regex: atomic-like bounded character sets without nested repetition
    PATTERN = re.compile(
        r"\b[a-zA-Z0-9._%+-]{1,64}@[a-zA-Z0-9.-]{1,255}\.[a-zA-Z]{2,24}\b",
        re.IGNORECASE,
    )

    def detect(self, text: str) -> List[Detection]:
        detections: List[Detection] = []
        for match in self.PATTERN.finditer(text):
            candidate = match.group(0)
            start, end = match.span()

            # Sanity checks
            if ".." in candidate or candidate.startswith(".") or candidate.endswith("."):
                continue

            parts = candidate.split("@", 1)
            if len(parts) != 2:
                continue

            user_part, domain_part = parts
            if not domain_part or "." not in domain_part:
                continue

            # Safe masking: e.g. jo***@domain.com
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


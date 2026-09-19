"""Detector for JSON Web Tokens (JWT)."""

import hashlib
import re
from typing import List
from app.detection.base import BaseDetector, Detection
from app.models.response import SeverityLevel


class JWTDetector(BaseDetector):
    """Detects standard JWT tokens (header.payload.signature in base64url)."""

    name = "jwt_detector"
    entity_type = "JWT"

    # Matches standard JWT tokens starting with eyJ (Base64 for {"...)
    PATTERN = re.compile(
        r"\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b"
    )

    def detect(self, text: str) -> List[Detection]:
        detections: List[Detection] = []
        for match in self.PATTERN.finditer(text):
            raw_token = match.group(0)
            start, end = match.span()

            # Hash the token deterministically for entity-consistent grouping without revealing it
            token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()[:12]
            masked = f"eyJ...{raw_token[-6:]}"

            detections.append(
                Detection(
                    type=self.entity_type,
                    start=start,
                    end=end,
                    confidence=0.99,
                    severity=SeverityLevel.CRITICAL,
                    strategy="jwt_token_pattern",
                    raw_value=raw_token,
                    normalized_key=f"jwt:{token_hash}",
                    masked_value=masked,
                )
            )

        return detections


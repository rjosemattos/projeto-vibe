"""Detector for PEM-encoded private keys (RSA, EC, OpenSSH, PGP, PKCS#8)."""

import hashlib
import re
from typing import List
from app.detection.base import BaseDetector, Detection
from app.models.response import SeverityLevel


class PrivateKeyDetector(BaseDetector):
    """Detects full PEM private key blocks, or a truncated block lacking the END marker."""

    name = "private_key_detector"
    entity_type = "PRIVATE_KEY"

    # Bounded quantifiers keep matching linear and ReDoS-safe.
    FULL_BLOCK = re.compile(
        r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----"
        r"[A-Za-z0-9+/=:,\s.\-]{16,20000}?"
        r"-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----"
    )
    # Fallback for pasted fragments with no END marker: redact header + following base64 lines
    PARTIAL_BLOCK = re.compile(
        r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----(?:[ \t]*\r?\n[A-Za-z0-9+/=:,.\- \t]{1,200}){0,400}"
    )

    def detect(self, text: str) -> List[Detection]:
        detections: List[Detection] = []
        spans = []
        for pattern, strategy, conf in (
            (self.FULL_BLOCK, "pem_private_key_block", 0.99),
            (self.PARTIAL_BLOCK, "pem_private_key_partial", 0.9),
        ):
            for match in pattern.finditer(text):
                start, end = match.span()
                if any(start < e and s < end for s, e in spans):
                    continue
                spans.append((start, end))
                raw = match.group(0)
                digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]
                detections.append(
                    Detection(
                        type=self.entity_type,
                        start=start,
                        end=end,
                        confidence=conf,
                        severity=SeverityLevel.CRITICAL,
                        strategy=strategy,
                        raw_value=raw,
                        normalized_key=f"pkey:{digest}",
                        masked_value="-----BEGIN PRIVATE KEY----- ********",
                    )
                )
        return detections

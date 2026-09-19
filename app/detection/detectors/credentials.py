"""Detector for generic credentials, Bearer tokens, passwords, and secrets in code/config/JSON."""

import hashlib
import re
from typing import List
from app.detection.base import BaseDetector, Detection
from app.models.response import SeverityLevel


class CredentialsDetector(BaseDetector):
    """Detects passwords, Bearer tokens, Authorization headers, and key-value secrets."""

    name = "credentials_detector"
    entity_type = "CREDENTIAL"

    # 1. Bearer Token pattern: Bearer <token>
    BEARER_PATTERN = re.compile(
        r"(?:Bearer\s+)([a-zA-Z0-9._\-~+/=]{16,128})",
        re.IGNORECASE,
    )

    # 2. Authorization Header pattern
    AUTH_HEADER_PATTERN = re.compile(
        r"(?:Authorization[:\s]+(?:Bearer|Basic)\s+)([a-zA-Z0-9._\-~+/=]{12,128})",
        re.IGNORECASE,
    )

    # 3. Key-Value pairs: (password|senha|secret|api_key|token) = "secret_val"
    KEY_VAL_PATTERN = re.compile(
        r"""(?:["']?(?:password|senha|secret|api[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token)["']?\s*[:=]\s*)"""
        r"""(?:["']([^"'\r\n]{4,128})["']|([a-zA-Z0-9!@#$%^&*()_+=\-{}\[\]:;<>,.?/~`]{6,128}))""",
        re.IGNORECASE,
    )

    # 4. URLs with embedded credentials: protocol://user:pass@host
    URL_CRED_PATTERN = re.compile(
        r"([a-zA-Z][a-zA-Z0-9+.-]*://[a-zA-Z0-9_.-]+:)([^@/\s]{3,64})(@[a-zA-Z0-9_.-]+)",
        re.IGNORECASE,
    )

    def detect(self, text: str) -> List[Detection]:
        detections: List[Detection] = []
        spans_seen = set()

        # Bearer tokens
        for match in self.BEARER_PATTERN.finditer(text):
            secret = match.group(1)
            start, end = match.span(1)
            self._add_detection(
                detections, spans_seen, "BEARER_TOKEN", secret, start, end, "bearer_token_pattern"
            )

        # Authorization header
        for match in self.AUTH_HEADER_PATTERN.finditer(text):
            secret = match.group(1)
            start, end = match.span(1)
            self._add_detection(
                detections, spans_seen, "AUTH_HEADER", secret, start, end, "auth_header_pattern"
            )

        # Key-Value assignments
        for match in self.KEY_VAL_PATTERN.finditer(text):
            secret = match.group(1) or match.group(2)
            if not secret:
                continue

            # Identify target span
            full_str = match.group(0)
            secret_start = match.start(0) + full_str.rfind(secret)
            secret_end = secret_start + len(secret)

            # Skip common placeholders like "placeholder", "xxx", "your_password_here"
            lower_sec = secret.lower()
            if lower_sec in ("your_password", "sua_senha", "changeme", "placeholder", "xxx", "null", "none"):
                continue

            self._add_detection(
                detections, spans_seen, "SENHA", secret, secret_start, secret_end, "key_value_assignment"
            )

        # Embedded URL credentials
        for match in self.URL_CRED_PATTERN.finditer(text):
            secret = match.group(2)
            start, end = match.span(2)
            self._add_detection(
                detections, spans_seen, "URL_PASSWORD", secret, start, end, "url_embedded_credential"
            )

        return detections

    def _add_detection(
        self,
        detections: List[Detection],
        spans_seen: set,
        entity_type: str,
        secret: str,
        start: int,
        end: int,
        strategy: str,
    ) -> None:
        if any(s <= start and end <= e for s, e in spans_seen):
            return

        token_hash = hashlib.sha256(secret.encode("utf-8")).hexdigest()[:12]
        masked = f"***{secret[-2:]}" if len(secret) > 4 else "******"

        detections.append(
            Detection(
                type=entity_type,
                start=start,
                end=end,
                confidence=0.96,
                severity=SeverityLevel.CRITICAL,
                strategy=strategy,
                raw_value=secret,
                normalized_key=f"secret:{token_hash}",
                masked_value=masked,
            )
        )
        spans_seen.add((start, end))


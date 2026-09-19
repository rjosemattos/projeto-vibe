"""Detector for known API Keys and provider tokens (OpenAI, AWS, GitHub, Google)."""

import hashlib
import re
from typing import List
from app.detection.base import BaseDetector, Detection
from app.models.response import SeverityLevel


class APIKeyDetector(BaseDetector):
    """Detects provider-specific API keys and secrets using structured signatures."""

    name = "api_key_detector"
    entity_type = "API_KEY"

    # Known structured patterns:
    # 1. OpenAI: sk-..., sk-proj-...
    # 2. AWS Access Key ID: AKIA...
    # 3. GitHub Personal/OAuth Tokens: ghp_..., gho_..., github_pat_...
    # 4. Google API Key: AIza...
    PATTERNS = [
        ("OpenAI API Key", re.compile(r"\b(sk-(?:proj-)?[a-zA-Z0-9_-]{20,64})\b")),
        ("AWS Access Key ID", re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
        ("GitHub Token", re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{22,})\b")),
        ("Google API Key", re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b")),
    ]

    def detect(self, text: str) -> List[Detection]:
        detections: List[Detection] = []
        spans_seen = set()

        for provider_name, pattern in self.PATTERNS:
            for match in pattern.finditer(text):
                raw_key = match.group(1)
                start, end = match.span(1)

                if any(s <= start and end <= e for s, e in spans_seen):
                    continue

                token_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:12]

                # Mask safely: e.g. sk-12************
                if len(raw_key) > 8:
                    masked = f"{raw_key[:4]}************{raw_key[-2:]}"
                else:
                    masked = "************"

                detections.append(
                    Detection(
                        type=self.entity_type,
                        start=start,
                        end=end,
                        confidence=0.99,
                        severity=SeverityLevel.CRITICAL,
                        strategy=f"provider_signature_{provider_name.lower().replace(' ', '_')}",
                        raw_value=raw_key,
                        normalized_key=f"apikey:{token_hash}",
                        masked_value=masked,
                    )
                )
                spans_seen.add((start, end))

        return detections


"""Detection Engine: orchestrates detectors and resolves overlapping entity spans."""

from typing import List, Optional
from app.detection.base import BaseDetector, Detection
from app.detection.detectors import (
    APIKeyDetector,
    CNPJDetector,
    CPFDetector,
    CreditCardDetector,
    CredentialsDetector,
    EmailDetector,
    JWTDetector,
    PhoneDetector,
)
from app.models.response import SeverityLevel


class DetectionEngine:
    """Central engine that coordinates modular sensitive data detectors and handles conflicts."""

    # Priority ranking for conflict resolution
    SEVERITY_WEIGHTS = {
        SeverityLevel.CRITICAL: 4,
        SeverityLevel.HIGH: 3,
        SeverityLevel.MEDIUM: 2,
        SeverityLevel.LOW: 1,
    }

    def __init__(self, detectors: Optional[List[BaseDetector]] = None) -> None:
        """Initialize engine with either custom or default detectors."""
        if detectors is not None:
            self.detectors = detectors
        else:
            self.detectors = [
                # Critical credentials first
                APIKeyDetector(),
                JWTDetector(),
                CredentialsDetector(),
                # High severity identifiers and financial data
                CPFDetector(),
                CNPJDetector(),
                CreditCardDetector(),
                # Medium severity personal contact data
                EmailDetector(),
                PhoneDetector(),
            ]

    def analyze(self, text: str) -> List[Detection]:
        """Run all registered detectors and return non-overlapping, prioritized detections."""
        raw_detections: List[Detection] = []
        for detector in self.detectors:
            try:
                results = detector.detect(text)
                raw_detections.extend(results)
            except Exception:
                # Individual detector failure must not crash entire pipeline; safe privacy isolation
                continue

        # Resolve overlapping spans
        return self._resolve_overlaps(raw_detections)

    def _resolve_overlaps(self, detections: List[Detection]) -> List[Detection]:
        """Resolve overlapping text spans by prioritizing severity, confidence, and span length."""
        if not detections:
            return []

        # Sort priority: Severity -> Confidence -> Length -> Start offset
        sorted_candidates = sorted(
            detections,
            key=lambda d: (
                self.SEVERITY_WEIGHTS.get(d.severity, 0),
                d.confidence,
                (d.end - d.start),
                -d.start,
            ),
            reverse=True,
        )

        accepted: List[Detection] = []

        for candidate in sorted_candidates:
            # Check overlap with already accepted detections
            has_overlap = False
            for acc in accepted:
                # Two spans overlap if max(start1, start2) < min(end1, end2)
                if max(candidate.start, acc.start) < min(candidate.end, acc.end):
                    has_overlap = True
                    break

            if not has_overlap:
                accepted.append(candidate)

        # Return final accepted detections sorted chronologically by start index
        accepted.sort(key=lambda d: d.start)
        return accepted


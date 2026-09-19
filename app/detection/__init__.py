"""Detection subpackage."""

from app.detection.base import BaseDetector, Detection
from app.detection.engine import DetectionEngine

__all__ = ["BaseDetector", "Detection", "DetectionEngine"]


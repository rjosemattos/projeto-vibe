"""Base interfaces and data structures for the detection engine."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List
from app.models.response import SeverityLevel


@dataclass
class Detection:
    """Represents an identified sensitive entity in the input text."""

    type: str
    start: int
    end: int
    confidence: float
    severity: SeverityLevel
    strategy: str
    raw_value: str
    normalized_key: str
    masked_value: str


class BaseDetector(ABC):
    """Abstract base class for all sensitive data detectors."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique detector identifier."""
        pass

    @property
    @abstractmethod
    def entity_type(self) -> str:
        """Entity type label (e.g. CPF, EMAIL, API_KEY)."""
        pass

    @abstractmethod
    def detect(self, text: str) -> List[Detection]:
        """Analyze text and return a list of identified detections."""
        pass


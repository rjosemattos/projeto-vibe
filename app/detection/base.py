"""Interfaces base e estruturas de dados do motor de detecção."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List
from app.models.response import SeverityLevel


@dataclass
class Detection:
    """Representa uma entidade sensível encontrada no texto de entrada."""

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
    """Classe base abstrata de todos os detectores de dados sensíveis."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Identificador único do detector."""
        pass

    @property
    @abstractmethod
    def entity_type(self) -> str:
        """Tipo da entidade (ex.: CPF, EMAIL, API_KEY)."""
        pass

    @abstractmethod
    def detect(self, text: str) -> List[Detection]:
        """Analisa o texto e retorna a lista de detecções encontradas."""
        pass


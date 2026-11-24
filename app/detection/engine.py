"""Motor de detecção: coordena os detectores e resolve trechos sobrepostos."""

from typing import List, Optional
from app.detection.base import BaseDetector, Detection
from app.detection.detectors import (
    APIKeyDetector,
    CNPJDetector,
    CPFDetector,
    CreditCardDetector,
    CredentialsDetector,
    EmailDetector,
    IPAddressDetector,
    JWTDetector,
    PhoneDetector,
    PrivateKeyDetector,
)
from app.models.response import SeverityLevel


class DetectionEngine:
    """Motor central que coordena os detectores de dados sensíveis e resolve conflitos entre eles."""

    # Ordem de prioridade para resolver conflitos
    SEVERITY_WEIGHTS = {
        SeverityLevel.CRITICAL: 4,
        SeverityLevel.HIGH: 3,
        SeverityLevel.MEDIUM: 2,
        SeverityLevel.LOW: 1,
    }

    def __init__(self, detectors: Optional[List[BaseDetector]] = None) -> None:
        """Inicializa o motor com detectores personalizados ou com os detectores padrão."""
        if detectors is not None:
            self.detectors = detectors
        else:
            self.detectors = [
                # Credenciais críticas primeiro
                PrivateKeyDetector(),
                APIKeyDetector(),
                JWTDetector(),
                CredentialsDetector(),
                # Identificadores e dados financeiros de alta severidade
                CPFDetector(),
                CNPJDetector(),
                CreditCardDetector(),
                # Dados pessoais de contato, de severidade média
                EmailDetector(),
                PhoneDetector(),
                IPAddressDetector(),
            ]

    def analyze(self, text: str) -> List[Detection]:
        """Roda todos os detectores e retorna as detecções priorizadas e sem sobreposição."""
        raw_detections: List[Detection] = []
        for detector in self.detectors:
            try:
                results = detector.detect(text)
                raw_detections.extend(results)
            except Exception:
                # A falha de um detector não pode derrubar o pipeline inteiro
                continue

        # Resolve trechos sobrepostos
        return self._resolve_overlaps(raw_detections)

    def _resolve_overlaps(self, detections: List[Detection]) -> List[Detection]:
        """Resolve trechos sobrepostos priorizando severidade, confiança e tamanho do trecho."""
        if not detections:
            return []

        # Ordem de prioridade: severidade -> confiança -> tamanho -> posição inicial
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
            # Verifica sobreposição com as detecções já aceitas
            has_overlap = False
            for acc in accepted:
                # Dois trechos se sobrepõem se max(inicio1, inicio2) < min(fim1, fim2)
                if max(candidate.start, acc.start) < min(candidate.end, acc.end):
                    has_overlap = True
                    break

            if not has_overlap:
                accepted.append(candidate)

        # Retorna as detecções aceitas em ordem de aparição no texto
        accepted.sort(key=lambda d: d.start)
        return accepted


"""Risk Assessment Engine for analyzing exposure severity in prompts."""

from typing import List, Set
from app.detection.base import Detection
from app.models.response import RiskReport, SeverityLevel


class RiskAnalyzer:
    """Evaluates aggregate privacy and security risks from identified sensitive detections."""

    def evaluate(self, detections: List[Detection]) -> RiskReport:
        """Calculate composite risk level, numerical score (0-100), and transparent reasons."""
        if not detections:
            return RiskReport(
                risk_level=SeverityLevel.LOW,
                score=0,
                reasons=["Nenhuma informação sensível identificada no prompt."],
            )

        types: Set[str] = {d.type for d in detections}
        severities: Set[SeverityLevel] = {d.severity for d in detections}
        total_count = len(detections)
        reasons: List[str] = []

        # 1. Critical credential evaluation
        has_credentials = SeverityLevel.CRITICAL in severities
        if has_credentials:
            reasons.append(
                "Presença de credenciais de acesso, chaves de API, senhas ou tokens de autorização ativos."
            )

        # 2. Financial / Official identification evaluation
        has_financial = "CARTAO_CREDITO" in types
        if has_financial:
            reasons.append("Identificação de dados de cartão de crédito validados matematicamente.")

        has_gov_id = ("CPF" in types) or ("CNPJ" in types)
        if has_gov_id:
            reasons.append("Presença de identificadores governamentais formais (CPF/CNPJ).")

        # 3. Contact PII evaluation
        has_contact = ("EMAIL" in types) or ("TELEFONE" in types)
        if has_contact and not has_gov_id and not has_credentials:
            reasons.append("Presença de canais de contato pessoal direto (e-mail ou telefone).")

        # 4. Correlation / Cross-referencing risk
        if has_gov_id and has_contact:
            reasons.append(
                "Combinação de documento oficial com dados de contato, elevando a probabilidade de ataques de engenharia social ou roubo de identidade."
            )

        # 5. Custom confidential rules evaluation
        if "REGRA_CUSTOMIZADA" in types:
            reasons.append(
                "Identificação de termos confidenciais sob regras dinâmicas personalizadas de ofuscação."
            )

        if total_count > 3:
            reasons.append(
                f"Volume elevado de entidades sensíveis detectadas ({total_count} ocorrências)."
            )

        # Calculate Score and Aggregate Level
        if has_credentials:
            base_score = 85
            score = min(100, base_score + (total_count - 1) * 3 + (10 if (has_gov_id or has_financial) else 0))
            risk_level = SeverityLevel.CRITICAL
        elif has_financial or (has_gov_id and has_contact) or (len(types) >= 2 and SeverityLevel.HIGH in severities):
            base_score = 75
            score = min(84, base_score + (total_count - 1) * 2)
            risk_level = SeverityLevel.HIGH
        elif SeverityLevel.HIGH in severities:
            base_score = 65
            score = min(74, base_score + (total_count - 1) * 2)
            risk_level = SeverityLevel.HIGH
        elif SeverityLevel.MEDIUM in severities:
            base_score = 35
            score = min(59, base_score + (total_count - 1) * 4)
            risk_level = SeverityLevel.MEDIUM
        else:
            score = 15
            risk_level = SeverityLevel.LOW

        return RiskReport(
            risk_level=risk_level,
            score=score,
            reasons=reasons,
        )


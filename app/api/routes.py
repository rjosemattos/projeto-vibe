from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from app.api.rules_routes import crypto_service, get_current_user_id, get_decrypted_rules_for_user
from app.core.config import settings
from app.core.logging import get_logger
from app.detection.base import Detection
from app.detection.engine import DetectionEngine
from app.models.request import PromptAnalyzeRequest
from app.models.response import PromptAnalyzeResponse, SeverityLevel
from app.risk.analyzer import RiskAnalyzer
from app.sanitization.custom_engine import CustomObfuscationEngine
from app.sanitization.engine import SanitizationEngine

logger = get_logger(__name__)
router = APIRouter()

# Reusable engine singletons
detection_engine = DetectionEngine()
risk_analyzer = RiskAnalyzer()
sanitization_engine = SanitizationEngine()


@router.get(
    "/health",
    tags=["System"],
    summary="Health check endpoint",
)
async def health_check():
    """Verify application operational status."""
    return {
        "status": "healthy",
        "version": settings.APP_VERSION,
        "app": settings.APP_NAME,
    }


@router.post(
    "/api/v1/analyze",
    response_model=PromptAnalyzeResponse,
    tags=["Analysis"],
    summary="Analyze and sanitize prompt before sending to AI",
    status_code=status.HTTP_200_OK,
)
async def analyze_prompt(
    payload: PromptAnalyzeRequest,
    user_id: str = Depends(get_current_user_id),
) -> PromptAnalyzeResponse:
    """Analyze the prompt for sensitive data, assess privacy risks, and return sanitized text.

    Guarantees:
    - Never logs prompt or sensitive findings.
    - Never transmits prompt to external services.
    - Never returns raw sensitive values in response.
    - Applies custom user confidential rules in a single-pass cascade-free engine.
    """
    try:
        prompt_text = payload.prompt

        # 0. Custom Confidential Rules (Per-user, in-memory, zero raw retention)
        decrypted_rules = await get_decrypted_rules_for_user(user_id)
        custom_sanitized_text, custom_matches = CustomObfuscationEngine.apply(
            prompt_text, decrypted_rules
        )

        custom_detections = [
            Detection(
                type="REGRA_CUSTOMIZADA",
                start=m.start,
                end=m.end,
                confidence=1.0,
                severity=SeverityLevel.HIGH,
                strategy="re_custom_rule",
                raw_value=m.raw_term,
                normalized_key=f"custom_{m.rule_id}",
                masked_value=crypto_service.mask_term(m.raw_term),
            )
            for m in custom_matches
        ]

        # 1. Detection Engine for structured PII and credentials in remaining text
        pii_detections = detection_engine.analyze(custom_sanitized_text)

        # 2. Sanitization Engine for detected PII entities
        final_sanitized_text = sanitization_engine.sanitize(custom_sanitized_text, pii_detections)

        # Combine all detections for comprehensive audit and risk scoring
        all_detections = custom_detections + pii_detections

        # 3. Risk Assessment
        risk_report = risk_analyzer.evaluate(all_detections)

        # 4. Safe API items (strictly strips raw values)
        safe_detection_items = [d.to_api_item() for d in all_detections]

        # Audit log only metadata, NEVER prompt contents or sensitive details
        logger.info(
            "Analyzed prompt safely: length=%d, custom_rules_matched=%d, pii_detections=%d, risk=%s, user=%s",
            len(prompt_text),
            len(custom_matches),
            len(pii_detections),
            risk_report.risk_level.value,
            user_id,
        )

        return PromptAnalyzeResponse(
            has_sensitive_data=bool(all_detections),
            risk_level=risk_report.risk_level,
            total_detections=len(all_detections),
            detections=safe_detection_items,
            sanitized_prompt=final_sanitized_text,
            risk_report=risk_report,
        )
    except Exception as exc:
        # Prevent stack trace or variable contents from leaking to caller
        logger.error("Internal error during prompt processing: %s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while analyzing the prompt. No sensitive data was retained.",
        )


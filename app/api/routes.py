"""API routes for Prompt Sanitizer."""

from fastapi import APIRouter, HTTPException, status
from app.core.config import settings
from app.core.logging import get_logger
from app.detection.engine import DetectionEngine
from app.models.request import PromptAnalyzeRequest
from app.models.response import PromptAnalyzeResponse
from app.risk.analyzer import RiskAnalyzer
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
async def analyze_prompt(payload: PromptAnalyzeRequest) -> PromptAnalyzeResponse:
    """Analyze the prompt for sensitive data, assess privacy risks, and return sanitized text.

    Guarantees:
    - Never logs prompt or sensitive findings.
    - Never transmits prompt to external services.
    - Never returns raw sensitive values in response.
    """
    try:
        prompt_text = payload.prompt

        # 1. Detection Engine
        detections = detection_engine.analyze(prompt_text)

        # 2. Risk Assessment
        risk_report = risk_analyzer.evaluate(detections)

        # 3. Sanitization Engine
        sanitized_text = sanitization_engine.sanitize(prompt_text, detections)

        # 4. Safe API items (strips raw values)
        safe_detection_items = [d.to_api_item() for d in detections]

        # Audit log only metadata, NEVER prompt contents or sensitive details
        logger.info(
            "Analyzed prompt safely: length=%d, detections=%d, risk=%s",
            len(prompt_text),
            len(detections),
            risk_report.risk_level.value,
        )

        return PromptAnalyzeResponse(
            has_sensitive_data=bool(detections),
            risk_level=risk_report.risk_level,
            total_detections=len(detections),
            detections=safe_detection_items,
            sanitized_prompt=sanitized_text,
            risk_report=risk_report,
        )
    except Exception as exc:
        # Prevent stack trace or variable contents from leaking to caller
        logger.error("Internal error during prompt processing: %s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while analyzing the prompt. No sensitive data was retained.",
        )


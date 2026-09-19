"""Request models for Prompt Sanitizer API."""

from pydantic import BaseModel, Field
from app.core.config import settings


class PromptAnalyzeRequest(BaseModel):
    """Payload for prompt analysis and sanitization."""

    prompt: str = Field(
        ...,
        min_length=1,
        max_length=settings.MAX_PROMPT_LENGTH,
        description="The prompt text to be analyzed and sanitized before sending to an AI.",
        examples=[
            "Analise este cliente: João da Silva, CPF 123.456.789-09, e me diga se ele pode contratar o serviço."
        ],
    )


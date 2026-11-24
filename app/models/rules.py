"""Modelos de domínio e esquemas Pydantic das regras confidenciais de ofuscação."""

import re
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID, uuid4
from pydantic import BaseModel, Field, field_validator

# Formato válido da tag: [MAIUSCULAS_DIGITOS_OU_SUBLINHADO]
TAG_REGEX = re.compile(r"^\[[A-Z0-9_]{2,40}\]$")


class RuleCreateRequest(BaseModel):
    """Dados para cadastrar uma regra de ofuscação de termo confidencial."""

    term: str = Field(
        ...,
        min_length=2,
        max_length=150,
        description="Termo sensível a ser ofuscado do prompt.",
        examples=["CESAR", "Projeto Vibe"],
    )
    replacement_tag: str = Field(
        ...,
        description="Tag canônica de substituição no formato [TAG_NOME].",
        examples=["[COMPANY_SENSITIVE]", "[PROJETO_SECRETO]"],
    )
    case_sensitive: bool = Field(
        default=False,
        description="Indica se a correspondência diferencia maiúsculas de minúsculas.",
    )
    match_whole_word: bool = Field(
        default=True,
        description="Indica se a substituição só deve ocorrer em palavras completas.",
    )

    @field_validator("term")
    @classmethod
    def validate_term(cls, value: str) -> str:
        cleaned = value.strip()
        if len(cleaned) < 2:
            raise ValueError("O termo confidencial deve conter ao menos 2 caracteres válidos.")
        return cleaned

    @field_validator("replacement_tag")
    @classmethod
    def validate_tag(cls, value: str) -> str:
        cleaned = value.strip()
        if not (cleaned.startswith("[") and cleaned.endswith("]")):
            cleaned = f"[{cleaned.upper()}]"
        else:
            cleaned = f"[{cleaned[1:-1].upper()}]"

        if not TAG_REGEX.match(cleaned):
            raise ValueError(
                "A tag de substituição deve conter apenas letras maiúsculas, dígitos ou sublinhados "
                "entre colchetes (ex: [TAG_SENSIVEL]). Tamanho permitido: 2 a 40 caracteres."
            )
        return cleaned


class RuleUpdateRequest(BaseModel):
    """Dados para atualizar uma regra confidencial existente."""

    term: Optional[str] = Field(None, min_length=2, max_length=150)
    replacement_tag: Optional[str] = None
    case_sensitive: Optional[bool] = None
    match_whole_word: Optional[bool] = None

    @field_validator("term")
    @classmethod
    def validate_term(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        cleaned = value.strip()
        if len(cleaned) < 2:
            raise ValueError("O termo confidencial deve conter ao menos 2 caracteres válidos.")
        return cleaned

    @field_validator("replacement_tag")
    @classmethod
    def validate_tag(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        cleaned = value.strip()
        if not (cleaned.startswith("[") and cleaned.endswith("]")):
            cleaned = f"[{cleaned.upper()}]"
        else:
            cleaned = f"[{cleaned[1:-1].upper()}]"

        if not TAG_REGEX.match(cleaned):
            raise ValueError("Tag inválida. Deve seguir o formato [TAG_MAIUSCULA].")
        return cleaned


class RuleResponse(BaseModel):
    """Representação pública de uma regra de ofuscação.

    Garantia de que o termo nunca aparece em texto claro:
    o termo original NUNCA é devolvido, para não vazar em logs ou na interface.
    No lugar dele, é devolvida uma prévia mascarada (ex.: 'C***R').
    """

    id: UUID
    masked_term: str = Field(description="Visualização protegida do termo confidencial.")
    replacement_tag: str
    case_sensitive: bool
    match_whole_word: bool
    created_at: datetime
    updated_at: Optional[datetime] = None


class ConfidentialRuleRecord:
    """Entidade interna gravada no cofre, com o termo apenas na forma cifrada."""

    def __init__(
        self,
        id: UUID,
        
        encrypted_term: str,
        term_blind_index: str,
        replacement_tag: str,
        case_sensitive: bool,
        match_whole_word: bool,
        created_at: Optional[datetime] = None,
        updated_at: Optional[datetime] = None,
    ):
        self.id = id
        
        self.encrypted_term = encrypted_term
        self.term_blind_index = term_blind_index
        self.replacement_tag = replacement_tag
        self.case_sensitive = case_sensitive
        self.match_whole_word = match_whole_word
        self.created_at = created_at or datetime.now(timezone.utc)
        self.updated_at = updated_at

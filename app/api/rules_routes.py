"""API endpoints for managing dynamic confidential obfuscation rules."""

from typing import List, Optional
from uuid import UUID, uuid4
from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from app.auth import service as auth_service
from app.auth.routes import COOKIE_NAME, SAFE_METHODS, _origin_ok
from app.core.config import settings
from app.core.crypto import RuleCryptoService
from app.core.logging import get_logger
from app.models.rules import (
    ConfidentialRuleRecord,
    RuleCreateRequest,
    RuleResponse,
    RuleUpdateRequest,
)
from app.repositories.sqlite_rules_repository import RepositorySelector
from app.sanitization.custom_engine import DecryptedRule

logger = get_logger("rules_api")
rules_router = APIRouter(prefix="/api/v1/rules", tags=["Confidential Rules"])

# Instâncias seguras de serviço compartilhadas neste módulo
crypto_service = RuleCryptoService()
rules_repository = RepositorySelector()
_user_crypto: dict = {}


def crypto_for(user_id: str) -> RuleCryptoService:
    """Per-user derived keys when hosted (auth enabled); shared local keys otherwise."""
    if not settings.AUTH_ENABLED:
        return crypto_service
    if user_id not in _user_crypto:
        _user_crypto[user_id] = crypto_service.for_user(user_id)
    return _user_crypto[user_id]


def get_current_user_id(
    request: Request,
    x_user_id: Optional[str] = Header(
        default="default_tenant",
        description="Somente modo local (AUTH_ENABLED=false): identificador do tenant.",
    ),
) -> str:
    """Resolves the tenant.

    Priority:
    1. Authorization: Bearer <JWT> (Supabase / Google OAuth).
    2. Cookie-based session (Hosted standalone mode).
    3. Header X-User-Id (Local single-user mode).
    """
    # 1. Bearer Token (Supabase / Google Auth)
    auth_header = request.headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
        from app.auth.supabase_jwt import verify_supabase_jwt
        payload = verify_supabase_jwt(token)
        if payload and "sub" in payload:
            return f"sb_{payload['sub']}"
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token de autorização inválido ou expirado.")

    # 2. Cookie session (Hosted mode)
    if settings.AUTH_ENABLED or settings.SUPABASE_URL:
        session = auth_service.resolve_session(request.cookies.get(COOKIE_NAME))
        if session is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Sessão inválida ou expirada.")
        if request.method not in SAFE_METHODS and (
            not _origin_ok(request)
            or not auth_service.csrf_valid(session, request.headers.get("x-csrf-token"))
        ):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Falha na verificação CSRF.")
        return f"u{session.user_id}"

    user = (x_user_id or "default_tenant").strip()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Identificação de usuário necessária para isolamento de regras.",
        )
    return user


async def get_decrypted_rules_for_user(user_id: str) -> List[DecryptedRule]:
    """Helper que recupera e decifra regras em memória exclusivamente no escopo da requisição."""
    records = await rules_repository.list_by_user(user_id)
    decrypted_list: List[DecryptedRule] = []
    for r in records:
        try:
            term = crypto_for(user_id).decrypt(r.encrypted_term)
            decrypted_list.append(
                DecryptedRule(
                    id=str(r.id),
                    term=term,
                    replacement_tag=r.replacement_tag,
                    case_sensitive=r.case_sensitive,
                    match_whole_word=r.match_whole_word,
                )
            )
        except Exception as exc:
            logger.error("Falha ao decifrar regra %s: %s", r.id, type(exc).__name__)
            continue
    return decrypted_list


@rules_router.post(
    "",
    response_model=RuleResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Cadastrar nova regra de ofuscação confidencial",
)
async def create_rule(
    payload: RuleCreateRequest,
    user_id: str = Depends(get_current_user_id),
):
    """Cadastra um termo confidencial com tag de substituição.
    
    Garantias:
    - O termo em texto claro NUNCA é persistido nem logado.
    - Criptografia em repouso com AES-256-GCM.
    - Blind index gerado para detecção de duplicatas.
    """
    try:
        encrypted_term = crypto_for(user_id).encrypt(payload.term)
        blind_index = crypto_for(user_id).compute_blind_index(payload.term)

        record = ConfidentialRuleRecord(
            id=uuid4(),
            user_id=user_id,
            encrypted_term=encrypted_term,
            term_blind_index=blind_index,
            replacement_tag=payload.replacement_tag,
            case_sensitive=payload.case_sensitive,
            match_whole_word=payload.match_whole_word,
        )

        saved = await rules_repository.create(record)

        # Log de auditoria seguro: apenas metadados
        logger.info(
            "Regra confidencial cadastrada com sucesso: id=%s, tag=%s, user=%s",
            saved.id,
            saved.replacement_tag,
            user_id,
        )

        return RuleResponse(
            id=saved.id,
            masked_term=crypto_service.mask_term(payload.term),
            replacement_tag=saved.replacement_tag,
            case_sensitive=saved.case_sensitive,
            match_whole_word=saved.match_whole_word,
            created_at=saved.created_at,
            updated_at=saved.updated_at,
        )
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(ve))
    except Exception as exc:
        logger.error("Erro interno ao criar regra confidencial: %s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Falha interna ao registrar a regra confidencial.",
        )


@rules_router.get(
    "",
    response_model=List[RuleResponse],
    summary="Listar regras ativas do usuário",
)
async def list_rules(user_id: str = Depends(get_current_user_id)):
    """Retorna as regras ativas do usuário autenticado.
    
    Garantia: O termo original é retornado apenas em formato mascarado para a UI.
    """
    records = await rules_repository.list_by_user(user_id)
    output: List[RuleResponse] = []

    for r in records:
        try:
            term = crypto_for(user_id).decrypt(r.encrypted_term)
            masked = crypto_service.mask_term(term)
        except Exception:
            masked = "[PROTEGIDO]"

        output.append(
            RuleResponse(
                id=r.id,
                masked_term=masked,
                replacement_tag=r.replacement_tag,
                case_sensitive=r.case_sensitive,
                match_whole_word=r.match_whole_word,
                created_at=r.created_at,
                updated_at=r.updated_at,
            )
        )
    return output


@rules_router.get(
    "/{rule_id}",
    response_model=RuleResponse,
    summary="Consultar uma regra específica",
)
async def get_rule(
    rule_id: UUID,
    user_id: str = Depends(get_current_user_id),
):
    """Consulta os metadados de uma regra específica."""
    record = await rules_repository.get_by_id(user_id, rule_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Regra confidencial não encontrada.",
        )

    try:
        term = crypto_for(user_id).decrypt(record.encrypted_term)
        masked = crypto_service.mask_term(term)
    except Exception:
        masked = "[PROTEGIDO]"

    return RuleResponse(
        id=record.id,
        masked_term=masked,
        replacement_tag=record.replacement_tag,
        case_sensitive=record.case_sensitive,
        match_whole_word=record.match_whole_word,
        created_at=record.created_at,
        updated_at=record.updated_at,
    )


@rules_router.put(
    "/{rule_id}",
    response_model=RuleResponse,
    summary="Atualizar regra de ofuscação existente",
)
async def update_rule(
    rule_id: UUID,
    payload: RuleUpdateRequest,
    user_id: str = Depends(get_current_user_id),
):
    """Atualiza o termo, tag ou opções de correspondência de uma regra."""
    record = await rules_repository.get_by_id(user_id, rule_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Regra confidencial não encontrada.",
        )

    term_to_mask = None
    if payload.term is not None:
        record.encrypted_term = crypto_for(user_id).encrypt(payload.term)
        record.term_blind_index = crypto_for(user_id).compute_blind_index(payload.term)
        term_to_mask = payload.term
    else:
        try:
            term_to_mask = crypto_for(user_id).decrypt(record.encrypted_term)
        except Exception:
            term_to_mask = "[PROTEGIDO]"

    if payload.replacement_tag is not None:
        record.replacement_tag = payload.replacement_tag
    if payload.case_sensitive is not None:
        record.case_sensitive = payload.case_sensitive
    if payload.match_whole_word is not None:
        record.match_whole_word = payload.match_whole_word

    try:
        updated = await rules_repository.update(user_id, record)
        logger.info("Regra confidencial atualizada: id=%s, user=%s", updated.id, user_id)
        return RuleResponse(
            id=updated.id,
            masked_term=crypto_service.mask_term(term_to_mask),
            replacement_tag=updated.replacement_tag,
            case_sensitive=updated.case_sensitive,
            match_whole_word=updated.match_whole_word,
            created_at=updated.created_at,
            updated_at=updated.updated_at,
        )
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(ve))
    except Exception as exc:
        logger.error("Erro ao atualizar regra: %s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Falha ao atualizar a regra.",
        )


@rules_router.delete(
    "/{rule_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Remover regra de ofuscação",
)
async def delete_rule(
    rule_id: UUID,
    user_id: str = Depends(get_current_user_id),
):
    """Remove definitivamente a regra de ofuscação confidencial do usuário."""
    deleted = await rules_repository.delete(user_id, rule_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Regra confidencial não encontrada.",
        )
    logger.info("Regra confidencial removida: id=%s, user=%s", rule_id, user_id)
    return None

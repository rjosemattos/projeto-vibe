"""Serviço central do agente desktop para Windows.

Executa todo o pipeline do Prompt Sanitizer no próprio processo, sem rede:
1. Cofre local cifrado com as regras confidenciais do usuário (AES-256-GCM + índice cego HMAC).
2. Ofuscação dos termos confidenciais em uma única passada (CustomObfuscationEngine).
3. Detecção de dados pessoais com validação matemática (DetectionEngine: CPF/CNPJ por módulo 11, cartão por Luhn, chaves de API).
4. Substituição pelas tags padronizadas (SanitizationEngine).
5. Cálculo do risco (RiskAnalyzer: pontuação de 0 a 100 e níveis LOW/MEDIUM/HIGH/CRITICAL).

Também concentra o CRUD das regras confidenciais (criar, listar, editar, excluir) e o backup do cofre.
"""

import hashlib
import json
import os
import sys
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional
from uuid import UUID, uuid4

from app.core.crypto import RuleCryptoService
from app.core.logging import get_logger
from app.core.paths import get_data_dir
from app.detection.base import Detection
from app.detection.engine import DetectionEngine
from app.models.response import SeverityLevel
from app.models.rules import (
    ConfidentialRuleRecord,
    RuleCreateRequest,
    RuleResponse,
    RuleUpdateRequest,
)
from app.risk.analyzer import RiskAnalyzer
from app.sanitization.custom_engine import CustomObfuscationEngine, DecryptedRule
from app.sanitization.engine import SanitizationEngine
from typing import Dict, List, Optional, Tuple
from app.core.crypto import RuleCryptoService, decrypt_backup, encrypt_backup

logger = get_logger(__name__)

class RulesStoreError(RuntimeError):
    """Raised when the encrypted rules store cannot be written to disk."""

def get_default_storage_path() -> Path:
    """Retorna o caminho do cofre cifrado (em %APPDATA% no Windows, com alternativa portátil)."""
    return get_data_dir() / "rules.enc.json"


@dataclass
class DesktopSanitizeResult:
    """Resultado de uma sanitização feita pelo agente."""

    original_length: int
    sanitized_text: str
    changed: bool
    total_detections: int
    custom_matches_count: int
    pii_matches_count: int
    risk_level: SeverityLevel
    risk_score: int
    detected_types: List[str] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)
    sanitized_hash: str = ""
    timestamp: str = ""

    @property
    def summary_badge(self) -> str:
        """Mensagem curta e segura para o HUD e as notificações."""
        if not self.changed or self.total_detections == 0:
            return "Nenhum dado sensível detectado (Prompt Seguro)"
        types_str = ", ".join(self.detected_types[:3])
        if len(self.detected_types) > 3:
            types_str += f" +{len(self.detected_types) - 3}"
        return (
            f"{self.total_detections} dado(s) ocultado(s) [{types_str}] • "
            f"Risco {self.risk_level.value} ({self.risk_score}/100)"
        )


class DesktopSanitizerService:
    """Motor de sanitização e CRUD de regras do agente, seguro para uso por várias threads."""

    def __init__(
        self,
        storage_path: Optional[Path] = None,
        crypto_service: Optional[RuleCryptoService] = None,
        
    ):
        
        self.storage_path = storage_path or get_default_storage_path()
        self.crypto_service = crypto_service or RuleCryptoService()
        self.detection_engine = DetectionEngine()
        self.sanitization_engine = SanitizationEngine()
        self.risk_analyzer = RiskAnalyzer()

        self._lock = threading.RLock()
        self._rules: Dict[UUID, ConfidentialRuleRecord] = {}
        self._known_sanitized_hashes: set[str] = set()

        # Estatísticas da sessão atual
        self.total_prompts_protected: int = 0
        self.total_entities_redacted: int = 0
        self.last_result: Optional[DesktopSanitizeResult] = None

        self._load_encrypted_store()

    @staticmethod
    def compute_text_hash(text: str) -> str:
        """Calcula a impressão digital SHA-256 do texto, usada para evitar sanitizar o mesmo texto em loop."""
        return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()

    def is_already_sanitized(self, text: str) -> bool:
        """Verifica se o texto é uma saída que o próprio agente sanitizou há pouco."""
        if not text:
            return True
        text_hash = self.compute_text_hash(text)
        with self._lock:
            return text_hash in self._known_sanitized_hashes

    # ------------------------------------------------------------------
    # Gravação local cifrada (o termo nunca fica em texto claro)
    # ------------------------------------------------------------------

    def _load_encrypted_store(self) -> None:
        """Carrega do disco as regras cifradas, sem decifrar os termos."""
        with self._lock:
            if not self.storage_path.exists():
                return
            try:
                raw_data = self.storage_path.read_text(encoding="utf-8")
                items = json.loads(raw_data)
                loaded: Dict[UUID, ConfidentialRuleRecord] = {}
                for item in items:
                    rule_id = UUID(item["id"])
                    created_at = datetime.fromisoformat(item["created_at"])
                    updated_at = (
                        datetime.fromisoformat(item["updated_at"])
                        if item.get("updated_at")
                        else None
                    )
                    record = ConfidentialRuleRecord(
                        id=rule_id,
                        
                        encrypted_term=item["encrypted_term"],
                        term_blind_index=item["term_blind_index"],
                        replacement_tag=item["replacement_tag"],
                        case_sensitive=bool(item.get("case_sensitive", False)),
                        match_whole_word=bool(item.get("match_whole_word", True)),
                        created_at=created_at,
                        updated_at=updated_at,
                    )
                    loaded[rule_id] = record
                self._rules = loaded
            except Exception as exc:
                logger.error("Falha ao carregar o cofre de regras: %s", type(exc).__name__)
                # Preserva o arquivo ilegível para que a próxima gravação não apague os dados do usuário sem aviso
                try:
                    backup = self.storage_path.with_suffix(".corrupt")
                    self.storage_path.replace(backup)
                    logger.error("Cofre de regras corrompido movido para %s", backup.name)
                except OSError:
                    pass

    def _save_encrypted_store(self) -> None:
        """Grava em disco APENAS os textos cifrados (AES-256-GCM) e os índices cegos (HMAC)."""
        with self._lock:
            try:
                self.storage_path.parent.mkdir(parents=True, exist_ok=True)
                payload = [
                    {
                        "id": str(rec.id),
                        
                        "encrypted_term": rec.encrypted_term,
                        "term_blind_index": rec.term_blind_index,
                        "replacement_tag": rec.replacement_tag,
                        "case_sensitive": rec.case_sensitive,
                        "match_whole_word": rec.match_whole_word,
                        "created_at": rec.created_at.isoformat(),
                        "updated_at": rec.updated_at.isoformat() if rec.updated_at else None,
                    }
                    for rec in sorted(self._rules.values(), key=lambda r: r.created_at)
                ]
                # Grava num arquivo temporário e depois o renomeia por cima do original:
                # assim o cofre nunca fica gravado pela metade se algo falhar no meio.
                temp_path = self.storage_path.with_suffix(".tmp")
                temp_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
                temp_path.replace(self.storage_path)
            except Exception as exc:
                logger.error("Failed to save encrypted rules store: %s", type(exc).__name__)
                raise RulesStoreError(
                    "Não foi possível salvar as regras no disco. A alteração foi desfeita."
                ) from exc

    # ------------------------------------------------------------------
    # Operações de CRUD dos termos confidenciais
    # ------------------------------------------------------------------

    def create_rule(
        self,
        term: str,
        replacement_tag: str,
        case_sensitive: bool = False,
        match_whole_word: bool = True,
    ) -> RuleResponse:
        """Valida, cifra e grava uma nova regra de termo confidencial."""
        req = RuleCreateRequest(
            term=term,
            replacement_tag=replacement_tag,
            case_sensitive=case_sensitive,
            match_whole_word=match_whole_word,
        )
        # C (Create): o índice cego permite checar duplicidade comparando hashes,
        # sem decifrar os termos já cadastrados.
        blind_index = self.crypto_service.compute_blind_index(req.term)

        with self._lock:
            for existing in self._rules.values():
                if existing.term_blind_index == blind_index:
                    raise ValueError("Este termo confidencial já está cadastrado.")

            # Só a versão cifrada do termo vai para o registro; o texto original não é guardado.
            encrypted_term = self.crypto_service.encrypt(req.term)
            record = ConfidentialRuleRecord(
                id=uuid4(),
              
                encrypted_term=encrypted_term,
                term_blind_index=blind_index,
                replacement_tag=req.replacement_tag,
                case_sensitive=req.case_sensitive,
                match_whole_word=req.match_whole_word,
            )
            # Atualiza a memória e regrava o cofre inteiro em disco.
            self._rules[record.id] = record
            
            self._rules[record.id] = record
            try:
                self._save_encrypted_store()
            except RulesStoreError:
                del self._rules[record.id]
                raise

            return RuleResponse(
                id=record.id,
                masked_term=self.crypto_service.mask_term(req.term),
                replacement_tag=record.replacement_tag,
                case_sensitive=record.case_sensitive,
                match_whole_word=record.match_whole_word,
                created_at=record.created_at,
                updated_at=record.updated_at,
            )

    def list_rules(self) -> List[RuleResponse]:
        """Retorna todas as regras com a prévia mascarada (nunca o termo original)."""
        with self._lock:
            responses: List[RuleResponse] = []
            # R (Read): cada termo é decifrado só em memória para gerar a prévia mascarada;
            # a interface nunca recebe o termo original.
            for rec in sorted(self._rules.values(), key=lambda r: r.created_at):
                try:
                    plain_ephemeral = self.crypto_service.decrypt(rec.encrypted_term)
                    masked = self.crypto_service.mask_term(plain_ephemeral)
                except ValueError:
                    masked = "***"
                responses.append(
                    RuleResponse(
                        id=rec.id,
                        masked_term=masked,
                        replacement_tag=rec.replacement_tag,
                        case_sensitive=rec.case_sensitive,
                        match_whole_word=rec.match_whole_word,
                        created_at=rec.created_at,
                        updated_at=rec.updated_at,
                    )
                )
            return responses

    def update_rule(
        self,
        rule_id: UUID,
        term: Optional[str] = None,
        replacement_tag: Optional[str] = None,
        case_sensitive: Optional[bool] = None,
        match_whole_word: Optional[bool] = None,
    ) -> RuleResponse:
        """Atualiza uma regra existente e cifra o termo de novo se ele mudou."""
        req = RuleUpdateRequest(
            term=term,
            replacement_tag=replacement_tag,
            case_sensitive=case_sensitive,
            match_whole_word=match_whole_word,
        )

        with self._lock:
            record = self._rules.get(rule_id)
            if not record:
                raise KeyError("Regra confidencial não encontrada.")
                snapshot = dict(vars(record))
            # ... (as alterações do termo, da tag e das opções continuam iguais)
            record.updated_at = datetime.now(timezone.utc)
            try:
                save_encrypted_store()
            except RulesStoreError:
                vars(record).update(snapshot)
                raise
            if not record:
                raise KeyError("Regra confidencial não encontrada.")

            # U (Update): termo em branco na interface chega como None e mantém o termo atual.
            # Com termo novo, confere duplicidade com as OUTRAS regras e cifra de novo.
            if req.term is not None:
                new_blind_index = self.crypto_service.compute_blind_index(req.term)
                for existing in self._rules.values():
                    if existing.id != rule_id and existing.term_blind_index == new_blind_index:
                        raise ValueError("Já existe outra regra cadastrada com este termo.")
                record.encrypted_term = self.crypto_service.encrypt(req.term)
                record.term_blind_index = new_blind_index

            if req.replacement_tag is not None:
                record.replacement_tag = req.replacement_tag
            if req.case_sensitive is not None:
                record.case_sensitive = req.case_sensitive
            if req.match_whole_word is not None:
                record.match_whole_word = req.match_whole_word

            record.updated_at = datetime.now(timezone.utc)
            self._save_encrypted_store()

            plain_ephemeral = self.crypto_service.decrypt(record.encrypted_term)
            return RuleResponse(
                id=record.id,
                masked_term=self.crypto_service.mask_term(plain_ephemeral),
                replacement_tag=record.replacement_tag,
                case_sensitive=record.case_sensitive,
                match_whole_word=record.match_whole_word,
                created_at=record.created_at,
                updated_at=record.updated_at,
            )

    def delete_rule(self, rule_id: UUID) -> bool:
        """Deletes a rule by UUID and updates encrypted storage."""
        with self._lock:
            record = self._rules.pop(rule_id, None)
            if record is None:
                return False
            try:
                self._save_encrypted_store()
            except RulesStoreError:
                self._rules[rule_id] = record
                raise
            return True


    def export_rules(self, destination: Path, password: str) -> int:
        """Grava todas as regras num arquivo de backup protegido por senha; retorna quantas foram exportadas."""
        with self._lock:
            items = [
                {
                    "term": rule.term,
                    "replacement_tag": rule.replacement_tag,
                    "case_sensitive": rule.case_sensitive,
                    "match_whole_word": rule.match_whole_word,
                }
                for rule in self._get_ephemeral_decrypted_rules()
            ]
        # O backup inteiro é cifrado com uma chave derivada da senha (scrypt + AES-256-GCM).
        payload = encrypt_backup(json.dumps(items).encode("utf-8"), password)
        Path(destination).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return len(items)

    def import_rules(self, source: Path, password: str) -> Tuple[int, int]:
        """Importa regras de um arquivo de backup. Retorna (importadas, ignoradas)."""
        try:
            payload = json.loads(Path(source).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ValueError("Não foi possível ler o arquivo de backup.") from exc

        # Com a senha errada, decrypt_backup lança ValueError aqui, antes de qualquer regra ser criada.
        items = json.loads(decrypt_backup(payload, password).decode("utf-8"))
        imported = skipped = 0
        for item in items:
            try:
                # Reaproveita o create_rule: valida, cifra e recusa termos que já existem.
                self.create_rule(
                    term=item["term"],
                    replacement_tag=item["replacement_tag"],
                    case_sensitive=item.get("case_sensitive", False),
                    match_whole_word=item.get("match_whole_word", True),
                )
                imported += 1
            except ValueError:  # termo já cadastrado ou inválido
                skipped += 1
        return imported, skipped
    

    def _get_ephemeral_decrypted_rules(self) -> List[DecryptedRule]:
        """Decifra as regras só em memória, para uma única sanitização."""
        with self._lock:
            decrypted_list: List[DecryptedRule] = []
            for rec in self._rules.values():
                try:
                    plain_term = self.crypto_service.decrypt(rec.encrypted_term)
                    decrypted_list.append(
                        DecryptedRule(
                            id=str(rec.id),
                            term=plain_term,
                            replacement_tag=rec.replacement_tag,
                            case_sensitive=rec.case_sensitive,
                            match_whole_word=rec.match_whole_word,
                        )
                    )
                except ValueError:
                    continue
            return decrypted_list

    # ------------------------------------------------------------------
    # Pipeline completo de sanitização em tempo real
    # ------------------------------------------------------------------

    def sanitize_prompt(self, prompt_text: str) -> DesktopSanitizeResult:
        """Executa o pipeline completo de sanitização e avaliação de risco sobre um texto."""
        if not prompt_text or not prompt_text.strip():
            return DesktopSanitizeResult(
                original_length=len(prompt_text or ""),
                sanitized_text=prompt_text or "",
                changed=False,
                total_detections=0,
                custom_matches_count=0,
                pii_matches_count=0,
                risk_level=SeverityLevel.LOW,
                risk_score=0,
            )

        with self._lock:
            # 1. Regras confidenciais do usuário (motor de regex de passada única)
            ephemeral_rules = self._get_ephemeral_decrypted_rules()
            custom_sanitized, custom_matches = CustomObfuscationEngine.apply(
                prompt_text, ephemeral_rules
            )
            # Descarta imediatamente as regras decifradas
            del ephemeral_rules

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
                    masked_value=self.crypto_service.mask_term(m.raw_term),
                )
                for m in custom_matches
            ]

            # 2. Detecção de dados pessoais e credenciais (CPF, cartão, e-mail, telefone, chaves de API)
            pii_detections = self.detection_engine.analyze(custom_sanitized)

            # 3. Substituição pelas tags padronizadas
            final_text = self.sanitization_engine.sanitize(custom_sanitized, pii_detections)

            all_detections = custom_detections + pii_detections
            risk_report = self.risk_analyzer.evaluate(all_detections)

            changed = final_text != prompt_text
            sanitized_hash = self.compute_text_hash(final_text)

            if changed:
                self._known_sanitized_hashes.add(sanitized_hash)
                # Limita o tamanho do cache de hashes em memória
                if len(self._known_sanitized_hashes) > 500:
                    self._known_sanitized_hashes.clear()
                    self._known_sanitized_hashes.add(sanitized_hash)

                self.total_prompts_protected += 1
                self.total_entities_redacted += len(all_detections)

            unique_types: List[str] = []
            for d in all_detections:
                if d.type not in unique_types:
                    unique_types.append(d.type)

            result = DesktopSanitizeResult(
                original_length=len(prompt_text),
                sanitized_text=final_text,
                changed=changed,
                total_detections=len(all_detections),
                custom_matches_count=len(custom_matches),
                pii_matches_count=len(pii_detections),
                risk_level=risk_report.risk_level,
                risk_score=risk_report.score,
                detected_types=unique_types,
                reasons=risk_report.reasons,
                sanitized_hash=sanitized_hash,
                timestamp=datetime.now().strftime("%H:%M:%S"),
            )
            self.last_result = result
            return result

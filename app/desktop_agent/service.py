"""Core service for the Windows Global Desktop Agent.

Executes the full Prompt Sanitizer pipeline in-process with zero network latency:
1. Encrypted-at-rest local storage for custom confidential rules (AES-256-GCM + HMAC Blind Index).
2. Single-pass custom rule obfuscation (CustomObfuscationEngine).
3. Mathematical and semantic PII detection (DetectionEngine: Mod 11 CPF/CNPJ, Luhn Credit Card, API Keys).
4. Canonical placeholder replacement (SanitizationEngine).
5. Composite risk scoring (RiskAnalyzer: 0-100 score and LOW/MEDIUM/HIGH/CRITICAL classification).
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

logger = get_logger(__name__)


def get_default_storage_path() -> Path:
    """Returns the platform-appropriate encrypted storage path (prioritizing Windows %APPDATA% with portable fallback)."""
    return get_data_dir() / "rules.enc.json"


@dataclass
class DesktopSanitizeResult:
    """Result of a real-time desktop prompt sanitization operation."""

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
        """Short safe status message for the HUD and notifications."""
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
    """Autonomous thread-safe sanitization and CRUD engine for the Desktop Agent."""

    def __init__(
        self,
        storage_path: Optional[Path] = None,
        crypto_service: Optional[RuleCryptoService] = None,
        user_id: str = "windows-desktop-user",
    ):
        self.user_id = user_id
        self.storage_path = storage_path or get_default_storage_path()
        self.crypto_service = crypto_service or RuleCryptoService()
        self.detection_engine = DetectionEngine()
        self.sanitization_engine = SanitizationEngine()
        self.risk_analyzer = RiskAnalyzer()

        self._lock = threading.RLock()
        self._rules: Dict[UUID, ConfidentialRuleRecord] = {}
        self._known_sanitized_hashes: set[str] = set()

        # Statistics for the active session
        self.total_prompts_protected: int = 0
        self.total_entities_redacted: int = 0
        self.last_result: Optional[DesktopSanitizeResult] = None

        self._load_encrypted_store()

    @staticmethod
    def compute_text_hash(text: str) -> str:
        """Computes a fast SHA-256 fingerprint of text to avoid re-sanitizing loops."""
        return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()

    def is_already_sanitized(self, text: str) -> bool:
        """Checks if the text matches a recently sanitized output produced by this agent."""
        if not text:
            return True
        text_hash = self.compute_text_hash(text)
        with self._lock:
            return text_hash in self._known_sanitized_hashes

    # ------------------------------------------------------------------
    # Encrypted Local Disk Persistence (Zero Plaintext Guarantee)
    # ------------------------------------------------------------------

    def _load_encrypted_store(self) -> None:
        """Loads encrypted rule records from disk without decrypting terms."""
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
                        user_id=item.get("user_id", self.user_id),
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
                logger.error("Failed to load encrypted rules store: %s", type(exc).__name__)
                # Preserve the unreadable file so the next save cannot silently destroy user data
                try:
                    backup = self.storage_path.with_suffix(".corrupt")
                    self.storage_path.replace(backup)
                    logger.error("Corrupt rules store moved to %s", backup.name)
                except OSError:
                    pass

    def _save_encrypted_store(self) -> None:
        """Persists ONLY AES-256-GCM ciphertexts and HMAC blind indexes to disk."""
        with self._lock:
            try:
                self.storage_path.parent.mkdir(parents=True, exist_ok=True)
                payload = [
                    {
                        "id": str(rec.id),
                        "user_id": rec.user_id,
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
                temp_path = self.storage_path.with_suffix(".tmp")
                temp_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
                temp_path.replace(self.storage_path)
            except Exception as exc:
                logger.error("Failed to save encrypted rules store: %s", type(exc).__name__)

    # ------------------------------------------------------------------
    # CRUD Operations for Confidential Terms
    # ------------------------------------------------------------------

    def create_rule(
        self,
        term: str,
        replacement_tag: str,
        case_sensitive: bool = False,
        match_whole_word: bool = True,
    ) -> RuleResponse:
        """Validates, encrypts, and stores a new confidential term rule."""
        req = RuleCreateRequest(
            term=term,
            replacement_tag=replacement_tag,
            case_sensitive=case_sensitive,
            match_whole_word=match_whole_word,
        )
        blind_index = self.crypto_service.compute_blind_index(req.term)

        with self._lock:
            for existing in self._rules.values():
                if existing.term_blind_index == blind_index:
                    raise ValueError("Este termo confidencial já está cadastrado.")

            encrypted_term = self.crypto_service.encrypt(req.term)
            record = ConfidentialRuleRecord(
                id=uuid4(),
                user_id=self.user_id,
                encrypted_term=encrypted_term,
                term_blind_index=blind_index,
                replacement_tag=req.replacement_tag,
                case_sensitive=req.case_sensitive,
                match_whole_word=req.match_whole_word,
            )
            self._rules[record.id] = record
            self._save_encrypted_store()

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
        """Returns all active rules with masked previews (never raw terms)."""
        with self._lock:
            responses: List[RuleResponse] = []
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
        """Updates an existing confidential rule and re-encrypts if term changed."""
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
            if rule_id in self._rules:
                del self._rules[rule_id]
                self._save_encrypted_store()
                return True
            return False

    def _get_ephemeral_decrypted_rules(self) -> List[DecryptedRule]:
        """Decrypts rules strictly in local scope for a single sanitization pass."""
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
    # Full Real-Time Sanitization Pipeline
    # ------------------------------------------------------------------

    def sanitize_prompt(self, prompt_text: str) -> DesktopSanitizeResult:
        """Runs the complete sanitization and risk evaluation pipeline on a text string."""
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
            # 1. Custom confidential rules (Single-Pass Regex Engine)
            ephemeral_rules = self._get_ephemeral_decrypted_rules()
            custom_sanitized, custom_matches = CustomObfuscationEngine.apply(
                prompt_text, ephemeral_rules
            )
            # Clear ephemeral references immediately
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

            # 2. Structured PII and Credentials Detection (CPF, Credit Card, Email, Phone, API Keys)
            pii_detections = self.detection_engine.analyze(custom_sanitized)

            # 3. Canonical Placeholder Replacement
            final_text = self.sanitization_engine.sanitize(custom_sanitized, pii_detections)

            all_detections = custom_detections + pii_detections
            risk_report = self.risk_analyzer.evaluate(all_detections)

            changed = final_text != prompt_text
            sanitized_hash = self.compute_text_hash(final_text)

            if changed:
                self._known_sanitized_hashes.add(sanitized_hash)
                # Bound hash cache size in memory
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

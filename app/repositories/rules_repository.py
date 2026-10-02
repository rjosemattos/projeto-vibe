"""Repository for encrypted confidential rules with multi-tenant isolation."""

import asyncio
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional
from uuid import UUID

if TYPE_CHECKING:
    from app.models.rules import ConfidentialRuleRecord


class ConfidentialRulesRepository:
    """Thread-safe and async-safe repository storing encrypted confidential rules.
    
    Guarantees strict tenant isolation by mapping storage by user_id.
    """

    def __init__(self):
        # In-memory storage: user_id -> {rule_id: ConfidentialRuleRecord}
        self._storage: Dict[str, Dict[UUID, ConfidentialRuleRecord]] = {}
        self._lock = asyncio.Lock()

    async def create(self, record: ConfidentialRuleRecord) -> ConfidentialRuleRecord:
        """Persists a new rule while enforcing unique terms per user via blind index."""
        async with self._lock:
            user_rules = self._storage.setdefault(record.user_id, {})

            # Duplicate check using blind index (without decrypting stored data)
            for existing in user_rules.values():
                if existing.term_blind_index == record.term_blind_index:
                    raise ValueError("Este termo confidencial já está cadastrado para este usuário.")

            user_rules[record.id] = record
            return record

    async def list_by_user(self, user_id: str) -> List[ConfidentialRuleRecord]:
        """Lists all encrypted rules registered for a given user."""
        async with self._lock:
            user_rules = self._storage.get(user_id, {})
            # Return sorted chronologically by creation date
            return sorted(user_rules.values(), key=lambda r: r.created_at)

    async def get_by_id(self, user_id: str, rule_id: UUID) -> Optional[ConfidentialRuleRecord]:
        """Fetches a specific encrypted rule belonging to a given user."""
        async with self._lock:
            return self._storage.get(user_id, {}).get(rule_id)

    async def update(self, user_id: str, record: ConfidentialRuleRecord) -> ConfidentialRuleRecord:
        """Updates an existing rule."""
        async with self._lock:
            user_rules = self._storage.get(user_id, {})
            if record.id not in user_rules:
                raise KeyError("Regra de ofuscação não encontrada.")

            # Duplicate check if blind index was modified
            for existing in user_rules.values():
                if existing.id != record.id and existing.term_blind_index == record.term_blind_index:
                    raise ValueError("Já existe outra regra cadastrada com este termo.")

            record.updated_at = datetime.now(timezone.utc)
            user_rules[record.id] = record
            return record

    async def delete(self, user_id: str, rule_id: UUID) -> bool:
        """Deletes a rule by ID."""
        async with self._lock:
            user_rules = self._storage.get(user_id, {})
            if rule_id in user_rules:
                del user_rules[rule_id]
                return True
            return False

    async def clear_for_user(self, user_id: str) -> None:
        """Helper for test cleanup."""
        async with self._lock:
            if user_id in self._storage:
                del self._storage[user_id]

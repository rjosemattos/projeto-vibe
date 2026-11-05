"""SQLite-backed repository for confidential rules (same async interface as the in-memory one)."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import List, Optional
from uuid import UUID

from app.auth.store import get_store, iso, parse
from app.core.config import settings
from app.models.rules import ConfidentialRuleRecord
from app.repositories.rules_repository import ConfidentialRulesRepository


def _to_record(row) -> ConfidentialRuleRecord:
    return ConfidentialRuleRecord(
        id=UUID(row["id"]),
        user_id=row["user_id"],
        encrypted_term=row["encrypted_term"],
        term_blind_index=row["term_blind_index"],
        replacement_tag=row["replacement_tag"],
        case_sensitive=bool(row["case_sensitive"]),
        match_whole_word=bool(row["match_whole_word"]),
        created_at=parse(row["created_at"]),
        updated_at=parse(row["updated_at"]),
    )


class SqliteRulesRepository:
    """Every query is scoped by user_id, giving tenant isolation at the data layer."""

    async def create(self, record: ConfidentialRuleRecord) -> ConfidentialRuleRecord:
        store = get_store()
        if store.query_one(
            "SELECT 1 FROM rules WHERE user_id = ? AND term_blind_index = ?",
            (record.user_id, record.term_blind_index),
        ):
            raise ValueError("Este termo confidencial já está cadastrado para este usuário.")
        store.execute(
            "INSERT INTO rules VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                str(record.id), record.user_id, record.encrypted_term, record.term_blind_index,
                record.replacement_tag, int(record.case_sensitive), int(record.match_whole_word),
                iso(record.created_at), iso(record.updated_at) if record.updated_at else None,
            ),
        )
        return record

    async def list_by_user(self, user_id: str) -> List[ConfidentialRuleRecord]:
        rows = get_store().query("SELECT * FROM rules WHERE user_id = ? ORDER BY created_at", (user_id,))
        return [_to_record(r) for r in rows]

    async def get_by_id(self, user_id: str, rule_id: UUID) -> Optional[ConfidentialRuleRecord]:
        row = get_store().query_one(
            "SELECT * FROM rules WHERE user_id = ? AND id = ?", (user_id, str(rule_id))
        )
        return _to_record(row) if row else None

    async def update(self, user_id: str, record: ConfidentialRuleRecord) -> ConfidentialRuleRecord:
        store = get_store()
        if not store.query_one("SELECT 1 FROM rules WHERE user_id = ? AND id = ?", (user_id, str(record.id))):
            raise KeyError("Regra de ofuscação não encontrada.")
        if store.query_one(
            "SELECT 1 FROM rules WHERE user_id = ? AND term_blind_index = ? AND id != ?",
            (user_id, record.term_blind_index, str(record.id)),
        ):
            raise ValueError("Já existe outra regra cadastrada com este termo.")
        record.updated_at = datetime.now(timezone.utc)
        store.execute(
            "UPDATE rules SET encrypted_term = ?, term_blind_index = ?, replacement_tag = ?, "
            "case_sensitive = ?, match_whole_word = ?, updated_at = ? WHERE user_id = ? AND id = ?",
            (
                record.encrypted_term, record.term_blind_index, record.replacement_tag,
                int(record.case_sensitive), int(record.match_whole_word), iso(record.updated_at),
                user_id, str(record.id),
            ),
        )
        return record

    async def delete(self, user_id: str, rule_id: UUID) -> bool:
        cur = get_store().execute("DELETE FROM rules WHERE user_id = ? AND id = ?", (user_id, str(rule_id)))
        return cur.rowcount > 0

    async def clear_for_user(self, user_id: str) -> None:
        get_store().execute("DELETE FROM rules WHERE user_id = ?", (user_id,))


class RepositorySelector:
    """Chooses persistent storage (Postgres/Supabase or SQLite) or the local in-memory repository."""

    def __init__(self) -> None:
        self._memory = ConfidentialRulesRepository()
        self._sqlite = SqliteRulesRepository()
        self._postgres = None

    def _active(self):
        if settings.DATABASE_URL:
            if self._postgres is None:
                from app.repositories.postgres_rules_repository import PostgresRulesRepository
                self._postgres = PostgresRulesRepository()
            return self._postgres
        return self._sqlite if settings.AUTH_ENABLED else self._memory

    def __getattr__(self, name: str):
        return getattr(self._active(), name)

"""PostgreSQL / Supabase implementation of the rules repository."""

from __future__ import annotations

import threading
from datetime import datetime
from typing import List, Optional
from uuid import UUID

from app.core.config import settings
from app.core.logging import get_logger
from app.models.rules import ConfidentialRuleRecord

logger = get_logger("postgres_repo")

PG_SCHEMA = """
CREATE TABLE IF NOT EXISTS rules (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    encrypted_term TEXT NOT NULL,
    term_blind_index TEXT NOT NULL,
    replacement_tag TEXT NOT NULL,
    case_sensitive BOOLEAN NOT NULL DEFAULT FALSE,
    match_whole_word BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ,
    UNIQUE(user_id, term_blind_index)
);
CREATE INDEX IF NOT EXISTS idx_rules_user ON rules(user_id);
"""


class PostgresRulesRepository:
    """PostgreSQL storage backed by Supabase with per-user tenant isolation."""

    def __init__(self, db_url: Optional[str] = None):
        self.db_url = db_url or settings.DATABASE_URL
        self._initialized = False
        self._init_lock = threading.Lock()

    def _get_connection(self):
        import psycopg
        from psycopg.rows import dict_row

        # Auto-convert postgres:// to postgresql:// if needed
        conn_str = self.db_url
        if conn_str.startswith("postgres://"):
            conn_str = "postgresql://" + conn_str[len("postgres://"):]

        return psycopg.connect(conn_str, row_factory=dict_row)

    def _ensure_schema(self):
        if not self._initialized:
            with self._init_lock:
                if not self._initialized:
                    try:
                        with self._get_connection() as conn:
                            with conn.cursor() as cur:
                                cur.execute(PG_SCHEMA)
                            conn.commit()
                        self._initialized = True
                    except Exception as exc:
                        logger.error("Failed to initialize PostgreSQL schema: %s", exc)

    def _row_to_record(self, row: dict) -> ConfidentialRuleRecord:
        c_at = row["created_at"]
        if isinstance(c_at, str):
            c_at = datetime.fromisoformat(c_at)

        u_at = row.get("updated_at")
        if isinstance(u_at, str):
            u_at = datetime.fromisoformat(u_at)

        return ConfidentialRuleRecord(
            id=UUID(str(row["id"])),
            user_id=str(row["user_id"]),
            encrypted_term=str(row["encrypted_term"]),
            term_blind_index=str(row["term_blind_index"]),
            replacement_tag=str(row["replacement_tag"]),
            case_sensitive=bool(row["case_sensitive"]),
            match_whole_word=bool(row["match_whole_word"]),
            created_at=c_at,
            updated_at=u_at,
        )

    async def create(self, record: ConfidentialRuleRecord) -> ConfidentialRuleRecord:
        self._ensure_schema()
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT 1 FROM rules WHERE user_id = %s AND term_blind_index = %s",
                    (record.user_id, record.term_blind_index),
                )
                if cur.fetchone():
                    raise ValueError("Este termo confidencial já está cadastrado para este usuário.")

                cur.execute(
                    """
                    INSERT INTO rules (id, user_id, encrypted_term, term_blind_index, replacement_tag,
                                       case_sensitive, match_whole_word, created_at, updated_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        str(record.id),
                        record.user_id,
                        record.encrypted_term,
                        record.term_blind_index,
                        record.replacement_tag,
                        record.case_sensitive,
                        record.match_whole_word,
                        record.created_at,
                        record.updated_at,
                    ),
                )
            conn.commit()
        return record

    async def list_by_user(self, user_id: str) -> List[ConfidentialRuleRecord]:
        self._ensure_schema()
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT * FROM rules WHERE user_id = %s ORDER BY created_at ASC",
                    (user_id,),
                )
                rows = cur.fetchall()
                return [self._row_to_record(r) for r in rows]

    async def get_by_id(self, user_id: str, rule_id: UUID) -> Optional[ConfidentialRuleRecord]:
        self._ensure_schema()
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT * FROM rules WHERE user_id = %s AND id = %s",
                    (user_id, str(rule_id)),
                )
                row = cur.fetchone()
                return self._row_to_record(row) if row else None

    async def update(self, user_id: str, record: ConfidentialRuleRecord) -> ConfidentialRuleRecord:
        self._ensure_schema()
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT 1 FROM rules WHERE user_id = %s AND id = %s",
                    (user_id, str(record.id)),
                )
                if not cur.fetchone():
                    raise KeyError("Regra de ofuscação não encontrada.")

                cur.execute(
                    "SELECT 1 FROM rules WHERE user_id = %s AND term_blind_index = %s AND id != %s",
                    (user_id, record.term_blind_index, str(record.id)),
                )
                if cur.fetchone():
                    raise ValueError("Já existe outra regra cadastrada com este termo.")

                from datetime import timezone
                record.updated_at = datetime.now(timezone.utc)

                cur.execute(
                    """
                    UPDATE rules SET encrypted_term = %s, term_blind_index = %s, replacement_tag = %s,
                                     case_sensitive = %s, match_whole_word = %s, updated_at = %s
                    WHERE user_id = %s AND id = %s
                    """,
                    (
                        record.encrypted_term,
                        record.term_blind_index,
                        record.replacement_tag,
                        record.case_sensitive,
                        record.match_whole_word,
                        record.updated_at,
                        user_id,
                        str(record.id),
                    ),
                )
            conn.commit()
        return record

    async def delete(self, user_id: str, rule_id: UUID) -> bool:
        self._ensure_schema()
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM rules WHERE user_id = %s AND id = %s",
                    (user_id, str(rule_id)),
                )
                deleted = cur.rowcount > 0
            conn.commit()
            return deleted

    async def clear_for_user(self, user_id: str) -> None:
        self._ensure_schema()
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM rules WHERE user_id = %s", (user_id,))
            conn.commit()

-- ==============================================================================
-- Prompt Sanitizer — Supabase PostgreSQL Schema
-- Copie e cole este script no "SQL Editor" do seu painel Supabase se preferir
-- inicializar a estrutura manualmente com Row Level Security (RLS).
-- ==============================================================================

-- 1. Tabela de Regras Confidenciais (Termos criptografados com AES-256-GCM)
CREATE TABLE IF NOT EXISTS public.rules (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    encrypted_term TEXT NOT NULL,
    term_blind_index TEXT NOT NULL,
    replacement_tag TEXT NOT NULL,
    case_sensitive BOOLEAN NOT NULL DEFAULT FALSE,
    match_whole_word BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT TIMEZONE('utc'::text, NOW()),
    updated_at TIMESTAMPTZ,
    CONSTRAINT uq_user_blind_index UNIQUE(user_id, term_blind_index)
);

-- 2. Índice para consultas rápidas isoladas por usuário
CREATE INDEX IF NOT EXISTS idx_rules_user_id ON public.rules(user_id);

-- 3. Habilitar Row Level Security (RLS)
ALTER TABLE public.rules ENABLE ROW LEVEL SECURITY;

-- 4. Política RLS: Usuários autenticados no Supabase (ex: Google OAuth)
-- só podem ler, inserir, atualizar e excluir as suas próprias regras.
DROP POLICY IF EXISTS "Usuário gerencia suas próprias regras" ON public.rules;
CREATE POLICY "Usuário gerencia suas próprias regras"
ON public.rules
FOR ALL
TO authenticated
USING (user_id = 'sb_' || auth.uid()::text)
WITH CHECK (user_id = 'sb_' || auth.uid()::text);

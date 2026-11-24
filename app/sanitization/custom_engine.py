"""Motor de ofuscação dos termos confidenciais cadastrados pelo usuário.

Feito para substituir vários termos em uma única passada:
1. Monta uma regex de alternativas ordenada do termo mais longo para o mais curto, evitando colisões entre trechos.
2. Escapa todos os termos com re.escape(), o que elimina o risco de ataques de ReDoS.
3. Usa limites de palavra que entendem Unicode (acentos) para a opção "palavra inteira".
4. Faz uma única substituição por grupo (diferencia e não diferencia maiúsculas),
   o que impede substituições em cascata (um termo sendo trocado dentro da tag de outro).
"""

import re
from dataclasses import dataclass
from typing import Dict, List, NamedTuple, Tuple


class DecryptedRule(NamedTuple):
    """Regra decifrada que existe apenas em memória, durante uma sanitização."""

    id: str
    term: str
    replacement_tag: str
    case_sensitive: bool
    match_whole_word: bool


@dataclass
class CustomMatch:
    """Registro de um termo confidencial encontrado e substituído."""

    rule_id: str
    raw_term: str
    replacement_tag: str
    start: int
    end: int


class CustomObfuscationEngine:
    """Motor de regex de passada única que oculta os termos confidenciais do usuário."""

    @staticmethod
    def _make_pattern(term: str, whole_word: bool) -> str:
        """Monta o trecho da regex de um termo, com escape seguro e limites de palavra."""
        escaped = re.escape(term)
        if not whole_word:
            return escaped

        # Limites de palavra que consideram símbolos no começo ou no fim do termo
        prefix = r"(?<!\w)" if re.match(r"^\w", term) else ""
        suffix = r"(?!\w)" if re.search(r"\w$", term) else ""
        return f"{prefix}{escaped}{suffix}"

    @classmethod
    def apply(cls, text: str, rules: List[DecryptedRule]) -> Tuple[str, List[CustomMatch]]:
        """Aplica as regras ao texto de forma determinística e sem substituições em cascata.

        Retorna:
            Tuple[str, List[CustomMatch]]: o texto sanitizado e os detalhes de cada termo encontrado.
        """
        if not text or not rules:
            return text, []

        cs_rules = [r for r in rules if r.case_sensitive]
        ci_rules = [r for r in rules if not r.case_sensitive]

        current_text = text
        all_matches: List[CustomMatch] = []

        # 1. Primeiro as regras que diferenciam maiúsculas
        if cs_rules:
            current_text, cs_matches = cls._apply_group(current_text, cs_rules, flags=0)
            all_matches.extend(cs_matches)

        # 2. Depois as que não diferenciam
        if ci_rules:
            current_text, ci_matches = cls._apply_group(
                current_text, ci_rules, flags=re.IGNORECASE
            )
            all_matches.extend(ci_matches)

        return current_text, all_matches

    @classmethod
    def _apply_group(
        cls, text: str, rules: List[DecryptedRule], flags: int
    ) -> Tuple[str, List[CustomMatch]]:
        """Compila e executa a substituição de passada única para um grupo de regras."""
        # Ordena do maior para o menor, priorizando termos mais longos e específicos
        sorted_rules = sorted(rules, key=lambda r: len(r.term), reverse=True)

        group_map: Dict[str, DecryptedRule] = {}
        patterns: List[str] = []

        for idx, rule in enumerate(sorted_rules):
            group_name = f"cr_{idx}"
            pattern_chunk = rf"(?P<{group_name}>{cls._make_pattern(rule.term, rule.match_whole_word)})"
            patterns.append(pattern_chunk)
            group_map[group_name] = rule

        combined_regex = re.compile("|".join(patterns), flags=flags | re.UNICODE)
        matches_found: List[CustomMatch] = []

        def _replacement_callback(match: re.Match) -> str:
            group_name = match.lastgroup
            if group_name and group_name in group_map:
                matched_rule = group_map[group_name]
                matches_found.append(
                    CustomMatch(
                        rule_id=matched_rule.id,
                        raw_term=match.group(0),
                        replacement_tag=matched_rule.replacement_tag,
                        start=match.start(),
                        end=match.end(),
                    )
                )
                return matched_rule.replacement_tag
            return match.group(0)

        result_text = combined_regex.sub(_replacement_callback, text)
        return result_text, matches_found

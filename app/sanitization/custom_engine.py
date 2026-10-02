"""Custom Confidential Term Obfuscation Engine.

Designed for high-performance single-pass multi-pattern substitution:
1. Compiles alternation Regex with length-descending precedence to prevent substring collisions.
2. Escapes all terms with re.escape() to guarantee immunity against ReDoS attacks.
3. Uses intelligent Unicode-aware lookarounds for whole-word boundaries.
4. Performs a single substitution pass per category (case-sensitive and case-insensitive),
   completely eliminating cascading substitution anomalies.
"""

import re
from dataclasses import dataclass
from typing import Dict, List, NamedTuple, Tuple


class DecryptedRule(NamedTuple):
    """Ephemeral in-memory decrypted rule structure."""

    id: str
    term: str
    replacement_tag: str
    case_sensitive: bool
    match_whole_word: bool


@dataclass
class CustomMatch:
    """Record of a matched and replaced confidential term."""

    rule_id: str
    raw_term: str
    replacement_tag: str
    start: int
    end: int


class CustomObfuscationEngine:
    """High-efficiency single-pass regex engine for custom confidential term redaction."""

    @staticmethod
    def _make_pattern(term: str, whole_word: bool) -> str:
        """Build regex chunk with safe escaping and smart boundary lookarounds."""
        escaped = re.escape(term)
        if not whole_word:
            return escaped

        # Smart lookaround boundaries aware of non-alphanumeric leading/trailing symbols
        prefix = r"(?<!\w)" if re.match(r"^\w", term) else ""
        suffix = r"(?!\w)" if re.search(r"\w$", term) else ""
        return f"{prefix}{escaped}{suffix}"

    @classmethod
    def apply(cls, text: str, rules: List[DecryptedRule]) -> Tuple[str, List[CustomMatch]]:
        """Applies custom rules to the text in a deterministic, cascade-free manner.

        Returns:
            Tuple[str, List[CustomMatch]]: The sanitized text and details of all matches.
        """
        if not text or not rules:
            return text, []

        cs_rules = [r for r in rules if r.case_sensitive]
        ci_rules = [r for r in rules if not r.case_sensitive]

        current_text = text
        all_matches: List[CustomMatch] = []

        # 1. Process Case-Sensitive rules first
        if cs_rules:
            current_text, cs_matches = cls._apply_group(current_text, cs_rules, flags=0)
            all_matches.extend(cs_matches)

        # 2. Process Case-Insensitive rules
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
        """Compiles and executes single-pass substitution for a group of rules."""
        # Sort by length descending to prioritize longer and more specific terms
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

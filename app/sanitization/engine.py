"""Sanitization Engine for entity-consistent, reversible-index redaction."""

from collections import Counter
from typing import Dict, List
from app.detection.base import Detection


class SanitizationEngine:
    """Transforms raw prompt text into sanitized text preserving contextual meaning and entity consistency."""

    # Standard placeholder prefixes according to specifications
    TYPE_PREFIX_MAP: Dict[str, str] = {
        "CPF": "CPF_USUARIO",
        "CNPJ": "CNPJ_USUARIO",
        "CARTAO_CREDITO": "CARTAO_USUARIO",
        "EMAIL": "EMAIL_USUARIO",
        "TELEFONE": "TELEFONE_USUARIO",
        "API_KEY": "API_KEY",
        "JWT": "JWT",
        "SENHA": "SENHA",
        "BEARER_TOKEN": "BEARER_TOKEN",
        "AUTH_HEADER": "AUTH_TOKEN",
        "URL_PASSWORD": "CREDENTIAL",
        "CREDENTIAL": "CREDENTIAL",
        "IP_ADDRESS": "IP_USUARIO",
        "PRIVATE_KEY": "CHAVE_PRIVADA",
    }

    def sanitize(self, text: str, detections: List[Detection]) -> str:
        """Sanitize text by replacing sensitive entities with consistent placeholders.

        Rules:
        1. If an entity type appears only once in the prompt, use [PREFIX] (e.g. [CPF_USUARIO]).
        2. If an entity type appears more than once (either distinct entities or repeated occurrences),
           use indexed placeholders [PREFIX_1], [PREFIX_2] consistently mapped by normalized_key.
        3. Replacements are performed in reverse offset order to prevent character index drift.
        """
        if not detections:
            return text

        # Count total occurrences of each type
        type_counts = Counter(d.type for d in detections)

        # Build consistent mapping: normalized_key -> assigned placeholder
        type_entity_registry: Dict[str, Dict[str, str]] = {}
        type_entity_counter: Dict[str, int] = {}

        # Detections in chronological appearance order
        chrono_detections = sorted(detections, key=lambda d: d.start)

        entity_to_placeholder: Dict[str, str] = {}

        for det in chrono_detections:
            ent_type = det.type
            prefix = self.TYPE_PREFIX_MAP.get(ent_type, ent_type)
            norm_key = det.normalized_key

            if type_counts[ent_type] == 1:
                # Singular occurrence in the whole prompt
                placeholder = f"[{prefix}]"
            else:
                # Multiple occurrences of this type exist in the prompt
                if ent_type not in type_entity_registry:
                    type_entity_registry[ent_type] = {}
                    type_entity_counter[ent_type] = 0

                if norm_key not in type_entity_registry[ent_type]:
                    type_entity_counter[ent_type] += 1
                    index = type_entity_counter[ent_type]
                    type_entity_registry[ent_type][norm_key] = f"[{prefix}_{index}]"

                placeholder = type_entity_registry[ent_type][norm_key]

            entity_to_placeholder[f"{det.start}_{det.end}"] = placeholder

        # Perform replacements from right to left (reverse start order)
        # to ensure previous character indices remain completely valid
        reverse_detections = sorted(detections, key=lambda d: d.start, reverse=True)
        sanitized_chars = list(text)

        for det in reverse_detections:
            key = f"{det.start}_{det.end}"
            placeholder = entity_to_placeholder.get(key, f"[{det.type}]")
            sanitized_chars[det.start : det.end] = list(placeholder)

        return "".join(sanitized_chars)


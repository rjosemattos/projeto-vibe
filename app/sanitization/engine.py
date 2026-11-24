"""Motor de sanitização: troca os dados detectados por tags consistentes."""

from collections import Counter
from typing import Dict, List
from app.detection.base import Detection


class SanitizationEngine:
    """Transforma o prompt original em texto sanitizado, mantendo o sentido e a consistência das entidades."""

    # Prefixos padrão das tags de substituição
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
        """Substitui as entidades sensíveis do texto por tags consistentes.

        Regras:
        1. Se um tipo de entidade aparece uma única vez no prompt, usa [PREFIXO] (ex.: [CPF_USUARIO]).
        2. Se o tipo aparece mais de uma vez (entidades diferentes ou repetidas), usa tags numeradas
           [PREFIXO_1], [PREFIXO_2], sempre a mesma tag para o mesmo valor (pela normalized_key).
        3. As substituições são feitas do fim para o começo do texto, para não deslocar as posições.
        """
        if not detections:
            return text

        # Conta o total de ocorrências de cada tipo
        type_counts = Counter(d.type for d in detections)

        # Monta o mapeamento consistente: normalized_key -> tag atribuída
        type_entity_registry: Dict[str, Dict[str, str]] = {}
        type_entity_counter: Dict[str, int] = {}

        # Detecções na ordem em que aparecem no texto
        chrono_detections = sorted(detections, key=lambda d: d.start)

        entity_to_placeholder: Dict[str, str] = {}

        for det in chrono_detections:
            ent_type = det.type
            prefix = self.TYPE_PREFIX_MAP.get(ent_type, ent_type)
            norm_key = det.normalized_key

            if type_counts[ent_type] == 1:
                # Ocorrência única em todo o prompt
                placeholder = f"[{prefix}]"
            else:
                # Este tipo aparece mais de uma vez no prompt
                if ent_type not in type_entity_registry:
                    type_entity_registry[ent_type] = {}
                    type_entity_counter[ent_type] = 0

                if norm_key not in type_entity_registry[ent_type]:
                    type_entity_counter[ent_type] += 1
                    index = type_entity_counter[ent_type]
                    type_entity_registry[ent_type][norm_key] = f"[{prefix}_{index}]"

                placeholder = type_entity_registry[ent_type][norm_key]

            entity_to_placeholder[f"{det.start}_{det.end}"] = placeholder

        # Substitui da direita para a esquerda (ordem inversa de início)
        # para que as posições dos caracteres anteriores continuem válidas
        reverse_detections = sorted(detections, key=lambda d: d.start, reverse=True)
        sanitized_chars = list(text)

        for det in reverse_detections:
            key = f"{det.start}_{det.end}"
            placeholder = entity_to_placeholder.get(key, f"[{det.type}]")
            sanitized_chars[det.start : det.end] = list(placeholder)

        return "".join(sanitized_chars)


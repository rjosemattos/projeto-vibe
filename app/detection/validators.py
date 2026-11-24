"""Algoritmos de validação matemática de documentos e dados financeiros."""

import re


def validate_cpf(raw_value: str) -> bool:
    """Valida um CPF pelo cálculo dos dígitos verificadores (módulo 11).

    Rejeita:
    - Tamanho diferente de 11 dígitos
    - Sequências de dígitos iguais (ex.: 000.000.000-00, 111.111.111-11)
    - Dígitos verificadores matematicamente inválidos
    """
    digits = re.sub(r"\D", "", raw_value)
    if len(digits) != 11:
        return False

    # Rejeita dígitos todos iguais
    if digits == digits[0] * 11:
        return False

    # Valida o primeiro dígito verificador
    s1 = sum(int(d) * (10 - i) for i, d in enumerate(digits[:9]))
    d1 = (s1 * 10 % 11) % 10
    if d1 != int(digits[9]):
        return False

    # Valida o segundo dígito verificador
    s2 = sum(int(d) * (11 - i) for i, d in enumerate(digits[:10]))
    d2 = (s2 * 10 % 11) % 10
    return d2 == int(digits[10])


def validate_cnpj(raw_value: str) -> bool:
    """Valida um CNPJ pelo cálculo dos dígitos verificadores (módulo 11).

    Rejeita:
    - Tamanho diferente de 14 dígitos
    - Sequências de dígitos iguais
    - Dígitos verificadores matematicamente inválidos
    """
    digits = re.sub(r"\D", "", raw_value)
    if len(digits) != 14:
        return False

    if digits == digits[0] * 14:
        return False

    weights_1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    s1 = sum(int(d) * w for d, w in zip(digits[:12], weights_1))
    r1 = s1 % 11
    d1 = 0 if r1 < 2 else 11 - r1
    if d1 != int(digits[12]):
        return False

    weights_2 = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    s2 = sum(int(d) * w for d, w in zip(digits[:13], weights_2))
    r2 = s2 % 11
    d2 = 0 if r2 < 2 else 11 - r2
    return d2 == int(digits[13])


def validate_luhn(raw_value: str) -> bool:
    """Valida um número de cartão de crédito/débito pelo algoritmo de Luhn (módulo 10).

    Rejeita:
    - Valores não numéricos ou com tamanho fora de 13 a 19 dígitos
    - Sequências que não passam na soma de verificação
    """
    digits_str = re.sub(r"\D", "", raw_value)
    if not (13 <= len(digits_str) <= 19):
        return False

    digits = [int(c) for c in digits_str]
    total = 0
    # Percorre os dígitos da direita para a esquerda
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            doubled = d * 2
            total += (doubled - 9) if doubled > 9 else doubled
        else:
            total += d

    return total % 10 == 0


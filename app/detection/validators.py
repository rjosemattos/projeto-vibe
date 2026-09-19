"""Mathematical and semantic validation algorithms for identity and financial data."""

import re


def validate_cpf(raw_value: str) -> bool:
    """Validate a Brazilian CPF number using modulo 11 check-digit verification.

    Rejects:
    - Length != 11 digits
    - Sequences of identical digits (e.g., 000.000.000-00, 111.111.111-11)
    - Mathematically invalid check digits
    """
    digits = re.sub(r"\D", "", raw_value)
    if len(digits) != 11:
        return False

    # Check for repeated digits
    if digits == digits[0] * 11:
        return False

    # Validate first check digit
    s1 = sum(int(d) * (10 - i) for i, d in enumerate(digits[:9]))
    d1 = (s1 * 10 % 11) % 10
    if d1 != int(digits[9]):
        return False

    # Validate second check digit
    s2 = sum(int(d) * (11 - i) for i, d in enumerate(digits[:10]))
    d2 = (s2 * 10 % 11) % 10
    return d2 == int(digits[10])


def validate_cnpj(raw_value: str) -> bool:
    """Validate a Brazilian CNPJ number using modulo 11 check-digit verification.

    Rejects:
    - Length != 14 digits
    - Sequences of identical digits
    - Mathematically invalid check digits
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
    """Validate a credit/debit card number using the Luhn checksum algorithm (Mod 10).

    Rejects:
    - Non-numeric or lengths outside 13-19 digits
    - Sequences that fail the checksum
    """
    digits_str = re.sub(r"\D", "", raw_value)
    if not (13 <= len(digits_str) <= 19):
        return False

    digits = [int(c) for c in digits_str]
    total = 0
    # Process digits from right to left
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            doubled = d * 2
            total += (doubled - 9) if doubled > 9 else doubled
        else:
            total += d

    return total % 10 == 0


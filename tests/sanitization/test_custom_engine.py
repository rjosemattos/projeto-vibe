"""Tests for CustomObfuscationEngine (Single-pass multi-pattern regex engine)."""

import pytest
from app.sanitization.custom_engine import CustomObfuscationEngine, DecryptedRule


def test_custom_engine_case_insensitivity():
    rules = [
        DecryptedRule(
            id="1",
            term="CESAR",
            replacement_tag="[COMPANY_SENSITIVE]",
            case_sensitive=False,
            match_whole_word=True,
        )
    ]

    text = "O CESAR, o cesar e o CeSaR desenvolvem tecnologias."
    sanitized, matches = CustomObfuscationEngine.apply(text, rules)

    assert "[COMPANY_SENSITIVE]" in sanitized
    assert "CESAR" not in sanitized
    assert "cesar" not in sanitized
    assert "CeSaR" not in sanitized
    assert sanitized == "O [COMPANY_SENSITIVE], o [COMPANY_SENSITIVE] e o [COMPANY_SENSITIVE] desenvolvem tecnologias."
    assert len(matches) == 3


def test_custom_engine_case_sensitivity():
    rules = [
        DecryptedRule(
            id="1",
            term="Apple",
            replacement_tag="[BRAND]",
            case_sensitive=True,
            match_whole_word=True,
        )
    ]

    text = "A Apple lançou um produto, mas eu comi uma apple no almoço."
    sanitized, matches = CustomObfuscationEngine.apply(text, rules)

    # Only uppercase "Apple" is replaced
    assert sanitized == "A [BRAND] lançou um produto, mas eu comi uma apple no almoço."
    assert len(matches) == 1


def test_custom_engine_whole_word_boundary_isolation():
    rules = [
        DecryptedRule(
            id="1",
            term="Sol",
            replacement_tag="[ESTRELA]",
            case_sensitive=False,
            match_whole_word=True,
        )
    ]

    text = "O sol brilha no céu. A solidão é dura. O sistema solar é vasto."
    sanitized, matches = CustomObfuscationEngine.apply(text, rules)

    # "solidão" and "solar" MUST NOT be replaced!
    assert "solidão" in sanitized
    assert "solar" in sanitized
    assert "[ESTRELA]" in sanitized
    assert sanitized == "O [ESTRELA] brilha no céu. A solidão é dura. O sistema solar é vasto."
    assert len(matches) == 1


def test_custom_engine_partial_match_when_enabled():
    rules = [
        DecryptedRule(
            id="1",
            term="bug",
            replacement_tag="[DEFEITO]",
            case_sensitive=False,
            match_whole_word=False,
        )
    ]

    text = "Temos um bug e outro debugger aqui."
    sanitized, matches = CustomObfuscationEngine.apply(text, rules)

    assert sanitized == "Temos um [DEFEITO] e outro [DEFEITO]ger aqui."
    assert len(matches) == 2


def test_custom_engine_longer_terms_precedence_no_collisions():
    rules = [
        DecryptedRule(
            id="1",
            term="Banco do Brasil",
            replacement_tag="[INSTITUICAO_FINANCEIRA]",
            case_sensitive=False,
            match_whole_word=True,
        ),
        DecryptedRule(
            id="2",
            term="Banco",
            replacement_tag="[ENTIDADE]",
            case_sensitive=False,
            match_whole_word=True,
        ),
    ]

    text = "Fui à agência do Banco do Brasil e depois sentei no banco da praça."
    sanitized, matches = CustomObfuscationEngine.apply(text, rules)

    assert "[INSTITUICAO_FINANCEIRA]" in sanitized
    assert "[ENTIDADE]" in sanitized
    # "Banco do Brasil" should not become "[ENTIDADE] do Brasil"
    assert sanitized == "Fui à agência do [INSTITUICAO_FINANCEIRA] e depois sentei no [ENTIDADE] da praça."


def test_custom_engine_special_characters_and_symbols():
    rules = [
        DecryptedRule(
            id="1",
            term="C++",
            replacement_tag="[LINGUAGEM_COMPILADA]",
            case_sensitive=True,
            match_whole_word=True,
        ),
        DecryptedRule(
            id="2",
            term="R$ 1.000,00",
            replacement_tag="[VALOR_SIGILOSO]",
            case_sensitive=False,
            match_whole_word=True,
        ),
    ]

    text = "Desenvolvi em C++ um módulo que custou R$ 1.000,00 no total."
    sanitized, matches = CustomObfuscationEngine.apply(text, rules)

    assert "[LINGUAGEM_COMPILADA]" in sanitized
    assert "[VALOR_SIGILOSO]" in sanitized
    assert sanitized == "Desenvolvi em [LINGUAGEM_COMPILADA] um módulo que custou [VALOR_SIGILOSO] no total."


def test_custom_engine_no_cascade_replacement():
    # If rule 1 replaces "Alpha" with "Beta", and rule 2 replaces "Beta" with "Gamma",
    # "Alpha" must NOT end up as "Gamma"!
    rules = [
        DecryptedRule(
            id="1",
            term="Alpha",
            replacement_tag="Beta",
            case_sensitive=True,
            match_whole_word=True,
        ),
        DecryptedRule(
            id="2",
            term="Beta",
            replacement_tag="Gamma",
            case_sensitive=True,
            match_whole_word=True,
        ),
    ]

    text = "Projeto Alpha e Projeto Beta."
    sanitized, matches = CustomObfuscationEngine.apply(text, rules)

    # In single-pass regex, "Alpha" becomes "Beta" and stays "Beta"; existing "Beta" becomes "Gamma"
    assert sanitized == "Projeto Beta e Projeto Gamma."

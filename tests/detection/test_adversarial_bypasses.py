"""Testes com formatos complexos e tentativas de burlar a detecção (JSON, Markdown, cabeçalhos, ofuscação)."""

from app.detection.engine import DetectionEngine
from app.sanitization.engine import SanitizationEngine


def test_sensitive_data_inside_json_structure():
    engine = DetectionEngine()
    sanitizer = SanitizationEngine()
    json_prompt = """
    Analise o seguinte payload de integração:
    {
        "usuario": "Carlos Mendes",
        "cpf": "123.456.789-09",
        "api_key": "sk-proj-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
        "auth": {
            "token": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozGzT_WwtqP_ErQDhbP_Wtc8qEkWk7_8b5wB2uF01g"
        }
    }
    """
    detections = engine.analyze(json_prompt)
    sanitized = sanitizer.sanitize(json_prompt, detections)

    assert len(detections) >= 3
    assert "123.456.789-09" not in sanitized
    assert "sk-proj-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6" not in sanitized
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in sanitized
    assert "[CPF_USUARIO]" in sanitized


def test_sensitive_data_inside_markdown():
    engine = DetectionEngine()
    sanitizer = SanitizationEngine()
    markdown_prompt = """
    # Relatório de Auditoria
    
    * **Cliente**: Ana Pereira
    * **CPF**: `123.456.789-09`
    * **Cartão**: `4532 1234 5678 9014`
    
    ```bash
    curl -H "Authorization: Bearer mySecretToken12345678" https://api.empresa.com
    ```
    """
    detections = engine.analyze(markdown_prompt)
    sanitized = sanitizer.sanitize(markdown_prompt, detections)

    assert "123.456.789-09" not in sanitized
    assert "4532 1234 5678 9014" not in sanitized
    assert "mySecretToken12345678" not in sanitized


def test_multiple_repeated_and_distinct_entities_mix():
    engine = DetectionEngine()
    sanitizer = SanitizationEngine()
    prompt = (
        "Transferir de CPF 123.456.789-09 para CPF 529.982.247-25. "
        "Depois confirmar envio para o titular do CPF 123.456.789-09."
    )
    detections = engine.analyze(prompt)
    sanitized = sanitizer.sanitize(prompt, detections)

    # 123.456.789-09 aparece duas vezes -> as duas viram [CPF_USUARIO_1]
    # 529.982.247-25 aparece uma vez -> vira [CPF_USUARIO_2]
    assert sanitized.count("[CPF_USUARIO_1]") == 2
    assert sanitized.count("[CPF_USUARIO_2]") == 1
    assert "123.456.789-09" not in sanitized
    assert "529.982.247-25" not in sanitized


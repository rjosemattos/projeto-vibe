# 🛡️ Prompt Sanitizer

**Camada Preventiva de Privacidade e Segurança para Uso de IAs Conversacionais**

O **Prompt Sanitizer** é uma ferramenta desenvolvida sob a filosofia de **Privacy by Design**, cujo objetivo primordial é funcionar como um freio preventivo para o uso irrefletido de dados sensíveis (identificadores pessoais, documentos, cartões de crédito, chaves de API, senhas e credenciais) em ferramentas de IA como ChatGPT, Claude, Microsoft Copilot e LLMs em geral.

---

## 📌 1. Visão Geral

O avanço rápido das ferramentas de IA generativa facilitou o compartilhamento inadvertido de informações confidenciais em ambientes corporativos e pessoais. Um prompt como:

> *"Analise este cliente: João da Silva, CPF 123.456.789-09, cartão 4532 1234 5678 9014 e email joao@empresa.com, e me diga se ele pode contratar o serviço."*

Ao ser enviado diretamente a um serviço externo, expõe dados pessoais sob a LGPD/GDPR e dados financeiros confidenciais.

O Prompt Sanitizer intercepta esse fluxo através do conceito:

```text
PARE. PENSE. SANITIZE. CONTINUE.
```

Transformando o texto em uma versão segura e semanticamente consistente:

> *"Analise este cliente: João da Silva, CPF [CPF_USUARIO], cartão [CARTAO_USUARIO] e email [EMAIL_USUARIO], e me diga se ele pode contratar o serviço."*

---

## 🏗️ 2. Arquitetura do Sistema

O sistema foi estruturado com forte desacoplamento, responsabilidade única e processamento **100% local**:

```text
                   [ Prompt do Usuário ]
                             ↓
              [ Middlewares de Segurança & Limite ]
                 (Tamanho de payload, CSP, Anti-DoS)
                             ↓
                    [ Detection Engine ]
            ┌────────────────────────────────────┐
            │ • CPFDetector (Mod 11)             │
            │ • CNPJDetector (Mod 11)            │
            │ • CreditCardDetector (Luhn Mod 10) │
            │ • EmailDetector (Safe RFC Regex)   │
            │ • PhoneDetector (BR DDD + E.164)   │
            │ • APIKeyDetector (OpenAI, AWS, GH) │
            │ • JWTDetector (Base64url Tokens)   │
            │ • CredentialsDetector (Auth/Pass)  │
            └────────────────────────────────────┘
                             ↓
              [ Overlap & Conflict Resolution ]
            (Priorização por severidade e cobertura)
                             ↓
                     [ Risk Analyzer ]
           (Matriz de Risco: LOW, MEDIUM, HIGH, CRITICAL)
                             ↓
                   [ Sanitization Engine ]
            (Substituição Consistente de Entidades)
                             ↓
          [ Resposta da API / Interface Web Local ]
```

### Componentes Principais

* `app/core/`: Configurações de ambiente (`config.py`), criptografia autenticada AES-256-GCM e blind indexing (`crypto.py`), middlewares de headers e tamanho de payload (`security.py`), e logging seguro com redaction automático (`logging.py`).
* `app/detection/`:
  * `validators.py`: Implementações semânticas matemáticas puras (Módulo 11 para CPF e CNPJ; Algoritmo de Luhn para cartões).
  * `base.py`: Contrato abstrato `BaseDetector` e estrutura `Detection`.
  * `detectors/`: Módulos de detecção especializados por entidade.
  * `engine.py`: Orquestrador de detecções e algoritmo de resolução de colisões de spans.
* `app/risk/`: Avaliador transparente com matriz de severidade e pontuação contextual (0 a 100).
* `app/sanitization/`:
  * `engine.py`: Motor de substituição reversa de índices garantindo consistência referencial (`[CPF_USUARIO_1]`, `[CPF_USUARIO_2]`).
  * `custom_engine.py`: Motor determinístico em passe único para regras dinâmicas e palavras confidenciais personalizadas.
* `app/repositories/`: Repositório criptografado em repouso (`rules_repository.py`) com isolamento multi-inquilino.
* `app/api/`: Rotas FastAPI seguras (`/health`, `/api/v1/analyze` e o CRUD `/api/v1/rules`).
* `app/static/`: Interface gráfica moderna com suporte completo ao gerenciamento de regras e análise em tempo real.

---

## 🚀 3. Instalação e Execução Local

### Pré-requisitos
* Python 3.10 ou superior
* Pip

### Passo 1: Clonar o repositório e entrar na pasta
```bash
cd projeto-vibe-cesar
```

### Passo 2: Criar e ativar ambiente virtual
```bash
python3 -m venv .venv
source .venv/bin/activate
```

*(No Windows PowerShell: `.venv\Scripts\Activate.ps1`)*

### Passo 3: Instalar as dependências
```bash
pip install -r requirements.txt
```

### Passo 4: Executar a aplicação
```bash
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

### Passo 5: Acessar a aplicação
Abra o navegador em:
👉 **[http://localhost:8000](http://localhost:8000)**

---

## 🧪 4. Execução dos Testes Automatizados

O projeto conta com uma suíte abrangente de testes automatizados unitários, de integração e de segurança contra adversariais e ReDoS:

```bash
pytest -v
```

Para ver o resumo enxuto:
```bash
pytest --tb=short
```

---

## 🔒 5. Políticas de Privacidade & Segurança

### 5.1 Processamento Estritamente Local
* **Sem envio externo:** A aplicação não se comunica com OpenAI, Google, Anthropic ou qualquer endpoint de terceiros.
* **Sem persistência em disco/banco:** Prompts nunca são salvos em SQLite, arquivos de cache temporários ou bases relacionais.
* **Headers anti-cache:** As respostas da API incluem `Cache-Control: no-store, no-cache, must-revalidate` para impedir armazenamento em cache de navegador ou proxies locais.

### 5.2 Regra Zero de Exposição de Segredos
* Valores brutos de segredos, senhas e tokens **nunca** são retornados na API, mesmo após a detecção.
* A API retorna apenas o metadado estruturado e o valor com mascaramento seguro (ex: `sk-12************`).
* O `PrivacyRedactingFilter` intercepta o subsistema de log padrão do Python para garantir que nenhuma mensagem acidental grave PIIs ou credenciais em texto claro.

### 5.3 Validação Semântica vs. Falsos Positivos
* O sistema não utiliza regex cega para dados numéricos:
  * **CPF:** Candidatos passam por cálculo dos dígitos verificadores (Módulo 11) e checagem de sequências homogêneas (`111.111.111-11` é rejeitado).
  * **CNPJ:** Validação dos pesos e dígitos verificadores.
  * **Cartões de Crédito:** Algoritmo de Luhn obrigatório; números de pedido ou timestamps que não atendem ao checksum são automaticamente descartados.

### 5.4 Prevenção de ReDoS (Regular Expression Denial of Service)
* Todas as regexes foram construídas com:
  * Ausência de quantificadores sobrepostos ou aninhados (`(a+)+`).
  * Conjuntos de caracteres estritos e limitadores de comprimento `{min,max}`.
  * Testes de estresse com strings de ataque repetitivas (`tests/security/test_redos_safety.py`).

### 5.5 Limite de Payload
* Middleware HTTP configurado para rejeitar requisições que excedam 50 KB com código de status `HTTP 413 Payload Too Large`.

---

## ⚠️ 6. Limitações Conhecidas

Uma ferramenta de engenharia de privacidade responsável deve ser transparente quanto às suas limitações técnicas:

1. **Falsos Positivos Residuais:**
   * Um identificador numérico arbitrário de 11 dígitos (ex: um ID interno de banco de dados ou código de produto) pode coincidentemente ser matematicamente válido sob o Módulo 11 do CPF. Embora o sistema verifique pontuações e prefixos contextuais, a coincidência matemática pura ainda é possível.
2. **Falsos Negativos (Ofuscação Extrema):**
   * Se um usuário malicioso deliberadamente separar dígitos por palavras (`meu c p f é um dois três...`), padrões baseados em caracteres e heurísticas locais não os detectarão sem um modelo NLP contextual profundo.
3. **Chaves e Segredos de Formato Genérico:**
   * Chaves estruturadas (OpenAI `sk-...`, AWS `AKIA...`, GitHub `ghp_...`, JWT `eyJ...`) são identificadas com precisão próxima a 100%. No entanto, chaves de API sem prefixo padrão ou entropia atípica em variáveis com nomes não convencionais podem não ser sinalizadas.
4. **Revisão Humana Indispensável:**
   * A ferramenta funciona como um assistente de segurança preventivo, mas **não substitui o julgamento e a revisão humana final**.

---

## 🗺️ 7. Roadmap Futuro

Possíveis evoluções planejadas para versões subsequentes:

1. **Extensão de Navegador (Chrome / Firefox / Edge):** Interceptação inline diretamente no campo de texto das interfaces do ChatGPT, Claude e Copilot.
2. **Interceptação de Área de Transferência (Clipboard Guard):** Sanitização opcional antes de colar conteúdos em aplicativos de IA.
3. **Mecanismo NLP / LLM Local (Ollama / Llama.cpp):** Detecção semântica contextual para entidades não estruturadas (ex: nomes de pessoas, diagnósticos médicos, endereços residenciais completos) executada 100% on-device.
4. **Exportação de Regras DLP Corporativas:** Integração com políticas JSON/YAML centralizadas para compliance empresarial.
5. **Painel de Auditoria Anonimizado:** Métricas de volume e risco agregado para times de SecOps e DPOs sem expor o texto original dos prompts.

---

## 📄 Licença

Desenvolvido para fins educacionais, conformidade com privacidade e segurança de dados.


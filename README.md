# 🛡️ Prompt Sanitizer

**Camada Preventiva de Privacidade, Ofuscação Dinâmica e Segurança em Tempo Real para Uso de IAs Conversacionais**

O **Prompt Sanitizer** é uma solução de engenharia de privacidade construída sob a filosofia de **Privacy by Design** e **Zero-Leakage**. Seu objetivo é atuar como uma barreira inteligente e transparente que impede o vazamento acidental de dados sensíveis (CPF, CNPJ, cartões de crédito, e-mails, telefones, chaves de API, tokens, senhas e **termos confidenciais de negócio**) em ferramentas de IA como **ChatGPT, Claude, Microsoft Copilot, Gemini, DeepSeek, Cursor e VS Code**.

O Prompt Sanitizer é um **agente para Windows que roda em segundo plano** e processa tudo **100% localmente**. Ele fica na bandeja do sistema (*System Tray*), pode iniciar sozinho a cada logon e protege qualquer chat de IA de duas formas:
* **Clipboard protegido em tempo real:** todo texto copiado (`Ctrl+C`) é higienizado antes de ser colado (`Ctrl+V`).
* **Limpeza do campo do chat (`Ctrl+Shift+S`):** o texto já digitado na caixa de mensagem da IA é substituído pela versão segura.

Um **HUD flutuante** opcional (*Always-on-Top*) mostra alertas e o escore de risco, e o gerenciador de **termos confidenciais** guarda as regras do usuário em um cofre cifrado com AES-256-GCM.

---

## 📌 1. Visão Geral

O avanço das ferramentas de IA generativa facilitou o compartilhamento inadvertido de informações críticas (*Shadow AI*). Um prompt cotidiano como:

> *"Olá ChatGPT, revise o contrato da CESAR para o cliente João da Silva, CPF 123.456.789-09, cartão 4532 1234 5678 9014 e email joao@empresa.com."*

Ao ser enviado diretamente a um provedor externo, expõe dados protegidos pela **LGPD/GDPR**, dados financeiros e segredos corporativos.

Com o **Prompt Sanitizer** ativo, o prompt é transformado em menos de **2,5 ms** em uma versão segura e semanticamente consistente antes de chegar à IA:

> *"Olá ChatGPT, revise o contrato da [COMPANY_SENSITIVE] para o cliente João da Silva, CPF [CPF_USUARIO], cartão [CARTAO_USUARIO] e email [EMAIL_USUARIO]."*

---

## 🏗️ 2. Arquitetura do Sistema

O projeto possui arquitetura modular, desacoplada e processamento **100% local** (nenhum dado sai da máquina do usuário durante a sanitização):

```text
                [ Chat de IA Ativo (Windows) / Clipboard ]
                                    ↓
         [ 0. Custom Obfuscation Engine (CRUD Termos Confidenciais) ]
         ┌──────────────────────────────────────────────────────────┐
         │ • Cofre Local AES-256-GCM (Nonces aleatórios de 96 bits) │
         │ • Índice Cego Determinístico via HMAC-SHA256             │
         │ • Single-Pass Multi-Pattern Regex O(N) anti-colisão      │
         │ • Escape estrito anti-ReDoS e Unicode Word Boundaries    │
         └──────────────────────────────────────────────────────────┘
                                    ↓
                         [ 1. Detection Engine ]
         ┌──────────────────────────────────────────────────────────┐
         │ • CPFDetector (Validação Matemática Módulo 11)           │
         │ • CNPJDetector (Validação Matemática Módulo 11)          │
         │ • CreditCardDetector (Algoritmo de Luhn Mod 10)          │
         │ • EmailDetector (Safe RFC Regex)                         │
         │ • PhoneDetector (BR DDD + E.164)                         │
         │ • APIKeyDetector (OpenAI sk-..., AWS AKIA..., GitHub)    │
         │ • JWTDetector (Tokens Base64url)                         │
         │ • CredentialsDetector (Bearer, Passwords, Basic Auth)    │
          │ • IPAddressDetector (IPv4 validado)                      │
          │ • PrivateKeyDetector (blocos PEM/OpenSSH de chave privada)│
         └──────────────────────────────────────────────────────────┘
                                    ↓
                  [ 2. Overlap & Conflict Resolution ]
                (Priorização por severidade e cobertura)
                                    ↓
                        [ 3. Risk Analyzer ]
          (Pontuação 0–100 e Classificação: LOW, MEDIUM, HIGH, CRITICAL)
                                    ↓
                     [ 4. Sanitization Engine ]
            (Substituição Canônica e Consistência Referencial)
                                    ↓
            [ Prompt Limpo no Chat da IA / HUD Flutuante ]
```

### Estrutura de Diretórios e Módulos

* `app/desktop_agent/` — **Agente em segundo plano para Windows:**
  * `service.py`: Motor autônomo `DesktopSanitizerService` com persistência local criptografada (`%APPDATA%\PromptSanitizer\rules.enc.json`), CRUD completo e controle de hashes SHA-256 anti-loop.
  * `win32_bridge.py`: Ponte nativa com a API Win32 (`user32.dll` e `kernel32.dll` via `ctypes`), gerenciando leitura/escrita Unicode no clipboard, detecção da janela de chat ativa (`GetForegroundWindow`), simulação de teclas (`Ctrl+A` ➔ `Ctrl+C` ➔ Sanitização ➔ `Ctrl+V`) e atalhos globais do sistema (`RegisterHotKey`).
  * `clipboard_monitor.py`: Daemon `ClipboardGuardMonitor` que monitora e higieniza a área de transferência em tempo real.
  * `ui_hud.py`: Interface gráfica nativa em tema Dark (`PromptSanitizerDesktopApp`), com HUD Flutuante *Always-on-Top*, ícone dinâmico na Bandeja do Windows (*System Tray*) e janela nativa de gerenciamento CRUD (`RulesManagerWindow`).
  * `autostart.py`: Registro do agente para iniciar com o Windows em `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` (sem precisar de administrador), em modo `--background`.
* `app/core/` — Resolução da pasta de dados do usuário (`paths.py`), criptografia autenticada AES-256-GCM e blind indexing HMAC-SHA256 (`crypto.py`) e logging com redaction (`logging.py`).
* `app/detection/` — Validadores matemáticos Módulo 11 e Luhn (`validators.py`), detectores especializados (`detectors/`) e motor de resolução de sobreposições (`engine.py`).
* `app/sanitization/` — Motor de substituição de PII (`engine.py`) e motor de passe único para regras customizadas (`custom_engine.py`).
* `app/risk/` — Avaliador vetorial de risco de privacidade de 0 a 100 (`analyzer.py`).
* `app/models/` — Modelos de regras confidenciais (`rules.py`) e níveis de severidade/relatório de risco (`response.py`).
* `run_desktop_agent.py` — Ponto de entrada: agente (HUD + bandeja), modo `--background`, início automático, auto-teste e sanitizador de linha de comando.

---

## 🖥️ 3. Como Instalar e Rodar o Agente (Windows)

O agente protege o **ChatGPT, Claude, Copilot, Gemini ou qualquer aplicativo no Windows** diretamente, sem abrir nenhum site ou servidor.

### Pré-requisitos
* Python 3.10 ou superior instalado no Windows.

### Instalação
Nada para instalar manualmente: o `start_agent_windows.bat` localiza o Python (`py`/`python`), cria o `.venv`, instala as dependências (somente quando `requirements.txt` muda) e inicia o agente. Instalação manual, se preferir:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

> Se o PowerShell bloquear o `Activate.ps1`, use `.venv\Scripts\python.exe` diretamente ou rode `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`.

### Opção A: Iniciar com Clique Duplo (Modo Recomendado no Windows)
Basta dar **dois cliques** no arquivo:
👉 **`start_agent_windows.bat`**

*(Ele cria o `.venv` e instala as dependências na primeira execução e inicia o agente em segundo plano via `pythonw`, apenas com o ícone de escudo na bandeja perto do relógio; o HUD flutuante abre com `Ctrl+Shift+H` ou pelo menu da bandeja. Use `start_agent_windows.bat --console` para ver logs e erros com o HUD visível.)*

### Opção B: Iniciar via Terminal
```powershell
python run_desktop_agent.py                 # HUD + ícone na bandeja
pythonw run_desktop_agent.py --background   # só a bandeja, sem console
```
Apenas uma instância roda por vez; abrir uma segunda exibe um aviso.

### Rodar em Segundo Plano Junto com o Windows
O agente precisa acessar o clipboard, a janela ativa e os atalhos globais da sessão do usuário. Por isso ele não é um *Windows Service* clássico (que roda isolado na Sessão 0 e não enxerga a área de trabalho): ele é registrado para iniciar **no logon do usuário**, direto na bandeja, sem janela e sem precisar de administrador. Escolha uma das formas:
* Clique com o botão direito no ícone da bandeja e marque **"Iniciar com o Windows"**.
* Ou execute `start_agent_windows.bat --install` (para remover: `start_agent_windows.bat --uninstall`).
* Ou pelo terminal: `python run_desktop_agent.py --enable-autostart` / `--disable-autostart`.

O registro aponta para o `pythonw.exe` do `.venv` (ou para o `PromptSanitizerAgent.exe`, se você usar o executável) com a flag `--background`. Se você mover a pasta do projeto ou o `.exe`, registre de novo.

### Opção C: Gerar um Executável `.exe` Único para Windows
Caso queira empacotar todo o projeto em um único arquivo executável (`dist\PromptSanitizerAgent.exe`) que roda sem precisar abrir terminal:
1. Dê dois cliques em **`build_windows_exe.bat`** (ou execute `.\\build_windows_exe.bat` no PowerShell).
2. O executável standalone será gerado em:
   ```text
   dist\PromptSanitizerAgent.exe
   ```
3. Para iniciar o executável com o Windows: `PromptSanitizerAgent.exe --enable-autostart`.

---

### ⚡ Como Usar o Agente em Tempo Real nos Chats de IA

Com o agente rodando no Windows, você tem **dois fluxos de proteção simultâneos**:

1. **Auto-Sanitização de Clipboard (`Ctrl+C` / `Ctrl+V` Automático):**
   * Quando o botão estiver **`🟢 LIGADO (ON)`**, qualquer texto copiado (`Ctrl+C`) de um documento, código ou planilha que contenha CPFs, cartões, e-mails, chaves de API ou termos confidenciais do seu CRUD é **automaticamente higienizado na memória do Windows**.
   * Ao dar `Ctrl+V` no ChatGPT/Claude, o texto já é colado limpo e o HUD exibe o alerta de proteção e o escore de risco.

2. **Limpeza In-Place da Caixa de Mensagem do Chat (`Ctrl + Shift + S`):**
   * Digite seu prompt livremente direto na caixa de mensagem do **ChatGPT, Claude, Copilot, Gemini ou Cursor**.
   * Antes de apertar `Enter`, pressione **`Ctrl + Shift + S`** (ou clique no botão **"⚡ Limpar Campo do Chat Ativo"** no HUD flutuante).
   * O Agente captura o texto do campo ativo, substitui todos os dados sensíveis pelas respectivas tags e cola o texto limpo de volta no mesmo lugar instantaneamente!

#### ⌨️ Atalhos Globais do Windows
| Atalho Global | Ação Executada |
| :--- | :--- |
| **`Ctrl + Shift + S`** | Higieniza imediatamente o texto já digitado no campo do chat de IA ativo |
| **`Ctrl + Shift + E`** | Liga / Pausa (`ON` / `OFF`) a proteção automática em tempo real |
| **`Ctrl + Shift + H`** | Mostra / Oculta o mini-HUD flutuante na tela |

#### 🔐 Gerenciando Termos Confidenciais (CRUD Desktop)
* Clique no botão **"🔐 Termos Confidenciais (CRUD)"** no HUD (ou pelo ícone da bandeja do sistema).
* Cadastre termos sensíveis (ex: `CESAR` ➔ `[COMPANY_SENSITIVE]`, `Projeto Vibe` ➔ `[PROJETO_SECRETO]`), escolha se diferencia maiúsculas/minúsculas (*Case-Sensitive*) e se exige palavra inteira.
* Os termos ficam salvos localmente de forma criptografada com **AES-256-GCM** em `%APPDATA%\PromptSanitizer\rules.enc.json`, exibindo apenas prévias mascaradas (`C***R`).

---

## 🧪 4. Execução dos Testes Automatizados

A suíte automatizada cobre os validadores matemáticos (CPF, CNPJ, Luhn), a criptografia AES-256-GCM, o blind indexing HMAC-SHA256, o motor regex de passe único, a proteção anti-ReDoS, o filtro de logs e o pipeline do agente (clipboard, serviço de regras e início automático):

```bash
# Instalar dependências de desenvolvimento
pip install -r requirements-dev.txt

# Executar toda a suíte de testes
pytest -v

# Executar o auto-teste rápido do agente no terminal
python run_desktop_agent.py --self-test
```

### 🧰 Sanitizador de Linha de Comando (Windows, Linux e macOS)
Sem interface gráfica, ideal para scripts, hooks de pre-commit ou pipes:
```bash
python run_desktop_agent.py --sanitize "CPF 123.456.789-09, IP 10.0.0.5"
cat prompt.txt | python run_desktop_agent.py --sanitize - --json
```
O código de saída é `10` quando dados sensíveis foram encontrados e `0` quando o texto está limpo.

---

## 🔒 5. Garantias de Privacidade & Segurança

1. **Zero Persistência de Texto Claro (AES-256-GCM + Blind Index):**
   * Termos confidenciais cadastrados pelos usuários nunca são gravados em texto claro em arquivos ou logs.
   * Cada termo é cifrado com **AES-256-GCM** usando um nonce aleatório único de 96 bits (`os.urandom(12)`) e verificado contra duplicidade via **HMAC-SHA256 Blind Index**.
2. **Processamento Estritamente Local:**
   * Nenhuma informação é transmitida para servidores externos durante a análise e higienização.
3. **Validação Matemática vs. Falsos Positivos:**
   * CPFs e CNPJs são validados pelo cálculo dos dígitos verificadores (**Módulo 11**).
   * Cartões de crédito passam obrigatoriamente pelo **Algoritmo de Luhn (Módulo 10)**.
4. **Imunidade contra ReDoS e Colisões em Cascata:**
   * Termos customizados passam por `re.escape()` e são compilados em uma união regex ordenada decrescentemente por tamanho, executada em **passe único $O(N)$**, impedindo substituições em cascata ou *catastrophic backtracking*.
5. **Logs Redigidos (`PrivacyRedactingFilter`):**
   * Prompts brutos e valores sensíveis jamais são registrados em logs ou exibidos sem máscara.

---

## 🔑 6. Chaves de Criptografia

Sem configuração, cada instalação gera chaves **aleatórias** (`.aes.key` e `.blind.key`, permissão `0600`) em `%APPDATA%\PromptSanitizer` (Windows) ou `~/.config/prompt-sanitizer` (Linux/macOS). Cofres já existentes continuam legíveis com a chave legada até serem recriados. Para usar chaves próprias, defina `PROMPT_SANITIZER_ENCRYPTION_KEY` e `PROMPT_SANITIZER_BLIND_INDEX_KEY` (Base64 de 32 bytes) como variáveis de ambiente ou em um arquivo `.env` na pasta de onde o agente é iniciado. Use `PROMPT_SANITIZER_DATA_DIR` para mudar a pasta de dados. **Faça backup da pasta**: sem as chaves, as regras não podem ser decifradas. Um `rules.enc.json` ilegível é preservado como `rules.enc.corrupt`.

---

## 📄 Licença

Desenvolvido para fins educacionais, conformidade com privacidade (LGPD/GDPR) e segurança da informação em ambientes de IA Generativa.

document.addEventListener("DOMContentLoaded", () => {
    const promptInput = document.getElementById("prompt-input");
    const charCount = document.getElementById("char-count");
    const btnAnalyze = document.getElementById("btn-analyze");
    const btnClear = document.getElementById("btn-clear");
    const loadingSpinner = document.getElementById("loading-spinner");
    const resultsCard = document.getElementById("results-card");
    const statusIcon = document.getElementById("status-icon");
    const statusTitle = document.getElementById("status-title");
    const statusSubtitle = document.getElementById("status-subtitle");
    const riskBadge = document.getElementById("risk-badge");
    const riskReasonsList = document.getElementById("risk-reasons-list");
    const detectionCount = document.getElementById("detection-count");
    const detectionsGrid = document.getElementById("detections-grid");
    const sanitizedOutput = document.getElementById("sanitized-output");
    const btnCopy = document.getElementById("btn-copy");
    const btnEditToggle = document.getElementById("btn-edit-toggle");
    const copyFeedback = document.getElementById("copy-feedback");

    // Presets
    const presets = {
        "preset-cpf-email": "Analise este cliente: João da Silva, CPF 123.456.789-09, email joao.silva@empresa.com.br, tel (11) 98765-4321, e me diga se ele pode contratar o serviço.",
        "preset-secrets": 'Aqui está o script de conexão:\nimport os\nOPENAI_KEY = "sk-proj-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"\nDB_PASS = "SuperSecretPass123!"\nBearerToken = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozGzT_WwtqP_ErQDhbP_Wtc8qEkWk7_8b5wB2uF01g"',
        "preset-card": "Por favor processe o estorno do pagamento no cartão Visa 4532 1234 5678 9014 e CPF 123.456.789-09.",
        "preset-clean": "Crie um algoritmo em Python para calcular o Fibonacci de um número N de forma recursiva e com memoização.",
    };

    // Update character count
    const updateCharCount = () => {
        const count = promptInput.value.length;
        charCount.textContent = count.toLocaleString("pt-BR");
    };

    promptInput.addEventListener("input", updateCharCount);

    // Preset handlers
    Object.keys(presets).forEach((presetId) => {
        const btn = document.getElementById(presetId);
        if (btn) {
            btn.addEventListener("click", () => {
                promptInput.value = presets[presetId];
                updateCharCount();
                resultsCard.classList.add("hidden");
                promptInput.focus();
            });
        }
    });

    // Clear
    btnClear.addEventListener("click", () => {
        promptInput.value = "";
        updateCharCount();
        resultsCard.classList.add("hidden");
        promptInput.focus();
    });

    // Analyze action
    btnAnalyze.addEventListener("click", async () => {
        const prompt = promptInput.value.trim();
        if (!prompt) {
            alert("Por favor, digite ou cole um prompt antes de analisar.");
            promptInput.focus();
            return;
        }

        // UI state
        btnAnalyze.disabled = true;
        loadingSpinner.classList.remove("hidden");
        resultsCard.classList.add("hidden");
        copyFeedback.classList.add("hidden");

        try {
            const response = await fetch("/api/v1/analyze", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                body: JSON.stringify({ prompt }),
            });

            if (!response.ok) {
                const errData = await response.json().catch(() => ({}));
                throw new Error(errData.detail || "Falha ao processar análise do prompt.");
            }

            const data = await response.json();
            renderResults(data);
        } catch (err) {
            alert(`Erro: ${err.message}`);
        } finally {
            btnAnalyze.disabled = false;
            loadingSpinner.classList.add("hidden");
        }
    });

    // Render results
    function renderResults(data) {
        resultsCard.classList.remove("hidden");

        // Risk Level Badge styling
        const level = data.risk_level.toLowerCase();
        riskBadge.className = `risk-badge risk-${level}`;
        riskBadge.textContent = data.risk_level;

        // Status Header
        if (data.has_sensitive_data) {
            statusIcon.textContent = "⚠️";
            statusTitle.textContent = "Informações sensíveis detectadas no prompt";
            statusSubtitle.textContent = "Revise a sanitização antes de enviar este conteúdo para qualquer ferramenta de IA.";
        } else {
            statusIcon.textContent = "✓";
            statusTitle.textContent = "Nenhuma informação sensível identificada";
            statusSubtitle.textContent = "O prompt não apresentou padrões conhecidos de identificadores formais ou credenciais.";
        }

        // Reasons
        riskReasonsList.innerHTML = "";
        const reasons = data.risk_report?.reasons || [];
        if (reasons.length === 0) {
            const li = document.createElement("li");
            li.textContent = "Nenhum fator de risco identificado.";
            riskReasonsList.appendChild(li);
        } else {
            reasons.forEach((r) => {
                const li = document.createElement("li");
                li.textContent = r;
                riskReasonsList.appendChild(li);
            });
        }

        // Detections Grid
        detectionCount.textContent = data.total_detections;
        detectionsGrid.innerHTML = "";

        if (data.detections.length === 0) {
            const emptyMsg = document.createElement("p");
            emptyMsg.className = "text-muted";
            emptyMsg.textContent = "Nenhuma entidade individual sinalizada.";
            detectionsGrid.appendChild(emptyMsg);
        } else {
            data.detections.forEach((item) => {
                const card = document.createElement("div");
                card.className = "detection-card";

                const header = document.createElement("div");
                header.className = "detection-card-header";

                const typeSpan = document.createElement("span");
                typeSpan.className = "detection-type";
                typeSpan.textContent = item.type;

                const sevSpan = document.createElement("span");
                sevSpan.className = `detection-severity risk-${item.severity.toLowerCase()}`;
                sevSpan.textContent = item.severity;

                header.appendChild(typeSpan);
                header.appendChild(sevSpan);

                const maskedSpan = document.createElement("span");
                maskedSpan.className = "detection-masked";
                maskedSpan.textContent = item.masked_value;

                const stratSpan = document.createElement("span");
                stratSpan.className = "detection-strategy";
                stratSpan.textContent = `Estratégia: ${item.strategy} (${Math.round(item.confidence * 100)}% conf.)`;

                card.appendChild(header);
                card.appendChild(maskedSpan);
                card.appendChild(stratSpan);
                detectionsGrid.appendChild(card);
            });
        }

        // Sanitized prompt
        sanitizedOutput.value = data.sanitized_prompt;
        sanitizedOutput.readOnly = true;
        btnEditToggle.textContent = "✏️ Editar Sanitização";

        // Smooth scroll to results
        resultsCard.scrollIntoView({ behavior: "smooth", block: "nearest" });
    }

    // Toggle edit mode
    btnEditToggle.addEventListener("click", () => {
        if (sanitizedOutput.readOnly) {
            sanitizedOutput.readOnly = false;
            sanitizedOutput.focus();
            btnEditToggle.textContent = "🔒 Concluir Edição";
        } else {
            sanitizedOutput.readOnly = true;
            btnEditToggle.textContent = "✏️ Editar Sanitização";
        }
    });

    // Copy to clipboard
    btnCopy.addEventListener("click", async () => {
        const text = sanitizedOutput.value;
        if (!text) return;

        try {
            await navigator.clipboard.writeText(text);
            copyFeedback.classList.remove("hidden");
            setTimeout(() => {
                copyFeedback.classList.add("hidden");
            }, 3000);
        } catch (err) {
            // Fallback
            sanitizedOutput.select();
            document.execCommand("copy");
            copyFeedback.classList.remove("hidden");
            setTimeout(() => {
                copyFeedback.classList.add("hidden");
            }, 3000);
        }
    });
});


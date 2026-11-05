(function () {
    "use strict";

    const $ = (id) => document.getElementById(id);
    const el = {
        input: $("prompt-input"), count: $("char-count"), analyze: $("btn-analyze"), clear: $("btn-clear"),
        preset: $("preset-select"), empty: $("result-empty"), loading: $("loading-spinner"), results: $("results-card"),
        status: $("status-line"), risk: $("risk-badge"), reasons: $("risk-reasons-list"), reasonsBox: $("risk-breakdown"),
        detCount: $("detection-count"), detList: $("detections-grid"), detBox: $("detections-section"),
        output: $("sanitized-output"), copy: $("btn-copy"), edit: $("btn-edit-toggle"),
        toggleRule: $("btn-toggle-new-rule"), ruleForm: $("new-rule-form"), cancelRule: $("btn-cancel-rule"),
        term: $("rule-term"), tag: $("rule-tag"), whole: $("rule-whole-word"), cs: $("rule-case-sensitive"),
        ruleErr: $("rule-form-feedback"), rulesEmpty: $("rules-empty-state"), rulesWrap: $("rules-table-wrapper"),
        rulesBody: $("rules-table-body"), toast: $("toast"), theme: $("btn-theme"),
        logout: $("btn-logout"), user: $("user-label"),
    };

    const PRESETS = {
        custom: "Confirme os dados do gestor Carlos Menezes, CPF 123.456.789-09, e-mail carlos@cesar.school.",
        "cpf-email": "Cliente: João da Silva, CPF 123.456.789-09, e-mail joao.silva@empresa.com.br, telefone (11) 98765-4321. Ele pode contratar o serviço?",
        secrets: 'import os\nOPENAI_KEY = "sk-proj-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"\nDB_PASS = "SuperSecretPass123!"\nAuthorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozGzT_WwtqP_ErQDhbP_Wtc8qEkWk7_8b5wB2uF01g',
        card: "Estorne o pagamento no cartão 4532 1234 5678 9014 do CPF 123.456.789-09.",
        infra: "O banco em 10.20.30.40 recusa conexões. Chave usada:\n-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n-----END OPENSSH PRIVATE KEY-----",
        clean: "Escreva uma função em Python que calcula Fibonacci com memoização.",
    };

    const RISK_LABEL = { LOW: "Baixo", MEDIUM: "Médio", HIGH: "Alto", CRITICAL: "Crítico" };
    let csrfToken = "";
    let authEnabled = false;
    let supabaseClient = null;
    let supabaseBearerToken = null;

    // ---------- helpers ----------
    let toastTimer;
    function notify(message, isError) {
        el.toast.textContent = message;
        el.toast.classList.toggle("error", !!isError);
        el.toast.classList.remove("hidden");
        clearTimeout(toastTimer);
        toastTimer = setTimeout(() => el.toast.classList.add("hidden"), 3500);
    }

    async function api(path, options) {
        const opts = Object.assign({ credentials: "same-origin" }, options);
        opts.headers = Object.assign({ Accept: "application/json" }, opts.headers);
        if (opts.body) opts.headers["Content-Type"] = "application/json";
        if (supabaseBearerToken) {
            opts.headers["Authorization"] = "Bearer " + supabaseBearerToken;
        } else if (csrfToken) {
            opts.headers["X-CSRF-Token"] = csrfToken;
        }
        const res = await fetch(path, opts);
        if (res.status === 401 && authEnabled) {
            if (supabaseClient) await supabaseClient.auth.signOut();
            window.location.href = "/login";
            throw new Error("Sessão expirada.");
        }
        if (!res.ok) {
            const data = await res.json().catch(() => ({}));
            const detail = Array.isArray(data.detail) ? "Dados inválidos. Revise os campos." : data.detail;
            throw new Error(detail || "Não foi possível concluir a operação.");
        }
        return res.status === 204 ? null : res.json();
    }

    function icon(name) {
        const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
        svg.setAttribute("class", "icon");
        const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
        use.setAttribute("href", "#i-" + name);
        svg.appendChild(use);
        return svg;
    }

    // ---------- theme ----------
    el.theme.addEventListener("click", () => {
        const root = document.documentElement;
        const current = root.getAttribute("data-theme") ||
            (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
        const next = current === "dark" ? "light" : "dark";
        root.setAttribute("data-theme", next);
        try { localStorage.setItem("ps-theme", next); } catch (e) { /* ignore */ }
    });

    // ---------- input ----------
    const updateCount = () => { el.count.textContent = el.input.value.length.toLocaleString("pt-BR"); };
    el.input.addEventListener("input", updateCount);
    el.input.addEventListener("keydown", (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key === "Enter") { e.preventDefault(); el.analyze.click(); }
    });

    function resetResults() {
        el.results.classList.add("hidden");
        el.risk.classList.add("hidden");
        el.empty.classList.remove("hidden");
    }

    el.preset.addEventListener("change", () => {
        if (PRESETS[el.preset.value]) {
            el.input.value = PRESETS[el.preset.value];
            updateCount();
            resetResults();
            el.input.focus();
        }
        el.preset.value = "";
    });

    el.clear.addEventListener("click", () => {
        el.input.value = "";
        updateCount();
        resetResults();
        el.input.focus();
    });

    // ---------- analyze ----------
    el.analyze.addEventListener("click", async () => {
        const prompt = el.input.value.trim();
        if (!prompt) {
            notify("Digite ou cole um texto para analisar.", true);
            el.input.focus();
            return;
        }
        el.analyze.disabled = true;
        el.empty.classList.add("hidden");
        el.results.classList.add("hidden");
        el.loading.classList.remove("hidden");
        try {
            render(await api("/api/v1/analyze", { method: "POST", body: JSON.stringify({ prompt }) }));
        } catch (err) {
            el.empty.classList.remove("hidden");
            notify(err.message, true);
        } finally {
            el.analyze.disabled = false;
            el.loading.classList.add("hidden");
        }
    });

    function render(data) {
        el.results.classList.remove("hidden");
        const level = data.risk_level;
        el.risk.className = "risk risk-" + level.toLowerCase();
        el.risk.textContent = "Risco " + (RISK_LABEL[level] || level).toLowerCase();

        el.status.textContent = data.has_sensitive_data
            ? data.total_detections + (data.total_detections === 1 ? " item sensível foi substituído." : " itens sensíveis foram substituídos.")
            : "Nenhum dado sensível encontrado. O texto está igual ao original.";

        el.reasons.replaceChildren();
        (data.risk_report.reasons || []).forEach((r) => {
            const li = document.createElement("li");
            li.textContent = r;
            el.reasons.appendChild(li);
        });

        el.detCount.textContent = data.total_detections;
        el.detList.replaceChildren();
        el.detBox.classList.toggle("hidden", data.detections.length === 0);
        data.detections.forEach((d) => {
            const li = document.createElement("li");
            const type = document.createElement("span");
            type.className = "detect-type";
            type.textContent = d.type.replace(/_/g, " ").toLowerCase();
            const masked = document.createElement("span");
            masked.className = "detect-masked";
            masked.textContent = d.masked_value;
            const sev = document.createElement("span");
            sev.className = "risk risk-" + d.severity.toLowerCase();
            sev.textContent = RISK_LABEL[d.severity] || d.severity;
            li.append(type, masked, sev);
            el.detList.appendChild(li);
        });

        el.output.value = data.sanitized_prompt;
        el.output.readOnly = true;
        setEditLabel(false);
        el.results.scrollIntoView({ behavior: "smooth", block: "nearest" });
    }

    function setEditLabel(editing) {
        el.edit.replaceChildren(icon("edit"), document.createTextNode(editing ? " Concluir edição" : " Editar"));
    }
    el.edit.addEventListener("click", () => {
        el.output.readOnly = !el.output.readOnly;
        setEditLabel(!el.output.readOnly);
        if (!el.output.readOnly) el.output.focus();
    });

    el.copy.addEventListener("click", async () => {
        if (!el.output.value) return;
        try {
            await navigator.clipboard.writeText(el.output.value);
        } catch (e) {
            el.output.select();
            document.execCommand("copy");
        }
        notify("Texto seguro copiado.");
    });

    // ---------- rules ----------
    function renderRules(rules) {
        el.rulesBody.replaceChildren();
        const has = rules && rules.length > 0;
        el.rulesEmpty.classList.toggle("hidden", has);
        el.rulesWrap.classList.toggle("hidden", !has);
        if (!has) return;

        rules.forEach((rule) => {
            const tr = document.createElement("tr");
            const tdTerm = document.createElement("td");
            tdTerm.className = "mono";
            tdTerm.textContent = rule.masked_term;
            const tdTag = document.createElement("td");
            tdTag.className = "mono";
            tdTag.textContent = rule.replacement_tag;
            const tdMode = document.createElement("td");
            [rule.match_whole_word ? "Palavra inteira" : "Parcial",
             rule.case_sensitive ? "Diferencia maiúsculas" : "Ignora maiúsculas"].forEach((t) => {
                const s = document.createElement("span");
                s.className = "tag";
                s.textContent = t;
                tdMode.appendChild(s);
            });
            const tdAct = document.createElement("td");
            tdAct.appendChild(deleteButton(rule.id));
            tr.append(tdTerm, tdTag, tdMode, tdAct);
            el.rulesBody.appendChild(tr);
        });
    }

    // Two-step inline confirmation instead of a blocking confirm() dialog
    function deleteButton(ruleId) {
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "btn btn-sm btn-danger";
        const reset = () => {
            btn.classList.remove("confirming");
            btn.replaceChildren(icon("trash"), document.createTextNode(" Excluir"));
        };
        reset();
        let timer;
        btn.addEventListener("click", async () => {
            if (!btn.classList.contains("confirming")) {
                btn.classList.add("confirming");
                btn.textContent = "Confirmar exclusão";
                timer = setTimeout(reset, 3500);
                return;
            }
            clearTimeout(timer);
            try {
                await api("/api/v1/rules/" + encodeURIComponent(ruleId), { method: "DELETE" });
                notify("Termo removido.");
                loadRules();
            } catch (err) {
                notify(err.message, true);
                reset();
            }
        });
        return btn;
    }

    async function loadRules() {
        try { renderRules(await api("/api/v1/rules")); }
        catch (err) { if (!/Sessão/.test(err.message)) notify(err.message, true); }
    }

    el.toggleRule.addEventListener("click", () => {
        el.ruleForm.classList.toggle("hidden");
        if (!el.ruleForm.classList.contains("hidden")) el.term.focus();
    });
    el.cancelRule.addEventListener("click", () => {
        el.ruleForm.classList.add("hidden");
        el.ruleForm.reset();
        el.ruleErr.classList.add("hidden");
    });
    el.ruleForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        el.ruleErr.classList.add("hidden");
        const term = el.term.value.trim();
        const tag = el.tag.value.trim();
        if (term.length < 2 || !tag) {
            el.ruleErr.textContent = "Informe o termo (mínimo 2 caracteres) e o marcador.";
            el.ruleErr.classList.remove("hidden");
            return;
        }
        try {
            await api("/api/v1/rules", {
                method: "POST",
                body: JSON.stringify({
                    term, replacement_tag: tag,
                    match_whole_word: el.whole.checked, case_sensitive: el.cs.checked,
                }),
            });
            el.ruleForm.reset();
            el.whole.checked = true;
            el.ruleForm.classList.add("hidden");
            notify("Termo salvo.");
            loadRules();
        } catch (err) {
            el.ruleErr.textContent = err.message;
            el.ruleErr.classList.remove("hidden");
        }
    });

    // ---------- session ----------
    el.logout.addEventListener("click", async () => {
        if (supabaseClient) {
            try { await supabaseClient.auth.signOut(); } catch (e) { /* ignore */ }
        }
        try { await api("/api/v1/auth/logout", { method: "POST" }); } catch (e) { /* ignore */ }
        window.location.href = "/login";
    });

    async function init() {
        try {
            const cfg = await fetch("/api/v1/auth/config").then((r) => r.json()).catch(() => ({}));
            authEnabled = !!cfg.auth_enabled;

            // 1. Check Supabase (Google OAuth) Session
            if (cfg.supabase_enabled && window.supabase) {
                supabaseClient = window.supabase.createClient(cfg.supabase_url, cfg.supabase_anon_key);
                const { data: { session } } = await supabaseClient.auth.getSession();
                if (session) {
                    supabaseBearerToken = session.access_token;
                    const email = session.user?.email || "Google User";
                    el.user.textContent = email;
                    el.user.classList.remove("hidden");
                    el.logout.classList.remove("hidden");

                    supabaseClient.auth.onAuthStateChange((_event, newSession) => {
                        if (newSession) {
                            supabaseBearerToken = newSession.access_token;
                        } else {
                            window.location.href = "/login";
                        }
                    });
                    loadRules();
                    return;
                }
            }

            // 2. Fallback to standard cookie session
            const me = await fetch("/api/v1/auth/me", { credentials: "same-origin" }).then((r) => r.json());
            if (authEnabled) {
                if (!me.authenticated) { window.location.href = "/login"; return; }
                csrfToken = me.csrf_token;
                el.user.textContent = me.username;
                el.user.classList.remove("hidden");
                el.logout.classList.remove("hidden");
            }
        } catch (e) {
            notify("Não foi possível verificar a sessão.", true);
        }
        loadRules();
    }
    init();
})();

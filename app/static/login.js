(function () {
    "use strict";
    const form = document.getElementById("login-form");
    const errorBox = document.getElementById("login-error");
    const button = document.getElementById("btn-login");
    const noteEl = document.getElementById("login-restriction-note");

    let supabaseClient = null;
    let allowedDomains = ["cesar.school"];

    function isDomainAllowed(email) {
        if (!email || !allowedDomains || allowedDomains.length === 0) return true;
        const lower = email.trim().toLowerCase();
        return allowedDomains.some((d) => lower.endsWith("@" + d.replace(/^@/, "")));
    }

    async function checkAuthStatus() {
        try {
            const cfg = await fetch("/api/v1/auth/config").then((r) => r.json());
            if (cfg.allowed_domains && cfg.allowed_domains.length > 0) {
                allowedDomains = cfg.allowed_domains;
                if (noteEl) {
                    const domainList = allowedDomains.map((d) => "@" + d.replace(/^@/, "")).join(", ");
                    noteEl.innerHTML = `Acesso exclusivo para contas <strong>${domainList}</strong>.`;
                }
            }

            if (cfg.supabase_enabled && window.supabase) {
                supabaseClient = window.supabase.createClient(cfg.supabase_url, cfg.supabase_anon_key);
                const { data: { session } } = await supabaseClient.auth.getSession();
                if (session) {
                    const email = session.user?.email || "";
                    if (!isDomainAllowed(email)) {
                        await supabaseClient.auth.signOut();
                        errorBox.textContent = `Acesso negado: a conta ${email} não pertence ao domínio @${allowedDomains[0]}.`;
                        errorBox.classList.remove("hidden");
                        return;
                    }
                    window.location.replace("/");
                    return;
                }
            }

            const me = await fetch("/api/v1/auth/me", { credentials: "same-origin" }).then((r) => r.json());
            if (!me.auth_enabled || me.authenticated) {
                window.location.replace("/");
            }
        } catch (e) {
            /* ignore network errors on init */
        }
    }

    form.addEventListener("submit", async (e) => {
        e.preventDefault();
        errorBox.classList.add("hidden");
        const username = form.username.value.trim();
        const password = form.password.value;
        if (!username || !password) {
            errorBox.textContent = "Informe seu e-mail e senha.";
            errorBox.classList.remove("hidden");
            return;
        }

        // Domain validation for emails
        if (username.includes("@") && !isDomainAllowed(username)) {
            errorBox.textContent = `Acesso negado: utilize uma conta @${allowedDomains[0] || "cesar.school"}.`;
            errorBox.classList.remove("hidden");
            return;
        }

        button.disabled = true;

        // 1. Try Supabase Auth (Email + Password) if configured
        if (supabaseClient) {
            try {
                const { data, error } = await supabaseClient.auth.signInWithPassword({
                    email: username,
                    password: password,
                });
                if (!error && data?.session) {
                    const email = data.session.user?.email || username;
                    if (!isDomainAllowed(email)) {
                        await supabaseClient.auth.signOut();
                        errorBox.textContent = `Acesso negado: a conta ${email} não pertence ao domínio @${allowedDomains[0]}.`;
                        errorBox.classList.remove("hidden");
                        button.disabled = false;
                        return;
                    }
                    window.location.replace("/");
                    return;
                }
            } catch (sbErr) {
                // Fallthrough to local auth API
            }
        }

        // 2. Try Standard Backend Auth (FastAPI / Database)
        try {
            const res = await fetch("/api/v1/auth/login", {
                method: "POST",
                credentials: "same-origin",
                headers: { "Content-Type": "application/json", Accept: "application/json" },
                body: JSON.stringify({ username, password }),
            });
            if (res.ok) { window.location.replace("/"); return; }
            const data = await res.json().catch(() => ({}));
            errorBox.textContent = typeof data.detail === "string" ? data.detail : "E-mail ou senha incorretos.";
        } catch (err) {
            errorBox.textContent = "Sem conexão com o servidor.";
        }

        form.password.value = "";
        errorBox.classList.remove("hidden");
        button.disabled = false;
    });

    checkAuthStatus();
})();

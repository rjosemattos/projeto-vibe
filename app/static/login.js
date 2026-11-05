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

    async function verifyTokenWithBackend(accessToken) {
        try {
            const res = await fetch("/api/v1/auth/me", {
                credentials: "same-origin",
                headers: {
                    Accept: "application/json",
                    Authorization: "Bearer " + accessToken,
                },
            });
            if (!res.ok) return false;
            const me = await res.json();
            return !!me.authenticated;
        } catch (e) {
            return false;
        }
    }

    async function clearSupabaseSession() {
        if (!supabaseClient) return;
        try {
            await supabaseClient.auth.signOut({ scope: "local" });
        } catch (e) {
            try { await supabaseClient.auth.signOut(); } catch (err) { /* ignore */ }
        }
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
                if (session && session.access_token) {
                    const email = session.user?.email || "";
                    if (!isDomainAllowed(email)) {
                        await clearSupabaseSession();
                        errorBox.textContent = `Acesso negado: a conta ${email} não pertence ao domínio @${allowedDomains[0]}.`;
                        errorBox.classList.remove("hidden");
                        return;
                    }
                    const validOnBackend = await verifyTokenWithBackend(session.access_token);
                    if (validOnBackend) {
                        window.location.replace("/");
                        return;
                    }
                    await clearSupabaseSession();
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
        let supabaseAuthError = null;

        // 1. Try Supabase Auth (Email + Password) if configured
        if (supabaseClient) {
            try {
                const { data, error } = await supabaseClient.auth.signInWithPassword({
                    email: username,
                    password: password,
                });
                if (error) {
                    supabaseAuthError = error.message;
                } else if (data?.session) {
                    const email = data.session.user?.email || username;
                    if (!isDomainAllowed(email)) {
                        await clearSupabaseSession();
                        errorBox.textContent = `Acesso negado: a conta ${email} não pertence ao domínio @${allowedDomains[0]}.`;
                        errorBox.classList.remove("hidden");
                        button.disabled = false;
                        return;
                    }
                    const validOnBackend = await verifyTokenWithBackend(data.session.access_token);
                    if (validOnBackend) {
                        window.location.replace("/");
                        return;
                    }
                    await clearSupabaseSession();
                    errorBox.textContent = "Não foi possível validar o token de sessão no servidor.";
                    errorBox.classList.remove("hidden");
                    button.disabled = false;
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
            if (supabaseAuthError && /Email not confirmed/i.test(supabaseAuthError)) {
                errorBox.textContent = "Confirme seu e-mail no link enviado pelo Supabase antes de entrar.";
            } else {
                errorBox.textContent = typeof data.detail === "string" ? data.detail : "E-mail ou senha incorretos.";
            }
        } catch (err) {
            errorBox.textContent = "Sem conexão com o servidor.";
        }

        form.password.value = "";
        errorBox.classList.remove("hidden");
        button.disabled = false;
    });

    checkAuthStatus();
})();

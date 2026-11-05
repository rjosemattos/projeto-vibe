#!/usr/bin/env bash
# Prompt Sanitizer — instala (se necessário) e inicia o servidor web local no Linux/macOS.
# Uso: ./start_server.sh [--port 9000] [--no-browser]
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

PY="${PYTHON:-python3}"
if ! command -v "$PY" >/dev/null 2>&1; then
    echo "[ERRO] python3 não encontrado. Instale Python 3.10+." >&2
    exit 1
fi
if ! "$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)'; then
    echo "[ERRO] Python 3.10+ é necessário (encontrado: $("$PY" --version))." >&2
    exit 1
fi

if [ ! -x .venv/bin/python ]; then
    echo "[+] Criando ambiente virtual .venv ..."
    "$PY" -m venv .venv || {
        echo "[ERRO] Falha ao criar venv. No Debian/Ubuntu: sudo apt install python3-venv" >&2
        exit 1
    }
fi

STAMP=.venv/.requirements.stamp
if ! cmp -s requirements.txt "$STAMP" 2>/dev/null; then
    echo "[+] Instalando dependências ..."
    .venv/bin/python -m pip install --disable-pip-version-check -r requirements.txt
    cp requirements.txt "$STAMP"
fi

exec .venv/bin/python run_server.py "$@"

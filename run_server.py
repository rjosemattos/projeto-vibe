#!/usr/bin/env python3
"""Launcher for the Prompt Sanitizer local web server (FastAPI + web UI).

Usage:
    python run_server.py                 # starts on PROMPT_SANITIZER_HOST:PORT and opens the browser
    python run_server.py --port 9000 --no-browser
"""

import argparse
import socket
import sys
import threading
import webbrowser

from app.core.config import settings


def _port_is_free(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
            return True
        except OSError:
            return False


def main() -> int:
    parser = argparse.ArgumentParser(description="Prompt Sanitizer — servidor web local")
    parser.add_argument("--host", default=settings.HOST)
    parser.add_argument("--port", type=int, default=settings.PORT)
    parser.add_argument("--no-browser", action="store_true", help="Não abre o navegador automaticamente.")
    parser.add_argument("--reload", action="store_true", help="Recarrega automaticamente (desenvolvimento).")
    args = parser.parse_args()

    try:
        import uvicorn
    except ImportError:
        print("[ERRO] uvicorn não instalado. Execute: pip install -r requirements.txt", file=sys.stderr)
        return 1

    port = args.port
    if not _port_is_free(args.host, port):
        for candidate in range(port + 1, port + 20):
            if _port_is_free(args.host, candidate):
                print(f"[!] Porta {port} ocupada; usando {candidate}.")
                port = candidate
                break
        else:
            print(f"[ERRO] Nenhuma porta livre encontrada a partir de {port}.", file=sys.stderr)
            return 1

    url = f"http://{'localhost' if args.host in ('127.0.0.1', '0.0.0.0') else args.host}:{port}"
    print(f"[+] Prompt Sanitizer em {url}  (Ctrl+C para encerrar)")
    if not args.no_browser:
        threading.Timer(1.2, lambda: webbrowser.open(url)).start()

    uvicorn.run("app.main:app", host=args.host, port=port, reload=args.reload, log_level="info")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""User administration for the hosted Prompt Sanitizer (no public sign-up by design).

Usage:
    python manage_users.py create alice [--admin]
    python manage_users.py passwd alice
    python manage_users.py disable alice | enable alice
    python manage_users.py list

Passwords are always prompted (never passed as arguments, to avoid shell history leaks).
Set PROMPT_SANITIZER_DB_PATH to target a specific database.
"""

import argparse
import getpass
import sys

from app.auth import service
from app.auth.store import get_store


def _ask_password() -> str:
    pw = getpass.getpass("Senha: ")
    if pw != getpass.getpass("Confirme a senha: "):
        raise ValueError("As senhas não coincidem.")
    return pw


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("create")
    c.add_argument("username")
    c.add_argument("--admin", action="store_true")
    for name in ("passwd", "disable", "enable"):
        sub.add_parser(name).add_argument("username")
    sub.add_parser("list")
    args = parser.parse_args()

    store = get_store()
    try:
        if args.cmd == "create":
            service.create_user(args.username, _ask_password(), args.admin)
            print(f"[+] Usuário '{args.username}' criado.")
        elif args.cmd == "passwd":
            service.set_password(args.username, _ask_password())
            print("[+] Senha atualizada; todas as sessões foram encerradas.")
        elif args.cmd in ("disable", "enable"):
            flag = 1 if args.cmd == "disable" else 0
            cur = store.execute("UPDATE users SET disabled = ? WHERE username = ?", (flag, args.username))
            if cur.rowcount == 0:
                raise ValueError("Usuário não encontrado.")
            if flag:
                store.execute("DELETE FROM sessions WHERE user_id = (SELECT id FROM users WHERE username = ?)", (args.username,))
            print(f"[+] Usuário '{args.username}' {'desativado' if flag else 'ativado'}.")
        else:
            for r in store.query("SELECT username, is_admin, disabled, created_at FROM users ORDER BY username"):
                flags = ("admin " if r["is_admin"] else "") + ("desativado" if r["disabled"] else "")
                print(f"{r['username']:<32} {flags:<18} {r['created_at']}")
    except ValueError as exc:
        print(f"[ERRO] {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

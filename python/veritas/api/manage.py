"""Administrative commands.

    python -m veritas.api.manage create-admin --id admin --name "Admin"   (password read from VERITAS_ADMIN_PASSWORD or prompted)
    python -m veritas.api.manage verify-store
    python -m veritas.api.manage verify-custody <case_id>
    python -m veritas.api.manage verify-audit
"""
from __future__ import annotations

import argparse
import getpass
import os
import sys

from .auth import hash_password
from .config import load
from .context import AppContext
from .db import User


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="veritas-manage")
    sub = ap.add_subparsers(dest="cmd", required=True)
    ca = sub.add_parser("create-admin")
    ca.add_argument("--id", required=True)
    ca.add_argument("--name", required=True)
    ca.add_argument("--email")
    cu = sub.add_parser("create-user")
    cu.add_argument("--id", required=True)
    cu.add_argument("--name", required=True)
    sub.add_parser("verify-store")
    vc = sub.add_parser("verify-custody")
    vc.add_argument("case_id")
    sub.add_parser("verify-audit")
    args = ap.parse_args(argv)
    ctx = AppContext(load())

    if args.cmd in ("create-admin", "create-user"):
        pw = os.environ.get("VERITAS_ADMIN_PASSWORD") if args.cmd == "create-admin" else os.environ.get("VERITAS_USER_PASSWORD")
        pw = pw or getpass.getpass("password (min 12 chars): ")
        if len(pw) < 12:
            print("password too short", file=sys.stderr)
            return 2
        with ctx.Session() as s:
            u = s.get(User, args.id)
            if u is None:
                u = User(id=args.id, display_name=args.name, email=getattr(args, "email", None))
                s.add(u)
            u.password_hash = hash_password(pw)
            u.is_admin = args.cmd == "create-admin"
            u.can_unmask_pii = u.is_admin
            s.commit()
        print(f"user {args.id} ready; signing key {ctx.vault.get_or_create(args.id).key_id}")
        return 0
    if args.cmd == "verify-store":
        bad = [a for a, ok in ctx.store.iter_verify() if not ok]
        print("PASS" if not bad else "FAIL " + " ".join(bad))
        return 0 if not bad else 1
    if args.cmd == "verify-custody":
        ok, failures = ctx.verify_custody(args.case_id)
        for f in failures:
            print("  FAIL", f)
        print("PASS" if ok else "FAIL")
        return 0 if ok else 1
    if args.cmd == "verify-audit":
        from ..audit.log import verify

        ok, failures = verify(ctx.audit.all_rows())
        for f in failures:
            print("  FAIL", f)
        print("PASS" if ok else "FAIL")
        return 0 if ok else 1
    return 2


if __name__ == "__main__":
    sys.exit(main())

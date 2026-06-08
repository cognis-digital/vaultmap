"""VAULTMAP command-line interface.

Subcommands:
  init      Create a new encrypted vault.
  add       Add an entry to a vault.
  list      List entries.
  summary   Show estate-planning rollup (net worth, readiness, gaps).
  remove    Remove an entry by id.

Password resolution (in order): --password, $VAULTMAP_PASSWORD.
This keeps tests/automation non-interactive and avoids leaking via argv when
the env var is used.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import Vault, VaultError, Entry


def _get_password(args) -> str:
    pw = getattr(args, "password", None) or os.environ.get("VAULTMAP_PASSWORD")
    if not pw:
        raise VaultError("no password provided (use --password or $VAULTMAP_PASSWORD)")
    return pw


def _emit(obj, fmt: str) -> None:
    if fmt == "json":
        print(json.dumps(obj, indent=2, default=str))
        return
    _emit_table(obj)


def _emit_table(obj) -> None:
    if isinstance(obj, dict) and "entries" in obj:
        rows = obj["entries"]
        if not rows:
            print("(no entries)")
            return
        hdr = ("id", "name", "category", "institution", "value", "beneficiary")
        print("  ".join(f"{h:<14}" for h in hdr))
        print("-" * (16 * len(hdr)))
        for r in rows:
            print("  ".join(f"{str(r.get(c, '')):<14.14}" for c in hdr))
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            print(f"{k:<22}: {v}")
        return
    print(obj)


def _do_init(args) -> int:
    pw = _get_password(args)
    if os.path.exists(args.vault) and not args.force:
        raise VaultError(f"vault already exists: {args.vault} (use --force to overwrite)")
    v = Vault()
    v.save(args.vault, pw)
    _emit({"status": "created", "vault": args.vault, "tool": TOOL_NAME}, args.format)
    return 0


def _do_add(args) -> int:
    pw = _get_password(args)
    v = Vault.load(args.vault, pw)
    entry = Entry(
        id=args.id,
        name=args.name,
        category=args.category,
        institution=args.institution or "",
        identifier=args.identifier or "",
        value=args.value,
        currency=args.currency,
        beneficiary=args.beneficiary or "",
        location=args.location or "",
        notes=args.notes or "",
    )
    v.add(entry)
    v.save(args.vault, pw)
    _emit({"status": "added", "id": entry.id, "entry_count": len(v.entries)}, args.format)
    return 0


def _do_list(args) -> int:
    pw = _get_password(args)
    v = Vault.load(args.vault, pw)
    entries = v.entries
    if args.category:
        entries = [e for e in entries if e.category == args.category]
    from dataclasses import asdict
    _emit({"entries": [asdict(e) for e in entries]}, args.format)
    return 0


def _do_summary(args) -> int:
    pw = _get_password(args)
    v = Vault.load(args.vault, pw)
    _emit(v.summary(), args.format)
    return 0


def _do_remove(args) -> int:
    pw = _get_password(args)
    v = Vault.load(args.vault, pw)
    if not v.remove(args.id):
        raise VaultError(f"no entry with id: {args.id}")
    v.save(args.vault, pw)
    _emit({"status": "removed", "id": args.id, "entry_count": len(v.entries)}, args.format)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog=TOOL_NAME, description="Encrypted personal asset & account inventory.")
    p.add_argument("--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}")
    p.add_argument("--format", choices=("table", "json"), default="table")
    p.add_argument("--password", help="vault password (or set $VAULTMAP_PASSWORD)")
    sub = p.add_subparsers(dest="command", required=True)

    pi = sub.add_parser("init", help="create a new encrypted vault")
    pi.add_argument("vault")
    pi.add_argument("--force", action="store_true")
    pi.set_defaults(func=_do_init)

    pa = sub.add_parser("add", help="add an entry")
    pa.add_argument("vault")
    pa.add_argument("--id", required=True)
    pa.add_argument("--name", required=True)
    pa.add_argument("--category", default="other")
    pa.add_argument("--institution")
    pa.add_argument("--identifier")
    pa.add_argument("--value", type=float, default=0.0)
    pa.add_argument("--currency", default="USD")
    pa.add_argument("--beneficiary")
    pa.add_argument("--location")
    pa.add_argument("--notes")
    pa.set_defaults(func=_do_add)

    pl = sub.add_parser("list", help="list entries")
    pl.add_argument("vault")
    pl.add_argument("--category")
    pl.set_defaults(func=_do_list)

    ps = sub.add_parser("summary", help="estate rollup & readiness")
    ps.add_argument("vault")
    ps.set_defaults(func=_do_summary)

    pr = sub.add_parser("remove", help="remove an entry by id")
    pr.add_argument("vault")
    pr.add_argument("--id", required=True)
    pr.set_defaults(func=_do_remove)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except VaultError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # pragma: no cover - defensive
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

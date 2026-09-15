# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""CLI entrypoint for the wallet service: ``wallet init`` and ``wallet run``."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ..common import did as did_mod
from ..common import keys
from .server import create_app


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="wallet")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("init", help="Generate a fresh wallet keypair")
    p_init.add_argument("--keys-dir", type=Path, default=Path("keys"))
    p_init.add_argument("--label", default="wallet")

    p_run = sub.add_parser("run", help="Run the wallet HTTP service")
    p_run.add_argument("--keys-dir", type=Path, default=Path("keys"))
    p_run.add_argument("--label", default="wallet")
    p_run.add_argument("--host", default="127.0.0.1")
    p_run.add_argument("--port", type=int, default=7401)
    p_run.add_argument(
        "--membership-path",
        type=Path,
        default=None,
        help="path to the admin-signed FamilyMembership JWT for this wallet",
    )
    p_run.add_argument(
        "--approve",
        choices=("terminal", "web"),
        default="terminal",
        help="approval surface: stdin prompt (default) or a browser page at /ui",
    )

    args = parser.parse_args(argv)
    if args.cmd == "init":
        return _cmd_init(args.keys_dir, args.label)
    if args.cmd == "run":
        return _cmd_run(
            args.keys_dir, args.label, args.host, args.port, args.membership_path,
            approve_mode=args.approve,
        )
    return 1


def _key_path(keys_dir: Path, label: str) -> Path:
    return keys_dir / f"{label}.jwk"


def _cmd_init(keys_dir: Path, label: str) -> int:
    path = _key_path(keys_dir, label)
    if path.exists():
        print(f"refusing to overwrite existing key at {path}", file=sys.stderr)
        return 1
    key = keys.generate_keypair()
    keys.save_private_jwk(key, path)
    did = did_mod.did_key_from_public_key(key)
    print(f"wrote {path}")
    print(f"did:  {did}")
    return 0


def _cmd_run(
    keys_dir: Path,
    label: str,
    host: str,
    port: int,
    membership_path: Path | None,
    *,
    approve_mode: str = "terminal",
) -> int:
    path = _key_path(keys_dir, label)
    if not path.exists():
        print(f"no wallet key at {path}; run `wallet init` first", file=sys.stderr)
        return 1
    key = keys.load_private_jwk(path)
    membership_token: str | None = None
    if membership_path is not None:
        if not membership_path.exists():
            print(
                f"no membership JWT at {membership_path}", file=sys.stderr
            )
            return 1
        membership_token = membership_path.read_text().strip()

    web = None
    if approve_mode == "web":
        from .webapproval import WebApproval

        web = WebApproval()
    app = create_app(
        private_key=key,
        label=label,
        membership_token=membership_token,
        approve=web.approve if web is not None else None,
    )
    if web is not None:
        web.mount(app, label)
        print(f"[{label}] browser approvals at http://{host}:{port}/ui")

    import uvicorn

    uvicorn.run(app, host=host, port=port)
    return 0

# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""CLI entrypoint for the DID server: init, issue-membership, run."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ..common import jws, keys
from .document import make_did_document
from .membership import make_membership_vc
from .server import create_app


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="did-server")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("init", help="Generate admin keypair and write did.json")
    p_init.add_argument("--did", required=True, help="e.g. did:web:family.example.com")
    p_init.add_argument("--keys-dir", type=Path, default=Path("keys"))
    p_init.add_argument("--public-dir", type=Path, default=Path("public"))

    p_issue = sub.add_parser(
        "issue-membership", help="Sign a membership VC for a member's did:key"
    )
    p_issue.add_argument("--did", required=True, help="admin did (must match init)")
    p_issue.add_argument("--keys-dir", type=Path, default=Path("keys"))
    p_issue.add_argument("--member", required=True, help="member's did:key")
    p_issue.add_argument("--role", required=True)
    p_issue.add_argument("--ttl-days", type=int, default=365)

    p_run = sub.add_parser("run", help="Serve did.json over HTTP")
    p_run.add_argument("--did", required=True)
    p_run.add_argument("--public-dir", type=Path, default=Path("public"))
    p_run.add_argument("--host", default="127.0.0.1")
    p_run.add_argument("--port", type=int, default=7400)

    args = parser.parse_args(argv)
    if args.cmd == "init":
        return _cmd_init(args.did, args.keys_dir, args.public_dir)
    if args.cmd == "issue-membership":
        return _cmd_issue(
            args.did, args.keys_dir, args.member, args.role, args.ttl_days
        )
    if args.cmd == "run":
        return _cmd_run(args.did, args.public_dir, args.host, args.port)
    return 1


def _admin_key_path(keys_dir: Path) -> Path:
    return keys_dir / "admin.jwk"


def _did_document_path(public_dir: Path) -> Path:
    return public_dir / ".well-known" / "did.json"


def _cmd_init(did: str, keys_dir: Path, public_dir: Path) -> int:
    key_path = _admin_key_path(keys_dir)
    doc_path = _did_document_path(public_dir)
    if key_path.exists():
        print(f"refusing to overwrite admin key at {key_path}", file=sys.stderr)
        return 1
    key = keys.generate_keypair()
    keys.save_private_jwk(key, key_path)
    doc = make_did_document(did=did, key=key)
    doc_path.parent.mkdir(parents=True, exist_ok=True)
    doc_path.write_text(json.dumps(doc, indent=2) + "\n")
    print(f"wrote admin key: {key_path}")
    print(f"wrote did.json:  {doc_path}")
    print(f"did:             {did}")
    return 0


def _cmd_issue(
    did: str, keys_dir: Path, member: str, role: str, ttl_days: int
) -> int:
    key_path = _admin_key_path(keys_dir)
    if not key_path.exists():
        print(
            f"no admin key at {key_path}; run `did-server init` first", file=sys.stderr
        )
        return 1
    key = keys.load_private_jwk(key_path)
    payload = make_membership_vc(
        admin_did=did,
        member_did=member,
        role=role,
        ttl_seconds=ttl_days * 24 * 3600,
    )
    token = jws.sign_jwt(payload, key=key, kid=did)
    print(token)
    return 0


def _cmd_run(did: str, public_dir: Path, host: str, port: int) -> int:
    doc_path = _did_document_path(public_dir)
    if not doc_path.exists():
        print(
            f"no did document at {doc_path}; run `did-server init` first",
            file=sys.stderr,
        )
        return 1
    app = create_app(did_document_path=doc_path, did=did)

    import uvicorn

    uvicorn.run(app, host=host, port=port)
    return 0

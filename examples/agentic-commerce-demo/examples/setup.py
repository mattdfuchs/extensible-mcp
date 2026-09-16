# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Initialize a fresh demo workspace.

Generates admin + kid + parent keys, builds the admin DID document, issues
membership VCs for both wallets, and writes a vc-config.json the proxy can
consume. After this script you can start the wallets and the proxy.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from household_identity.common import did as did_mod
from household_identity.common import jws, keys
from household_identity.did_server.document import make_did_document
from household_identity.did_server.membership import make_membership_vc

ADMIN_DID = "did:web:family.example.com"


def main() -> None:
    parser = argparse.ArgumentParser(prog="setup")
    parser.add_argument(
        "--workspace", type=Path, default=Path("workspace"),
        help="directory to initialize (default: ./workspace)",
    )
    parser.add_argument(
        "--admin-did", default=ADMIN_DID,
        help=f"family admin did:web (default: {ADMIN_DID})",
    )
    args = parser.parse_args()
    ws: Path = args.workspace
    admin_did: str = args.admin_did

    # The guard is about not clobbering keys and memberships. The approval
    # service writes its own approval-users.json here the first time it starts,
    # so ignore that one file -- otherwise running the service before setup
    # (easy to do by hand) makes setup refuse for a reason that has nothing to
    # do with the state it cares about.
    owned_elsewhere = {"approval-users.json"}
    existing = [e for e in ws.iterdir() if e.name not in owned_elsewhere] if ws.exists() else []
    if existing:
        raise SystemExit(f"refusing to overwrite non-empty workspace at {ws}")
    (ws / "keys").mkdir(parents=True, exist_ok=True)
    (ws / "memberships").mkdir(parents=True, exist_ok=True)
    (ws / "public" / ".well-known").mkdir(parents=True, exist_ok=True)

    # --- admin -----------------------------------------------------------
    admin_key = keys.generate_keypair()
    keys.save_private_jwk(admin_key, ws / "keys" / "admin.jwk")
    admin_doc = make_did_document(did=admin_did, key=admin_key)
    (ws / "public" / ".well-known" / "did.json").write_text(
        json.dumps(admin_doc, indent=2) + "\n"
    )

    # --- members ---------------------------------------------------------
    kid_key = keys.generate_keypair()
    keys.save_private_jwk(kid_key, ws / "keys" / "kid.jwk")
    kid_did = did_mod.did_key_from_public_key(kid_key)

    parent_key = keys.generate_keypair()
    keys.save_private_jwk(parent_key, ws / "keys" / "parent.jwk")
    parent_did = did_mod.did_key_from_public_key(parent_key)

    # --- memberships -----------------------------------------------------
    for label, member_did, role in [
        ("kid", kid_did, "child"),
        ("parent", parent_did, "parent"),
    ]:
        payload = make_membership_vc(
            admin_did=admin_did, member_did=member_did, role=role
        )
        token = jws.sign_jwt(payload, key=admin_key, kid=admin_did)
        (ws / "memberships" / f"{label}.jwt").write_text(token + "\n")

    # --- proxy VC config -------------------------------------------------
    vc_config = {
        "originator_wallet_url": "http://127.0.0.1:7401",
        "approver_wallet_url": "http://127.0.0.1:7402",
        "trusted_admin_dids": [admin_did],
        # payments__spend always needs both VCs.
        "gated_tools": ["payments__spend"],
        # pizza__order_pizza needs the kid's request VC always, but the
        # parent's authorization VC is only required for orders above the
        # household-policy threshold. That threshold is a tier in the
        # family_spend_prod bundle, not a Python filter.
        "optional_authorization_tools": ["pizza__order_pizza"],
        "preresolved_did_documents": {admin_did: admin_doc},
        # Async wallet approval. The wallet returns 202 with an approval_id;
        # whenever the human approves, it POSTs the signed bundle back to
        # {callback_base_url}/vc-callback/{id}. Set to "" to fall back to
        # the synchronous mode (wallets block on stdin, proxy holds the
        # connection open).
        "callback_base_url": "http://127.0.0.1:7400",
        "callback_timeout_seconds": 150.0,
    }
    (ws / "vc-config.json").write_text(json.dumps(vc_config, indent=2) + "\n")

    # --- proxy mcp config ------------------------------------------------
    # Path resolution: backends are relative to this examples/ dir
    examples_dir = Path(__file__).resolve().parent
    mcp_config = {
        "mcpServers": {
            "payments": {
                "command": "uv",
                "args": [
                    "run",
                    "--project",
                    str(examples_dir.parent),
                    "python",
                    str(examples_dir / "payments_server.py"),
                ],
            },
            "pizza": {
                "command": "uv",
                "args": [
                    "run",
                    "--project",
                    str(examples_dir.parent),
                    "python",
                    str(examples_dir / "pizza_server.py"),
                ],
                "env": {
                    # Write order confirmations next to the workspace so a
                    # demo audience can `tail -f` the file in a separate
                    # terminal.
                    "PIZZA_ORDERS_LOG": str(ws.resolve() / "pizza-orders.log"),
                },
            },
        }
    }
    (ws / "config.json").write_text(json.dumps(mcp_config, indent=2) + "\n")

    print(f"Workspace initialized at: {ws.resolve()}")
    print(f"Admin DID:  {admin_did}")
    print(f"Kid DID:    {kid_did}")
    print(f"Parent DID: {parent_did}")
    print()
    print("Next steps — in four separate terminals:")
    print(
        "  1. uv run --package household-identity "
        f"wallet run --keys-dir {ws}/keys --label kid --port 7401 "
        f"--membership-path {ws}/memberships/kid.jwt"
    )
    print(
        "  2. uv run --package household-identity "
        f"wallet run --keys-dir {ws}/keys --label parent --port 7402 "
        f"--membership-path {ws}/memberships/parent.jwt"
    )
    print(
        f"  3. uv run python {examples_dir}/family_proxy_server.py "
        f"--vc-config {ws}/vc-config.json --host 0.0.0.0 --port 7400"
    )
    print(f"  4. tail -f {ws.resolve()}/pizza-orders.log")
    print()
    print(
        "Every gated call is decided by a policy bundle, so the wallets above "
        "supply evidence rather than authority. order_pizza runs on the two-VC "
        "wallet rail and needs only those two terminals; the passkey rails "
        "(spend, charge_invoice) additionally need the approval service:"
    )
    print(
        f"  APPROVAL_HOST=0.0.0.0 uv run python {examples_dir}/approval_service.py"
    )
    print()
    print(
        "Point any MCP-aware client at the proxy (HTTP on "
        "http://127.0.0.1:7400/mcp) and try:"
    )
    print("  \"order a large pepperoni from Dominos delivered to 123 Main St\"")
    print()
    print(
        "For the whole thing containerized, with a browser chat window and a "
        "passkey page, see deploy/README.md instead. For the smallest possible "
        f"run with no wallets at all: uv run python {examples_dir}/boot_demo.py"
    )


if __name__ == "__main__":
    main()

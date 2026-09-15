# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Boot the proxy with a supplied policy bundle as the live enforcer.

This is the smallest complete run of the enforcement path: it wires the
**core** ``extensible-mcp`` machinery around the artifacts
the bundle governs: it admits a downstream ``payments`` server to the
``family_spend_prod`` bundle via a ``BundleRouter``, augments search results
from the bundle's guidance, and enforces every call with ``VCPolicyFilter``
evaluating ``policy.wasm`` in-process.

It then drives a real server lifespan (FastMCP in-memory client, which runs
the true lifespan: spawns the downstream over stdio, indexes tools, builds the
pipelines) through four calls:

1. ``search_tools`` — the governed ``spend`` tool surfaces with the credential
   requirements the augmenter derives from the bundle's guidance;
2. ``call_tool`` with no credentials — denied by the policy, with the
   disjunctive "why it failed" message the renderer assembles from
   ``failed_checks`` × guidance;
3. ``call_tool`` with a valid $5 request VC — allowed (solo tier), and the
   downstream actually debits the balance;
4. ``call_tool`` for $50 with only a request VC — denied (over the $10 tier,
   needs the parent authorization), then allowed once the authorization VC is
   supplied.

The trust chain is minted fresh in-process (admin/kid/parent keys), so the run
is self-contained — no wallets or network.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from fastmcp import Client
from household_identity.common import did as did_mod
from household_identity.common import jws, keys, vc
from household_identity.did_server.membership import make_membership_vc

from extensible_mcp import (
    BundleRouter,
    DidWebResolver,
    LayeredBundleSelector,
    PolicyBundle,
    VCPolicyFilter,
    WalletBundleAdapter,
)
from extensible_mcp.augment import BundleAugmenter
from extensible_mcp.config import Config
from extensible_mcp.server import create_server
from extensible_mcp.types import ServerConfig

BUNDLE_DIR = (
    Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "family_spend_prod"
)
DOWNSTREAM = Path(__file__).resolve().parent / "demo_spend_server.py"
PROJECT = Path(__file__).resolve().parent.parent
ADMIN_DID = "did:web:family.example.com"


def _print(title: str, body: str) -> None:
    print(f"\n{'─' * 70}\n{title}\n{'─' * 70}\n{body.rstrip()}")


def _bundle(token: str, membership: str) -> dict:
    return {"token": token, "membership": membership}


def main() -> None:
    logging.basicConfig(level=logging.WARNING)

    # --- fresh trust chain (self-contained; no wallets / network) -----------
    admin, kid, parent = (keys.generate_keypair() for _ in range(3))
    kid_did = did_mod.did_key_from_public_key(kid)
    parent_did = did_mod.did_key_from_public_key(parent)

    def membership(member_key, member_did, role):
        payload = make_membership_vc(
            admin_did=ADMIN_DID, member_did=member_did, role=role
        )
        return jws.sign_jwt(payload, key=admin, kid=ADMIN_DID)

    kid_membership = membership(kid, kid_did, "child")  # role the wallets issue
    parent_membership = membership(parent, parent_did, "parent")

    def request_vc(*, amount, merchant="acme"):
        payload = vc.make_action_request(
            issuer_did=kid_did,
            request_type="spend",
            details={"amount": amount, "merchant": merchant},
        )
        token = jws.sign_jwt(payload, key=kid, kid=kid_did)
        return token, payload["jti"], _bundle(token, kid_membership)

    def authorization_vc(request_token, request_jti):
        payload = vc.make_action_authorization(
            issuer_did=parent_did,
            request_jti=request_jti,
            request_hash=vc.hash_request(request_token),
            scope={},
        )
        token = jws.sign_jwt(payload, key=parent, kid=parent_did)
        return _bundle(token, parent_membership)

    # --- the policy-bundle enforcement path ------------------------
    bundle = PolicyBundle.load(BUNDLE_DIR, name="family_spend_prod")
    resolver = DidWebResolver(
        [ADMIN_DID], preresolved={ADMIN_DID: keys.public_jwk(admin)}
    )

    def filter_factory(name: str):
        if name != "family_spend_prod":
            return None
        return VCPolicyFilter(
            bundle,
            adapter=WalletBundleAdapter(),  # LLM sends requestVC / authorizationVC
            resolver=resolver,
            trusted_admin_dids=[ADMIN_DID],
            # Manifest validation is off for this demo: the generated manifest
            # closes the W3C-VC claim objects (additionalProperties: false),
            # but real household-identity wallets carry @context/type/jti/id/
            # family, so default-on validation rejects genuine credentials the
            # policy itself accepts. Open reconciliation:
            # the manifest should leave externally-supplied VC claim sub-objects
            # open. See the boot-run finding.
            validate_input=False,
        )

    selector = LayeredBundleSelector(
        literal_map={"payments": "family_spend_prod"}, map_key="origin_server"
    )
    router = BundleRouter(selector, filter_factory)

    config = Config(
        servers=[
            ServerConfig(
                name="payments",
                command="uv",
                args=["run", "--project", str(PROJECT), "python", str(DOWNSTREAM)],
            )
        ]
    )
    server = create_server(
        config,
        bundle_router=router,
        extra_search_filters=[BundleAugmenter(router)],
    )

    async def drive() -> None:
        async with Client(server) as client:
            # 1. discovery — the governed tool surfaces with its requirements
            found = await client.call_tool(
                "search_tools", {"query": "spend money at a merchant"}
            )
            _print("1. search_tools → governed tool + bundle guidance", found.data)

            async def spend(args, label):
                out = await client.call_tool(
                    "call_tool", {"tool_name": "payments__spend", "arguments": args}
                )
                _print(label, out.data)

            # 2. no credentials → denied, rendered from failed_checks × guidance
            await spend(
                {"amount": 5.0, "merchant": "acme"},
                "2. call with NO credentials → policy denies",
            )

            # 3. valid $5 request VC → allowed (solo tier); balance debited
            _, _, req5 = request_vc(amount=5.0)
            await spend(
                {"amount": 5.0, "merchant": "acme", "requestVC": req5},
                "3. $5 with a valid request VC → allowed (solo tier)",
            )

            # 4a. $50 with only a request VC → denied (needs parent auth)
            tok50, jti50, req50 = request_vc(amount=50.0)
            await spend(
                {"amount": 50.0, "merchant": "acme", "requestVC": req50},
                "4a. $50 with only a request VC → denied (over $10 tier)",
            )

            # 4b. $50 with the parent authorization VC → allowed (full chain)
            tok50b, jti50b, req50b = request_vc(amount=50.0)
            auth = authorization_vc(tok50b, jti50b)
            await spend(
                {
                    "amount": 50.0,
                    "merchant": "acme",
                    "requestVC": req50b,
                    "authorizationVC": auth,
                },
                "4b. $50 with request + parent authorization → allowed (full chain)",
            )

    asyncio.run(drive())


if __name__ == "__main__":
    main()

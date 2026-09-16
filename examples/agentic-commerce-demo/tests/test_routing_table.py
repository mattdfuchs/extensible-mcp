# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""The live wiring: which bundle governs which server, and what that means
for a call.

Everything else in this suite tests a filter in isolation. This tests the
table ``family_proxy_server.main()`` actually builds — the literal map, the
per-bundle wire adapters, and the single-use guard — by calling the same
``build_bundle_router`` the server calls, and dispatching through
``router.check`` the way the proxy's call handler does. A copy of the map
inside a test would keep passing while the live wiring drifted.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

import httpx
import pytest

from extensible_mcp.types import CallRequest

# Make examples/ importable, as the other demo tests do.
_EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
sys.path.insert(0, str(_EXAMPLES))
from family_proxy_server import build_bundle_router  # noqa: E402

ADMIN_DID = "did:web:admin.example"


# -- local signing helpers, mirroring test_invoice_gated_filter.py's --------- #

def _new_key():
    from joserfc.jwk import OKPKey

    return OKPKey.generate_key("Ed25519")


def _public_jwk(key) -> str:
    return json.dumps(key.as_dict(private=False))


def _sign(payload: dict, key) -> str:
    from joserfc import jws as joserfc_jws

    return joserfc_jws.serialize_compact(
        {"alg": "Ed25519"}, json.dumps(payload).encode(), key, algorithms=["Ed25519"]
    )


_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    return "1" * (len(data) - len(data.lstrip(b"\x00"))) + out


def _did_key(key) -> str:
    x = key.as_dict(private=False)["x"]
    pub = base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))
    return "did:key:z" + _b58(b"\xed\x01" + pub)


@pytest.fixture(scope="module")
def keys():
    return {"kid": _new_key(), "parent": _new_key(), "admin": _new_key()}


@pytest.fixture
def router(keys):
    """The real router, built the way main() builds it. The approval client
    points nowhere: only the invoice rail uses it, and nothing here does."""
    r, _resolver = build_bundle_router(
        trusted=[ADMIN_DID],
        preresolved={ADMIN_DID: json.loads(_public_jwk(keys["admin"]))},
        approval_client=httpx.AsyncClient(base_url="http://approval.invalid", timeout=1.0),
    )
    return r


def _admit_all(router) -> dict[str, str | None]:
    out = {}
    for server in ("payments", "pizza", "settlement"):
        result = router.admit(
            server_name=server,
            url=f"http://{server}.invalid/mcp",
            how_loaded="config",
            transport="stdio",
        )
        out[server] = result.bundle if result.allowed else None
    return out


class TestTheMap:
    """A server the proxy cannot positively place is not connected, so the map
    is load-bearing: an entry that goes missing is a server that refuses to
    admit, and a wrong one is a server governed by the wrong policy."""

    def test_each_server_admits_to_its_own_bundle(self, router):
        assert _admit_all(router) == {
            "payments": "family_spend_prod",
            "pizza": "family_spend_pizza",
            "settlement": "family_spend_invoice",
        }

    def test_an_unmapped_server_is_refused(self, router):
        """Fail closed: no map entry and no classifier means no admission."""
        result = router.admit(
            server_name="somewhere_else",
            url="http://somewhere-else.invalid/mcp",
            how_loaded="runtime",
            transport="http",
        )
        assert result.allowed is False
        assert result.bundle is None

    def test_an_admitted_server_exposes_its_bundle_to_the_augmenter(self, router):
        _admit_all(router)
        assert router.bundle_for("payments").name == "family_spend_prod"
        assert router.bundle_for("settlement").name == "family_spend_invoice"
        assert router.bundle_for("somewhere_else") is None


class TestPaymentsSpend:
    """`payments__spend` through `router.check`, which is what the proxy's call
    handler invokes."""

    @staticmethod
    def _membership(keys, who, role):
        return _sign(
            {
                "iss": ADMIN_DID,
                "sub": _did_key(keys[who]),
                "nbf": 0,
                "exp": 9999999999,
                "vc": {"credentialSubject": {"role": role}},
            },
            keys["admin"],
        )

    @classmethod
    def _pair(cls, keys, *, amount: float, jti: str):
        kid = _did_key(keys["kid"])
        req = _sign(
            {
                "iss": kid, "nbf": 0, "exp": 9999999999, "jti": jti,
                "vc": {"credentialSubject": {
                    "id": kid,
                    "requests": {"type": "spend", "amount": amount, "merchant": "acme"},
                }},
            },
            keys["kid"],
        )
        parent = _did_key(keys["parent"])
        auth = _sign(
            {
                "iss": parent, "nbf": 0, "exp": 9999999999, "jti": f"{jti}-auth",
                "vc": {"credentialSubject": {
                    "id": parent,
                    "authorizes_request": jti,
                    "request_hash": "sha256:" + hashlib.sha256(req.encode()).hexdigest(),
                }},
            },
            keys["parent"],
        )
        return (
            {"token": req, "membership": cls._membership(keys, "kid", "child")},
            {"token": auth, "membership": cls._membership(keys, "parent", "parent")},
        )

    @staticmethod
    def _call(arguments: dict) -> CallRequest:
        return CallRequest(
            tool_name="payments__spend", arguments=arguments, server_name="payments"
        )

    async def test_denied_without_a_wallet_credential(self, router):
        _admit_all(router)
        result = await router.check(self._call({"amount": 15.00, "merchant": "acme"}))
        assert result.allowed is False
        assert result.arguments == {"amount": 15.00, "merchant": "acme"}

    async def test_allowed_once_and_refused_on_the_second_use(self, router, keys):
        """Both halves of the wiring in one pass: the prod bundle accepts a
        properly signed pair, and the guard the factory wraps it in refuses
        the same pair a second time."""
        _admit_all(router)
        req, auth = self._pair(keys, amount=15.00, jti="urn:routing-1")

        def call():
            return self._call({
                "amount": 15.00, "merchant": "acme",
                "requestVC": dict(req), "authorizationVC": dict(auth),
            })

        first = await router.check(call())
        assert first.allowed is True, first.reason
        # Evidence stripped before the downstream ever sees the call.
        assert first.arguments == {"amount": 15.00, "merchant": "acme"}

        second = await router.check(call())
        assert second.allowed is False
        assert "already been used" in second.reason

    async def test_a_tampered_amount_is_refused(self, router, keys):
        """The kid signed $15; the call claims $1. Every signature is valid."""
        _admit_all(router)
        req, auth = self._pair(keys, amount=15.00, jti="urn:routing-2")
        result = await router.check(self._call({
            "amount": 1.00, "merchant": "acme",
            "requestVC": req, "authorizationVC": auth,
        }))
        assert result.allowed is False

    async def test_an_ungated_tool_on_a_governed_server_passes(self, router):
        """The demo governs actions, not whole servers, so `balance` on the
        same downstream needs no credential."""
        _admit_all(router)
        result = await router.check(
            CallRequest(
                tool_name="payments__balance", arguments={}, server_name="payments"
            )
        )
        assert result.allowed is True, result.reason

    async def test_an_ungoverned_server_passes_through(self, router):
        """No bundle admitted for this server, so the router does not gate it
        -- `DiscoveredToolsFilter` and access control still do."""
        result = await router.check(
            CallRequest(
                tool_name="other__thing", arguments={}, server_name="other"
            )
        )
        assert result.allowed is True

# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Tests for the fetch-plan executor, including an end-to-end slice that
assembles the family_spend input via the real fetchplan.json and feeds it
straight into the WASM policy engine."""

from __future__ import annotations

import hashlib
import json
import logging
import shutil
from pathlib import Path

import pytest

from extensible_mcp.bundle import PolicyBundle
from extensible_mcp.fetchplan import (
    DerivePlanError,
    DeriveUndefined,
    FetchContext,
    FetchError,
    FetchExecutor,
    HostBuiltinError,
    default_primitives,
    default_resolvers,
    validate_derive_plan,
)
from extensible_mcp.cel_policy import default_cel_functions
from extensible_mcp.wasm_policy import OpaWasmPolicy, default_builtins
from tests import vc_helpers as vc

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "family_spend"
PLAN = json.loads((FIXTURE_DIR / "fetchplan.json").read_text())
WASM = FIXTURE_DIR / "policy.wasm"
ALLOW = "policybundle/examples/family_spend/allow"


@pytest.fixture(scope="module")
def key():
    return vc.new_key()


def _context(key, *, amount: int, with_auth: bool) -> FetchContext:
    """Build a fetch context for a family-spend call.

    Memberships are wallet-sourced (looked up by subject DID); the request and
    (optionally) authorization VCs are call-sourced in the envelope.
    """
    args = {"amountCents": amount, "merchant": "acme"}
    req = vc.request_vc(args=args, key=key)
    envelope = {"tool": "send", "arguments": args, "requestVC": req}
    if with_auth:
        envelope["authorizationVC"] = vc.authorization_vc(request_jws=req["jws"], key=key)
    else:
        # Present-but-inert authorization (solo path never reads its claims).
        envelope["authorizationVC"] = {
            "jws": req["jws"],
            "claims": {"jti": "r1", "iss": vc.PARENT_DID, "requestHash": "0" * 64,
                       "nbf": 0, "exp": 9999999999},
        }

    memberships = {
        vc.KID_DID: vc.membership(sub=vc.KID_DID, role="kid", key=key),
        vc.PARENT_DID: vc.membership(sub=vc.PARENT_DID, role="parent", key=key),
    }

    async def wallet_lookup(subject: str):
        return memberships.get(subject)

    return FetchContext(
        envelope=envelope,
        config={"trustRootDID": vc.TRUST_DID, "trustRootJwk": vc.public_jwk(key)},
        now=100,
        wallet=wallet_lookup,
    )


async def test_assembles_all_plan_fields(key):
    ctx = _context(key, amount=500, with_auth=False)
    assembled = await FetchExecutor().assemble(PLAN, ctx)
    # Every field the plan declares is present and closed.
    expected = {e["field"] for e in PLAN["entries"]}
    assert set(assembled) == expected
    # wallet lookup wired the kid's membership by the request's iss
    assert assembled["requesterMembership"]["claims"]["role"] == "kid"
    assert assembled["approverMembership"]["claims"]["role"] == "parent"


async def test_assembled_solo_input_allows_in_engine(key):
    """The whole point: assemble → evaluate → allow, end to end."""
    ctx = _context(key, amount=500, with_auth=False)
    assembled = await FetchExecutor().assemble(PLAN, ctx)
    policy = OpaWasmPolicy(WASM)
    result = policy.query(assembled, ALLOW)
    assert result[0]["result"] is True


async def test_assembled_full_chain_input_allows_in_engine(key):
    ctx = _context(key, amount=5000, with_auth=True)
    assembled = await FetchExecutor().assemble(PLAN, ctx)
    policy = OpaWasmPolicy(WASM)
    assert policy.query(assembled, ALLOW)[0]["result"] is True


async def test_missing_call_field_fails_closed(key):
    ctx = _context(key, amount=500, with_auth=False)
    del ctx.envelope["requestVC"]
    with pytest.raises(FetchError, match="requestVC"):
        await FetchExecutor().assemble(PLAN, ctx)


async def test_missing_config_fails_closed(key):
    ctx = _context(key, amount=500, with_auth=False)
    del ctx.config["trustRootJwk"]
    with pytest.raises(FetchError, match="trustRootJwk"):
        await FetchExecutor().assemble(PLAN, ctx)


async def test_wallet_miss_fails_closed(key):
    ctx = _context(key, amount=500, with_auth=False)

    async def empty_wallet(subject: str):
        return None

    ctx.wallet = empty_wallet
    with pytest.raises(FetchError, match="no credential for subject"):
        await FetchExecutor().assemble(PLAN, ctx)


async def test_input_substitution_navigates_assembled_fields(key):
    """The wallet subject is drawn from requestVC.claims.iss via $input."""
    ctx = _context(key, amount=500, with_auth=False)
    seen = []

    async def recording_wallet(subject: str):
        seen.append(subject)
        return vc.membership(sub=subject, role="kid", key=key)

    ctx.wallet = recording_wallet
    await FetchExecutor().assemble(PLAN, ctx)
    # requesterMembership subject = requestVC.claims.iss = KID_DID
    assert vc.KID_DID in seen and vc.PARENT_DID in seen


# --------------------------------------------------------------------------- #
# ``derive``: hoisting a primitive ahead of the policy
#
# The row the whole source kind exists for is the merchant swap: booleanized to
# ``invoiceSignatureOK: true``, a rule can no longer express *that the merchant
# the invoice claims is the merchant whose key signed it*, and an invoice signed
# by m1 claiming m2 is allowed. Derived fields keep both terms.
# --------------------------------------------------------------------------- #

MERCHANT_ID = "dominos"
OTHER_MERCHANT_ID = "pizza-hut"

_PRIMITIVE_CLASSES = {
    "sha256": {"class": "pure"},
    "parse_json": {"class": "pure"},
    "base64url_decode": {"class": "pure"},
    "base64url_encode_no_pad": {"class": "pure"},
    "verify_ed25519_raw": {"class": "key-consuming"},
    "verify_eddsa": {"class": "key-consuming"},
    "key_from_did_key": {"class": "key-producing"},
    "concat": {"class": "pure"},
    "format_int": {"class": "pure"},
}


def _b64u(raw: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _plan(*entries, primitives=None):
    """A fetch plan carrying only the entries a derive test needs."""
    declared = (
        _PRIMITIVE_CLASSES if primitives is None else primitives
    )
    return {"input": "DeriveInput", "primitives": declared, "entries": list(entries)}


def _config_entry(field):
    return {"field": field, "source": {"kind": "config"}}


def _merchant_key():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    return Ed25519PrivateKey.generate()


def _invoice(key, *, merchant_id=MERCHANT_ID, total_cents=400):
    invoice = {"merchantId": merchant_id, "totalCents": total_cents}
    canonical = json.dumps(invoice, sort_keys=True, separators=(",", ":"))
    return canonical, _b64u(key.sign(canonical.encode()))


def _invoice_ctx(key, *, merchant_id=MERCHANT_ID, trusted_key=None,
                 trusted_merchant_id=MERCHANT_ID):
    canonical, signature = _invoice(key, merchant_id=merchant_id)
    trusted_pub = (trusted_key or key).public_key().public_bytes_raw()
    return FetchContext(
        config={
            "invoiceCanonical": canonical,
            "invoiceSignature": signature,
            "trustedMerchants": [
                {"merchantId": trusted_merchant_id, "key": _b64u(trusted_pub)}
            ],
        }
    )


_SIGNER_IDS_ENTRY = {
    "field": "invoiceSignerIds",
    "source": {
        "kind": "derive",
        "fn": "verify_ed25519_raw",
        "over": {"$input": "trustedMerchants"},
        "args": [
            {"$input": "invoiceCanonical"},
            {"$input": "invoiceSignature"},
            {"$item": "key"},
        ],
        "project": "merchantId",
    },
}

_PARSED_ENTRY = {
    "field": "invoiceParsed",
    "source": {
        "kind": "derive",
        "fn": "parse_json",
        "args": [{"$input": "invoiceCanonical"}],
    },
}


async def test_derive_bare_applies_a_primitive_to_resolved_arguments():
    plan = _plan(
        _config_entry("requestVcJws"),
        {"field": "requestVcDigest",
         "source": {"kind": "derive", "fn": "sha256",
                    "args": [{"$input": "requestVcJws"}]}},
        {"field": "literalDigest",
         "source": {"kind": "derive", "fn": "sha256", "args": ["a-literal"]}},
    )
    ctx = FetchContext(config={"requestVcJws": "header.payload.sig"})
    assembled = await FetchExecutor().assemble(plan, ctx)
    assert assembled["requestVcDigest"] == hashlib.sha256(
        b"header.payload.sig"
    ).hexdigest()
    assert assembled["literalDigest"] == hashlib.sha256(b"a-literal").hexdigest()


async def test_derive_folded_projects_the_candidates_that_verified():
    key = _merchant_key()
    assembled = await FetchExecutor().assemble(
        _plan(_config_entry("invoiceCanonical"), _config_entry("invoiceSignature"),
              _config_entry("trustedMerchants"), _SIGNER_IDS_ENTRY),
        _invoice_ctx(key),
    )
    assert assembled["invoiceSignerIds"] == [MERCHANT_ID]


async def test_derive_folded_keeps_the_relation_across_a_merchant_swap():
    """The row the source kind exists for.

    The invoice is signed by the key trusted for ``dominos`` but names
    ``pizza-hut``. The derived fields are the *signer* and the *claim*, so the
    rule can still require them equal; a booleanized ``invoiceSignatureOK``
    would have said ``true`` with both terms consumed.
    """
    key = _merchant_key()
    assembled = await FetchExecutor().assemble(
        _plan(_config_entry("invoiceCanonical"), _config_entry("invoiceSignature"),
              _config_entry("trustedMerchants"), _SIGNER_IDS_ENTRY, _PARSED_ENTRY),
        _invoice_ctx(key, merchant_id=OTHER_MERCHANT_ID),
    )
    assert assembled["invoiceSignerIds"] == [MERCHANT_ID]
    assert assembled["invoiceParsed"]["merchantId"] == OTHER_MERCHANT_ID
    # The relation the rule keeps, and which denies here.
    assert assembled["invoiceParsed"]["merchantId"] not in assembled["invoiceSignerIds"]


async def test_derive_folded_no_match_emits_an_empty_set_and_does_not_raise():
    """A verification that does not match is a denial the *rule* makes.

    Raising here would surface as "Policy input could not be assembled",
    conflating a forged signature with an unreachable wallet and losing the
    guidance channel for the checks that most need explaining.
    """
    key = _merchant_key()
    assembled = await FetchExecutor().assemble(
        _plan(_config_entry("invoiceCanonical"), _config_entry("invoiceSignature"),
              _config_entry("trustedMerchants"), _SIGNER_IDS_ENTRY),
        _invoice_ctx(key, trusted_key=_merchant_key()),  # trusted key is a stranger's
    )
    assert assembled["invoiceSignerIds"] == []


async def test_derive_folded_over_an_empty_candidate_list_is_empty():
    key = _merchant_key()
    ctx = _invoice_ctx(key)
    ctx.config["trustedMerchants"] = []
    assembled = await FetchExecutor().assemble(
        _plan(_config_entry("invoiceCanonical"), _config_entry("invoiceSignature"),
              _config_entry("trustedMerchants"), _SIGNER_IDS_ENTRY),
        ctx,
    )
    assert assembled["invoiceSignerIds"] == []


async def test_derive_over_a_literal_list_resolves_input_inside_its_elements():
    """The single-key verification: one credential, one issuer, one key, and
    no candidate *list* anywhere to reference -- so the plan writes a
    one-element literal list whose element reads the key by ``$input``.

    Asserts on the value the primitive *received*, not only on the witness
    set: the defect was that a structurally plausible wrong value -- the
    marker dict itself -- reached the primitive, not that nothing did.
    """
    key = _merchant_key()
    canonical, signature = _invoice(key)
    pub = _b64u(key.public_key().public_bytes_raw())
    received = []

    def recording_verify(c, s, raw_key):
        received.append(raw_key)
        return default_primitives()["verify_ed25519_raw"](c, s, raw_key)

    executor = FetchExecutor(default_resolvers(
        primitives={**default_primitives(), "verify_ed25519_raw": recording_verify}
    ))
    plan = _plan(
        _config_entry("invoiceCanonical"), _config_entry("invoiceSignature"),
        _config_entry("merchantKey"),
        {"field": "invoiceSignerKeys",
         "source": {"kind": "derive", "fn": "verify_ed25519_raw",
                    "over": [{"key": {"$input": "merchantKey"}}],
                    "args": [{"$input": "invoiceCanonical"},
                             {"$input": "invoiceSignature"},
                             {"$item": "key"}],
                    "project": "key"}},
    )
    ctx = FetchContext(config={"invoiceCanonical": canonical,
                               "invoiceSignature": signature,
                               "merchantKey": pub})
    assembled = await executor.assemble(plan, ctx)
    assert received == [pub]
    assert assembled["invoiceSignerKeys"] == [pub]


async def test_derive_over_a_literal_list_keeps_the_relation_at_domain_size_one():
    """A one-element fold is not a boolean in disguise. The host supplied a
    stranger's key; the witness set is empty, and a rule checking that the
    claimed key is a witness denies -- which ``signatureOK: true`` could not
    express."""
    key = _merchant_key()
    canonical, signature = _invoice(key)
    stranger = _b64u(_merchant_key().public_key().public_bytes_raw())
    plan = _plan(
        _config_entry("invoiceCanonical"), _config_entry("invoiceSignature"),
        _config_entry("merchantKey"),
        {"field": "invoiceSignerKeys",
         "source": {"kind": "derive", "fn": "verify_ed25519_raw",
                    "over": [{"key": {"$input": "merchantKey"}}],
                    "args": [{"$input": "invoiceCanonical"},
                             {"$input": "invoiceSignature"},
                             {"$item": "key"}],
                    "project": "key"}},
    )
    ctx = FetchContext(config={"invoiceCanonical": canonical,
                               "invoiceSignature": signature,
                               "merchantKey": stranger})
    assembled = await FetchExecutor().assemble(plan, ctx)
    assert assembled["invoiceSignerKeys"] == []


async def test_derive_over_a_literal_list_with_plain_elements_still_works():
    """A literal element with no marker is a plain value, as before."""
    key = _merchant_key()
    canonical, signature = _invoice(key)
    pub = _b64u(key.public_key().public_bytes_raw())
    stranger = _b64u(_merchant_key().public_key().public_bytes_raw())
    plan = _plan(
        _config_entry("invoiceCanonical"), _config_entry("invoiceSignature"),
        {"field": "invoiceSignerIds",
         "source": {"kind": "derive", "fn": "verify_ed25519_raw",
                    "over": [{"merchantId": MERCHANT_ID, "key": pub},
                             {"merchantId": OTHER_MERCHANT_ID, "key": stranger}],
                    "args": [{"$input": "invoiceCanonical"},
                             {"$input": "invoiceSignature"},
                             {"$item": "key"}],
                    "project": "merchantId"}},
    )
    ctx = FetchContext(config={"invoiceCanonical": canonical,
                               "invoiceSignature": signature})
    assembled = await FetchExecutor().assemble(plan, ctx)
    assert assembled["invoiceSignerIds"] == [MERCHANT_ID]


async def test_derive_over_a_literal_element_reading_an_omitted_field_omits_the_derived_field():
    """Guard-aware in the ``over`` position too: an element whose ``$input``
    reads an omitted optional credential omits the derived field, exactly as
    an ``$input`` in ``args`` does. Not a raise."""
    key = _merchant_key()
    canonical, signature = _invoice(key)
    pub = _b64u(key.public_key().public_bytes_raw())
    plan = _plan(
        _config_entry("invoiceCanonical"), _config_entry("invoiceSignature"),
        {"field": "approverMembership",
         "source": {"kind": "call"},
         "guard": {"always": False, "required_in_tiers": [1],
                   "deciding_checks": ["t1.c7"]}},
        {"field": "approverKeyWitnesses",
         "source": {"kind": "derive", "fn": "verify_ed25519_raw",
                    "over": [{"key": {"$input": "approverMembership.adminKey"}}],
                    "args": [{"$input": "invoiceCanonical"},
                             {"$input": "invoiceSignature"},
                             {"$item": "key"}],
                    "project": "key"}},
    )
    config = {"invoiceCanonical": canonical, "invoiceSignature": signature}
    assembled = await FetchExecutor().assemble(
        plan, FetchContext(config=config, envelope={})
    )
    assert "approverKeyWitnesses" not in assembled

    assembled = await FetchExecutor().assemble(
        plan, FetchContext(config=config,
                           envelope={"approverMembership": {"adminKey": pub}}),
    )
    assert assembled["approverKeyWitnesses"] == [pub]


def _membership_plan():
    return _plan(
        _config_entry("membershipJws"),
        _config_entry("candidateMemberships"),
        {"field": "membershipSignerDids",
         "source": {"kind": "derive", "fn": "verify_eddsa",
                    "over": {"$input": "candidateMemberships"},
                    "args": [{"$input": "membershipJws"},
                             {"$apply": {"fn": "key_from_did_key",
                                         "args": [{"$item": "did"}]}}],
                    "project": "did"}},
    )


async def test_derive_composed_hoists_the_key_derivation_as_a_unit(key):
    """``key_from_did_key`` runs inside the verification that consumes its
    output, so the witness is the DID whose derived key verified — never the
    key, which floating free of its DID would be unbound."""
    stranger = vc.new_key()
    ctx = FetchContext(config={
        "membershipJws": vc.sign({"sub": "someone"}, key),
        "candidateMemberships": [
            {"did": vc.did_key(stranger)},
            {"did": vc.did_key(key)},
        ],
    })
    assembled = await FetchExecutor().assemble(_membership_plan(), ctx)
    assert assembled["membershipSignerDids"] == [vc.did_key(key)]


async def test_derive_composed_tolerates_a_malformed_did_key(key):
    """A bad ``did:key`` derives no key, which is a verification denial, not a
    fault — the same contract the in-policy builtin has."""
    ctx = FetchContext(config={
        "membershipJws": vc.sign({"sub": "someone"}, key),
        "candidateMemberships": [{"did": "did:key:not-a-key"}],
    })
    assembled = await FetchExecutor().assemble(_membership_plan(), ctx)
    assert assembled["membershipSignerDids"] == []


async def test_derive_apply_resolves_its_own_input_and_literal_arguments():
    """``$apply`` is an ordinary nested call: its arguments resolve the same
    three ways any other entry's do, and it is not restricted to a key
    position — only to one level, and to primitives that do not consume a key.
    """
    plan = _plan(
        _config_entry("encodedPayload"),
        {"field": "payloadDigest",
         "source": {"kind": "derive", "fn": "sha256",
                    "args": [{"$apply": {"fn": "base64url_decode",
                                         "args": [{"$input": "encodedPayload"}]}}]}},
        {"field": "literalDigest",
         "source": {"kind": "derive", "fn": "sha256",
                    "args": [{"$apply": {"fn": "base64url_decode",
                                         "args": ["YS1saXRlcmFs"]}}]}},
    )
    ctx = FetchContext(config={"encodedPayload": _b64u(b"the-payload")})
    assembled = await FetchExecutor().assemble(plan, ctx)
    assert assembled["payloadDigest"] == hashlib.sha256(b"the-payload").hexdigest()
    assert assembled["literalDigest"] == hashlib.sha256(b"a-literal").hexdigest()


async def test_derive_is_guard_aware(key):
    """A derived field whose ``$input`` reads an omitted optional credential is
    omitted too, exactly as a wallet lookup on one is."""
    plan = _plan(
        {"field": "authorizationVC",
         "source": {"kind": "call"},
         "guard": {"always": False, "required_in_tiers": [1],
                   "deciding_checks": ["t1.c7"]}},
        {"field": "authorizationDigest",
         "source": {"kind": "derive", "fn": "sha256",
                    "args": [{"$input": "authorizationVC.jws"}]}},
    )
    assembled = await FetchExecutor().assemble(plan, FetchContext(envelope={}))
    assert assembled == {}

    req = vc.request_vc(args={"amountCents": 1}, key=key)
    ctx = FetchContext(envelope={"authorizationVC": {"jws": req["jws"]}})
    assembled = await FetchExecutor().assemble(plan, ctx)
    assert assembled["authorizationDigest"] == hashlib.sha256(
        req["jws"].encode()
    ).hexdigest()


async def test_derive_unsatisfiable_primitive_fails_closed():
    """``verify_webauthn`` needs a configured relying party; without one there
    is no implementation, and a plan naming it cannot be assembled. (A bundle
    is refused for this at load — this is the resolver's own backstop.)"""
    plan = _plan(
        _config_entry("candidates"),
        {"field": "approvers",
         "source": {"kind": "derive", "fn": "verify_webauthn",
                    "over": {"$input": "candidates"},
                    "args": ["ad", "cd", "sig", {"$item": "jwk"}],
                    "project": "did"}},
        primitives={"verify_webauthn": {"class": "key-consuming"}},
    )
    ctx = FetchContext(config={"candidates": [{"did": "did:key:z1", "jwk": {}}]})
    with pytest.raises(FetchError, match="no registered implementation"):
        await FetchExecutor().assemble(plan, ctx)


async def test_derive_refuses_a_bare_key_consuming_primitive_at_runtime_too():
    """Defence in depth: this plan is refused at ``PolicyBundle.load``, so
    reaching the resolver means it never went through a bundle."""
    plan = _plan(
        _config_entry("invoiceCanonical"), _config_entry("invoiceSignature"),
        {"field": "invoiceSignatureOK",
         "source": {"kind": "derive", "fn": "verify_ed25519_raw",
                    "args": [{"$input": "invoiceCanonical"},
                             {"$input": "invoiceSignature"}, "AAAA"]}},
    )
    key = _merchant_key()
    with pytest.raises(FetchError, match="may not be applied bare"):
        await FetchExecutor().assemble(plan, _invoice_ctx(key))


async def test_derive_over_a_non_list_fails_closed():
    plan = _plan(
        _config_entry("trustedMerchants"), _config_entry("invoiceCanonical"),
        _config_entry("invoiceSignature"), _SIGNER_IDS_ENTRY,
    )
    key = _merchant_key()
    ctx = _invoice_ctx(key)
    ctx.config["trustedMerchants"] = {"merchantId": MERCHANT_ID, "key": "AAAA"}
    with pytest.raises(FetchError, match="not a list of candidates"):
        await FetchExecutor().assemble(plan, ctx)


async def test_derive_candidate_missing_the_projected_field_fails_closed():
    """The candidate list is config- or wallet-sourced, never LLM-supplied, so
    one missing its witness field is a malformed deployment input."""
    key = _merchant_key()
    ctx = _invoice_ctx(key)
    ctx.config["trustedMerchants"] = [
        {"key": _b64u(key.public_key().public_bytes_raw())}  # no merchantId
    ]
    with pytest.raises(FetchError, match="candidate has no field"):
        await FetchExecutor().assemble(
            _plan(_config_entry("invoiceCanonical"), _config_entry("invoiceSignature"),
                  _config_entry("trustedMerchants"), _SIGNER_IDS_ENTRY),
            ctx,
        )


# -- validate_derive_plan ---------------------------------------------------- #


def test_validate_accepts_the_bare_folded_and_composed_forms():
    validate_derive_plan(
        _plan(_config_entry("invoiceCanonical"), _config_entry("invoiceSignature"),
              _config_entry("trustedMerchants"), _SIGNER_IDS_ENTRY, _PARSED_ENTRY)
    )
    validate_derive_plan(_membership_plan())


def test_validate_passes_a_plan_that_declares_nothing_and_derives_nothing():
    """Every shipped bundle predates the source kind; none may start failing."""
    validate_derive_plan(PLAN)


def test_validate_rejects_an_undeclared_primitive():
    plan = _plan(
        _config_entry("jws"),
        {"field": "digest",
         "source": {"kind": "derive", "fn": "sha256", "args": [{"$input": "jws"}]}},
        primitives=["parse_json"],
    )
    with pytest.raises(DerivePlanError, match="not declared"):
        validate_derive_plan(plan)


def test_validate_rejects_two_levels_of_apply():
    plan = dict(_membership_plan())
    plan["entries"] = list(plan["entries"])
    plan["entries"][-1] = {
        "field": "membershipSignerDids",
        "source": {"kind": "derive", "fn": "verify_eddsa",
                   "over": {"$input": "candidateMemberships"},
                   "args": [{"$input": "membershipJws"},
                            {"$apply": {"fn": "key_from_did_key",
                                        "args": [{"$apply": {
                                            "fn": "base64url_decode",
                                            "args": [{"$item": "did"}]}}]}}],
                   "project": "did"},
    }
    with pytest.raises(DerivePlanError, match="nests one level only"):
        validate_derive_plan(plan)


def test_validate_rejects_item_outside_a_folded_entry():
    plan = _plan(
        {"field": "digest",
         "source": {"kind": "derive", "fn": "sha256", "args": [{"$item": "key"}]}},
    )
    with pytest.raises(DerivePlanError, match="outside a folded entry"):
        validate_derive_plan(plan)


def test_validate_rejects_a_folded_entry_with_no_projection():
    plan = _plan(
        _config_entry("invoiceCanonical"), _config_entry("invoiceSignature"),
        _config_entry("trustedMerchants"),
        {"field": "invoiceSignerIds",
         "source": {"kind": "derive", "fn": "verify_ed25519_raw",
                    "over": {"$input": "trustedMerchants"},
                    "args": [{"$input": "invoiceCanonical"},
                             {"$input": "invoiceSignature"}, {"$item": "key"}]}},
    )
    with pytest.raises(DerivePlanError, match="must 'project' a witness"):
        validate_derive_plan(plan)


def test_validate_rejects_an_unknown_argument_marker():
    plan = _plan(
        _config_entry("jws"),
        {"field": "digest",
         "source": {"kind": "derive", "fn": "sha256", "args": [{"$inputt": "jws"}]}},
    )
    with pytest.raises(DerivePlanError, match="unknown argument marker"):
        validate_derive_plan(plan)


def _one_key_fold(over_element):
    return _plan(
        _config_entry("jws"),
        {"field": "witnesses",
         "source": {"kind": "derive", "fn": "verify_eddsa",
                    "over": [over_element],
                    "args": [{"$input": "jws"}, {"$item": "key"}],
                    "project": "key"}},
    )


def test_validate_rejects_apply_inside_an_over_element():
    """Refused for the shape, before any availability check -- which is what
    keeps ``_referenced_primitives`` honest. It does not walk ``over``
    elements, so an ``$apply`` there would name a primitive the availability
    check never sees; the inner primitive here has no implementation without a
    relying-party id, and on a resolving ``over`` it would have passed
    validation and failed on the first real call."""
    plan = _one_key_fold(
        {"key": {"$apply": {"fn": "verify_webauthn", "args": []}}}
    )
    plan["primitives"] = {**plan["primitives"],
                          "verify_webauthn": {"class": "key-consuming"}}
    with pytest.raises(DerivePlanError, match="no meaning inside an 'over' element"):
        validate_derive_plan(plan)


def test_validate_rejects_item_inside_an_over_element():
    plan = _one_key_fold({"key": {"$item": "key"}})
    with pytest.raises(DerivePlanError, match="names the element being defined"):
        validate_derive_plan(plan)


def test_validate_rejects_an_over_element_with_an_empty_input_path():
    plan = _one_key_fold({"key": {"$input": ""}})
    with pytest.raises(DerivePlanError, match="must be a field path"):
        validate_derive_plan(plan)


def test_validate_rejects_a_marked_over_element_carrying_a_second_key():
    plan = _one_key_fold({"$input": "trustRootJwk", "key": "AAAA"})
    with pytest.raises(DerivePlanError, match="more than one key"):
        validate_derive_plan(plan)


def test_validate_accepts_input_inside_an_over_element_at_depth():
    """The shape the resolver will walk is the shape that was checked: a
    nested object and a list of candidates both pass."""
    validate_derive_plan(_one_key_fold({"meta": {"key": {"$input": "root.jwk"}}}))
    validate_derive_plan(_one_key_fold({"key": "AAAA"}))


# -- two entries, one field: refused at load, whatever the kinds (#31) ------- #
#
# ``assemble`` walks entries in order into one map, so the second writer wins
# and the rule reads a value computed for different arguments. Nothing raises,
# the manifest sees one property, and the verdict answers a question nobody
# asked -- the toolchain shipped six folds over one shared candidate domain
# that all generated the same field name, so five leaves were checking the
# wrong credential's signature. Their generator is fixed; this is the
# independent guard on the consuming side, and it is kind-agnostic because a
# ``call``/``call`` pair collapses identically.


def _derive_digest(field, of):
    return {"field": field,
            "source": {"kind": "derive", "fn": "sha256", "args": [{"$input": of}]}}


def test_validate_rejects_two_derive_entries_sharing_a_field():
    plan = _plan(
        _config_entry("jwsA"), _config_entry("jwsB"),
        _derive_digest("digest", "jwsA"), _derive_digest("digest", "jwsB"),
    )
    with pytest.raises(DerivePlanError, match=r"'digest' twice.*'derive'.*'derive'"):
        validate_derive_plan(plan)


def test_validate_rejects_two_call_entries_sharing_a_field():
    """Not confined to ``derive``: the kinds are named in the message so the
    author sees which two entries collided."""
    plan = _plan(
        {"field": "requestVC", "source": {"kind": "call"}},
        {"field": "requestVC", "source": {"kind": "call"}},
    )
    with pytest.raises(DerivePlanError, match=r"'requestVC' twice.*'call'.*'call'"):
        validate_derive_plan(plan)


def test_validate_rejects_a_call_and_a_wallet_entry_sharing_a_field():
    plan = _plan(
        {"field": "membership", "source": {"kind": "call"}},
        {"field": "membership", "source": {"kind": "wallet", "params": {}}},
    )
    with pytest.raises(DerivePlanError, match=r"'membership' twice.*'call'.*'wallet'"):
        validate_derive_plan(plan)


def test_validate_accepts_distinct_fields_of_the_same_shape():
    """The refusal is on the name, not on two entries looking alike."""
    validate_derive_plan(_plan(
        _config_entry("jwsA"), _config_entry("jwsB"),
        _derive_digest("digestA", "jwsA"), _derive_digest("digestB", "jwsB"),
    ))


# -- undefined: a parse that cannot read its evidence omits the field (#36) -- #
#
# OPA's ``json.unmarshal`` and ``base64url.decode`` are *undefined* on content
# they cannot read: the rule body that read them does not fire and every other
# rule is untouched. The derive twins are Python reimplementations of those
# natives, so that verdict has to be reproduced rather than inherited. ``None``
# written into the closed input would not reproduce it -- ``null`` is a
# defined value, truthy as a bare Rego term and present to a Cedar ``has`` --
# so the resolver omits the field instead, the way a dependent of an absent
# optional credential is already omitted. Measured before the change: a bare
# parse wrote ``null``, the same parse under ``$apply`` was a type fault in
# the consumer, and a later field reading through the ``null`` was omitted.

_GARBAGE = FetchContext(envelope={"raw": "not json", "b64": "not-base64-!!!"})


def _garbage_plan(*entries):
    return _plan(
        {"field": "raw", "source": {"kind": "call"}},
        {"field": "b64", "source": {"kind": "call"}},
        *entries,
    )


def _bare(field, fn, of):
    return {"field": field, "source": {"kind": "derive", "fn": fn, "args": [{"$input": of}]}}


async def test_bare_parse_of_garbage_omits_the_field_rather_than_writing_null():
    assembled = await FetchExecutor().assemble(
        _garbage_plan(_bare("parsed", "parse_json", "raw")), _GARBAGE)
    assert "parsed" not in assembled
    assert assembled["raw"] == "not json"


async def test_bare_decode_of_garbage_omits_the_field_too():
    assembled = await FetchExecutor().assemble(
        _garbage_plan(_bare("decoded", "base64url_decode", "b64")), _GARBAGE)
    assert "decoded" not in assembled


async def test_undefined_under_apply_makes_the_consumer_undefined_not_a_fault():
    """Before: ``sha256`` received ``None`` and raised a type fault, so garbage
    in evidence reached the model as an engine error. Undefined feeds
    undefined, as ``sha256(json.unmarshal(garbage))`` is in Rego."""
    plan = _garbage_plan({"field": "digest", "source": {
        "kind": "derive", "fn": "sha256",
        "args": [{"$apply": {"fn": "parse_json", "args": [{"$input": "raw"}]}}]}})
    assert "digest" not in await FetchExecutor().assemble(plan, _GARBAGE)


async def test_a_field_reading_an_undefined_field_is_omitted_in_turn():
    plan = _garbage_plan(
        _bare("parsed", "parse_json", "raw"),
        _bare("expDigest", "sha256", "parsed.exp"),
    )
    assembled = await FetchExecutor().assemble(plan, _GARBAGE)
    assert "parsed" not in assembled and "expDigest" not in assembled


async def test_an_undefined_candidate_is_no_witness_and_the_fold_goes_on():
    """Inside a fold, undefined for one candidate skips that candidate --
    the Rego comprehension's behaviour -- and the rule's membership check
    over what was collected is what fails closed. Here the signature is
    garbage, so decoding it is undefined for every candidate and the
    witness list is empty rather than the assembly faulting."""
    key = _merchant_key()
    ctx = _invoice_ctx(key)
    ctx.config["invoiceSignature"] = "not-base64-!!!"
    entry = json.loads(json.dumps(_SIGNER_IDS_ENTRY))
    entry["source"]["args"][1] = {"$apply": {"fn": "base64url_decode",
                                             "args": [{"$input": "invoiceSignature"}]}}
    plan = _plan(_config_entry("invoiceCanonical"), _config_entry("invoiceSignature"),
                 _config_entry("trustedMerchants"), entry)
    assembled = await FetchExecutor().assemble(plan, ctx)
    assert assembled["invoiceSignerIds"] == []


async def test_a_non_string_operand_is_still_a_fault_not_undefined():
    """The line between evidence and fault is unchanged: a plan that hands a
    parser the wrong *type* is broken, and fails the assembly closed."""
    plan = _garbage_plan(_bare("parsed", "parse_json", "raw"))
    with pytest.raises(FetchError, match="expects a string") as info:
        await FetchExecutor().assemble(plan, FetchContext(envelope={"raw": 12, "b64": ""}))
    assert not isinstance(info.value, DeriveUndefined)


def test_the_registry_union_claim_is_exactly_the_seven():
    """``default_primitives`` shares seven implementations with the engines by
    construction; the other four are reimplementations of OPA natives the
    Rego engine never imports. Pinned so the docstring's count stays true."""
    derive = default_primitives()
    rego = default_builtins()
    shared = {"sha256": "crypto.sha256", "verify_eddsa": "io.jwt.verify_eddsa",
              "verify_es256": "io.jwt.verify_es256",
              "verify_rs256": "io.jwt.verify_rs256",
              "verify_ed25519_raw": "verify_ed25519_raw",
              "key_from_did_key": "key_from_did_key",
              "base64url_encode_no_pad": "base64url.encode_no_pad"}
    for atom, builtin in shared.items():
        assert derive[atom] is rego[builtin], atom
    reimplemented = {"parse_json", "base64url_decode", "concat", "format_int"}
    assert set(derive) - set(shared) == reimplemented
    assert not (reimplemented | {"json.unmarshal", "base64url.decode"}) & set(rego)
    # CEL carries the seven plus the two parsers under the atom names -- as
    # adapters, which is why the parsers can answer an error value there and
    # None here. `concat` and `format_int` have no CEL twin: CEL concatenates
    # with `+` natively and formats nothing, so there is no function to adapt.
    assert set(default_cel_functions()) >= set(derive) - {"concat", "format_int"}
    assert not {"concat", "format_int"} & set(default_cel_functions())




# -- concat and format_int: reimplemented OPA natives, held to OPA (#27) ----- #
#
# Neither is a host import: a Rego bundle compiles both into its wasm, so the
# Python copies exist only for the derive path and their agreement with OPA
# has to be established by test. They sit on the path that computes a digest
# the rule compares, where a disagreement does not fail loudly -- it produces
# a different hash and a denial nobody can read. Every row below was measured
# against OPA 1.17.1 with ``opa eval``; the wasm-path differential lives in
# test_webauthn_policy.py and test_vc_policy.py, against the real bundles.

_CONCAT = default_primitives()["concat"]
_FORMAT_INT = default_primitives()["format_int"]


@pytest.mark.parametrize("delim, parts, expected", [
    ("|", ["a", "b", "c"], "a|b|c"),
    ("", ["sha256:", "dead"], "sha256:dead"),
    ("|", [], ""),
    ("|", ["a"], "a"),
    ("", [], ""),
])
def test_concat_agrees_with_opa(delim, parts, expected):
    assert _CONCAT(delim, parts) == expected


@pytest.mark.parametrize("delim, parts", [
    ("|", ["a", 12]),          # rego_type_error: OPA does not coerce
    ("|", ["a", None]),
    ("|", ["a", True]),
    ("|", ["a", ["b"]]),
    (12, ["a", "b"]),
    ("|", "ab"),               # a string is not an array
])
def test_concat_refuses_what_opa_refuses(delim, parts):
    """The drift a reimplementation would introduce is a helpful ``str(x)``;
    this is the guard against helpfulness."""
    with pytest.raises(HostBuiltinError, match="concat expects"):
        _CONCAT(delim, parts)


@pytest.mark.parametrize("value, base, expected", [
    (12, 10, "12"),
    (0, 10, "0"),
    (255, 16, "ff"),           # lowercase
    (-5, 16, "-5"),            # sign-magnitude, not two's complement
    (12, 2, "1100"),
    (12, 8, "14"),
    (9007199254740993, 10, "9007199254740993"),   # beyond 2**53, exact as an int
    (10 ** 23, 10, "100000000000000000000000"),
])
def test_format_int_agrees_with_opa_on_integers(value, base, expected):
    assert _FORMAT_INT(value, base) == expected


@pytest.mark.parametrize("base", [7, 1, 0, 10.0])
def test_format_int_unsupported_base_is_undefined_not_a_fault(base):
    """Measured: ``format_int(12, 7)`` is undefined in OPA -- no error, no
    value -- and so is a non-integer base. A raise here would turn a quiet
    undefined into a loud, misattributed "could not be assembled"."""
    assert _FORMAT_INT(12, base) is None


@pytest.mark.parametrize("value, base", [("12", 10), (True, 10), (None, 10), (12, "10"), (12, None)])
def test_format_int_type_errors_are_faults(value, base):
    with pytest.raises(HostBuiltinError, match="format_int expects"):
        _FORMAT_INT(value, base)


@pytest.mark.parametrize("value", [1.9999999999999999, 1e23, 12.0, 12.5, -0.5])
def test_format_int_refuses_a_float_because_the_exact_number_is_gone(value):
    """OPA formats ``1.9999999999999999`` as ``"1"`` and ``1e23`` as
    ``"100000000000000000000000"``, from the decimal literal. By the time a
    number reaches this function it is a float64: ``2.0`` and
    ``99999999999999991611392``. ``12.0`` is refused with them, because an
    integral float is exactly where the first case hides, and the manifest's
    ``integer`` accepts it. A fault, not undefined: the evidence was fine,
    the transport dropped the digits."""
    with pytest.raises(HostBuiltinError, match="as a float"):
        _FORMAT_INT(value, 10)


async def test_concat_takes_a_literal_array_whose_elements_resolve_three_ways():
    """The toolchain's WebAuthn challenge pre-image, as it emits it: literal
    strings, ``$input`` references and a nested ``$apply`` inside one array."""
    plan = _plan(
        {"field": "tool", "source": {"kind": "call"}},
        {"field": "arguments", "source": {"kind": "call"}},
        {"field": "preimage", "source": {"kind": "derive", "fn": "concat", "args": [
            "|", ["legov1", "spend", {"$input": "tool"},
                  {"$apply": {"fn": "format_int", "args": [{"$input": "arguments.amountCents"}, 10]}},
                  {"$input": "arguments.merchant"}]]}},
    )
    ctx = FetchContext(envelope={"tool": "spend", "arguments": {"amountCents": 5000, "merchant": "acme"}})
    assembled = await FetchExecutor().assemble(plan, ctx)
    assert assembled["preimage"] == "legov1|spend|spend|5000|acme"


def test_format_int_inside_an_array_counts_as_referenced():
    """A primitive applied inside a list operand is still an invocation: the
    availability check must see it, or an unimplemented one would pass load."""
    from extensible_mcp.fetchplan import _referenced_primitives
    plan = _plan({"field": "x", "source": {"kind": "derive", "fn": "concat", "args": [
        "|", [{"$apply": {"fn": "format_int", "args": [{"$input": "n"}, 10]}}]]}})
    assert _referenced_primitives(plan) == {"concat", "format_int"}


@pytest.mark.parametrize("args, match", [
    (["|", "a", "b"], "got 3 argument"),                       # variadic spelling
    (["|"], "got 1 argument"),
    (["|", "ab"], "takes an array"),
    ([["|"], ["a"]], "delimiter must be a string"),
])
def test_load_refuses_a_concat_that_is_not_regos_signature(args, match):
    plan = _plan({"field": "x", "source": {"kind": "derive", "fn": "concat", "args": args}})
    with pytest.raises(DerivePlanError, match=match):
        validate_derive_plan(plan)


@pytest.mark.parametrize("args, match", [
    ([{"$input": "n"}], "got 1 argument"),                      # base omitted
    ([{"$input": "n"}, 10, 2], "got 3 argument"),
    ([{"$input": "n"}, "10"], "literal integer"),
    ([{"$input": "n"}, 10.0], "literal integer"),
    ([{"$input": "n"}, True], "literal integer"),
    ([{"$input": "n"}, 7], "not one OPA supports"),
])
def test_load_refuses_a_format_int_that_is_not_regos_signature(args, match):
    plan = _plan({"field": "x", "source": {"kind": "derive", "fn": "format_int", "args": args}})
    with pytest.raises(DerivePlanError, match=match):
        validate_derive_plan(plan)


def test_load_refuses_the_same_shapes_under_apply():
    plan = _plan({"field": "x", "source": {"kind": "derive", "fn": "sha256", "args": [
        {"$apply": {"fn": "format_int", "args": [{"$input": "n"}]}}]}})
    with pytest.raises(DerivePlanError, match="got 1 argument"):
        validate_derive_plan(plan)
    plan = _plan({"field": "x", "source": {"kind": "derive", "fn": "sha256", "args": [
        {"$apply": {"fn": "concat", "args": ["|", "a", "b"]}}]}})
    with pytest.raises(DerivePlanError, match="got 3 argument"):
        validate_derive_plan(plan)


def test_load_accepts_the_toolchains_two_emitted_shapes():
    """The two call sites upstream emits, verbatim."""
    validate_derive_plan(_plan(
        {"field": "requestVCJwsDigest", "source": {"kind": "derive", "fn": "sha256",
                                                   "args": [{"$input": "requestVC.jws"}]}},
        {"field": "requestVCJwsDigestConcat", "source": {"kind": "derive", "fn": "concat",
            "args": ["", ["sha256:", {"$input": "requestVCJwsDigest"}]]}},
        {"field": "toolFormattedConcat", "source": {"kind": "derive", "fn": "concat",
            "args": ["|", ["legov1", "spend", {"$input": "tool"},
                           {"$apply": {"fn": "format_int", "args": [{"$input": "arguments.amountCents"}, 10]}},
                           {"$input": "arguments.merchant"}]]}},
    ))


# -- the refusals, where they actually have to happen: PolicyBundle.load ------ #
#
# A plan whose derived fields are shaped wrong is a bundle that must never
# govern a call, so it is refused when it is loaded — not when a call first
# reaches the unsafe entry. Same discipline as an unregistered host built-in.


def _bundle_dir(tmp_path, plan):
    """A real loadable bundle (the family_spend artifacts) with one planted
    fetch plan."""
    d = tmp_path / "derive_bundle"
    shutil.copytree(FIXTURE_DIR, d)
    (d / "fetchplan.json").write_text(json.dumps(plan))
    return d


def test_load_accepts_a_well_formed_derive_plan(tmp_path):
    plan = _plan(
        _config_entry("invoiceCanonical"), _config_entry("invoiceSignature"),
        _config_entry("trustedMerchants"), _SIGNER_IDS_ENTRY, _PARSED_ENTRY,
    )
    bundle = PolicyBundle.load(_bundle_dir(tmp_path, plan))
    assert bundle.fetchplan["entries"][-2]["source"]["fn"] == "verify_ed25519_raw"


def test_load_refuses_two_entries_sharing_a_field(tmp_path):
    """At load, not at assemble: a plan that cannot be right must not reach a
    call. The bundle is otherwise loadable, so the duplicate is the reason."""
    plan = _plan(
        _config_entry("invoiceCanonical"), _config_entry("invoiceCanonical"),
    )
    with pytest.raises(DerivePlanError, match="'invoiceCanonical' twice"):
        PolicyBundle.load(_bundle_dir(tmp_path, plan))


def test_load_refuses_a_bare_key_consuming_primitive(tmp_path):
    """There is no bare-boolean form of verification in the format at all: a
    single-trust-root deployment writes a one-element candidate list and the
    rule checks membership. So there is nothing for an author to remember."""
    plan = _plan(
        _config_entry("invoiceCanonical"), _config_entry("invoiceSignature"),
        {"field": "invoiceSignatureOK",
         "source": {"kind": "derive", "fn": "verify_ed25519_raw",
                    "args": [{"$input": "invoiceCanonical"},
                             {"$input": "invoiceSignature"}, "AAAA"]}},
    )
    with pytest.raises(DerivePlanError, match="folded"):
        PolicyBundle.load(_bundle_dir(tmp_path, plan))


def test_load_refuses_a_bare_verification_the_bundle_declares_key_free(tmp_path):
    """The classification is proxy-owned.

    A generator bug is enough to emit ``verify_ed25519_raw`` as a pure
    primitive; if the bundle's own declaration decided the question, the plan
    would get a bare boolean back from a load that passed its own check — the
    merchant-swap failure one layer down.
    """
    plan = _plan(
        _config_entry("invoiceCanonical"), _config_entry("invoiceSignature"),
        {"field": "invoiceSignatureOK",
         "source": {"kind": "derive", "fn": "verify_ed25519_raw",
                    "args": [{"$input": "invoiceCanonical"},
                             {"$input": "invoiceSignature"}, "AAAA"]}},
        primitives={"verify_ed25519_raw": {"class": "pure"}},
    )
    with pytest.raises(DerivePlanError, match="consumes a key"):
        PolicyBundle.load(_bundle_dir(tmp_path, plan))


def test_load_refuses_a_key_producing_primitive_as_a_top_level_fn(tmp_path):
    """A derived key emitted as its own field floats free of the DID it came
    from: the rule would check ``verify(jws, signerKey)`` and, separately,
    ``signerDid in trustedDids``, with nothing relating the two — a trusted DID
    presented alongside an attacker's key passes."""
    plan = _plan(
        _config_entry("signerDid"),
        {"field": "signerKey",
         "source": {"kind": "derive", "fn": "key_from_did_key",
                    "args": [{"$input": "signerDid"}]}},
    )
    with pytest.raises(DerivePlanError, match=r"only inside '\$apply'"):
        PolicyBundle.load(_bundle_dir(tmp_path, plan))


def test_load_refuses_a_key_producing_primitive_folded(tmp_path):
    """Folding it does not rescue it: the witness would still be the key."""
    plan = _plan(
        _config_entry("candidates"),
        {"field": "signerKeys",
         "source": {"kind": "derive", "fn": "key_from_did_key",
                    "over": {"$input": "candidates"},
                    "args": [{"$item": "did"}], "project": "did"}},
    )
    with pytest.raises(DerivePlanError, match="produces a key"):
        PolicyBundle.load(_bundle_dir(tmp_path, plan))


def test_load_refuses_an_fn_used_but_not_declared(tmp_path):
    plan = _plan(
        _config_entry("jws"),
        {"field": "digest",
         "source": {"kind": "derive", "fn": "sha256", "args": [{"$input": "jws"}]}},
        primitives=["parse_json"],
    )
    with pytest.raises(DerivePlanError, match="not declared"):
        PolicyBundle.load(_bundle_dir(tmp_path, plan))


def test_load_refuses_a_declared_primitive_the_proxy_cannot_satisfy(tmp_path):
    """``verify_webauthn`` exists only once a relying party is configured, so
    a bundle declaring it without one fails at load rather than denying
    quietly at the first call — and loads when the deployment supplies it."""
    plan = _plan(
        _config_entry("candidates"),
        {"field": "approverDids",
         "source": {"kind": "derive", "fn": "verify_webauthn",
                    "over": {"$input": "candidates"},
                    "args": [{"$input": "authData"}, {"$input": "clientDataJSON"},
                             {"$input": "signature"}, {"$item": "jwk"}],
                    "project": "did"}},
        primitives={"verify_webauthn": {"class": "key-consuming"}},
    )
    d = _bundle_dir(tmp_path, plan)
    with pytest.raises(DerivePlanError, match="no implementation for"):
        PolicyBundle.load(d)
    bundle = PolicyBundle.load(
        d, primitives=default_primitives(webauthn_rp_id="example.com")
    )
    assert bundle.name == "derive_bundle"


def test_load_still_accepts_every_shipped_fetch_plan():
    """The source kind is additive for the engines that run crypto in-policy:
    the rego and cel bundles keep their host builtins and never derive. Only
    a Cedar bundle derives, because Cedar cannot call a host function — and
    every Cedar bundle must, or its crypto leaves would be unstated."""
    plans = sorted((Path(__file__).parent / "fixtures").glob("*/fetchplan.json"))
    assert plans  # the corpus is the point of the assertion
    for path in plans:
        plan = json.loads(path.read_text())
        validate_derive_plan(plan)
        derives = [e for e in plan["entries"] if e["source"]["kind"] == "derive"]
        if (path.parent / "policy.cedar").exists():
            assert derives, f"{path} is a Cedar plan that hoists nothing"
        else:
            assert not derives, f"{path} uses derive; the migration is explicitly out of scope"
    assert PolicyBundle.load(FIXTURE_DIR).fetchplan["entries"]


# -- the 'primitives' block declares a vocabulary, not a registry request ----- #
#
# ``fetchplan.json`` is byte-identical between a rego bundle and its cel
# counterpart, so the block can only carry the union of what the policy reaches
# across both engines — including primitives the policy invokes *inside* itself,
# as host built-ins, with no ``derive`` entry anywhere in the plan. Requiring
# every declared name of the **derive** registry refused such a bundle from a
# deployment that had configured the engine correctly (#24).
#
# The two checks ask different questions, and the engine asks its own first:
# ``OpaWasmPolicy._verify_builtins_available`` fails closed on a built-in the
# policy actually calls, parsed out of the wasm, before ``validate_derive_plan``
# runs at all. So availability is required of what a ``derive`` entry invokes,
# and an unimplemented declaration beyond that is logged.

WA_FIXTURE_DIR = Path(__file__).parent / "fixtures" / "family_spend_webauthn"
WA_RP_ID = "approval.example"

# The block upstream emits for ``rego/family_spend_webauthn/fetchplan.json``:
# every primitive the policy reaches, whether or not the plan derives with it.
# In the toolchain's atom names, which is the vocabulary a ``derive`` entry
# names — not the Rego built-in names the engine registry is keyed by, where
# these are ``crypto.sha256`` / ``io.jwt.verify_eddsa`` /
# ``base64url.encode_no_pad``. Inline rather than added to the fixture, which
# is pinned at an upstream commit predating the block — so this holds before
# the bundles carrying it are adopted.
WA_DECLARED_PRIMITIVES = {
    "verify_webauthn": {"class": "key-consuming"},
    "verify_eddsa": {"class": "key-consuming"},
    "sha256": {"class": "pure"},
    "parse_json": {"class": "pure"},
    "key_from_did_key": {"class": "key-producing"},
    "base64url_encode_no_pad": {"class": "pure"},
    "base64url_decode": {"class": "pure"},
}

_WEBAUTHN_FOLDED_ENTRY = {
    "field": "approverDids",
    "source": {"kind": "derive", "fn": "verify_webauthn",
               "over": {"$input": "candidates"},
               "args": [{"$input": "authenticatorData"},
                        {"$input": "clientDataJSON"},
                        {"$input": "signature"}, {"$item": "jwk"}],
               "project": "did"},
}


def _webauthn_bundle_dir(tmp_path, *entries):
    """The real family_spend_webauthn bundle with the upstream ``primitives``
    block added, and any extra entries appended. Nothing else changes."""
    d = tmp_path / "family_spend_webauthn"
    shutil.copytree(WA_FIXTURE_DIR, d)
    plan = json.loads((d / "fetchplan.json").read_text())
    assert not [
        e for e in plan["entries"] if e["source"]["kind"] == "derive"
    ], "the fixture derives nothing — that is what makes this a regression"
    plan["primitives"] = WA_DECLARED_PRIMITIVES
    plan["entries"] = plan["entries"] + list(entries)
    (d / "fetchplan.json").write_text(json.dumps(plan))
    return d


def test_load_accepts_a_declared_primitive_no_entry_derives(tmp_path, caplog):
    """The regression: ``verify_webauthn`` is declared, the policy calls it as
    a host built-in, and the plan has no ``derive`` entry at all. Loaded the way
    every existing call site loads it — ``builtins`` configured, ``primitives``
    not, which is correct, because the bundle does not derive."""
    d = _webauthn_bundle_dir(tmp_path)
    with caplog.at_level(logging.WARNING, logger="extensible_mcp.fetchplan"):
        bundle = PolicyBundle.load(
            d, name="family_spend_webauthn",
            builtins=default_builtins(webauthn_rp_id=WA_RP_ID),
        )
    assert bundle.name == "family_spend_webauthn"
    # Logged, because a deployment that *meant* to derive with it is missing an
    # RP id and should hear about it — but not obeyed.
    assert "verify_webauthn" in caplog.text
    assert "no derive implementation" in caplog.text


def test_load_refuses_the_same_bundle_once_an_entry_derives_with_it(tmp_path):
    """The requirement is scoped, not dropped. One folded entry invoking
    ``verify_webauthn``, the same declaration, the same configured engine — and
    the bundle is refused, because the *derive* registry has no relying party."""
    d = _webauthn_bundle_dir(tmp_path, _WEBAUTHN_FOLDED_ENTRY)
    with pytest.raises(DerivePlanError, match="no implementation for"):
        PolicyBundle.load(
            d, name="family_spend_webauthn",
            builtins=default_builtins(webauthn_rp_id=WA_RP_ID),
        )
    bundle = PolicyBundle.load(
        d, name="family_spend_webauthn",
        builtins=default_builtins(webauthn_rp_id=WA_RP_ID),
        primitives=default_primitives(webauthn_rp_id=WA_RP_ID),
    )
    assert bundle.fetchplan["entries"][-1]["source"]["fn"] == "verify_webauthn"


def test_validate_refuses_an_unimplemented_primitive_inside_apply():
    """A reference is a top-level ``fn`` *or* an ``$apply.fn``: a primitive the
    proxy cannot satisfy is no more acceptable one level in."""
    plan = _plan(
        _config_entry("membershipJws"), _config_entry("candidateMemberships"),
        {"field": "membershipSignerDids",
         "source": {"kind": "derive", "fn": "verify_eddsa",
                    "over": {"$input": "candidateMemberships"},
                    "args": [{"$input": "membershipJws"},
                             {"$apply": {"fn": "key_from_did_web",
                                         "args": [{"$item": "did"}]}}],
                    "project": "did"}},
        primitives={"verify_eddsa": {"class": "key-consuming"},
                    "key_from_did_web": {"class": "key-producing"}},
    )
    with pytest.raises(DerivePlanError, match="no implementation for"):
        validate_derive_plan(plan)


def test_validate_still_refuses_a_derive_entry_with_no_primitives_block():
    """Deriving without declaring a vocabulary is still a load-time refusal:
    scoping the availability requirement did not touch ``_require_declared``."""
    plan = _plan(
        _config_entry("jws"),
        {"field": "digest",
         "source": {"kind": "derive", "fn": "sha256", "args": [{"$input": "jws"}]}},
    )
    del plan["primitives"]
    with pytest.raises(DerivePlanError, match="not declared"):
        validate_derive_plan(plan)


def test_validate_warns_rather_than_refusing_an_unimplemented_declaration(caplog):
    plan = _plan(
        _config_entry("jws"),
        primitives={"verify_webauthn": {"class": "key-consuming"}},
    )
    with caplog.at_level(logging.WARNING, logger="extensible_mcp.fetchplan"):
        validate_derive_plan(plan)
    assert "no derive implementation" in caplog.text


def test_validate_keeps_the_class_cross_check_advisory_for_an_unused_name(caplog):
    """The cross-check reports a disagreement for *every* declared name and
    obeys none of them — including a name nothing derives with."""
    plan = _plan(
        _config_entry("jws"), primitives={"verify_eddsa": {"class": "pure"}}
    )
    with caplog.at_level(logging.WARNING, logger="extensible_mcp.fetchplan"):
        validate_derive_plan(plan)
    assert "classifies it as 'key-consuming'" in caplog.text

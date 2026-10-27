# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Tests for the search-side BundleAugmenter: credential params + the
'what you need' description, including conditional guards."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from extensible_mcp.augment import BundleAugmenter
from extensible_mcp.bundle import PolicyBundle
from extensible_mcp.routing import BundleRouter
from extensible_mcp.selection import LayeredBundleSelector, RegoClassifier
from extensible_mcp.types import SearchResult, ToolRecord
from extensible_mcp.wasm_filter import WasmPolicyFilter
from tests import vc_helpers as vc

FIXTURES = Path(__file__).parent / "fixtures"
FAMILY_SPEND_DIR = FIXTURES / "family_spend"
CLASSIFIER_WASM = FIXTURES / "classifier" / "policy.wasm"


@pytest.fixture(scope="module")
def key():
    return vc.new_key()


def _router(key, bundle_dir: Path = FAMILY_SPEND_DIR) -> BundleRouter:
    """A router that governs ``payments`` with the family_spend bundle loaded
    from ``bundle_dir`` -- the shipped fixture, or a rewritten copy."""
    selector = LayeredBundleSelector(classifier=RegoClassifier(CLASSIFIER_WASM))

    def factory(name: str):
        if name != "family_spend":
            return None
        bundle = PolicyBundle.load(bundle_dir, name="family_spend")
        return WasmPolicyFilter(
            bundle,
            config={"trustRootDID": vc.TRUST_DID, "trustRootJwk": vc.public_jwk(key)},
        )

    r = BundleRouter(selector, factory)
    r.admit(server_name="payments", url="https://payments.example", how_loaded="static")
    return r


@pytest.fixture
def router(key):
    return _router(key)


def _result(server: str, tool: str = "send") -> SearchResult:
    return SearchResult(
        tool=ToolRecord(
            name=tool,
            qualified_name=f"{server}__{tool}",
            description="Send a payment.",
            input_schema={
                "type": "object",
                "properties": {"amountCents": {"type": "integer"}, "merchant": {"type": "string"}},
                "required": ["amountCents", "merchant"],
            },
            server_name=server,
        ),
        score=0.9,
    )


def test_injects_credential_params_for_governed_tool(router):
    aug = BundleAugmenter(router)
    [out] = aug.filter([_result("payments")], "send money")
    props = out.tool.input_schema["properties"]
    # native args preserved, credentials injected
    assert "amountCents" in props and "merchant" in props
    assert "requestVC" in props and "authorizationVC" in props


def test_always_required_credential_is_required(router):
    aug = BundleAugmenter(router)
    [out] = aug.filter([_result("payments")], "q")
    required = out.tool.input_schema["required"]
    assert "requestVC" in required  # always
    assert "authorizationVC" not in required  # conditional


def test_conditional_credential_describes_when(router):
    aug = BundleAugmenter(router)
    [out] = aug.filter([_result("payments")], "q")
    auth_desc = out.tool.input_schema["properties"]["authorizationVC"]["description"]
    # the deciding-check sentences from guidance.json are surfaced
    assert "Required only when" in auth_desc
    assert "amountCents" in auth_desc  # references the threshold condition


def test_description_lists_what_you_need(router):
    aug = BundleAugmenter(router)
    [out] = aug.filter([_result("payments")], "q")
    desc = out.tool.description
    assert "Always provide `requestVC`" in desc
    assert "Provide `authorizationVC` when" in desc


def test_ungoverned_tool_is_untouched(router):
    aug = BundleAugmenter(router)
    original = _result("weather", "forecast")
    [out] = aug.filter([original], "q")
    assert out is original  # not even rewrapped


def test_embedding_text_is_preserved(router):
    """Augmentation is presentation only — it must not change retrieval."""
    aug = BundleAugmenter(router)
    original = _result("payments")
    [out] = aug.filter([original], "q")
    assert out.tool.embedding_text == original.tool.embedding_text


def test_native_required_args_kept(router):
    aug = BundleAugmenter(router)
    [out] = aug.filter([_result("payments")], "q")
    required = out.tool.input_schema["required"]
    assert "amountCents" in required and "merchant" in required


# -- issuer roles + dependency edges (guidance's call_credentials) --------- #
# The family_spend fixture above predates call_credentials, so those tests
# double as fail-soft coverage; the prod bundle carries the derived records.


class _StubRouter:
    def __init__(self, bundle: PolicyBundle) -> None:
        self._bundle = bundle

    def bundle_for(self, server_name: str):
        return self._bundle if server_name == "payments" else None


@pytest.fixture(scope="module")
def prod_augmenter():
    bundle = PolicyBundle.load(FIXTURES / "family_spend_prod")
    return BundleAugmenter(_StubRouter(bundle))


def test_issuer_roles_rendered_in_description(prod_augmenter):
    [out] = prod_augmenter.filter([_result("payments")], "q")
    desc = out.tool.description
    assert "- Always provide `requestVC`, signed by the child." in desc
    assert "`authorizationVC`, signed by the parent, when" in desc


def test_dependency_edge_rendered_in_order(prod_augmenter):
    [out] = prod_augmenter.filter([_result("payments")], "q")
    desc = out.tool.description
    # requestVC listed before the credential that signs over it, and the
    # edge is spelled out
    assert desc.index("`requestVC`") < desc.index("`authorizationVC`")
    assert "obtain `requestVC` first — this credential signs over it" in desc


def test_credential_schema_names_the_signing_wallet(prod_augmenter):
    [out] = prod_augmenter.filter([_result("payments")], "q")
    props = out.tool.input_schema["properties"]
    assert "the child's wallet" in props["requestVC"]["description"]
    assert "the parent's wallet" in props["authorizationVC"]["description"]


def test_description_states_the_exact_action_identifier(router):
    # The policy binds the signed request's action to input.tool (the
    # unqualified name); the note must state the exact string so the LLM
    # never has to discover it by burning wallet approvals on wrong guesses.
    aug = BundleAugmenter(router)
    [out] = aug.filter([_result("payments")], "q")
    assert '`"send"`' in out.tool.description
    assert '`"payments__send"`' not in out.tool.description


def test_wire_schema_override_replaces_manifest_shape(router):
    # When the call path runs a translating adapter, the advertised schema
    # must be the wire shape ({token, membership}), not the policy shape the
    # manifest declares — advertising the policy shape misleads the LLM into
    # "fixing" a working call.
    wire = {
        "type": "object",
        "required": ["token"],
        "properties": {"token": {"type": "string"}, "membership": {"type": "string"}},
    }
    aug = BundleAugmenter(router, wire_schemas={"requestVC": wire})
    [out] = aug.filter([_result("payments")], "q")
    req = out.tool.input_schema["properties"]["requestVC"]
    assert "token" in req["properties"]
    assert "jws" not in req.get("properties", {})
    assert "Required" in req["description"]  # the requirement note still lands


def test_an_unemitted_credential_is_still_surfaced_with_its_schema(rewritten_bundle, key):
    """Hazard 2. The augmenter builds the parameter from the entry's own
    ``schema``, resolving ``$ref`` into the manifest's ``definitions``. With
    ``requestVC`` unemitted the manifest drops the property and keeps the
    definition, and the LLM must still be shown the credential, typed, and
    still be told it is required."""
    def plan(p):
        for e in p["entries"]:
            if e["field"] == "requestVC":
                e["emit"] = False

    def manifest(m):
        m["properties"].pop("requestVC")
        m["required"].remove("requestVC")

    d = rewritten_bundle(FAMILY_SPEND_DIR, plan=plan, manifest=manifest)
    definitions = json.loads((d / "manifest.json").read_text())["definitions"]
    assert "RequestVC" in definitions

    aug = BundleAugmenter(_router(key, d))
    [out] = aug.filter([_result("payments")], "q")
    schema = out.tool.input_schema
    assert "requestVC" in schema["required"]
    surfaced = schema["properties"]["requestVC"]
    assert surfaced["properties"] == definitions["RequestVC"]["properties"]
    assert surfaced["description"].startswith("Required:")
    assert "Always provide `requestVC`" in out.tool.description

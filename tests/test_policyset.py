# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""A policy set: the declaration is checked at load, every name it uses is
checked at bind, and a bound route governs exactly the tools it lists.

The fixture declaration routes two servers over one server type (the
``minimal_spend`` bundle) and names the committed classifier for the rest,
which is the shape the shipped demo has: more routes than bundles.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from extensible_mcp.augment import BundleAugmenter
from extensible_mcp.policyset import PolicySet, PolicySetError, Route, ServerType
from extensible_mcp.types import CallRequest, SearchResult, ToolRecord
from extensible_mcp.wasm_filter import WasmPolicyFilter
from tests import vc_helpers as vc

FIXTURES = Path(__file__).parent / "fixtures"
MINIMAL_SPEND = FIXTURES / "minimal_spend"
CLASSIFIER = FIXTURES / "classifier" / "policy.wasm"


@pytest.fixture(scope="module")
def key():
    return vc.new_key()


def _declaration(**overrides: Any) -> dict[str, Any]:
    base = {
        "selection": {
            "map_key": "origin_server",
            "map": {"payments": "payments-send", "refunds": "refunds-refund", "evil": "banned"},
        },
        "server_types": {"spend": {"path": str(MINIMAL_SPEND)}},
        "routes": {
            "payments-send": {"server_type": "spend", "tools": ["send"], "adapter": "plain"},
            "refunds-refund": {"server_type": "spend", "tools": ["refund"]},
        },
    }
    base.update(overrides)
    return base


def _routes_plus(name: str, route: dict[str, Any]) -> dict[str, Any]:
    """The base routes with one more, so the map still resolves and the
    refusal under test is the only one."""
    return {"routes": {**_declaration()["routes"], name: route}}


def _write(tmp_path: Path, declaration: dict[str, Any]) -> Path:
    path = tmp_path / "policyset.json"
    path.write_text(json.dumps(declaration))
    return path


def _spend_chain(key):
    def chain(bundle, route: Route, adapter):
        return WasmPolicyFilter(bundle, config={"requesterJwk": vc.public_jwk(key)})

    return chain


def _bound(tmp_path: Path, key, declaration: dict[str, Any] | None = None):
    policy_set = PolicySet.load(_write(tmp_path, declaration or _declaration()))
    return policy_set.bind(
        server_types={"spend": ServerType(chain=_spend_chain(key))},
        adapters={"plain": object()},
    )


def _call(server: str, tool: str, key, *, with_credential: bool = True) -> CallRequest:
    args: dict[str, Any] = {"amountCents": 500, "merchant": "acme"}
    if with_credential:
        args["requestVC"] = vc.request_vc(args={"amountCents": 500, "merchant": "acme"}, key=key)
    return CallRequest(tool_name=f"{server}__{tool}", arguments=args, server_name=server)


# --------------------------------------------------------------------------- #
# Load: the shape, and every cross-reference
# --------------------------------------------------------------------------- #


def test_the_declaration_loads_with_paths_resolved_against_the_file(tmp_path):
    bundles = tmp_path / "bundles"
    bundles.mkdir()
    (bundles / "spend").symlink_to(MINIMAL_SPEND, target_is_directory=True)
    declaration = _declaration(server_types={"spend": {"path": "bundles/spend"}})
    policy_set = PolicySet.load(_write(tmp_path, declaration))

    assert policy_set.server_types["spend"].path == bundles / "spend"
    assert policy_set.selection.map_key == "origin_server"
    assert policy_set.routes["payments-send"] == Route(
        name="payments-send", server_type="spend", tools=frozenset({"send"}), adapter="plain"
    )
    assert policy_set.routes["refunds-refund"].adapter is None


@pytest.mark.parametrize(
    "overrides, needle",
    [
        # Cross-references: the reason the three blocks share one file.
        (
            {"selection": {"map_key": "origin_server", "map": {"payments": "payment-send"}}},
            "names route 'payment-send', which 'routes' does not declare",
        ),
        (
            _routes_plus("r", {"server_type": "spen", "tools": ["send"]}),
            "names server type 'spen', which 'server_types' does not declare",
        ),
        # Shape.
        ({"extra": {}}, "unexpected field"),
        (_routes_plus("r", {"server_type": "spend", "tools": ["send"], "chain": []}), "unexpected field"),
        (_routes_plus("r", {"server_type": "spend", "tools": []}), "non-empty list"),
        (_routes_plus("r", {"server_type": "spend", "tools": ["send", "send"]}), "twice"),
        (_routes_plus("r", {"server_type": "spend", "tools": ["payments__send"]}), "qualified"),
        (_routes_plus("banned", {"server_type": "spend", "tools": ["send"]}), "reserved"),
        ({"routes": {}}, "declares nothing"),
        ({"server_types": {"spend": {"path": str(FIXTURES / "nowhere")}}}, "not a directory"),
        ({"server_types": {"spend": {"path": str(MINIMAL_SPEND), "engine": "prolog"}}}, "engine"),
        ({"selection": {"map": {}}}, "neither a map nor a classifier"),
        ({"selection": {"map": {"payments": "payments-send"}, "classifier": "none.wasm"}}, "not a file"),
    ],
)
def test_a_malformed_or_dangling_declaration_is_refused(tmp_path, overrides, needle):
    with pytest.raises(PolicySetError, match=needle):
        PolicySet.load(_write(tmp_path, _declaration(**overrides)))


def test_banned_is_the_one_map_value_that_names_no_route(tmp_path):
    policy_set = PolicySet.load(_write(tmp_path, _declaration()))
    assert policy_set.selection.map["evil"] == "banned"


# --------------------------------------------------------------------------- #
# Bind: every name resolves, in both directions, before any server is admitted
# --------------------------------------------------------------------------- #


def test_a_declared_server_type_with_no_registration_is_refused(tmp_path, key):
    policy_set = PolicySet.load(_write(tmp_path, _declaration()))
    with pytest.raises(PolicySetError, match=r"declared but not registered \['spend'\]"):
        policy_set.bind(server_types={}, adapters={"plain": object()})


def test_a_registration_for_no_declared_server_type_is_refused(tmp_path, key):
    """The typo can be on the deployment side too."""
    policy_set = PolicySet.load(_write(tmp_path, _declaration()))
    with pytest.raises(PolicySetError, match=r"registered but not declared \['spent'\]"):
        policy_set.bind(
            server_types={
                "spend": ServerType(chain=_spend_chain(key)),
                "spent": ServerType(chain=_spend_chain(key)),
            },
            adapters={"plain": object()},
        )


def test_an_adapter_a_route_names_must_be_registered(tmp_path, key):
    policy_set = PolicySet.load(_write(tmp_path, _declaration()))
    with pytest.raises(PolicySetError, match=r"named but not registered \['plain'\]"):
        policy_set.bind(server_types={"spend": ServerType(chain=_spend_chain(key))})


def test_a_bundle_that_does_not_load_is_a_bind_failure(tmp_path, key):
    """Everything is built at bind, so a bad bundle fails before admission."""
    declaration = _declaration(
        server_types={"spend": {"path": str(MINIMAL_SPEND), "engine": "cedar"}}
    )
    policy_set = PolicySet.load(_write(tmp_path, declaration))
    with pytest.raises(FileNotFoundError, match="policy.cedar"):
        policy_set.bind(
            server_types={"spend": ServerType(chain=_spend_chain(key))},
            adapters={"plain": object()},
        )


def test_the_chain_is_built_per_route_with_that_routes_adapter(tmp_path, key):
    seen: list[tuple[str, str, Any]] = []
    marker = object()

    def chain(bundle, route: Route, adapter):
        seen.append((bundle.name, route.name, adapter))
        return WasmPolicyFilter(bundle, config={"requesterJwk": vc.public_jwk(key)})

    PolicySet.load(_write(tmp_path, _declaration())).bind(
        server_types={"spend": ServerType(chain=chain)}, adapters={"plain": marker}
    )
    assert sorted(seen, key=lambda s: s[1]) == [
        ("spend", "payments-send", marker),
        ("spend", "refunds-refund", None),
    ]


# --------------------------------------------------------------------------- #
# The bound router
# --------------------------------------------------------------------------- #


def _admit(router, server: str):
    return router.admit(server_name=server, url=f"https://{server}.example", how_loaded="static")


def test_the_map_admits_each_server_to_its_route(tmp_path, key):
    router = _bound(tmp_path, key)
    assert _admit(router, "payments").route == "payments-send"
    assert _admit(router, "refunds").route == "refunds-refund"
    assert not _admit(router, "evil").allowed
    assert not _admit(router, "weather").allowed  # no map entry, no classifier
    assert router.bundle_for("payments").name == "spend"


def test_the_audit_names_the_route_its_tools_and_the_chain(tmp_path, key):
    router = _bound(tmp_path, key)
    _admit(router, "payments")
    _admit(router, "evil")
    by_server = {r.server_name: r for r in router.admissions()}
    assert by_server["payments"].chain == (
        "RouteScopedFilter[payments-send: send](WasmPolicyFilter(spend))"
    )
    assert by_server["evil"].summary() == (
        "'evil' (static) REFUSED via map: 'evil' explicitly banned"
    )


def test_a_classifier_route_the_declaration_does_not_carry_is_refused(tmp_path, key):
    """The committed classifier places a sandbox server under ``readonly``,
    which this declaration never routes: the router's existing refusal."""
    declaration = _declaration(
        selection={
            "map_key": "origin_server",
            "map": {"payments": "payments-send"},
            "classifier": str(CLASSIFIER),
        }
    )
    router = _bound(tmp_path, key, declaration)
    result = router.admit(
        server_name="scratch", url="https://scratch.example", how_loaded="static",
        trust_tier="sandbox",
    )
    assert not result.allowed and "unavailable" in result.reason


async def test_a_governed_tool_runs_the_chain(tmp_path, key):
    router = _bound(tmp_path, key)
    _admit(router, "payments")
    allowed = await router.check(_call("payments", "send", key))
    assert allowed.allowed, allowed.reason
    assert allowed.arguments == {"amountCents": 500, "merchant": "acme"}
    denied = await router.check(_call("payments", "send", key, with_credential=False))
    assert not denied.allowed


async def test_a_tool_outside_the_route_passes_with_credentials_stripped(tmp_path, key):
    """``refund`` is a tool on the payments server that the payments route
    does not list: no policy runs, and the stray credential never reaches
    the downstream. The stripped fields are the bundle's own."""
    router = _bound(tmp_path, key)
    _admit(router, "payments")
    result = await router.check(_call("payments", "refund", key))
    assert result.allowed
    assert result.arguments == {"amountCents": 500, "merchant": "acme"}


async def test_two_routes_over_one_server_type_govern_different_tools(tmp_path, key):
    router = _bound(tmp_path, key)
    _admit(router, "payments")
    _admit(router, "refunds")
    # On the refunds server, `refund` is the governed tool and `send` is not.
    assert not (await router.check(_call("refunds", "refund", key, with_credential=False))).allowed
    assert (await router.check(_call("refunds", "send", key, with_credential=False))).allowed


def test_the_augmenter_surfaces_credentials_only_on_the_routes_tools(tmp_path, key):
    router = _bound(tmp_path, key)
    _admit(router, "payments")
    assert router.bundle_for("payments", "payments__send") is not None
    assert router.bundle_for("payments", "payments__refund") is None

    def record(tool: str) -> SearchResult:
        return SearchResult(
            tool=ToolRecord(
                name=tool, qualified_name=f"payments__{tool}", description="",
                input_schema={"type": "object", "properties": {}}, server_name="payments",
            ),
            score=1.0,
        )

    out = BundleAugmenter(router).filter([record("send"), record("refund")], "money")
    by_name = {r.tool.name: r.tool.input_schema for r in out}
    assert "requestVC" in by_name["send"]["properties"]
    assert "requestVC" not in by_name["refund"]["properties"]

# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""A policy bundle attached from ``config.json``, with no Python written.

The claim under test is the one the README makes: someone who has written
a bundle by hand points ``filters.policy_bundles`` at the directory and runs
the proxy. So the startup tests here write a real config file, load it
through ``load_config``, build the server with ``create_server`` and drive
it through the MCP client — search, then call — over the ``minimal_spend``
trio, one engine at a time. Nothing in them constructs a filter.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client

from extensible_mcp.config import load_config
from extensible_mcp.server import create_server
from tests import vc_helpers as vc
from tests.test_minimal_bundle_differential import OVER_THE_CAP_DENIAL

FIXTURES = Path(__file__).parent / "fixtures"
MOCK_SERVER = str(Path(__file__).parent / "mock_server.py")
PAYMENTS_SERVER = str(Path(__file__).parent / "mock_payments_server.py")
TRIO = {
    "rego": "minimal_spend",
    "cel": "cel_minimal_spend",
    "cedar": "cedar_minimal_spend",
}


@pytest.fixture(scope="module")
def key():
    return vc.new_key()


def _write_config(tmp_path: Path, *, servers: dict[str, Any], filters: dict[str, Any]) -> Path:
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"mcpServers": servers, "filters": filters}))
    return path


def _payments_server() -> dict[str, Any]:
    return {"command": sys.executable, "args": [PAYMENTS_SERVER]}


def _bundle_entry(twin: str, key, **extra: Any) -> dict[str, Any]:
    return {
        "path": str(FIXTURES / TRIO[twin]),
        "config": {"requesterJwk": vc.public_jwk(key)},
        **extra,
    }


def _call(amount: int, key, *, with_credential: bool = True) -> dict[str, Any]:
    args = {"amountCents": amount, "merchant": "acme"}
    if not with_credential:
        return args
    return {**args, "requestVC": vc.request_vc(args=args, key=key)}


# --------------------------------------------------------------------------- #
# Parsing: the block is refused when it is ambiguous, resolved when it is not.
# --------------------------------------------------------------------------- #


def test_relative_path_resolves_against_the_config_directory(tmp_path, key):
    (tmp_path / "policies").mkdir()
    path = _write_config(
        tmp_path,
        servers={"payments": _payments_server()},
        filters={"policy_bundles": {"payments": {"path": "policies/spend"}}},
    )
    config = load_config(path)
    entry = config.filters.policy_bundles["payments"]
    assert entry.path == tmp_path / "policies" / "spend"
    assert entry.config == {} and entry.engine is None and entry.single_use == []


@pytest.mark.parametrize(
    "entry, needle",
    [
        ({"path": "p", "singe_use": ["requestVC"]}, "unexpected field"),
        ({"config": {}}, "must have a 'path'"),
        ({"path": "p", "engine": "prolog"}, "'engine' must be one of"),
        ({"path": "p", "single_use": "requestVC"}, "'single_use' must be a list"),
        ({"path": "p", "config": ["requesterJwk"]}, "'config' must be an object"),
    ],
)
def test_a_malformed_entry_is_refused_at_load(tmp_path, entry, needle):
    path = _write_config(
        tmp_path,
        servers={"payments": _payments_server()},
        filters={"policy_bundles": {"payments": entry}},
    )
    with pytest.raises(ValueError, match=needle):
        load_config(path)


def test_a_bundle_for_a_server_not_in_mcpServers_is_refused(tmp_path):
    """A typo in the server name would declare a gate and attach it to
    nothing; that is the quiet failure the loader refuses."""
    path = _write_config(
        tmp_path,
        servers={"payments": _payments_server()},
        filters={"policy_bundles": {"payment": {"path": "p"}}},
    )
    with pytest.raises(ValueError, match="not in 'mcpServers'"):
        load_config(path)


def test_policy_bundles_must_be_an_object(tmp_path):
    path = _write_config(
        tmp_path,
        servers={"payments": _payments_server()},
        filters={"policy_bundles": [{"path": "p"}]},
    )
    with pytest.raises(ValueError, match="must be an object"):
        load_config(path)


# --------------------------------------------------------------------------- #
# Building: what the declared form cannot serve fails at create_server, not
# on the first call.
# --------------------------------------------------------------------------- #


def test_a_bundle_with_a_wallet_source_is_refused_at_startup(tmp_path, key):
    """``family_spend`` fetches memberships from a wallet; that lookup is
    code, and the refusal says where to attach the bundle instead."""
    path = _write_config(
        tmp_path,
        servers={"payments": _payments_server()},
        filters={"policy_bundles": {"payments": {"path": str(FIXTURES / "family_spend")}}},
    )
    with pytest.raises(ValueError, match="'wallet' source") as e:
        create_server(load_config(path))
    assert "extra_call_filters" in str(e.value)


def test_a_missing_bundle_directory_is_a_startup_failure(tmp_path):
    path = _write_config(
        tmp_path,
        servers={"payments": _payments_server()},
        filters={"policy_bundles": {"payments": {"path": str(tmp_path / "nowhere")}}},
    )
    with pytest.raises((FileNotFoundError, ValueError)):
        create_server(load_config(path))


def test_single_use_on_a_field_the_bundle_does_not_take_is_refused(tmp_path, key):
    path = _write_config(
        tmp_path,
        servers={"payments": _payments_server()},
        filters={"policy_bundles": {"payments": _bundle_entry("cel", key, single_use=["authorizationVC"])}},
    )
    with pytest.raises(ValueError, match="'single_use' names"):
        create_server(load_config(path))


def test_engine_can_be_forced(tmp_path, key):
    """A directory carrying one artifact loads under its own engine; forcing
    an engine whose artifact is absent is the loader's existing refusal."""
    path = _write_config(
        tmp_path,
        servers={"payments": _payments_server()},
        filters={"policy_bundles": {"payments": _bundle_entry("rego", key, engine="cedar")}},
    )
    with pytest.raises(FileNotFoundError, match="policy.cedar"):
        create_server(load_config(path))


# --------------------------------------------------------------------------- #
# Startup: the trio, from a config file alone, through the real server.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("engine", sorted(TRIO))
async def test_the_bundle_governs_the_server_from_config_alone(tmp_path, key, engine):
    path = _write_config(
        tmp_path,
        servers={"payments": _payments_server()},
        filters={
            "similarity_threshold": 0.0,
            "policy_bundles": {"payments": _bundle_entry(engine, key)},
        },
    )
    server = create_server(load_config(path))
    async with Client(server) as client:
        found = await client.call_tool("search_tools", {"query": "send money", "top_k": 3})
        text = found.content[0].text
        assert "payments__send" in text
        # The augmenter advertised the credential the bundle requires, as a
        # required parameter: the obligation arrives with the definition.
        assert '"requestVC"' in text
        schema = json.loads(text.split("```json\n", 1)[1].split("\n```", 1)[0])
        assert "requestVC" in schema["required"]

        allowed = await client.call_tool(
            "call_tool", {"tool_name": "payments__send", "arguments": _call(500, key)}
        )
        # The credential was stripped: the downstream got its native arguments.
        assert allowed.content[0].text == "sent 500 to acme"

        denied = await client.call_tool(
            "call_tool", {"tool_name": "payments__send", "arguments": _call(5000, key)}
        )
        assert denied.content[0].text == f"Error: {OVER_THE_CAP_DENIAL}"

        bare = await client.call_tool(
            "call_tool",
            {"tool_name": "payments__send", "arguments": _call(500, key, with_credential=False)},
        )
        # A required credential the call did not carry: the plan cannot be
        # assembled, and the generic filter fails closed as a fault, with the
        # detail (which field) in the proxy log rather than in the reason.
        assert bare.content[0].text.startswith("Error: Policy input could not be assembled")


async def test_single_use_spends_the_credential_on_the_call_it_authorized(tmp_path, key):
    path = _write_config(
        tmp_path,
        servers={"payments": _payments_server()},
        filters={
            "similarity_threshold": 0.0,
            "policy_bundles": {"payments": _bundle_entry("cel", key, single_use=["requestVC"])},
        },
    )
    server = create_server(load_config(path))
    async with Client(server) as client:
        await client.call_tool("search_tools", {"query": "send money", "top_k": 3})
        args = _call(500, key)
        first = await client.call_tool("call_tool", {"tool_name": "payments__send", "arguments": args})
        assert first.content[0].text == "sent 500 to acme"
        second = await client.call_tool("call_tool", {"tool_name": "payments__send", "arguments": args})
        assert second.content[0].text.startswith("Error: ")
        assert "already been used" in second.content[0].text


async def test_a_server_without_a_bundle_is_untouched(tmp_path, key):
    """Scoped by server: the governed server is gated, the other passes
    through with no credential asked for and none required."""
    path = _write_config(
        tmp_path,
        servers={
            "payments": _payments_server(),
            "mock": {"command": sys.executable, "args": [MOCK_SERVER]},
        },
        filters={
            "similarity_threshold": 0.0,
            "policy_bundles": {"payments": _bundle_entry("rego", key)},
        },
    )
    server = create_server(load_config(path))
    async with Client(server) as client:
        found = await client.call_tool("search_tools", {"query": "add numbers", "top_k": 3})
        text = found.content[0].text
        assert "mock__add_numbers" in text
        schema = json.loads(text.split("## mock__add_numbers", 1)[1].split("```json\n", 1)[1].split("\n```", 1)[0])
        assert "requestVC" not in schema.get("properties", {})
        result = await client.call_tool(
            "call_tool", {"tool_name": "mock__add_numbers", "arguments": {"a": 10, "b": 20}}
        )
        assert "30" in result.content[0].text

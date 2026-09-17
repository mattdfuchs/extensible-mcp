# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""End-to-end integration tests for URL-server bearer-token auth.

Spins up a real FastMCP HTTP server in-process with a bearer-check ASGI
middleware, then exercises the proxy's tokens-file machinery against it.
Covers the connect path, the rotate-token path, and the 401-mid-session
path that should surface as TokenExpiredError.
"""

from __future__ import annotations

import asyncio
import time


import pytest

from extensible_mcp.client_manager import ClientManager, TokenExpiredError
from extensible_mcp.types import ServerConfig


@pytest.mark.asyncio
async def test_valid_token_connects_and_indexes_tools(tmp_path, mock_mcp_server):
    url, _ = mock_mcp_server
    tokens_file = tmp_path / "tokens"
    tokens_file.write_text("mockauth=correct-token\n")

    mgr = ClientManager(tokens_file=tokens_file)
    try:
        tools = await mgr.connect_all(
            [ServerConfig(name="mockauth", url=url)]
        )
        assert any(t.name == "echo" for t in tools)
    finally:
        await mgr.close_all()


@pytest.mark.asyncio
async def test_invalid_token_fails_to_connect(tmp_path, mock_mcp_server):
    url, _ = mock_mcp_server
    tokens_file = tmp_path / "tokens"
    tokens_file.write_text("mockauth=wrong-token\n")

    mgr = ClientManager(tokens_file=tokens_file)
    with pytest.raises(RuntimeError, match="Could not connect"):
        await mgr.connect_all([ServerConfig(name="mockauth", url=url)])


@pytest.mark.asyncio
async def test_missing_token_fails_to_connect(tmp_path, mock_mcp_server):
    """No token entry for the server name → no Authorization header → 401."""
    url, _ = mock_mcp_server
    tokens_file = tmp_path / "tokens"
    tokens_file.write_text("# no entry for mockauth\n")

    mgr = ClientManager(tokens_file=tokens_file)
    with pytest.raises(RuntimeError, match="Could not connect"):
        await mgr.connect_all([ServerConfig(name="mockauth", url=url)])


@pytest.mark.asyncio
async def test_call_after_server_revokes_token_translates_to_token_expired(
    tmp_path, mock_mcp_server
):
    """Connect successfully, then have the server stop accepting the token."""
    url, store = mock_mcp_server
    tokens_file = tmp_path / "tokens"
    tokens_file.write_text("mockauth=correct-token\n")

    mgr = ClientManager(tokens_file=tokens_file)
    try:
        await mgr.connect_all([ServerConfig(name="mockauth", url=url)])

        # Server-side: token is no longer accepted (simulates expiry/revocation).
        store.valid = {"different-token-now"}

        with pytest.raises(TokenExpiredError) as info:
            await mgr.call_tool("mockauth__echo", {"message": "hi"})
        assert info.value.server_name == "mockauth"
    finally:
        await mgr.close_all()


@pytest.mark.asyncio
async def test_token_rotation_via_file_picks_up_new_value(tmp_path, mock_mcp_server):
    """Update the tokens file mid-session; next call should use the new value."""
    url, store = mock_mcp_server
    tokens_file = tmp_path / "tokens"
    tokens_file.write_text("mockauth=correct-token\n")

    mgr = ClientManager(tokens_file=tokens_file)
    try:
        await mgr.connect_all([ServerConfig(name="mockauth", url=url)])

        # Rotate: server now accepts a different token, file updated to match.
        store.valid = {"new-token"}
        tokens_file.write_text("mockauth=new-token\n")

        result = await mgr.call_tool("mockauth__echo", {"message": "ping"})
        assert not result.isError
        assert "ping" in result.content[0].text
    finally:
        await mgr.close_all()


@pytest.mark.asyncio
async def test_runtime_loaded_url_does_not_receive_a_stored_token(
    tmp_path, mock_mcp_server
):
    """The exfiltration path: `load_mcp_server` lets the caller choose both
    the server *name* and the *URL*, and a token is keyed only by name. A
    prompt-injected model naming a server that has a token, pointed at a host
    it controls, would otherwise be handed that bearer.

    Asserted on what the server received, not merely on the connection
    failing: a bare `pytest.raises(Exception)` would also pass with the mock
    server down, the port wrong, or connect_url broken for some unrelated
    reason. The property under test is that the stored bearer never left the
    proxy."""
    url, store = mock_mcp_server
    tokens_file = tmp_path / "tokens"
    tokens_file.write_text("mockauth=correct-token\n")

    mgr = ClientManager(tokens_file=tokens_file)
    # No static config for this name, so the URL is caller-chosen.
    with pytest.raises(BaseException) as info:
        await mgr.connect_url("mockauth", url)

    # The server was reached -- so the failure is the refusal, not a dead port.
    assert store.seen_authorization, "the mock server was never contacted"
    # And it was reached with no credential at all.
    assert all(a == "" for a in store.seen_authorization), store.seen_authorization
    assert "correct-token" not in "".join(store.seen_authorization)

    # The refusal is the server's 401, unwrapped from anyio's task group.
    def leaves(exc: BaseException):
        if isinstance(exc, BaseExceptionGroup):
            for sub in exc.exceptions:
                yield from leaves(sub)
        else:
            yield exc

    assert any(
        "401" in str(leaf) or "Unauthorized" in str(leaf)
        for leaf in leaves(info.value)
    ), [str(leaf) for leaf in leaves(info.value)]


@pytest.mark.asyncio
async def test_a_configured_url_does_present_the_token(tmp_path, mock_mcp_server):
    """The companion assertion: the header machinery works, so the test above
    is proving a policy decision and not a broken code path."""
    url, store = mock_mcp_server
    tokens_file = tmp_path / "tokens"
    tokens_file.write_text("mockauth=correct-token\n")

    mgr = ClientManager(tokens_file=tokens_file)
    try:
        await mgr.connect_all([ServerConfig(name="mockauth", url=url)])
        assert any(
            a == "Bearer correct-token" for a in store.seen_authorization
        ), store.seen_authorization
    finally:
        await mgr.close_all()


@pytest.mark.asyncio
async def test_runtime_reconnect_to_a_configured_url_still_receives_the_token(
    tmp_path, mock_mcp_server
):
    """The legitimate case must keep working: once an operator has named this
    exact URL for this name in the config file, a runtime load of the same
    pair is a reconnect to an approved endpoint, not a redirect."""
    url, _store = mock_mcp_server
    tokens_file = tmp_path / "tokens"
    tokens_file.write_text("mockauth=correct-token\n")

    mgr = ClientManager(tokens_file=tokens_file)
    await mgr.connect_all([ServerConfig(name="mockauth", url=url)])
    mgr._connections.pop("mockauth")  # drop it so connect_url will re-add

    tools = await mgr.connect_url("mockauth", url)
    assert any(t.name == "echo" for t in tools)

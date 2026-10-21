# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""End-to-end integration tests for URL-server credentials.

Spins up a real FastMCP HTTP server in-process with a bearer-check ASGI
middleware, then exercises the proxy's credential machinery against it:
the deprecated tokens file, and a token acquired from the stub
authorization server by each of the two shipping grants.

Covers the connect path, the rotate-token path, the 401-mid-session path
that should surface as TokenExpiredError, and -- on the authorization
server's own record of what it was asked for -- that a runtime-named URL
triggers no acquisition at all.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import time


import pytest

from extensible_mcp.client_manager import ClientManager, TokenExpiredError, _Connection
from extensible_mcp.credentials import build_provider
from extensible_mcp.types import CredentialConfig, ServerConfig


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


CLIENT_ID = "extensible-mcp-proxy"


def _key_credential(stub, tmp_path, name="corp-as"):
    """A private_key_jwt credential whose key the stub knows."""
    from joserfc.jwk import ECKey

    key = ECKey.generate_key("P-256")
    key_file = tmp_path / "proxy-signing.pem"
    key_file.write_bytes(key.as_pem(private=True))
    stub.register_client_key(CLIENT_ID, key.as_pem(private=False), "ES256")
    return CredentialConfig(
        name=name,
        grant="private_key_jwt",
        token_endpoint=stub.url,
        client_id=CLIENT_ID,
        private_key_file=key_file,
    )


def _secret_credential(stub, monkeypatch, name="legacy-as"):
    stub.register_client_secret(CLIENT_ID, "s3cr3t")
    monkeypatch.setenv("TEST_CLIENT_SECRET", "s3cr3t")
    return CredentialConfig(
        name=name,
        grant="client_credentials",
        token_endpoint=stub.url,
        client_id=CLIENT_ID,
        client_secret_env="TEST_CLIENT_SECRET",
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("grant", ["private_key_jwt", "client_credentials"])
async def test_a_configured_server_presents_a_grant_acquired_token(
    grant, tmp_path, monkeypatch, mock_mcp_server, stub_auth_server
):
    """End to end on both grants: the proxy authenticates itself to the
    authorization server, and what reaches the downstream server is the token
    it was issued -- no bearer anywhere on disk."""
    url, store = mock_mcp_server
    credential = (
        _key_credential(stub_auth_server, tmp_path)
        if grant == "private_key_jwt"
        else _secret_credential(stub_auth_server, monkeypatch)
    )

    mgr = ClientManager(credentials={credential.name: credential})
    try:
        tools = await mgr.connect_all(
            [
                ServerConfig(
                    name="mockauth",
                    url=url,
                    credential=credential.name,
                    scope="echo.invoke",
                    audience="https://mockauth.example.com",
                )
            ]
        )
        assert any(t.name == "echo" for t in tools)
        assert any(a == "Bearer correct-token" for a in store.seen_authorization)

        (token_request,) = stub_auth_server.token_requests
        assert token_request["grant_type"] == "client_credentials"
        assert token_request["scope"] == "echo.invoke"
        assert token_request["audience"] == "https://mockauth.example.com"

        result = await mgr.call_tool("mockauth__echo", {"message": "ping"})
        assert "ping" in result.content[0].text
        # The acquired token is cached: a call does not re-acquire.
        assert len(stub_auth_server.token_requests) == 1
    finally:
        await mgr.close_all()


@pytest.mark.asyncio
async def test_a_downstream_refusal_reacquires_and_retries_once(
    tmp_path, mock_mcp_server, stub_auth_server
):
    """Refresh on 401, in the transport: the cached token is invalidated, one
    retry is made with a fresh one, and the call succeeds."""
    url, store = mock_mcp_server
    credential = _key_credential(stub_auth_server, tmp_path)
    stub_auth_server.default_token = "first-token"
    store.valid = {"first-token"}

    mgr = ClientManager(credentials={credential.name: credential})
    try:
        await mgr.connect_all(
            [ServerConfig(name="mockauth", url=url, credential=credential.name)]
        )
        assert len(stub_auth_server.token_requests) == 1

        # The downstream server stops accepting the issued token, and the
        # authorization server starts issuing the one it now wants.
        store.valid = {"second-token"}
        stub_auth_server.default_token = "second-token"

        result = await mgr.call_tool("mockauth__echo", {"message": "ping"})

        assert "ping" in result.content[0].text
        assert len(stub_auth_server.token_requests) == 2
        assert "Bearer second-token" in store.seen_authorization
    finally:
        await mgr.close_all()


@pytest.mark.asyncio
async def test_a_second_refusal_fails_rather_than_retrying_again(
    tmp_path, mock_mcp_server, stub_auth_server
):
    """One retry, then fail: asserted by the count at the authorization
    server, which is the only place a retry loop would show up."""
    url, store = mock_mcp_server
    credential = _key_credential(stub_auth_server, tmp_path)

    mgr = ClientManager(credentials={credential.name: credential})
    try:
        await mgr.connect_all(
            [ServerConfig(name="mockauth", url=url, credential=credential.name)]
        )
        assert len(stub_auth_server.token_requests) == 1

        # Nothing the authorization server will issue is accepted downstream.
        store.valid = {"a-token-the-as-will-never-issue"}

        with pytest.raises(TokenExpiredError) as info:
            await mgr.call_tool("mockauth__echo", {"message": "ping"})
        assert info.value.server_name == "mockauth"
        # Exactly one re-acquisition for the one retry.
        assert len(stub_auth_server.token_requests) == 2
    finally:
        await mgr.close_all()


@pytest.mark.asyncio
async def test_a_runtime_loaded_url_triggers_no_token_acquisition(
    tmp_path, mock_mcp_server, stub_auth_server
):
    """The strong form of the invariant. Acquiring a token is itself a
    credential use -- it spends the proxy's client assertion at the
    authorization server -- so a URL the LLM chose must not even induce the
    request, never mind receive the result.

    Asserted on the authorization server's own record of what it was asked
    for. "No Authorization header was sent" would be a weaker claim: it would
    still hold if the proxy had signed an assertion and fetched a token for a
    model-supplied host.
    """
    url, store = mock_mcp_server
    credential = _key_credential(stub_auth_server, tmp_path)

    # A connection for a name that *has* a provider, pointed at a URL no
    # operator configured. The provider existing is what makes this a test of
    # the gate rather than of its absence.
    provider = build_provider(credential)
    conn = _Connection(
        ServerConfig(name="mockauth", url=url),
        tokens_allowed=False,
        credential_provider=provider,
    )

    await conn.prefetch_credential()
    with pytest.raises(BaseException):
        await conn.list_tools_ephemeral()

    # The downstream server was reached, so the failure is the refusal rather
    # than a dead port -- and reached with no credential at all.
    assert store.seen_authorization, "the mock server was never contacted"
    assert all(a == "" for a in store.seen_authorization), store.seen_authorization
    # And the authorization server was never asked for anything.
    assert stub_auth_server.token_requests == []


@pytest.mark.asyncio
async def test_a_runtime_load_of_a_configured_name_acquires_nothing_new(
    tmp_path, mock_mcp_server, stub_auth_server
):
    """The same property through the real entry point: an operator-configured
    name re-pointed at a URL the LLM chose acquires nothing."""
    url, store = mock_mcp_server
    credential = _key_credential(stub_auth_server, tmp_path)

    mgr = ClientManager(credentials={credential.name: credential})
    try:
        await mgr.connect_all(
            [ServerConfig(name="mockauth", url=url, credential=credential.name)]
        )
        assert "mockauth" in mgr._providers  # a provider exists for this name
        assert len(stub_auth_server.token_requests) == 1
        mgr._connections.pop("mockauth")
        store.seen_authorization.clear()

        elsewhere = url + "?chosen-by-the-model"
        with pytest.raises(BaseException):
            await mgr.connect_url("mockauth", elsewhere)

        assert all(a == "" for a in store.seen_authorization), store.seen_authorization
        # No further acquisition: the admission-time one is all there is.
        assert len(stub_auth_server.token_requests) == 1
    finally:
        await mgr.close_all()


@pytest.mark.asyncio
async def test_a_missing_key_file_refuses_only_that_server(
    tmp_path, mock_mcp_server, stub_auth_server
):
    """A credential that cannot be acquired is a deployment fault, so it
    refuses its server at admission and leaves the rest of the proxy up."""
    url, _store = mock_mcp_server
    good = _key_credential(stub_auth_server, tmp_path)
    broken = CredentialConfig(
        name="broken-as",
        grant="private_key_jwt",
        token_endpoint=stub_auth_server.url,
        client_id=CLIENT_ID,
        private_key_file=tmp_path / "nowhere.pem",
    )

    mgr = ClientManager(credentials={good.name: good, broken.name: broken})
    try:
        tools = await mgr.connect_all(
            [
                ServerConfig(name="broken", url=url, credential=broken.name),
                ServerConfig(name="mockauth", url=url, credential=good.name),
            ]
        )
        assert mgr.server_names() == {"mockauth"}
        assert any(t.qualified_name == "mockauth__echo" for t in tools)
    finally:
        await mgr.close_all()


@pytest.mark.asyncio
async def test_an_unreachable_token_endpoint_refuses_only_that_server(
    tmp_path, mock_mcp_server, stub_auth_server
):
    url, _store = mock_mcp_server
    good = _key_credential(stub_auth_server, tmp_path)
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    dead_port = sock.getsockname()[1]
    sock.close()
    unreachable = CredentialConfig(
        name="down-as",
        grant="private_key_jwt",
        token_endpoint=f"http://127.0.0.1:{dead_port}/oauth/token",
        client_id=CLIENT_ID,
        private_key_file=good.private_key_file,
    )

    mgr = ClientManager(credentials={good.name: good, unreachable.name: unreachable})
    try:
        await mgr.connect_all(
            [
                ServerConfig(name="unreachable", url=url, credential=unreachable.name),
                ServerConfig(name="mockauth", url=url, credential=good.name),
            ]
        )
        assert mgr.server_names() == {"mockauth"}
    finally:
        await mgr.close_all()


@pytest.mark.asyncio
async def test_the_tokens_file_still_works_and_warns_exactly_once(
    tmp_path, mock_mcp_server, caplog
):
    """Deprecated, not removed: a deployment that has not migrated keeps
    working. The warning says so once per process rather than per call, since
    a credential is resolved per call and the audience is an operator reading
    logs."""
    url, _store = mock_mcp_server
    tokens_file = tmp_path / "tokens"
    tokens_file.write_text("mockauth=correct-token\n")

    mgr = ClientManager(tokens_file=tokens_file)
    with caplog.at_level(logging.WARNING, logger="extensible_mcp.client_manager"):
        try:
            await mgr.connect_all([ServerConfig(name="mockauth", url=url)])
            for _ in range(3):
                result = await mgr.call_tool("mockauth__echo", {"message": "ping"})
                assert "ping" in result.content[0].text
        finally:
            await mgr.close_all()

    deprecations = [r for r in caplog.records if "deprecated" in r.getMessage()]
    assert len(deprecations) == 1, [r.getMessage() for r in deprecations]
    assert "mockauth" in deprecations[0].getMessage()
    # The token itself is not in the log.
    assert "correct-token" not in caplog.text


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

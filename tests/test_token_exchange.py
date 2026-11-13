# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""RFC 8693 token exchange: the downstream sees the caller.

Over HTTP one proxy process serves many people, and a grant-acquired token
is one downstream identity for all of them. The ``token_exchange`` grant is
the other shape: the proxy presents the caller's verified inbound token as
the ``subject_token`` and is handed a token about that caller, so the
downstream sees the person as ``sub`` and the proxy as the client the token
was issued to.

Four things are under test. The request the provider makes, and that it is
authenticated as the proxy. The cache: one exchange per caller, never past
the subject token's own expiry, bounded. That a call with no caller behind
it is refused before any request, and nothing ever falls back to the
proxy's own identity. And the plumbing: the subject token travels from the
verified request to the client manager after the pipeline allowed the call,
through the MCP path and ``POST /call`` alike, and ``POST /decide``
exchanges nothing.
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path
from typing import Any

import httpx
import httpx2
import pytest
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.server.auth.providers.jwt import StaticTokenVerifier
from fastmcp.utilities.tests import run_server_async

from extensible_mcp.client_manager import ClientManager, TokenExpiredError
from extensible_mcp.config import (
    AccessControlConfig,
    AuthConfig,
    Config,
    FiltersConfig,
    RoleScope,
    load_config,
)
from extensible_mcp.credentials import (
    ACCESS_TOKEN_TYPE,
    PROXY_ITSELF,
    TOKEN_EXCHANGE_GRANT_TYPE,
    CredentialError,
    OAuthGrantAuth,
    SubjectToken,
    TokenExchangeProvider,
    build_provider,
)
from extensible_mcp.server import TransportError, check_http_deployment, create_server, main
from extensible_mcp.types import CredentialConfig, ServerConfig
from tests.test_credentials import write_ec_key
from tests.test_static_exposure import ISSUER, TOKENS

MOCK_SERVER = str(Path(__file__).parent / "mock_server.py")
CLIENT_ID = "family-proxy"
PARENT = {"Authorization": "Bearer parent-token"}
CHILD = {"Authorization": "Bearer child-token"}


def _subject(sub: str = "alice", *, value: str | None = None, expires_in: float | None = None) -> SubjectToken:
    return SubjectToken(
        value=value or f"inbound-{sub}",
        iss=ISSUER,
        sub=sub,
        expires_at=time.time() + expires_in if expires_in is not None else None,
    )


def _exchange(stub, tmp_path, **kwargs) -> TokenExchangeProvider:
    """A provider authenticating by private-key JWT, its key known to the stub."""
    private_key_file, public_pem = write_ec_key(tmp_path)
    stub.register_client_key(CLIENT_ID, public_pem, "ES256")
    return TokenExchangeProvider(
        name="corp-as",
        token_endpoint=stub.url,
        client_id=CLIENT_ID,
        private_key_file=private_key_file,
        **kwargs,
    )


def _exchanges(stub) -> list[dict[str, str]]:
    return [r for r in stub.token_requests if r.get("grant_type") == TOKEN_EXCHANGE_GRANT_TYPE]


def _service(stub) -> list[dict[str, str]]:
    return [r for r in stub.token_requests if r.get("grant_type") == "client_credentials"]


# --------------------------------------------------------------------------- #
# The request
# --------------------------------------------------------------------------- #


class TestTheExchangeRequest:
    async def test_the_request_is_an_rfc_8693_exchange_authenticated_as_the_proxy(
        self, stub_auth_server, tmp_path
    ):
        provider = _exchange(stub_auth_server, tmp_path, scope="payments.invoke", audience="payments")

        token = await provider.token(_subject("alice"))

        assert token == "exchanged(inbound-alice)"
        (request,) = stub_auth_server.token_requests
        assert request["grant_type"] == TOKEN_EXCHANGE_GRANT_TYPE
        assert request["subject_token"] == "inbound-alice"
        assert request["subject_token_type"] == ACCESS_TOKEN_TYPE
        assert request["requested_token_type"] == ACCESS_TOKEN_TYPE
        assert request["client_id"] == CLIENT_ID
        assert request["scope"] == "payments.invoke" and request["audience"] == "payments"
        # No actor token: the client authentication is the actor.
        assert "actor_token" not in request and "actor_token_type" not in request
        (claims,) = stub_auth_server.verified_assertions
        assert claims["iss"] == claims["sub"] == CLIENT_ID

    async def test_a_client_secret_authenticates_the_exchange_too(
        self, stub_auth_server, monkeypatch
    ):
        monkeypatch.setenv("EXCHANGE_SECRET", "s3cr3t")
        stub_auth_server.register_client_secret(CLIENT_ID, "s3cr3t")
        provider = TokenExchangeProvider(
            name="corp-as", token_endpoint=stub_auth_server.url, client_id=CLIENT_ID,
            client_secret_env="EXCHANGE_SECRET",
        )

        assert await provider.token(_subject()) == "exchanged(inbound-alice)"
        (request,) = stub_auth_server.token_requests
        assert request["client_secret"] == "s3cr3t" and "client_assertion" not in request

    def test_exactly_one_client_authentication(self, tmp_path):
        common = {"name": "corp-as", "token_endpoint": "https://as.example/token", "client_id": CLIENT_ID}
        with pytest.raises(CredentialError, match="exactly one"):
            TokenExchangeProvider(**common)
        with pytest.raises(CredentialError, match="exactly one"):
            TokenExchangeProvider(private_key_file=tmp_path / "k.pem", client_secret_env="X", **common)
        with pytest.raises(CredentialError, match="exactly one"):
            build_provider(CredentialConfig(name="corp-as", grant="token_exchange",
                                            token_endpoint="https://as.example/token", client_id=CLIENT_ID))
        provider = build_provider(CredentialConfig(
            name="corp-as", grant="token_exchange", token_endpoint="https://as.example/token",
            client_id=CLIENT_ID, client_secret_env="X",
        ))
        assert isinstance(provider, TokenExchangeProvider) and provider.per_caller is True

    async def test_the_proxy_itself_gets_its_own_token_which_is_what_lists_a_server(
        self, stub_auth_server, tmp_path
    ):
        provider = _exchange(stub_auth_server, tmp_path)

        assert await provider.token(PROXY_ITSELF) == "correct-token"
        (request,) = stub_auth_server.token_requests
        assert request["grant_type"] == "client_credentials"

    async def test_anything_but_a_callers_token_is_refused(self, stub_auth_server, tmp_path):
        provider = _exchange(stub_auth_server, tmp_path)
        for other in ("alice", None, object(), {"sub": "alice"}):
            with pytest.raises(CredentialError, match="not a caller's token"):
                await provider.token(other)  # type: ignore[arg-type]
        assert stub_auth_server.token_requests == []

    async def test_a_refused_exchange_fails_the_call_and_falls_back_to_nothing(
        self, stub_auth_server, tmp_path
    ):
        stub_auth_server.exchange_error = "invalid_target"
        provider = _exchange(stub_auth_server, tmp_path)

        with pytest.raises(CredentialError, match="refused the request"):
            await provider.token(_subject())
        # One request, the exchange; no client_credentials attempt followed.
        assert [r["grant_type"] for r in stub_auth_server.token_requests] == [TOKEN_EXCHANGE_GRANT_TYPE]

    async def test_an_issued_token_type_other_than_access_token_is_refused(
        self, stub_auth_server, tmp_path
    ):
        stub_auth_server.issued_token_type = "urn:ietf:params:oauth:token-type:id_token"
        provider = _exchange(stub_auth_server, tmp_path)
        with pytest.raises(CredentialError, match="issued"):
            await provider.token(_subject())

    async def test_a_response_that_states_no_issued_token_type_is_accepted(
        self, stub_auth_server, tmp_path
    ):
        stub_auth_server.issued_token_type = None
        provider = _exchange(stub_auth_server, tmp_path)
        assert await provider.token(_subject()) == "exchanged(inbound-alice)"

    async def test_the_subject_token_value_is_in_no_repr_and_no_log(
        self, stub_auth_server, tmp_path, caplog
    ):
        subject = _subject("alice", value="SECRET-INBOUND-VALUE")
        assert "SECRET-INBOUND-VALUE" not in repr(subject)
        assert "SECRET-INBOUND-VALUE" not in str(subject)
        assert repr(subject) == f"SubjectToken(iss={ISSUER!r}, sub='alice')"
        provider = _exchange(stub_auth_server, tmp_path)
        with caplog.at_level("DEBUG"):
            await provider.token(subject)
        assert "SECRET-INBOUND-VALUE" not in caplog.text
        assert "corp-as" in caplog.text

    def test_two_tokens_for_one_person_are_not_equal(self):
        a, b = _subject("alice"), _subject("alice")
        assert a != b and a == a
        assert len({a, b}) == 2


# --------------------------------------------------------------------------- #
# The cache
# --------------------------------------------------------------------------- #


class TestTheCache:
    async def test_one_caller_exchanges_once(self, stub_auth_server, tmp_path):
        provider = _exchange(stub_auth_server, tmp_path)
        subject = _subject("alice")
        first, second = await provider.token(subject), await provider.token(subject)
        assert first == second and len(stub_auth_server.token_requests) == 1

    async def test_two_callers_exchange_separately(self, stub_auth_server, tmp_path):
        provider = _exchange(stub_auth_server, tmp_path)
        alice = await provider.token(_subject("alice"))
        bob = await provider.token(_subject("bob"))
        assert (alice, bob) == ("exchanged(inbound-alice)", "exchanged(inbound-bob)")
        assert len(stub_auth_server.token_requests) == 2 and provider.cached_callers == 2

    async def test_the_cache_is_keyed_on_who_not_on_which_token(self, stub_auth_server, tmp_path):
        """One person, two sessions: one exchange. The exchanged token is
        about the person, and its lifetime was capped by the first session's
        expiry, so the second session cannot extend it."""
        provider = _exchange(stub_auth_server, tmp_path)
        await provider.token(_subject("alice", value="session-1"))
        await provider.token(_subject("alice", value="session-2"))
        assert len(stub_auth_server.token_requests) == 1

    async def test_an_exchanged_token_never_outlives_its_subject(self, stub_auth_server, tmp_path):
        """The server grants 300s; the subject token has 5s left, inside the
        skew, so the entry is not served again and the next call re-exchanges."""
        provider = _exchange(stub_auth_server, tmp_path)
        subject = _subject("alice", expires_in=5)
        await provider.token(subject)
        await provider.token(subject)
        assert len(stub_auth_server.token_requests) == 2

    async def test_a_subject_without_an_expiry_takes_the_servers_lifetime(
        self, stub_auth_server, tmp_path
    ):
        provider = _exchange(stub_auth_server, tmp_path)
        subject = _subject("alice")  # expires_at=None
        await provider.token(subject)
        await provider.token(subject)
        assert len(stub_auth_server.token_requests) == 1

    async def test_force_refresh_re_exchanges(self, stub_auth_server, tmp_path):
        provider = _exchange(stub_auth_server, tmp_path)
        subject = _subject("alice")
        await provider.token(subject)
        await provider.token(subject, force_refresh=True)
        assert len(stub_auth_server.token_requests) == 2

    async def test_the_cache_is_bounded_least_recently_used(self, stub_auth_server, tmp_path):
        provider = _exchange(stub_auth_server, tmp_path, cache_size=2)
        for who in ("alice", "bob", "carol"):
            await provider.token(_subject(who))
        assert provider.cached_callers == 2
        await provider.token(_subject("bob"))  # still held
        assert len(stub_auth_server.token_requests) == 3
        await provider.token(_subject("alice"))  # evicted: re-exchanged
        assert len(stub_auth_server.token_requests) == 4

    async def test_an_entry_that_cannot_be_served_again_is_not_kept(self, stub_auth_server, tmp_path):
        """A token expiring inside the skew is presented once and never
        served from the cache, so it is not held either: each call is its
        own exchange and nothing accumulates."""
        stub_auth_server.expires_in = 1
        provider = _exchange(stub_auth_server, tmp_path)
        await provider.token(_subject("alice"))
        await provider.token(_subject("bob"))
        await provider.token(_subject("alice"))
        assert provider.cached_callers == 0
        assert len(stub_auth_server.token_requests) == 3

    async def test_a_burst_from_one_caller_exchanges_once_and_two_callers_concurrently(
        self, stub_auth_server, tmp_path
    ):
        provider = _exchange(stub_auth_server, tmp_path)
        alice, bob = _subject("alice"), _subject("bob")
        results = await asyncio.gather(*[provider.token(alice) for _ in range(5)],
                                       *[provider.token(bob) for _ in range(5)])
        assert set(results) == {"exchanged(inbound-alice)", "exchanged(inbound-bob)"}
        assert len(stub_auth_server.token_requests) == 2

    def test_a_cache_bound_below_one_is_refused(self, tmp_path):
        with pytest.raises(CredentialError, match="cache_size"):
            TokenExchangeProvider(name="x", token_endpoint="https://as/t", client_id=CLIENT_ID,
                                  client_secret_env="X", cache_size=0)


# --------------------------------------------------------------------------- #
# The transport
# --------------------------------------------------------------------------- #


class TestTheAuthFlow:
    async def test_the_flow_presents_the_callers_exchanged_token(self, stub_auth_server, tmp_path):
        provider = _exchange(stub_auth_server, tmp_path)
        presented: list[str] = []

        def handler(request: httpx2.Request) -> httpx2.Response:
            presented.append(request.headers["Authorization"])
            return httpx2.Response(200)

        async with httpx2.AsyncClient(
            transport=httpx2.MockTransport(handler), auth=OAuthGrantAuth(provider, _subject("alice"))
        ) as client:
            await client.get("http://downstream.invalid/mcp")
        assert presented == ["Bearer exchanged(inbound-alice)"]

    async def test_a_refusal_re_exchanges_once(self, stub_auth_server, tmp_path):
        stub_auth_server.issue = ["stale", "fresh"]
        provider = _exchange(stub_auth_server, tmp_path)
        presented: list[str] = []

        def handler(request: httpx2.Request) -> httpx2.Response:
            presented.append(request.headers["Authorization"])
            return httpx2.Response(401 if len(presented) == 1 else 200)

        async with httpx2.AsyncClient(
            transport=httpx2.MockTransport(handler), auth=OAuthGrantAuth(provider, _subject("alice"))
        ) as client:
            response = await client.get("http://downstream.invalid/mcp")
        assert response.status_code == 200
        assert presented == ["Bearer stale", "Bearer fresh"]
        assert len(_exchanges(stub_auth_server)) == 2


# --------------------------------------------------------------------------- #
# The client manager: listing as the proxy, calling as the caller
# --------------------------------------------------------------------------- #


def _credential(tmp_path, stub, *, grant: str = "token_exchange") -> CredentialConfig:
    private_key_file, public_pem = write_ec_key(tmp_path)
    stub.register_client_key(CLIENT_ID, public_pem, "ES256")
    return CredentialConfig(
        name="corp-as", grant=grant, token_endpoint=stub.url, client_id=CLIENT_ID,
        private_key_file=private_key_file,
    )


def _manager(tmp_path, stub, *, grant: str = "token_exchange") -> ClientManager:
    return ClientManager(credentials={"corp-as": _credential(tmp_path, stub, grant=grant)})


class TestTheClientManager:
    async def test_admission_lists_as_the_proxy_and_a_call_speaks_for_the_caller(
        self, stub_auth_server, tmp_path, mock_mcp_server
    ):
        url, store = mock_mcp_server
        store.valid = {"correct-token", "exchanged(inbound-alice)"}
        mgr = _manager(tmp_path, stub_auth_server)
        try:
            await mgr.connect_all([ServerConfig(name="mockauth", url=url, credential="corp-as")])
            assert mgr.per_caller_servers() == {"mockauth"}
            assert store.seen_authorization[-1] == "Bearer correct-token"

            result = await mgr.call_tool("mockauth__echo", {"message": "hi"}, subject=_subject("alice"))
        finally:
            await mgr.close_all()
        assert result.content[0].text == "hi"
        assert store.seen_authorization[-1] == "Bearer exchanged(inbound-alice)"
        assert [r["grant_type"] for r in stub_auth_server.token_requests] == [
            "client_credentials", TOKEN_EXCHANGE_GRANT_TYPE,
        ]

    async def test_a_call_with_no_caller_is_refused_before_any_request(
        self, stub_auth_server, tmp_path, mock_mcp_server
    ):
        url, store = mock_mcp_server
        mgr = _manager(tmp_path, stub_auth_server)
        try:
            await mgr.connect_all([ServerConfig(name="mockauth", url=url, credential="corp-as")])
            seen_before = list(store.seen_authorization)
            requests_before = len(stub_auth_server.token_requests)
            with pytest.raises(CredentialError, match="carries no caller token"):
                await mgr.call_tool("mockauth__echo", {"message": "hi"})
        finally:
            await mgr.close_all()
        assert store.seen_authorization == seen_before
        assert len(stub_auth_server.token_requests) == requests_before

    async def test_a_caller_the_downstream_refuses_is_a_token_error_after_one_retry(
        self, stub_auth_server, tmp_path, mock_mcp_server
    ):
        url, store = mock_mcp_server  # bob's exchanged token is not in the store
        mgr = _manager(tmp_path, stub_auth_server)
        try:
            await mgr.connect_all([ServerConfig(name="mockauth", url=url, credential="corp-as")])
            with pytest.raises(TokenExpiredError):
                await mgr.call_tool("mockauth__echo", {"message": "hi"}, subject=_subject("bob"))
        finally:
            await mgr.close_all()
        assert len(_exchanges(stub_auth_server)) == 2
        assert all(r["subject_token"] == "inbound-bob" for r in _exchanges(stub_auth_server))

    async def test_a_service_identity_credential_ignores_the_caller(
        self, stub_auth_server, tmp_path, mock_mcp_server
    ):
        url, store = mock_mcp_server
        mgr = _manager(tmp_path, stub_auth_server, grant="private_key_jwt")
        try:
            await mgr.connect_all([ServerConfig(name="mockauth", url=url, credential="corp-as")])
            assert mgr.per_caller_servers() == set()
            await mgr.call_tool("mockauth__echo", {"message": "hi"}, subject=_subject("alice"))
        finally:
            await mgr.close_all()
        assert store.seen_authorization[-1] == "Bearer correct-token"
        assert _exchanges(stub_auth_server) == []

    async def test_a_runtime_named_url_exchanges_nothing(
        self, stub_auth_server, tmp_path, mock_mcp_server
    ):
        """The credential is keyed by name; a URL the model supplied for that
        name gets no token of either kind, so it does not even list."""
        url, store = mock_mcp_server
        mgr = _manager(tmp_path, stub_auth_server)
        with pytest.raises(Exception):
            await mgr.connect_url("mockauth", url)
        assert stub_auth_server.token_requests == []


# --------------------------------------------------------------------------- #
# The gates: an exchange needs a caller on every call
# --------------------------------------------------------------------------- #


def _exchange_config(tmp_path, *, auth: bool = False) -> Config:
    private_key_file, _ = write_ec_key(tmp_path)
    auth_config = None
    if auth:
        from fastmcp.server.auth.providers.jwt import RSAKeyPair

        pem = tmp_path / "idp.pem"
        pem.write_text(RSAKeyPair.generate().public_key)
        auth_config = AuthConfig(issuer=ISSUER, audience="family-proxy", public_key_file=pem)
    return Config(
        servers=[ServerConfig(name="m", command=sys.executable, args=[MOCK_SERVER])],
        credentials={"corp-as": CredentialConfig(
            name="corp-as", grant="token_exchange", token_endpoint="https://as.example/token",
            client_id=CLIENT_ID, private_key_file=private_key_file,
        )},
        auth=auth_config,
    )


class TestTheGates:
    def test_create_server_needs_require_principal(self, tmp_path):
        with pytest.raises(ValueError, match="token_exchange"):
            create_server(_exchange_config(tmp_path))
        with pytest.raises(ValueError, match="token_exchange"):
            create_server(_exchange_config(tmp_path, auth=True), require_principal=False)
        create_server(_exchange_config(tmp_path, auth=True), require_principal=True)

    def test_anonymous_http_is_refused(self, tmp_path):
        with pytest.raises(TransportError, match="token_exchange"):
            check_http_deployment(_exchange_config(tmp_path), allow_anonymous=True)
        assert check_http_deployment(_exchange_config(tmp_path, auth=True)) is True

    def test_stdio_is_refused_at_main(self, tmp_path, monkeypatch, capsys):
        import extensible_mcp.server as server_mod

        def refuse(*a, **k):
            raise AssertionError("create_server was reached; the gate did not hold")

        monkeypatch.setattr(server_mod, "create_server", refuse)
        private_key_file, _ = write_ec_key(tmp_path)
        config = tmp_path / "config.json"
        config.write_text(json.dumps({
            "mcpServers": {"m": {"command": sys.executable, "args": [MOCK_SERVER]}},
            "credentials": {"corp-as": {
                "grant": "token_exchange", "token_endpoint": "https://as.example/token",
                "client_id": CLIENT_ID, "private_key_file": private_key_file.name,
            }},
        }))
        rc = main(["--config", str(config)])
        assert rc == 2
        err = capsys.readouterr().err
        assert "token_exchange" in err and "stdio" in err


class TestTheConfigGrammar:
    def _load(self, tmp_path, credentials: dict[str, Any], **extra) -> Config:
        config = tmp_path / "config.json"
        config.write_text(json.dumps({
            "mcpServers": {"m": {"command": sys.executable, "args": [MOCK_SERVER]}},
            "credentials": credentials,
            **extra,
        }))
        return load_config(config)

    def test_the_grant_takes_exactly_one_client_authentication(self, tmp_path):
        base = {"grant": "token_exchange", "token_endpoint": "https://as.example/token", "client_id": CLIENT_ID}
        with_key = self._load(tmp_path, {"c": {**base, "private_key_file": "proxy.pem"}})
        assert with_key.credentials["c"].private_key_file == tmp_path / "proxy.pem"
        assert with_key.credentials["c"].client_secret_env is None
        with_secret = self._load(tmp_path, {"c": {**base, "client_secret_env": "S"}})
        assert with_secret.credentials["c"].client_secret_env == "S"
        for bad in ({}, {"private_key_file": "proxy.pem", "client_secret_env": "S"}):
            with pytest.raises(ValueError, match="exactly one"):
                self._load(tmp_path, {"c": {**base, **bad}})
        with pytest.raises(ValueError, match="unexpected field"):
            self._load(tmp_path, {"c": {**base, "client_secret_env": "S", "actor_token": "x"}})

    def test_a_rider_host_may_not_delegate(self, tmp_path):
        with pytest.raises(ValueError, match="token_exchange"):
            self._load(
                tmp_path,
                {"c": {"grant": "token_exchange", "token_endpoint": "https://as.example/token",
                       "client_id": CLIENT_ID, "client_secret_env": "S"}},
                platform={"http_request": {"hosts": {"https://api.bank.example": {
                    "methods": ["POST"], "paths": ["/transfers"], "credential": "c"}}}},
            )


# --------------------------------------------------------------------------- #
# Through the proxy: the verified request's token becomes the subject
# --------------------------------------------------------------------------- #


def _proxy(tmp_path, stub, url: str):
    config = Config(
        servers=[ServerConfig(name="mockauth", url=url, credential="corp-as")],
        credentials={"corp-as": _credential(tmp_path, stub)},
        filters=FiltersConfig(
            similarity_threshold=0.0,
            access_control=AccessControlConfig(by_role={
                "parent": RoleScope(allow_servers=["mockauth"]),
                "child": RoleScope(allow_servers=[]),
            }),
        ),
        exposure="static",
    )
    return create_server(config, auth=StaticTokenVerifier(tokens=TOKENS), require_principal=True)


async def _call_route(base: str, tool: str, arguments: dict[str, Any], headers: dict[str, str]) -> httpx.Response:
    async with httpx.AsyncClient() as http:
        return await http.post(f"{base}/call", json={"tool": tool, "arguments": arguments}, headers=headers)


class TestThroughTheProxy:
    async def test_the_mcp_path_exchanges_the_callers_token(
        self, stub_auth_server, tmp_path, mock_mcp_server
    ):
        url, store = mock_mcp_server
        store.valid = {"correct-token", "exchanged(parent-token)"}
        async with run_server_async(_proxy(tmp_path, stub_auth_server, url)) as proxy_url:
            async with Client(StreamableHttpTransport(proxy_url, headers=PARENT)) as client:
                result = await client.call_tool("mockauth__echo", {"message": "hi"})
                again = await client.call_tool("mockauth__echo", {"message": "again"})
        assert result.content[0].text == "hi" and again.content[0].text == "again"
        assert "Bearer exchanged(parent-token)" in store.seen_authorization
        assert "Bearer parent-token" not in store.seen_authorization
        exchanges = _exchanges(stub_auth_server)
        assert len(exchanges) == 1 and exchanges[0]["subject_token"] == "parent-token"

    async def test_the_call_route_exchanges_the_callers_token(
        self, stub_auth_server, tmp_path, mock_mcp_server
    ):
        url, store = mock_mcp_server
        store.valid = {"correct-token", "exchanged(parent-token)"}
        async with run_server_async(_proxy(tmp_path, stub_auth_server, url)) as proxy_url:
            r = await _call_route(proxy_url.removesuffix("/mcp"), "mockauth__echo", {"message": "hi"}, PARENT)
        assert r.status_code == 200
        assert r.json()["content"] == [{"type": "text", "text": "hi"}] and r.json()["is_error"] is False
        assert store.seen_authorization[-1] == "Bearer exchanged(parent-token)"
        assert [e["subject_token"] for e in _exchanges(stub_auth_server)] == ["parent-token"]

    async def test_a_verdict_exchanges_nothing(self, stub_auth_server, tmp_path, mock_mcp_server):
        url, store = mock_mcp_server
        async with run_server_async(_proxy(tmp_path, stub_auth_server, url)) as proxy_url:
            async with httpx.AsyncClient() as http:
                r = await http.post(f"{proxy_url.removesuffix('/mcp')}/decide",
                                    json={"tool": "mockauth__echo", "arguments": {"message": "hi"}}, headers=PARENT)
        assert r.status_code == 200 and r.json()["allowed"] is True
        assert _exchanges(stub_auth_server) == []

    async def test_a_refused_call_exchanges_nothing(self, stub_auth_server, tmp_path, mock_mcp_server):
        """The pipeline runs first; a call it refuses never reaches the
        credential, so the child's token is never exchanged."""
        url, store = mock_mcp_server
        async with run_server_async(_proxy(tmp_path, stub_auth_server, url)) as proxy_url:
            r = await _call_route(proxy_url.removesuffix("/mcp"), "mockauth__echo", {"message": "hi"}, CHILD)
        assert r.status_code == 200 and r.json()["is_error"] is True
        assert _exchanges(stub_auth_server) == []

    async def test_a_failed_exchange_is_the_calls_error_with_no_token_in_it(
        self, stub_auth_server, tmp_path, mock_mcp_server
    ):
        url, store = mock_mcp_server
        async with run_server_async(_proxy(tmp_path, stub_auth_server, url)) as proxy_url:
            listed = len(store.seen_authorization)  # admission's listing, as the proxy
            stub_auth_server.exchange_error = "invalid_target"
            r = await _call_route(proxy_url.removesuffix("/mcp"), "mockauth__echo", {"message": "hi"}, PARENT)
        body = r.json()
        assert r.status_code == 200 and body["is_error"] is True
        text = body["content"][0]["text"]
        assert "corp-as" in text and "parent-token" not in text
        # Nothing reached the downstream at all, as the proxy least of all.
        assert store.seen_authorization[listed:] == []

# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Shared fixtures.

The bearer-checking mock MCP server lives here rather than in one test module
because two modules use it. Importing a fixture from another test module
almost works -- until the fixture grows a dependency of its own, which is not
imported along with it, and pytest reports it simply "not found".
"""

from __future__ import annotations

import asyncio
import socket
import threading
import time

import httpx
import pytest
import uvicorn
from fastmcp import FastMCP
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from starlette.middleware import Middleware
from starlette.responses import Response


class TokenStore:
    """Mutable set of accepted bearers. Tests mutate `valid` to simulate rotation."""

    def __init__(self, initial: set[str]) -> None:
        self.valid: set[str] = set(initial)
        # Every Authorization header the server actually received, so a test
        # can assert on what left the proxy rather than only on whether the
        # connection failed -- a failure has many causes, a leaked credential
        # has one.
        self.seen_authorization: list[str] = []


class BearerAuthMiddleware:
    """Reject any request whose Authorization bearer isn't in the shared store.

    Pure ASGI rather than ``BaseHTTPMiddleware``, deliberately.
    ``BaseHTTPMiddleware`` pumps the response through its own task group,
    which cannot carry a long-lived streaming ASGI response -- and MCP's
    streamable-http transport is exactly that. Against it, the middleware
    intermittently raises ``RuntimeError("No response returned.")`` from
    ``call_next``, which surfaces as a 500 and, one layer up, as a connection
    that fails for no visible reason. It cost a red CI run to find, because
    under light load the race usually does not land.
    """

    def __init__(self, app, store: TokenStore) -> None:
        self.app = app
        self.store = store

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = dict(scope.get("headers") or [])
        auth = headers.get(b"authorization", b"").decode()
        self.store.seen_authorization.append(auth)
        if not auth.startswith("Bearer "):
            await Response("Missing bearer", status_code=401)(scope, receive, send)
            return
        if auth[7:] not in self.store.valid:
            await Response("Bad bearer", status_code=401)(scope, receive, send)
            return
        await self.app(scope, receive, send)


def _bound_socket() -> socket.socket:
    """A listening socket to hand uvicorn, rather than a port number.

    Picking a free port and closing it leaves a window: the port is free, so
    anything else -- including the next test's teardown releasing a socket the
    kernel then re-hands out -- can take it before uvicorn binds. Passing the
    socket itself closes the window, because it is never unbound.
    """
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(128)
    return sock


@pytest.fixture(scope="session")
def _mock_server():
    """One bearer-checking MCP server for the whole test session, in its own
    thread with its own event loop.

    Session-scoped and threaded, rather than one server per test, for two
    reasons learned the hard way:

    - a server per test meant the *second* one in a process would accept
      connections and then never answer -- uvicorn logging "ASGI callable
      returned without completing response" while a handshake timed out. It
      reproduces under pytest and not in a standalone script, so it is
      something about how the per-test event loops and the server's lifespan
      interact. One long-lived server sidesteps the question entirely.
    - it was the flakiness CI kept hitting: the more servers a run starts and
      stops, the more chances to land in a window where one is not serving.

    A thread with its own loop also means tests on any event loop can use it,
    since HTTP does not care which loop the client is on.
    """
    store = TokenStore({"correct-token"})

    server = FastMCP(name="mock-bearer-server")

    @server.tool()
    def echo(message: str) -> str:
        """Return the input unchanged."""
        return message

    app = server.http_app(
        middleware=[Middleware(BearerAuthMiddleware, store=store)],
        transport="streamable-http",
    )

    sock = _bound_socket()
    port = sock.getsockname()[1]
    url = f"http://127.0.0.1:{port}/mcp"
    uv_server = uvicorn.Server(
        uvicorn.Config(app=app, host="127.0.0.1", port=port,
                       log_level="error", lifespan="on")
    )
    # Not the main thread, so uvicorn installs no signal handlers of its own --
    # which matters here, because these tests install their own SIGHUP handler.
    thread = threading.Thread(
        target=lambda: uv_server.run(sockets=[sock]), daemon=True
    )
    thread.start()

    async def _handshake() -> None:
        async with httpx.AsyncClient(
            headers={"Authorization": "Bearer correct-token"}, timeout=2.0
        ) as http:
            async with streamable_http_client(url, http_client=http) as (r, w, _):
                async with ClientSession(r, w) as session:
                    await session.initialize()

    # Ready means "completes a real MCP handshake", not "the socket accepts".
    # uvicorn's `started` flag only says the latter, and a request landing in
    # that window comes back 500 rather than failing to connect -- which is
    # what made the original CI failure so confusing.
    last_error: BaseException | None = None
    for _ in range(60):  # ~30s
        try:
            asyncio.run(asyncio.wait_for(_handshake(), timeout=3.0))
            break
        except BaseException as e:  # noqa: BLE001 - any failure means not ready
            last_error = e
            time.sleep(0.2)
    else:
        uv_server.should_exit = True
        raise RuntimeError(f"Mock MCP server never became ready: {last_error!r}")

    yield url, store

    uv_server.should_exit = True
    thread.join(timeout=10)
    sock.close()


@pytest.fixture
def mock_mcp_server(_mock_server):
    """Per-test view of the shared server: same URL, state reset.

    The store is shared, so the token set and the record of what arrived are
    both reset here -- otherwise one test revoking a token, or the readiness
    probe's own request, would be visible to the next.
    """
    url, store = _mock_server
    store.valid = {"correct-token"}
    store.seen_authorization.clear()
    return url, store


class StubAuthorizationServer:
    """An OAuth 2.0 token endpoint, in-process, for the two shipping grants.

    Real enough to be worth testing against: it parses the form body, checks
    client authentication (a registered secret, or a ``private_key_jwt``
    assertion verified against a registered public key with its ``iss``,
    ``sub``, ``aud``, ``exp`` and single-use ``jti`` all enforced), and
    answers with a token response of the shape RFC 6749 section 5.1 specifies.

    It records every request it receives, which is what lets a test assert
    the stronger property: not "no Authorization header was sent" but "the
    authorization server was never asked for a token at all".
    """

    def __init__(self) -> None:
        self.url = ""  # filled in by the fixture once the port is known
        self.token_requests: list[dict[str, str]] = []
        self.verified_assertions: list[dict] = []
        self.seen_jti: set[str] = set()
        self.client_secrets: dict[str, str] = {}
        self.client_keys: dict[str, tuple[object, str]] = {}
        # Tokens handed out in order; falls back to default_token once empty,
        # so a test that does not care about rotation need queue nothing.
        self.issue: list[str] = []
        self.default_token = "correct-token"
        self.expires_in: int | None = 300

    def reset(self) -> None:
        self.token_requests.clear()
        self.verified_assertions.clear()
        self.seen_jti.clear()
        self.client_secrets.clear()
        self.client_keys.clear()
        self.issue.clear()
        self.default_token = "correct-token"
        self.expires_in = 300

    def register_client_secret(self, client_id: str, secret: str) -> None:
        self.client_secrets[client_id] = secret

    def register_client_key(self, client_id: str, public_pem: bytes, alg: str) -> None:
        from joserfc.jwk import ECKey, RSAKey

        key = (ECKey if alg.startswith("ES") else RSAKey).import_key(public_pem)
        self.client_keys[client_id] = (key, alg)

    def check_assertion(self, record: dict[str, str]) -> str | None:
        """Return an OAuth error code, or None if the assertion is good."""
        from joserfc import jwt

        if record.get("client_assertion_type") != (
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        ):
            return "invalid_request"
        client_id = record.get("client_id", "")
        registered = self.client_keys.get(client_id)
        if registered is None:
            return "invalid_client"
        key, alg = registered
        try:
            token = jwt.decode(record["client_assertion"], key, algorithms=[alg])
        except Exception:
            return "invalid_client"
        claims = token.claims
        if claims.get("iss") != client_id or claims.get("sub") != client_id:
            return "invalid_client"
        # The audience is what stops an assertion captured by one
        # authorization server being replayed at another.
        if claims.get("aud") != self.url:
            return "invalid_client"
        if not isinstance(claims.get("exp"), int) or claims["exp"] <= time.time():
            return "invalid_client"
        jti = claims.get("jti")
        if not jti or jti in self.seen_jti:
            return "invalid_client"
        self.seen_jti.add(jti)
        self.verified_assertions.append(claims)
        return None


def _stub_as_app(stub: StubAuthorizationServer):
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    async def token_endpoint(request):
        form = await request.form()
        record = {k: str(v) for k, v in form.items()}
        stub.token_requests.append(record)

        if record.get("grant_type") != "client_credentials":
            return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)
        if "client_assertion" in record:
            error = stub.check_assertion(record)
            if error:
                return JSONResponse({"error": error}, status_code=401)
        elif "client_secret" in record:
            client_id = record.get("client_id", "")
            if stub.client_secrets.get(client_id) != record["client_secret"]:
                return JSONResponse({"error": "invalid_client"}, status_code=401)
        else:
            return JSONResponse({"error": "invalid_client"}, status_code=401)

        access_token = stub.issue.pop(0) if stub.issue else stub.default_token
        body = {"access_token": access_token, "token_type": "Bearer"}
        if stub.expires_in is not None:
            body["expires_in"] = stub.expires_in
        return JSONResponse(body)

    return Starlette(routes=[Route("/oauth/token", token_endpoint, methods=["POST"])])


@pytest.fixture(scope="session")
def _auth_server():
    """One stub authorization server for the session, in its own thread.

    Session-scoped and threaded for the same reasons as ``_mock_server``
    above; state is reset per test by ``stub_auth_server``.
    """
    stub = StubAuthorizationServer()
    sock = _bound_socket()
    port = sock.getsockname()[1]
    stub.url = f"http://127.0.0.1:{port}/oauth/token"
    uv_server = uvicorn.Server(
        uvicorn.Config(
            app=_stub_as_app(stub), host="127.0.0.1", port=port, log_level="error"
        )
    )
    thread = threading.Thread(target=lambda: uv_server.run(sockets=[sock]), daemon=True)
    thread.start()

    # Ready means "answers a token request", not "the socket accepts".
    last_error: BaseException | None = None
    for _ in range(60):  # ~12s
        try:
            response = httpx.post(stub.url, data={}, timeout=2.0)
            if response.status_code == 400:
                break
            last_error = RuntimeError(f"unexpected status {response.status_code}")
        except BaseException as e:  # noqa: BLE001 - any failure means not ready
            last_error = e
        time.sleep(0.2)
    else:
        uv_server.should_exit = True
        raise RuntimeError(
            f"Stub authorization server never became ready: {last_error!r}"
        )

    yield stub

    uv_server.should_exit = True
    thread.join(timeout=10)
    sock.close()


@pytest.fixture
def stub_auth_server(_auth_server):
    """Per-test view of the stub authorization server: same URL, state reset.

    Reset *before* the test rather than after, so neither the readiness
    probe's own request nor anything a previous test asked for is counted
    against an assertion that no token was requested.
    """
    _auth_server.reset()
    return _auth_server



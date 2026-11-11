# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""The console on the organization's identity provider: the sign-in relay
with the console's own client, a bearer on every chat request, and one MCP
session per signed-in person presenting that person's token -- so the
proxy's principal is the person at the console. Without a provider, the
home shape: one anonymous session and no sign-in routes."""

from __future__ import annotations

import importlib.util
import itertools
import sys
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import httpx2
import pytest
from fastapi.testclient import TestClient
from fastmcp.server.auth.providers.jwt import RSAKeyPair

from extensible_mcp_vc.oauth import CONSOLE_CLIENT_ID, PROXY_AUDIENCE, ExternalIssuer

from .idp_fixtures import INTERNAL, ISSUER, FakeProvider, bearer, mint, mock_client

CONSOLE = Path(__file__).resolve().parents[1] / "examples" / "console_server.py"
_loads = itertools.count()


class FakeAgent:
    busy = False

    def __init__(self, label):
        self.label, self.turns, self.resumed = label, [], []

    async def turn(self, message):
        self.turns.append(message)
        return f"{self.label} heard: {message}"

    async def resume(self, message):
        self.resumed.append(message)
        return f"{self.label} resumed: {message}"


def load_console(monkeypatch, provider=None):
    """A fresh console module, in external mode when a provider is given.
    The agent factory and the anonymous connection are stubbed, so no proxy
    and no model are needed; what is under test is who gets which session."""
    monkeypatch.setenv("APPROVAL_URL", "")  # no approval service to watch here
    if provider is None:
        monkeypatch.delenv("APPROVAL_ISSUER", raising=False)
    else:
        monkeypatch.setenv("APPROVAL_ISSUER", ISSUER)
        monkeypatch.setenv("APPROVAL_ISSUER_INTERNAL", INTERNAL)
    spec = importlib.util.spec_from_file_location(f"console_server_{next(_loads)}", CONSOLE)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod  # a dataclass with string annotations looks itself up here
    spec.loader.exec_module(mod)
    monkeypatch.setattr(mod.anthropic, "AsyncAnthropic", lambda: SimpleNamespace(messages=object()))
    opened = []

    async def open_agent(app, seat):
        opened.append(seat)
        return FakeAgent(seat.sub)

    async def connect(stack, http_client=None):
        return SimpleNamespace(kind="anonymous session")

    monkeypatch.setattr(mod, "_open_agent", open_agent)
    monkeypatch.setattr(mod, "_connect", connect)
    monkeypatch.setattr(mod, "ChatAgent", lambda **kw: FakeAgent("household"))
    if provider is not None:
        mod._external = ExternalIssuer(mod._external.config, http_client=mock_client(provider))
    mod.opened = opened
    return mod


@pytest.fixture
def keypair():
    return RSAKeyPair.generate()


@pytest.fixture
def provider(keypair):
    return FakeProvider(keypair)


@pytest.fixture
def external(monkeypatch, provider):
    return load_console(monkeypatch, provider)


def console_token(keypair, sub, roles=("child",)):
    return mint(keypair, list(roles), audience=PROXY_AUDIENCE, sub=sub)


# -- the relay --------------------------------------------------------------- #

PAGE_QUERY = {
    "response_type": "code", "client_id": CONSOLE_CLIENT_ID, "redirect_uri": "/",
    "state": "s1", "code_challenge": "c" * 43, "code_challenge_method": "S256",
}


def test_the_console_uses_its_own_client_and_the_proxys_audience(external):
    assert external._external.config.client_id == CONSOLE_CLIENT_ID
    assert external._external.config.audience == PROXY_AUDIENCE


def test_authorize_sends_the_browser_to_the_provider_with_the_console_client(external):
    with TestClient(external.app) as c:
        r = c.get("/authorize", params=PAGE_QUERY, follow_redirects=False)
        assert r.status_code == 302, r.text
        target = urlparse(r.headers["location"])
        assert f"{target.scheme}://{target.netloc}{target.path}" == f"{ISSUER}/protocol/openid-connect/auth"
        q = {k: v[0] for k, v in parse_qs(target.query).items()}
        assert q["client_id"] == CONSOLE_CLIENT_ID and q["redirect_uri"] == "http://testserver/"
        assert q["code_challenge_method"] == "S256" and q["state"] == "s1"
        assert c.get("/authorize", params={**PAGE_QUERY, "client_id": "approval-page"}).status_code == 400
        assert c.get("/authorize", params={**PAGE_QUERY, "redirect_uri": "https://evil.example/"}).status_code == 400


def test_the_code_exchange_is_forwarded_for_the_console_client(external, provider):
    with TestClient(external.app) as c:
        r = c.post("/token", data={"grant_type": "authorization_code", "code": "abc",
                                   "code_verifier": "v" * 43, "redirect_uri": "/",
                                   "client_id": CONSOLE_CLIENT_ID})
        assert r.status_code == 200 and r.json()["access_token"] == "provider-token"
        assert provider.token_requests[-1]["client_id"] == CONSOLE_CLIENT_ID
        assert provider.token_requests[-1]["redirect_uri"] == "http://testserver/"
        r = c.post("/token", data={"grant_type": "authorization_code", "code": "abc",
                                   "code_verifier": "v", "redirect_uri": "/", "client_id": "approval-page"})
        assert r.status_code == 400 and r.json()["error"] == "unauthorized_client"


def test_me_reports_the_signed_in_person(external, keypair):
    with TestClient(external.app) as c:
        r = c.get("/me", headers=bearer(console_token(keypair, "child-id", ["child"])))
        assert r.json() == {"sub": "child-id", "roles": ["child"]}
        assert c.get("/me").status_code == 401


# -- a session per signed-in person ------------------------------------------ #


def test_chat_requires_the_bearer_in_external_mode(external):
    with TestClient(external.app) as c:
        r = c.post("/chat", json={"message": "hi"})
        assert r.status_code == 401 and r.headers["WWW-Authenticate"].startswith("Bearer")
        assert external.opened == []


def test_a_token_for_the_passkey_page_is_not_a_token_for_the_console(external, keypair):
    with TestClient(external.app) as c:
        page_token = mint(keypair, ["child"], sub="child-id")  # audience approval-service
        assert c.post("/chat", json={"message": "hi"}, headers=bearer(page_token)).status_code == 401


def test_each_person_gets_one_session_and_keeps_it(external, keypair):
    with TestClient(external.app) as c:
        child = bearer(console_token(keypair, "child-id", ["child"]))
        parent = bearer(console_token(keypair, "parent-id", ["parent"]))
        r1 = c.post("/chat", json={"message": "one"}, headers=child)
        r2 = c.post("/chat", json={"message": "two"}, headers=child)
        r3 = c.post("/chat", json={"message": "three"}, headers=parent)
        assert r1.json()["reply"] == "child-id heard: one"
        assert r2.json()["reply"] == "child-id heard: two"
        assert r3.json()["reply"] == "parent-id heard: three"
        assert [s.sub for s in external.opened] == ["child-id", "parent-id"]
        seats = external.app.state.seats
        assert seats["child-id"].agent.turns == ["one", "two"]
        assert seats["child-id"].roles == ["child"] and seats["parent-id"].roles == ["parent"]


def test_a_fresh_token_for_the_same_person_updates_the_seat_not_the_session(external, keypair):
    with TestClient(external.app) as c:
        first = console_token(keypair, "child-id", ["child"])
        # A later sign-in: same person, a different token (RS256 signing is
        # deterministic, so the claims have to differ for the bytes to).
        second = mint(keypair, ["child"], audience=PROXY_AUDIENCE, sub="child-id", amr=["hwk", "user"])
        assert first != second
        c.post("/chat", json={"message": "a"}, headers=bearer(first))
        c.post("/chat", json={"message": "b"}, headers=bearer(second))
        seat = external.app.state.seats["child-id"]
        assert seat.token == second and len(external.opened) == 1


async def test_the_seats_session_presents_the_seats_current_token(external):
    """What reaches the proxy: the auth the per-person session is built with
    reads the seat's token per request, so a re-sign-in after expiry needs
    no new session."""
    seat = external.Seat(sub="child-id", roles=["child"], token="t1")
    auth = external._SeatBearer(seat)
    req = httpx2.Request("POST", "http://proxy.test/mcp/")
    flow = auth.async_auth_flow(req)
    sent = await flow.__anext__()
    assert sent.headers["Authorization"] == "Bearer t1"
    seat.token = "t2"
    flow2 = auth.async_auth_flow(httpx2.Request("POST", "http://proxy.test/mcp/"))
    assert (await flow2.__anext__()).headers["Authorization"] == "Bearer t2"


# -- the home shape ---------------------------------------------------------- #


def test_without_a_provider_the_console_is_anonymous_and_has_no_sign_in(monkeypatch):
    mod = load_console(monkeypatch)
    assert mod._external is None
    with TestClient(mod.app) as c:
        assert c.get("/authorize", params=PAGE_QUERY).status_code == 404
        assert c.get("/me").status_code == 404
        r = c.post("/chat", json={"message": "hi"})
        assert r.status_code == 200 and r.json()["reply"] == "household heard: hi"
        assert mod.opened == []
        assert "const EXTERNAL = false;" in c.get("/").text


def test_a_message_while_the_assistant_is_busy_is_refused_with_the_reply_to_show(monkeypatch):
    mod = load_console(monkeypatch)
    with TestClient(mod.app) as c:
        mod.app.state.agent.busy = True
        r = c.post("/chat", json={"message": "did you send it?"})
        assert r.status_code == 409
        assert r.json()["detail"] == mod.BUSY_REPLY
        assert mod.app.state.agent.turns == []
        mod.app.state.agent.busy = False
        assert c.post("/chat", json={"message": "hi"}).status_code == 200
        page = c.get("/").text
    assert "res.status === 409" in page and "input.disabled = true" in page


def test_the_page_knows_which_mode_it_is_in(external):
    with TestClient(external.app) as c:
        assert "const EXTERNAL = true;" in c.get("/").text


# -- approval tasks: opened in a conversation, finished by a human elsewhere -- #


def test_a_task_the_conversation_opened_is_remembered_by_its_id(monkeypatch):
    mod = load_console(monkeypatch)
    with TestClient(mod.app):
        app = mod.app
        mod._note_task(app, mod.HOUSEHOLD, "call_tool",
                       {"tool_name": "request_invoice_approval"}, '{"task_id": "t-1", "status": "input_required"}')
        # other calls, and results that are not a task, leave no trace
        mod._note_task(app, mod.HOUSEHOLD, "search_tools", {"query": "x"}, "Found 2")
        mod._note_task(app, mod.HOUSEHOLD, "call_tool", {"tool_name": "pizza__negotiate"}, '{"reply": "hi"}')
        mod._note_task(app, mod.HOUSEHOLD, "call_tool", {"tool_name": "request_invoice_approval"}, "not json")
        assert app.state.tasks == {"t-1": mod.HOUSEHOLD}


async def test_a_terminal_event_resumes_the_conversation_and_fills_its_inbox(monkeypatch):
    mod = load_console(monkeypatch)
    with TestClient(mod.app) as c:
        app = mod.app
        app.state.tasks["t-1"] = mod.HOUSEHOLD
        await mod._on_event(app, {"task_id": "t-1", "status": "approved"})
        agent = app.state.agent
        assert len(agent.resumed) == 1
        assert "t-1 is approved" in agent.resumed[0] and "approval_result" in agent.resumed[0]
        assert agent.turns == []  # not a person's message
        assert "t-1" not in app.state.tasks  # delivered once
        # the page collects it, and it is gone after that
        assert c.get("/chat/inbox").json()["replies"] == [f"household resumed: {agent.resumed[0]}"]
        assert c.get("/chat/inbox").json()["replies"] == []
        # a task nobody here opened is ignored, not resumed
        await mod._on_event(app, {"task_id": "t-other", "status": "expired"})
        assert len(agent.resumed) == 1


async def test_in_external_mode_the_event_reaches_the_person_who_opened_the_task(external, keypair):
    with TestClient(external.app) as c:
        child = bearer(mint(keypair, ["child"], sub="child-1", audience=PROXY_AUDIENCE))
        parent = bearer(mint(keypair, ["parent"], sub="parent-1", audience=PROXY_AUDIENCE, amr=("hwk", "user")))
        c.post("/chat", json={"message": "order"}, headers=child)
        c.post("/chat", json={"message": "hello"}, headers=parent)
        app = external.app
        app.state.tasks["t-2"] = "child-1"
        await external._on_event(app, {"task_id": "t-2", "status": "approved"})
        assert len(app.state.seats["child-1"].agent.resumed) == 1
        assert app.state.seats["parent-1"].agent.resumed == []
        assert c.get("/chat/inbox", headers=parent).json()["replies"] == []
        assert len(c.get("/chat/inbox", headers=child).json()["replies"]) == 1
        assert c.get("/chat/inbox").status_code == 401  # no bearer, no inbox


def test_the_event_stream_is_read_for_its_data_lines(monkeypatch):
    mod = load_console(monkeypatch)
    lines = [": connected", "", "data: {\"task_id\": \"t-1\", \"status\": \"approved\"}", ": keepalive", "data: not json"]
    assert list(mod._sse_events(lines)) == [{"task_id": "t-1", "status": "approved"}]

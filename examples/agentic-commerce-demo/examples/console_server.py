# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""A single browser-facing console for the pizza demo: a chat window that
drives the family proxy through its own MCP endpoint (search_tools /
call_tool / load_mcp_server — the same three meta-tools any MCP client would
see), plus a live log of what happens as a result. Meant to replace running
``claude`` in a terminal and grepping container logs by hand: one page to
type into, a second to watch.

Talks to the proxy exactly as an external MCP client would (Streamable HTTP,
the same endpoint ``claude mcp add`` would point at) — nothing here reaches
into the proxy's internals.

With ``APPROVAL_ISSUER`` set, the console runs on the organization's
identity provider: the page signs the person in there (the same
authorization-code + PKCE relay the passkey page uses, with the console's
own client and the proxy's own audience), every chat request carries the
bearer, and the console holds one MCP session *per signed-in person*, each
presenting that person's token to the proxy — so the proxy's principal on
every call is the person at this console, not the console itself. Unset,
one anonymous session serves the one household on loopback, as before.

    uv run python examples/console_server.py      # -> http://localhost:7300
"""

from __future__ import annotations

import asyncio
import dataclasses
import os
import re
import time
from contextlib import AsyncExitStack, asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator

import anthropic
import httpx2
import uvicorn
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from extensible_mcp.client_manager import negotiate

from extensible_mcp_vc.chat_agent import ChatAgent
from extensible_mcp_vc.oauth import (
    CONSOLE_CLIENT_ID,
    PROXY_AUDIENCE,
    ExternalIssuer,
    ExternalIssuerConfig,
    ExternalIssuerError,
    OAuthError,
    eligible_roles,
)

PROJECT = Path(__file__).resolve().parent.parent
PROXY_URL = os.environ.get("PROXY_URL", "http://127.0.0.1:7400/mcp/")
LOG_FILE = Path(
    os.environ.get("DEMO_LOG_FILE", str(PROJECT / "workspace" / "demo.log"))
)


def _log(line: str) -> None:
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with LOG_FILE.open("a") as f:
        f.write(f"[{time.strftime('%H:%M:%S')}] {line}\n")


# The organization's identity provider, when configured: the console's own
# client, and the proxy's audience -- the token it relays is the proxy's
# principal, never the passkey page's.
_external_config = ExternalIssuerConfig.from_env()
_external: ExternalIssuer | None = (
    ExternalIssuer(dataclasses.replace(
        _external_config, client_id=CONSOLE_CLIENT_ID, audience=PROXY_AUDIENCE,
    ))
    if _external_config is not None else None
)

# The proxy is launched a couple of seconds before this process, but "a
# couple of seconds" is a guess, not a guarantee (vector-index build time
# varies with load) — a single failed connection attempt here used to take
# the whole container down. Retry instead of racing a fixed sleep.
_CONNECT_RETRIES = 15
_CONNECT_RETRY_DELAY = 2.0


@dataclasses.dataclass
class Seat:
    """One signed-in person at this console: their subject, the bearer
    their last request carried, and the agent whose MCP session presents it.
    The token is read per request by the session's auth, so a re-sign-in
    after expiry needs no new session."""

    sub: str
    roles: list[str]
    token: str
    agent: Any = None
    stack: AsyncExitStack = dataclasses.field(default_factory=AsyncExitStack)


class _SeatBearer(httpx2.Auth):
    """Presents the seat's current token on every request to the proxy."""

    def __init__(self, seat: Seat) -> None:
        self._seat = seat

    async def async_auth_flow(self, request: httpx2.Request):  # type: ignore[override]
        request.headers["Authorization"] = f"Bearer {self._seat.token}"
        yield request

    def sync_auth_flow(self, request: httpx2.Request):  # type: ignore[override]
        raise RuntimeError("async only")


async def _connect(stack: AsyncExitStack, http_client: httpx2.AsyncClient | None = None):
    """A negotiated MCP session on ``stack``, retrying while the proxy comes up."""
    session = None
    for attempt in range(1, _CONNECT_RETRIES + 1):
            # A fresh, disposable stack per attempt: on failure it's closed
            # outright instead of leaving broken connections piled onto the
            # long-lived outer stack; on success its entries are transferred
            # into the outer stack via pop_all() so they outlive this loop.
            attempt_stack = AsyncExitStack()
            try:
                if http_client is not None:
                    await attempt_stack.enter_async_context(http_client)
                read, write = await attempt_stack.enter_async_context(
                    streamable_http_client(PROXY_URL, http_client=http_client)
                )
                session = await attempt_stack.enter_async_context(
                    ClientSession(read, write)
                )
                await negotiate(session)
            except (Exception, BaseExceptionGroup) as e:
                # BaseExceptionGroup as well as Exception: the mcp client's
                # own task group wraps a plain connection failure together
                # with its sibling tasks' cancellation, and the group is not
                # an Exception subclass -- so `except Exception` alone
                # silently let every attempt but the last one crash the whole
                # container instead of retrying. Not bare BaseException,
                # which also swallows the CancelledError of a shutdown
                # arriving mid-retry: that used to sleep out the remaining
                # attempts before the process could exit.
                try:
                    await attempt_stack.aclose()
                except Exception:
                    # The transport's own task group may already have crashed
                    # and unwound, in which case exiting it from here raises
                    # anyio's "different task" RuntimeError. The connection is
                    # dead either way; a teardown error must not replace the
                    # connection error we are retrying on -- doing so used to
                    # kill the console on its first attempt instead of
                    # retrying.
                    pass
                session = None
                if isinstance(e, BaseExceptionGroup) and e.subgroup(
                    lambda leaf: not isinstance(leaf, asyncio.CancelledError)
                ) is None:
                    # Nothing in the group but cancellations: this process is
                    # being shut down, not a downstream that is not up yet.
                    # (A group holding *only* a cancellation is the test --
                    # a plain connection failure arrives in a group carrying
                    # the sibling tasks' cancellations alongside it, so the
                    # presence of one proves nothing.)
                    raise
                if attempt == _CONNECT_RETRIES:
                    raise
                _log(
                    f"console: proxy not ready yet ({e}); retry "
                    f"{attempt}/{_CONNECT_RETRIES} in {_CONNECT_RETRY_DELAY}s"
                )
                await asyncio.sleep(_CONNECT_RETRY_DELAY)
            else:
                stack.push_async_exit(attempt_stack.pop_all().aclose)
                _log(f"console connected to proxy at {PROXY_URL} (attempt {attempt})")
                return session
    raise RuntimeError("unreachable: the last attempt re-raises")


async def _open_agent(app: FastAPI, seat: Seat) -> Any:
    """The seat's agent: a session of its own, presenting the seat's bearer."""
    client = httpx2.AsyncClient(auth=_SeatBearer(seat), timeout=httpx2.Timeout(300.0))
    session = await _connect(seat.stack, client)
    return ChatAgent(session=session, anthropic_messages=app.state.anthropic, log=_log)


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    app.state.anthropic = anthropic.AsyncAnthropic().messages
    app.state.seats = {}
    async with AsyncExitStack() as stack:
        if _external is None:
            # The home shape: one anonymous session for the one household.
            session = await _connect(stack)
            app.state.agent = ChatAgent(
                session=session, anthropic_messages=app.state.anthropic, log=_log,
            )
        else:
            # Nobody has signed in yet, and the proxy refuses an anonymous
            # session; each person's session opens on their first message.
            app.state.agent = None
            _log(f"console: sign-in via {_external.config.issuer}; a session per person")
        try:
            yield
        finally:
            for seat in list(app.state.seats.values()):
                await seat.stack.aclose()


app = FastAPI(title="Family assistant console", lifespan=_lifespan)

_OAUTH_STATUS = {"invalid_token": 401, "insufficient_scope": 403}


def _refused(e: OAuthError) -> HTTPException:
    headers = {"WWW-Authenticate": 'Bearer realm="console"'} if e.code == "invalid_token" else None
    return HTTPException(_OAUTH_STATUS.get(e.code, 400), f"{e.code}: {e.description}", headers=headers)


async def _claims(request: Request) -> dict[str, Any]:
    assert _external is not None
    try:
        return await _external.verify_token(request.headers.get("Authorization"))
    except OAuthError as e:
        raise _refused(e) from e
    except ExternalIssuerError as e:
        raise HTTPException(503, str(e)) from e


async def _seat_for(request: Request) -> Seat:
    """The signed-in person's seat, opened on their first message. Keyed on
    the subject, so two browser windows holding the same person's tokens
    share one session and two people never do."""
    claims = await _claims(request)
    token = request.headers["Authorization"][7:].strip()
    seats: dict[str, Seat] = request.app.state.seats
    seat = seats.get(claims["sub"])
    if seat is None:
        seat = Seat(sub=claims["sub"], roles=eligible_roles(claims), token=token)
        seats[claims["sub"]] = seat
    seat.token = token
    seat.roles = eligible_roles(claims)
    if seat.agent is None:
        seat.agent = await _open_agent(request.app, seat)
        _log(f"console: session opened for {seat.sub} ({', '.join(seat.roles) or 'no role'})")
    return seat


@app.post("/chat")
async def chat(request: Request) -> JSONResponse:
    body = await request.json()
    message = (body.get("message") or "").strip()
    if not message:
        raise HTTPException(400, "message is required")
    if _external is not None:
        seat = await _seat_for(request)
        agent, who = seat.agent, f"user {seat.sub}"
    else:
        agent, who = request.app.state.agent, "user"
    _log(f"{who}: {message}")
    try:
        reply = await agent.turn(message)
    except Exception as e:  # noqa: BLE001 - surfaced to the chat, not a bare 500
        _log(f"error: {e}")
        raise HTTPException(502, str(e)) from e
    _log(f"assistant: {reply}")
    return JSONResponse({"reply": reply})


# -- sign-in at the organization's provider, relayed as the passkey page does -- #


def _absolute(request: Request, redirect_uri: str) -> str:
    origin = f"{request.url.scheme}://{request.headers.get('host', request.url.netloc)}"
    return origin + redirect_uri if redirect_uri.startswith("/") else redirect_uri


def _require_external() -> ExternalIssuer:
    if _external is None:
        raise HTTPException(404, "no sign-in: this console serves one household anonymously")
    return _external


@app.get("/authorize")
async def authorize(request: Request) -> Response:
    ext = _require_external()
    q = request.query_params
    if q.get("client_id") != CONSOLE_CLIENT_ID:
        raise HTTPException(400, "unauthorized_client: unknown client_id")
    if q.get("redirect_uri") != "/":
        raise HTTPException(400, "invalid_request: redirect_uri is not registered")
    if q.get("response_type") != "code" or q.get("code_challenge_method") != "S256":
        raise HTTPException(400, "invalid_request: only code + S256 is supported")
    if not q.get("code_challenge"):
        raise HTTPException(400, "invalid_request: code_challenge is required (PKCE)")
    try:
        target = await ext.authorize_url(
            redirect_uri=_absolute(request, q["redirect_uri"]),
            code_challenge=q["code_challenge"], state=q.get("state", ""),
        )
    except ExternalIssuerError as e:
        raise HTTPException(503, str(e)) from e
    return RedirectResponse(target, status_code=302)


@app.post("/token")
async def token(request: Request) -> JSONResponse:
    ext = _require_external()
    form = await request.form()
    try:
        status, body = await ext.exchange_code(
            code=str(form.get("code", "")),
            code_verifier=str(form.get("code_verifier", "")),
            redirect_uri=_absolute(request, str(form.get("redirect_uri", ""))),
            client_id=str(form.get("client_id", "")),
        )
    except OAuthError as e:
        return JSONResponse({"error": e.code, "error_description": e.description}, status_code=400)
    except ExternalIssuerError as e:
        raise HTTPException(503, str(e)) from e
    return JSONResponse(body, status_code=status, headers={"Cache-Control": "no-store"})


@app.get("/me")
async def me(request: Request) -> JSONResponse:
    _require_external()
    claims = await _claims(request)
    return JSONResponse({"sub": claims["sub"], "roles": eligible_roles(claims)})


@app.get("/", response_class=HTMLResponse)
async def index() -> HTMLResponse:
    return HTMLResponse(_CHAT_HTML.replace("__EXTERNAL__", "true" if _external else "false"))


@app.get("/logs", response_class=HTMLResponse)
async def logs_page() -> HTMLResponse:
    return HTMLResponse(_LOGS_HTML)


# Two distinct noisy formats, both logging the same "some request happened"
# fact, and both filtered out here:
#   INFO:     127.0.0.1:56934 - "POST /mcp HTTP/1.1" 200 OK             (uvicorn access log:
#                                                                        method+path+version
#                                                                        inside the quotes)
#   INFO:httpx:HTTP Request: GET http://x/y "HTTP/1.1 200 OK"           (httpx's own client-
#                                                                        side request log:
#                                                                        method+url OUTSIDE
#                                                                        the quotes, only the
#                                                                        version+status inside)
# The approval page's own /pending poll (every 1.5s) alone produces both of
# these every tick, so they dominate at demo traffic volumes, drowning out
# the narration (trust exchange, policy verdicts, settlement) that's
# actually worth watching. Filtered here, not at each service's own logging
# config, so this stays a one-file change. Matches any HTTP status line
# (any 3-digit code), not just 200 — a redirect or an error is exactly as
# uninteresting as a success here.
_ACCESS_LOG_RE = re.compile(
    r'"\s*(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s\S+\sHTTP/\d\.\d"\s\d{3}'
    r'|HTTP Request:.*"\s*HTTP/\d\.\d\s+\d{3}'
)


async def _tail(path: Path) -> AsyncIterator[str]:
    """Poll-based ``tail -f``: simple, and good enough for a demo's log
    volume. Handles the file not existing yet and being truncated/rotated
    underneath us (falls back to reading from the start). Skips per-request
    access-log noise (see ``_ACCESS_LOG_RE``) so the narration doesn't
    scroll off screen behind a wall of "200 OK"."""
    pos = path.stat().st_size if path.exists() else 0
    while True:
        await asyncio.sleep(0.4)
        if not path.exists():
            continue
        size = path.stat().st_size
        if size < pos:
            pos = 0
        if size > pos:
            with path.open("rb") as f:
                f.seek(pos)
                chunk = f.read()
                pos = f.tell()
            for line in chunk.decode(errors="replace").splitlines():
                if _ACCESS_LOG_RE.search(line):
                    continue
                yield f"data: {line}\n\n"


@app.get("/logs/stream")
async def logs_stream() -> StreamingResponse:
    return StreamingResponse(_tail(LOG_FILE), media_type="text/event-stream")


_CHAT_HTML = """<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Family assistant</title>
<style>
  body { font-family: -apple-system, sans-serif; max-width: 640px; margin: 2rem auto; padding: 0 1rem; }
  #transcript { border: 1px solid #ccc; border-radius: 8px; padding: 1rem; min-height: 300px;
                max-height: 60vh; overflow-y: auto; margin-bottom: 1rem; }
  .msg { margin: 0.5rem 0; white-space: pre-wrap; }
  .user { color: #0645ad; }
  .assistant { color: #222; }
  .pending { color: #888; font-style: italic; }
  form { display: flex; gap: 0.5rem; }
  input[type=text] { flex: 1; padding: 0.5rem; font-size: 1rem; }
  button { padding: 0.5rem 1rem; font-size: 1rem; }
</style>
</head>
<body>
<h1>Family assistant</h1>
<p><a href="/logs">Live log</a> <span id="who"></span></p>
<div id="transcript"></div>
<form id="form">
  <input id="input" type="text" autocomplete="off"
         placeholder="Order a cheese slice from Domino's, delivered to 12 Main St" />
  <button type="submit">Send</button>
</form>
<script>
const EXTERNAL = __EXTERNAL__;
const transcript = document.getElementById('transcript');
const form = document.getElementById('form');
const input = document.getElementById('input');

// -- sign-in at the organization's identity provider (authorization code +
// PKCE, relayed by this console; the same flow the passkey page runs) ---- //
const S = sessionStorage;
const b64 = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');
const rnd = n => b64(crypto.getRandomValues(new Uint8Array(n)));
async function s256(v){ return b64(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(v))); }
let token = null;

async function signIn(){
  const verifier = rnd(48); S.setItem('pkce_v', verifier);
  const state = rnd(12); S.setItem('pkce_s', state);
  const q = new URLSearchParams({response_type:'code', client_id:'family-console', redirect_uri:'/',
    state, code_challenge: await s256(verifier), code_challenge_method:'S256'});
  location.href = '/authorize?' + q;
}

async function completeSignIn(){
  const u = new URL(location.href), code = u.searchParams.get('code'), state = u.searchParams.get('state');
  if (!code) return false;
  if (state !== S.getItem('pkce_s')) { addMessage('assistant', 'sign-in state mismatch; sign in again'); return false; }
  const body = new URLSearchParams({grant_type:'authorization_code', code,
    code_verifier: S.getItem('pkce_v'), redirect_uri:'/', client_id:'family-console'});
  const r = await fetch('/token', {method:'POST', headers:{'content-type':'application/x-www-form-urlencoded'}, body});
  if (!r.ok) { addMessage('assistant', 'token exchange failed'); return false; }
  const j = await r.json();
  S.setItem('tok', j.access_token); S.removeItem('pkce_v'); S.removeItem('pkce_s');
  history.replaceState({}, '', '/');
  return true;
}

const auth = () => token ? {'Authorization': 'Bearer ' + token} : {};

async function boot(){
  if (!EXTERNAL) return;
  await completeSignIn();
  token = S.getItem('tok');
  if (!token) { await signIn(); return; }
  const r = await fetch('/me', {headers: auth()});
  if (r.status === 401) { S.removeItem('tok'); await signIn(); return; }
  const me = await r.json();
  document.getElementById('who').textContent = '— signed in as ' + me.sub + ' (' + me.roles.join('/') + ')';
}

function addMessage(cls, text) {
  const div = document.createElement('div');
  div.className = 'msg ' + cls;
  div.textContent = text;
  transcript.appendChild(div);
  transcript.scrollTop = transcript.scrollHeight;
  return div;
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const message = input.value.trim();
  if (!message) return;
  input.value = '';
  addMessage('user', message);
  const pending = addMessage('pending', 'thinking...');
  try {
    const res = await fetch('/chat', {
      method: 'POST',
      headers: {'Content-Type': 'application/json', ...auth()},
      body: JSON.stringify({message}),
    });
    if (res.status === 401 && EXTERNAL) { pending.remove(); S.removeItem('tok'); await signIn(); return; }
    const data = await res.json();
    pending.remove();
    addMessage('assistant', res.ok ? data.reply : ('Error: ' + (data.detail || res.status)));
  } catch (err) {
    pending.remove();
    addMessage('assistant', 'Error: ' + err);
  }
});
boot();
</script>
</body>
</html>
"""

_LOGS_HTML = """<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Demo log</title>
<style>
  body { font-family: ui-monospace, monospace; background: #111; color: #ddd; margin: 0; }
  #top { padding: 0.5rem 1rem; background: #000; }
  #top a { color: #7ab7ff; }
  #log { padding: 1rem; white-space: pre-wrap; word-break: break-all; font-size: 0.85rem; }
</style>
</head>
<body>
<div id="top"><a href="/">&larr; back to chat</a></div>
<div id="log"></div>
<script>
const log = document.getElementById('log');
const es = new EventSource('/logs/stream');
es.onmessage = (e) => {
  log.textContent += e.data + '\\n';
  window.scrollTo(0, document.body.scrollHeight);
};
</script>
</body>
</html>
"""


if __name__ == "__main__":
    uvicorn.run(
        app,
        host=os.environ.get("CONSOLE_HOST", "127.0.0.1"),
        port=int(os.environ.get("CONSOLE_PORT", "7300")),
    )

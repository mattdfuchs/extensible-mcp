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

    uv run python examples/console_server.py      # -> http://localhost:7300
"""

from __future__ import annotations

import asyncio
import os
import re
import time
from contextlib import AsyncExitStack, asynccontextmanager
from pathlib import Path
from typing import AsyncIterator

import anthropic
import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from extensible_mcp_vc.chat_agent import ChatAgent

PROJECT = Path(__file__).resolve().parent.parent
PROXY_URL = os.environ.get("PROXY_URL", "http://127.0.0.1:7400/mcp/")
LOG_FILE = Path(
    os.environ.get("DEMO_LOG_FILE", str(PROJECT / "workspace" / "demo.log"))
)


def _log(line: str) -> None:
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with LOG_FILE.open("a") as f:
        f.write(f"[{time.strftime('%H:%M:%S')}] {line}\n")


# The proxy is launched a couple of seconds before this process, but "a
# couple of seconds" is a guess, not a guarantee (vector-index build time
# varies with load) — a single failed connection attempt here used to take
# the whole container down. Retry instead of racing a fixed sleep.
_CONNECT_RETRIES = 15
_CONNECT_RETRY_DELAY = 2.0


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    async with AsyncExitStack() as stack:
        session = None
        for attempt in range(1, _CONNECT_RETRIES + 1):
            # A fresh, disposable stack per attempt: on failure it's closed
            # outright instead of leaving broken connections piled onto the
            # long-lived outer stack; on success its entries are transferred
            # into the outer stack via pop_all() so they outlive this loop.
            attempt_stack = AsyncExitStack()
            try:
                read, write, _ = await attempt_stack.enter_async_context(
                    streamable_http_client(PROXY_URL)
                )
                session = await attempt_stack.enter_async_context(
                    ClientSession(read, write)
                )
                await session.initialize()
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
                break
        app.state.agent = ChatAgent(
            session=session,
            anthropic_messages=anthropic.AsyncAnthropic().messages,
            log=_log,
        )
        _log(f"console connected to proxy at {PROXY_URL} (attempt {attempt})")
        yield


app = FastAPI(title="Family assistant console", lifespan=_lifespan)


@app.post("/chat")
async def chat(request: Request) -> JSONResponse:
    body = await request.json()
    message = (body.get("message") or "").strip()
    if not message:
        raise HTTPException(400, "message is required")
    _log(f"user: {message}")
    try:
        reply = await request.app.state.agent.turn(message)
    except Exception as e:  # noqa: BLE001 - surfaced to the chat, not a bare 500
        _log(f"error: {e}")
        raise HTTPException(502, str(e)) from e
    _log(f"assistant: {reply}")
    return JSONResponse({"reply": reply})


@app.get("/", response_class=HTMLResponse)
async def index() -> HTMLResponse:
    return HTMLResponse(_CHAT_HTML)


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
<p><a href="/logs">Live log</a></p>
<div id="transcript"></div>
<form id="form">
  <input id="input" type="text" autocomplete="off"
         placeholder="Order a cheese slice from Domino's, delivered to 12 Main St" />
  <button type="submit">Send</button>
</form>
<script>
const transcript = document.getElementById('transcript');
const form = document.getElementById('form');
const input = document.getElementById('input');

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
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({message}),
    });
    const data = await res.json();
    pending.remove();
    addMessage('assistant', res.ok ? data.reply : ('Error: ' + (data.detail || res.status)));
  } catch (err) {
    pending.remove();
    addMessage('assistant', 'Error: ' + err);
  }
});
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

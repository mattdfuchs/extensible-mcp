# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Browser-based approval surface for wallet sign operations.

The terminal prompt (:mod:`.approval`) needs a tty; a containerized wallet
has none. This module provides the same ``approve(message) -> bool`` contract
backed by a minimal web page: pending prompts are held in memory, the page
polls and renders them with Approve / Deny buttons, and the human's click
resolves the waiting sign request. One surface per wallet — the kid's tab and
the parent's tab are different ports, exactly as their terminals were.

No authentication: like the terminal prompt, whoever can reach the wallet's
page *is* its human. Bind the port accordingly (localhost / a published
container port on the demo machine).
"""

from __future__ import annotations

import asyncio
import itertools
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse

_DEFAULT_TIMEOUT_SECONDS = 600.0


class WebApproval:
    """Pending-prompt store + the ``approve`` callable to inject into
    :func:`~household_identity.wallet.server.create_app`."""

    def __init__(self, *, timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS) -> None:
        self._timeout = timeout_seconds
        self._counter = itertools.count(1)
        self._pending: dict[int, dict[str, Any]] = {}

    async def approve(self, message: str) -> bool:
        prompt_id = next(self._counter)
        future: asyncio.Future[bool] = asyncio.get_running_loop().create_future()
        self._pending[prompt_id] = {"message": message, "future": future}
        try:
            return await asyncio.wait_for(future, timeout=self._timeout)
        except asyncio.TimeoutError:
            return False  # unanswered = declined, same as EOF on the terminal
        finally:
            self._pending.pop(prompt_id, None)

    def mount(self, app: FastAPI, label: str) -> None:
        """Add the approval routes and page to a wallet app."""

        @app.get("/approvals")
        async def approvals() -> JSONResponse:
            return JSONResponse(
                [
                    {"id": pid, "message": p["message"]}
                    for pid, p in sorted(self._pending.items())
                ]
            )

        @app.post("/approvals/{prompt_id}")
        async def decide(prompt_id: int, body: dict) -> JSONResponse:
            p = self._pending.get(prompt_id)
            if p is None or p["future"].done():
                raise HTTPException(404, "no such pending approval")
            p["future"].set_result(bool(body.get("approve")))
            return JSONResponse({"ok": True})

        @app.get("/ui")
        async def ui() -> HTMLResponse:
            return HTMLResponse(_PAGE.replace("__LABEL__", label))


_PAGE = """<!doctype html><meta charset=utf-8>
<title>__LABEL__ wallet</title>
<style>body{font:16px system-ui;max-width:42em;margin:2.5em auto;padding:0 1em}
.prompt{background:#f7f7f2;border:1px solid #ddd;border-radius:8px;padding:1em;margin:1em 0}
pre{white-space:pre-wrap;font:14px ui-monospace,monospace;margin:.5em 0}
button{font:inherit;padding:.5em 1.2em;margin-right:.6em;cursor:pointer}
.approve{background:#2a7;color:#fff;border:none;border-radius:6px}
.deny{background:#eee;border:1px solid #ccc;border-radius:6px}
#empty{color:#888}</style>
<h1>__LABEL__ wallet</h1>
<div id=list></div><p id=empty>No pending approvals.</p>
<script>
async function decide(id, approve){
  await fetch('/approvals/'+id,{method:'POST',
    headers:{'content-type':'application/json'},body:JSON.stringify({approve})});
  poll();
}
async function poll(){
  try{
    const items = await (await fetch('/approvals')).json();
    document.getElementById('empty').style.display = items.length ? 'none' : '';
    document.getElementById('list').innerHTML = items.map(p =>
      '<div class=prompt><pre>'+p.message.replace(/&/g,'&amp;').replace(/</g,'&lt;')+
      '</pre><button class=approve onclick=decide('+p.id+',true)>Approve</button>'+
      '<button class=deny onclick=decide('+p.id+',false)>Deny</button></div>'
    ).join('');
  }catch(e){}
}
setInterval(poll, 1200); poll();
</script>"""

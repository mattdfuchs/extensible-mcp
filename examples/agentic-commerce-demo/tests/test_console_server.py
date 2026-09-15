# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""console_server's log tailer: the one piece of genuinely custom logic in
that module (everything else is thin FastAPI wiring + the already-tested
ChatAgent). Covers the cases that matter for a demo log a human is staring
at live: the file not existing yet, growth mid-stream, a truncated/rotated
file (falls back to reading from the start again), and filtering out
per-request access-log noise so the narration doesn't scroll off screen."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

# Make examples/ importable like family_proxy_server.py does in production.
_EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
sys.path.insert(0, str(_EXAMPLES))
from console_server import _tail  # noqa: E402


async def _collect(gen, count: int, timeout: float = 2.0) -> list[str]:
    """The first ``count`` SSE ``data:`` lines the generator yields, with
    the "data: " prefix and trailing blank line stripped back to plain text."""
    out = []
    async with asyncio.timeout(timeout):
        async for chunk in gen:
            assert chunk.startswith("data: ") and chunk.endswith("\n\n")
            out.append(chunk[len("data: ") : -2])
            if len(out) == count:
                return out
    return out


async def test_tail_yields_lines_appended_after_start(tmp_path):
    log = tmp_path / "demo.log"
    log.write_text("")
    gen = _tail(log)

    async def _writer():
        await asyncio.sleep(0.05)
        log.write_text("first line\n")
        await asyncio.sleep(0.6)
        with log.open("a") as f:
            f.write("second line\n")

    writer = asyncio.create_task(_writer())
    lines = await _collect(gen, count=2)
    await writer

    assert lines == ["first line", "second line"]


async def test_tail_starts_from_existing_content_not_the_beginning(tmp_path):
    """A viewer opening the log page mid-demo shouldn't be replayed the
    entire history — only what's appended after they connect."""
    log = tmp_path / "demo.log"
    log.write_text("stale line from before the page loaded\n")
    gen = _tail(log)

    async def _writer():
        await asyncio.sleep(0.05)
        with log.open("a") as f:
            f.write("new line\n")

    writer = asyncio.create_task(_writer())
    lines = await _collect(gen, count=1)
    await writer

    assert lines == ["new line"]


async def test_tail_handles_missing_file_until_created(tmp_path):
    log = tmp_path / "not-yet.log"
    gen = _tail(log)

    async def _writer():
        await asyncio.sleep(0.6)
        log.write_text("appeared\n")

    writer = asyncio.create_task(_writer())
    lines = await _collect(gen, count=1)
    await writer

    assert lines == ["appeared"]


async def test_tail_recovers_from_truncation(tmp_path):
    """A log that shrinks (rotated/truncated underneath the reader) is read
    from the start again rather than getting stuck at a stale offset."""
    log = tmp_path / "demo.log"
    log.write_text("a" * 100 + "\n")
    gen = _tail(log)

    async def _writer():
        await asyncio.sleep(0.5)
        log.write_text("after rotation\n")

    writer = asyncio.create_task(_writer())
    lines = await _collect(gen, count=1)
    await writer

    assert lines == ["after rotation"]


async def test_tail_filters_access_log_noise(tmp_path):
    """Both noisy formats actually seen in a live run: uvicorn's own access
    log (method+path+version inside the quotes) and httpx's client-side
    request log (method+url outside the quotes, only version+status
    inside) — the second one is what a prior filter pass missed, since it
    was tested only against the first format."""
    log = tmp_path / "demo.log"
    log.write_text("")
    gen = _tail(log)

    async def _writer():
        await asyncio.sleep(0.05)
        with log.open("a") as f:
            f.write(
                '[10:05:18] user: order a cheese slice\n'
                'INFO:     127.0.0.1:35096 - "POST /mcp/ HTTP/1.1" 307 Temporary Redirect\n'
                'INFO:     127.0.0.1:35096 - "POST /mcp HTTP/1.1" 200 OK\n'
                'INFO:httpx:HTTP Request: GET http://localhost:7500/pending/abc "HTTP/1.1 200 OK"\n'
                'INFO:mcp.server.lowlevel.server:Processing request of type ListToolsRequest\n'
                '[10:05:19] assistant: Found it.\n'
            )

    writer = asyncio.create_task(_writer())
    lines = await _collect(gen, count=3)
    await writer

    assert lines == [
        "[10:05:18] user: order a cheese slice",
        "INFO:mcp.server.lowlevel.server:Processing request of type ListToolsRequest",
        "[10:05:19] assistant: Found it.",
    ]

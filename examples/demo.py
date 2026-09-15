#!/usr/bin/env python3
# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Scripted asciinema demo for extensible-mcp.

Drives the proxy directly via JSON-RPC over stdio, showing the security
pipeline against the official GitHub MCP server:

1. Search for delete tools           → hidden by deny pattern
2. Try delete_repo directly          → blocked by access control
3. Search for issue tools            → discoverable
4. Create a real issue               → succeeds
5. List issues                       → shows the new issue
6. Try to close that exact issue     → blocked by Rego argument-shape policy

Designed for asciinema playback — deterministic output with paced
narration. Run from the repo root:

    asciinema rec demo.cast
    uv run python examples/demo.py
    # Ctrl-D when the script finishes to stop recording.

Requires the proxy to be configured against examples/github-proxy-config.json
with a valid GITHUB_PERSONAL_ACCESS_TOKEN (see examples/README.md).

NOTE: The demo creates a real GitHub issue on DEMO_OWNER/DEMO_REPO and the
proxy's Rego policy prevents it from closing it. Close the issue manually
in the GitHub UI when you're done.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from typing import Any

CONFIG_PATH = "examples/github-proxy-config.json"
PAUSE = 1.4  # seconds between narrated beats, tuned for asciinema playback

# Tool names from the official GitHub MCP server. Verify against your
# downstream server's actual tool list (run `extensible-mcp` once and
# search broadly to see real names) and adjust if these differ.
DELETE_REPO = "github__delete_repo"
CREATE_ISSUE = "github__create_issue"
LIST_ISSUES = "github__list_issues"
ISSUE_WRITE = "github__issue_write"  # the tool the Rego policy gates

# Repo the demo will create an issue on. Pick a public repo you own —
# the demo cannot close the issue (that's the point), so you'll close
# it manually after the recording.
DEMO_OWNER = "mattdfuchs"
DEMO_REPO = "extensible-mcp"


def banner(title: str) -> None:
    bar = "═" * 70
    print(f"\n{bar}\n  {title}\n{bar}", flush=True)
    time.sleep(0.4)


def step(num: int, title: str) -> None:
    print(f"\n── Step {num}: {title} ──", flush=True)
    time.sleep(0.3)


def narrate(text: str) -> None:
    print(f"\n  → {text}", flush=True)
    time.sleep(PAUSE)


class MCPClient:
    """Minimal JSON-RPC over stdio client for the proxy subprocess."""

    def __init__(self, args: list[str]) -> None:
        self.proc = subprocess.Popen(
            args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,  # hide proxy startup logs for clean demo
            text=True,
            bufsize=1,
        )
        self._id = 0

    def _next_id(self) -> int:
        self._id += 1
        return self._id

    def request(
        self, method: str, params: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        msg: dict[str, Any] = {"jsonrpc": "2.0", "id": self._next_id(), "method": method}
        if params is not None:
            msg["params"] = params
        assert self.proc.stdin is not None and self.proc.stdout is not None
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        if not line:
            raise RuntimeError("Proxy closed stdout unexpectedly")
        return json.loads(line)

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        msg: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()

    def close(self) -> None:
        if self.proc.stdin is not None:
            try:
                self.proc.stdin.close()
            except Exception:
                pass
        self.proc.terminate()
        try:
            self.proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def call_meta_tool(
    client: MCPClient, name: str, arguments: dict[str, Any]
) -> str:
    """Call one of the proxy's meta-tools and return joined text content."""
    response = client.request(
        "tools/call",
        {"name": name, "arguments": arguments},
    )
    result = response.get("result") or {}
    parts: list[str] = []
    for block in result.get("content", []):
        if block.get("type") == "text":
            parts.append(block.get("text", ""))
    return "\n".join(parts)


def trim_search_results(text: str, max_tools: int = 3) -> str:
    """Show only the first `max_tools` tool blocks from a search_tools result.

    The proxy formats results with `## tool_name` headers. Trimming the
    displayed output keeps the demo readable while leaving all tools
    registered with the discovered-tools filter.
    """
    lines = text.split("\n")
    block_starts = [i for i, line in enumerate(lines) if line.startswith("## ")]
    if len(block_starts) <= max_tools:
        return text
    cutoff = block_starts[max_tools]
    omitted = len(block_starts) - max_tools
    return "\n".join(lines[:cutoff]).rstrip() + f"\n\n  ... ({omitted} more results) ..."


def extract_issue_number(text: str) -> int:
    """Pull the issue number out of a create_issue response.

    The GitHub MCP server typically returns JSON-shaped text; if that
    fails, fall back to regex on the `"number": N` field.
    """
    try:
        data = json.loads(text)
        if isinstance(data, dict) and "number" in data:
            return int(data["number"])
    except (json.JSONDecodeError, ValueError):
        pass
    match = re.search(r'"number"\s*:\s*(\d+)', text)
    if match:
        return int(match.group(1))
    raise RuntimeError(
        "Could not extract issue number from create_issue response:\n" + text
    )


def main() -> None:
    args = ["uv", "run", "extensible-mcp", "--config", CONFIG_PATH]
    print("Starting extensible-mcp proxy and indexing downstream tools...", flush=True)
    client = MCPClient(args)

    # MCP handshake
    client.request(
        "initialize",
        {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "demo-script", "version": "0.1.0"},
        },
    )
    client.notify("notifications/initialized")
    time.sleep(0.4)

    banner("extensible-mcp — security pipeline demo")
    print(
        "\nProxy configuration:\n"
        "  • access_control.deny_patterns: ['*__delete_*']\n"
        "  • rego_policy: deny_close_issue.rego  (blocks state='closed')\n"
        "  • downstream: GitHub MCP server",
        flush=True,
    )
    time.sleep(PAUSE)

    # ── Step 1 ─────────────────────────────────────────────────────────
    step(1, "Search for tools to delete a GitHub repository")
    print(call_meta_tool(
        client, "search_tools", {"query": "delete a GitHub repository"}
    ))
    narrate(
        "The deny pattern *__delete_* hides matching tools from search.\n"
        "    The LLM never learns that a delete tool exists."
    )

    # ── Step 2 ─────────────────────────────────────────────────────────
    step(2, f"Attempt {DELETE_REPO} directly (e.g., via prompt injection)")
    print(call_meta_tool(client, "call_tool", {
        "tool_name": DELETE_REPO,
        "arguments": {"owner": DEMO_OWNER, "repo": "scratch"},
    }))
    narrate(
        "Even with a known tool name, access control blocks the call.\n"
        "    The same filter applies at search-time AND at call-time."
    )

    # ── Step 3 ─────────────────────────────────────────────────────────
    # Broad search with high top_k surfaces create, list, and write
    # together; we show only the first few but all register with the
    # discovered-tools filter so subsequent call_tool invocations work.
    step(3, "Search for tools to manage GitHub issues")
    raw = call_meta_tool(client, "search_tools", {
        "query": "create, list, update, or close a GitHub issue",
        "top_k": 15,
    })
    print(trim_search_results(raw, max_tools=3))
    narrate("Issue tools are visible and now discoverable by call_tool.")

    # ── Step 4 ─────────────────────────────────────────────────────────
    step(4, f"Create a real issue via {CREATE_ISSUE}")
    create_response = call_meta_tool(client, "call_tool", {
        "tool_name": CREATE_ISSUE,
        "arguments": {
            "owner": DEMO_OWNER,
            "repo": DEMO_REPO,
            "title": "extensible-mcp demo issue",
            "body": "Created by examples/demo.py — safe to close manually.",
        },
    })
    issue_number = extract_issue_number(create_response)
    print(f'  ✓ Created issue #{issue_number} on {DEMO_OWNER}/{DEMO_REPO}')
    narrate("Writes are allowed in general — the policy is argument-shape, not tool-wide.")

    # ── Step 5 ─────────────────────────────────────────────────────────
    step(5, f"List open issues via {LIST_ISSUES}")
    list_response = call_meta_tool(client, "call_tool", {
        "tool_name": LIST_ISSUES,
        "arguments": {"owner": DEMO_OWNER, "repo": DEMO_REPO, "state": "open"},
    })
    # Show evidence that #issue_number appears in the listing.
    match = re.search(rf'#?{issue_number}[^\n]*', list_response)
    if match:
        print(f"  ✓ Listing includes the issue we just created:")
        print(f"    {match.group(0).strip()[:80]}")
    else:
        print(f"  (Issue #{issue_number} should appear in this listing.)")
    narrate("Read operations pass all filters; the call completes normally.")

    # ── Step 6 ─────────────────────────────────────────────────────────
    step(6, f"Attempt to close issue #{issue_number} via {ISSUE_WRITE}")
    print(call_meta_tool(client, "call_tool", {
        "tool_name": ISSUE_WRITE,
        "arguments": {
            "owner": DEMO_OWNER,
            "repo": DEMO_REPO,
            "issue_number": issue_number,
            "state": "closed",
        },
    }))
    narrate(
        "The tool itself is allowed, but the Rego policy inspects the\n"
        f"    arguments and rejects state == 'closed'. Issue #{issue_number}\n"
        "    stays open. The denial is at call-time, by argument shape."
    )

    banner("Three enforcement points — all evaluated outside the LLM.")
    print(
        "\nFilters run deterministically. No LLM judgment in the security\n"
        "path. Stages are configurable in Python or Rego.\n"
        f"\n(Clean up afterwards: close issue #{issue_number} in the GitHub UI.)\n"
        "\nRepo: https://github.com/mattdfuchs/extensible-mcp",
        flush=True,
    )
    time.sleep(PAUSE)

    client.close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(1)

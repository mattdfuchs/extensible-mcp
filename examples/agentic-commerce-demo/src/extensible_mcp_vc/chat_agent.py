# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""A minimal Claude tool-use loop against the proxy's own MCP endpoint — the
same three meta-tools (search_tools, call_tool, load_mcp_server) a real MCP
client would see, driven by the Anthropic API directly so the demo's "type a
prompt, approve in a browser tab" loop can be exposed as a chat window
instead of a terminal session.

Deliberately not a general-purpose agent framework: one conversation, one
MCP session, no retries or planning beyond what the model does on its own.
The point is parity with what a human already does by hand — type a prompt,
let the model call search_tools/call_tool, wait for a human's browser
approval, retry — not a more capable agent. See console_server.py for the
process that owns the MCP session and Anthropic client this class is handed.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

DEFAULT_MODEL = "claude-sonnet-5"

DEFAULT_SYSTEM = (
    "You are a household assistant reachable through a chat window. You "
    "have exactly three tools, proxied from an MCP server: search_tools to "
    "discover what you can do, call_tool to invoke something you've "
    "discovered, and load_mcp_server to connect a new server. Every "
    "capability — a downstream tool like pizza__negotiate as well as a "
    "proxy-native one like request_invoice_approval or record_fulfillment — "
    "is reached the same way: search_tools first, then call_tool with that "
    "exact name. You must call search_tools for a capability before you can "
    "call_tool it — that is structurally enforced, not a suggestion, for "
    "every tool without exception. When a gated action needs a signed "
    "credential (a request VC, an authorization VC, or a WebAuthn passkey "
    "approval), call the tool that requests it, tell the human which "
    "browser tab to approve in, and retry the gated call once they have. "
    "Narrate what you're doing in plain language between tool calls; the "
    "human sees only your text, never your tool calls.\n\n"
    "For ordering food, always use this exact sequence, never the direct "
    "order_pizza tool or the spend tool (those route approval to the "
    "kid/parent wallet pages, which are not reachable in this deployment):\n"
    "  1. pizza__negotiate and pizza__request_invoice\n"
    "  2. request_invoice_approval — blocks until the human approves at the "
    "passkey page (:7500), then returns the invoice, signature, and "
    "approval evidence together\n"
    "  3. settlement__charge_invoice — pass amountCents/merchantId/nonce "
    "plus the invoice and approval(s) exactly as request_invoice_approval "
    "returned them; the nonce is the invoice's own nonce, and names which "
    "invoice to settle\n"
    "  4. pizza__fulfill with the receipt charge_invoice returned\n"
    "  5. record_fulfillment with the commitment fulfill returned — this is "
    "the last step; only report the order complete once it succeeds."
)

LogFn = Callable[[str], None]


class McpSession(Protocol):
    """The subset of mcp.ClientSession this module actually uses — kept
    narrow so tests can hand in a plain stub instead of a live connection."""

    async def list_tools(self) -> Any: ...

    async def call_tool(self, name: str, arguments: dict[str, Any] | None) -> Any: ...


class AnthropicMessages(Protocol):
    """The subset of an Anthropic client this module uses — ``client.messages``."""

    async def create(self, **kwargs: Any) -> Any: ...


def _mcp_tools_to_anthropic(list_tools_result: Any) -> list[dict[str, Any]]:
    """MCP's Tool objects (``name``/``description``/``inputSchema``) to
    Anthropic's tool dicts (``name``/``description``/``input_schema``) —
    same shape, different key."""
    return [
        {
            "name": t.name,
            "description": t.description or "",
            "input_schema": t.inputSchema,
        }
        for t in list_tools_result.tools
    ]


def _tool_result_text(result: Any) -> str:
    """An MCP ``CallToolResult``'s text content, joined; falls back to a
    JSON dump of the whole result for a non-text (or empty) result."""
    parts = [
        block.text
        for block in getattr(result, "content", [])
        if getattr(block, "type", None) == "text"
    ]
    if parts:
        return "\n".join(parts)
    dump = getattr(result, "model_dump", None)
    return json.dumps(dump(mode="json")) if dump else str(result)


def _truncate(s: str, limit: int = 400) -> str:
    return s if len(s) <= limit else s[:limit] + "…"


@dataclass
class ChatAgent:
    """One chat session: history plus a live MCP session and Anthropic
    client, both supplied by the caller — this class owns no I/O lifecycle
    of its own, so a test can hand in stubs for both."""

    session: McpSession
    anthropic_messages: AnthropicMessages
    model: str = DEFAULT_MODEL
    system: str = DEFAULT_SYSTEM
    log: LogFn = field(default=lambda line: None)
    max_tool_rounds: int = 20
    history: list[dict[str, Any]] = field(default_factory=list)

    async def turn(self, user_message: str) -> str:
        """Run one full turn: the user's message, any number of tool calls
        against the proxy, until Claude produces a final text reply — or
        ``max_tool_rounds`` is hit, which surfaces as a plain error string
        rather than looping forever against a stuck approval."""
        self.history.append({"role": "user", "content": user_message})
        tools = _mcp_tools_to_anthropic(await self.session.list_tools())
        for _ in range(self.max_tool_rounds):
            response = await self.anthropic_messages.create(
                model=self.model,
                max_tokens=4096,
                system=self.system,
                tools=tools,
                messages=self.history,
            )
            self.history.append({"role": "assistant", "content": response.content})
            tool_uses = [
                block for block in response.content
                if getattr(block, "type", None) == "tool_use"
            ]
            if not tool_uses:
                # Don't key off stop_reason alone: a response can be cut off
                # by max_tokens mid-tool-call, in which case content holds no
                # (complete) tool_use block even though the model clearly
                # intended one. Returning here without a tool_result is safe
                # in that case; appending an incomplete tool_use above and
                # then returning without one would permanently break every
                # later turn's history (every tool_use needs a tool_result in
                # the very next message) — which is what used to happen.
                return "".join(
                    block.text
                    for block in response.content
                    if getattr(block, "type", None) == "text"
                )
            self.history.append(
                {"role": "user", "content": await self._run_tool_calls(response.content)}
            )
        return (
            "I've gone through several tool calls without finishing — something "
            "may be stuck waiting on an approval. Try again once you've approved "
            "in the browser tab."
        )

    async def _run_tool_calls(self, blocks: list[Any]) -> list[dict[str, Any]]:
        results = []
        for block in blocks:
            if getattr(block, "type", None) != "tool_use":
                continue
            self.log(f"-> {block.name}({json.dumps(block.input)})")
            try:
                result = await self.session.call_tool(block.name, block.input)
                content = _tool_result_text(result)
                is_error = bool(getattr(result, "isError", False))
            except Exception as e:  # noqa: BLE001 - surfaced to the model, not swallowed
                content, is_error = f"error: {e}", True
            self.log(f"<- {block.name}: {_truncate(content)}")
            results.append(
                {
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": content,
                    "is_error": is_error,
                }
            )
        return results

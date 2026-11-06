# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""ChatAgent's tool-use loop, against stub MCP session + Anthropic client —
no real network, no real model. Proves the loop shape: search_tools/
call_tool round-trip correctly, a tool error surfaces to the model as an
``is_error`` tool_result rather than raising, and the round cap kicks in
before an infinite loop against a permanently-denying tool."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from extensible_mcp_vc.chat_agent import BUSY_REPLY, AgentBusy, ChatAgent, DEFAULT_MODEL

# -- stub MCP session ------------------------------------------------------- #


class StubSession:
    def __init__(self, tools, call_tool_fn):
        self._tools = tools
        self._call_tool_fn = call_tool_fn
        self.calls: list[tuple[str, dict]] = []

    async def list_tools(self):
        return SimpleNamespace(tools=self._tools)

    async def call_tool(self, name, arguments):
        self.calls.append((name, arguments))
        return self._call_tool_fn(name, arguments)


def _tool(name, description="", input_schema=None):
    return SimpleNamespace(
        name=name, description=description, input_schema=input_schema or {}
    )


def _text_result(text, is_error=False):
    return SimpleNamespace(
        content=[SimpleNamespace(type="text", text=text)], isError=is_error
    )


# -- stub Anthropic client --------------------------------------------------- #


def _text_block(text):
    return SimpleNamespace(type="text", text=text)


def _tool_use_block(id_, name, input_):
    return SimpleNamespace(type="tool_use", id=id_, name=name, input=input_)


class ScriptedAnthropic:
    """Returns each of ``responses`` in order, one per ``create()`` call."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls: list[dict] = []

    async def create(self, **kwargs):
        self.calls.append(kwargs)
        return self._responses.pop(0)


def _response(stop_reason, content):
    return SimpleNamespace(stop_reason=stop_reason, content=content)


# -- tests -------------------------------------------------------------------- #


@pytest.fixture
def tools():
    return [_tool("search_tools"), _tool("call_tool"), _tool("load_mcp_server")]


async def test_immediate_text_reply_makes_no_tool_calls(tools):
    session = StubSession(tools, call_tool_fn=lambda name, args: pytest.fail("unused"))
    anthropic = ScriptedAnthropic(
        [_response("end_turn", [_text_block("Hi there.")])]
    )
    agent = ChatAgent(session=session, anthropic_messages=anthropic)

    reply = await agent.turn("hello")

    assert reply == "Hi there."
    assert session.calls == []
    # the loop's tools param used the MCP tool names, translated to Anthropic's shape
    assert [t["name"] for t in anthropic.calls[0]["tools"]] == [
        "search_tools",
        "call_tool",
        "load_mcp_server",
    ]


async def test_one_tool_round_trip_then_final_reply(tools):
    session = StubSession(
        tools,
        call_tool_fn=lambda name, args: _text_result('{"results": []}'),
    )
    anthropic = ScriptedAnthropic(
        [
            _response(
                "tool_use",
                [_tool_use_block("t1", "search_tools", {"query": "order pizza"})],
            ),
            _response("end_turn", [_text_block("Found it.")]),
        ]
    )
    agent = ChatAgent(session=session, anthropic_messages=anthropic)

    reply = await agent.turn("order a pizza")

    assert reply == "Found it."
    assert session.calls == [("search_tools", {"query": "order pizza"})]
    # the tool result round-tripped back into history as a user message
    tool_result_msg = agent.history[2]
    assert tool_result_msg["role"] == "user"
    assert tool_result_msg["content"][0]["tool_use_id"] == "t1"
    assert tool_result_msg["content"][0]["content"] == '{"results": []}'
    assert tool_result_msg["content"][0]["is_error"] is False


async def test_tool_exception_surfaces_as_error_result_not_a_raise(tools):
    def _raise(name, args):
        raise RuntimeError("downstream unreachable")

    session = StubSession(tools, call_tool_fn=_raise)
    anthropic = ScriptedAnthropic(
        [
            _response("tool_use", [_tool_use_block("t1", "call_tool", {})]),
            _response("end_turn", [_text_block("Something went wrong.")]),
        ]
    )
    agent = ChatAgent(session=session, anthropic_messages=anthropic)

    reply = await agent.turn("spend $15")

    assert reply == "Something went wrong."
    tool_result = agent.history[2]["content"][0]
    assert tool_result["is_error"] is True
    assert "downstream unreachable" in tool_result["content"]


async def test_max_tool_rounds_stops_instead_of_looping_forever(tools):
    session = StubSession(tools, call_tool_fn=lambda name, args: _text_result("no"))
    # Every response asks for another tool call — never terminates on its own.
    responses = [
        _response("tool_use", [_tool_use_block(f"t{i}", "call_tool", {})])
        for i in range(10)
    ]
    anthropic = ScriptedAnthropic(responses)
    agent = ChatAgent(session=session, anthropic_messages=anthropic, max_tool_rounds=3)

    reply = await agent.turn("do something")

    assert "stuck waiting on an approval" in reply
    assert len(session.calls) == 3


async def test_log_records_call_and_result(tools):
    session = StubSession(tools, call_tool_fn=lambda name, args: _text_result("ok"))
    anthropic = ScriptedAnthropic(
        [
            _response("tool_use", [_tool_use_block("t1", "search_tools", {"query": "x"})]),
            _response("end_turn", [_text_block("done")]),
        ]
    )
    lines: list[str] = []
    agent = ChatAgent(session=session, anthropic_messages=anthropic, log=lines.append)

    await agent.turn("hi")

    assert any(line.startswith("-> search_tools(") for line in lines)
    assert any(line.startswith("<- search_tools: ok") for line in lines)


def test_default_model_is_a_claude_5_family_model():
    assert DEFAULT_MODEL.startswith("claude-")


# -- one turn at a time, and a failed turn leaves no trace ------------------- #


class BlockingAnthropic:
    """``create()`` parks until released — a turn stuck on the model, or on
    a tool call the model made, looks the same from the outside."""

    def __init__(self, response):
        self._response = response
        self.release = asyncio.Event()

    async def create(self, **kwargs):
        await self.release.wait()
        return self._response


async def test_a_second_message_mid_turn_is_refused_not_interleaved(tools):
    session = StubSession(tools, call_tool_fn=lambda name, args: pytest.fail("unused"))
    anthropic = BlockingAnthropic(_response("end_turn", [_text_block("done")]))
    agent = ChatAgent(session=session, anthropic_messages=anthropic)

    first = asyncio.create_task(agent.turn("order a pizza"))
    await asyncio.sleep(0)  # let the first turn take the lock and park
    assert agent.busy

    with pytest.raises(AgentBusy) as excinfo:
        await agent.turn("did you send it?")
    assert str(excinfo.value) == BUSY_REPLY

    anthropic.release.set()
    assert await first == "done"
    assert not agent.busy
    # the refused message never entered the conversation
    assert [m["content"] for m in agent.history if m["role"] == "user"] == ["order a pizza"]


class FailingAnthropic:
    """Answers one tool_use, then the API refuses the conversation."""

    def __init__(self):
        self.calls = 0

    async def create(self, **kwargs):
        self.calls += 1
        if self.calls == 1:
            return _response(
                "tool_use", [_tool_use_block("t1", "search_tools", {"query": "pizza"})]
            )
        if self.calls == 2:
            raise RuntimeError("Error code: 400 - invalid_request_error")
        return _response("end_turn", [_text_block("Second time lucky.")])


async def test_a_turn_that_raises_rolls_the_history_back_so_the_next_turn_works(tools):
    session = StubSession(tools, call_tool_fn=lambda name, args: _text_result("[]"))
    agent = ChatAgent(session=session, anthropic_messages=FailingAnthropic())

    with pytest.raises(RuntimeError, match="400"):
        await agent.turn("order a pizza")

    # nothing of the failed turn survives: not the user line, not the
    # tool_use, not the tool_result that answered it
    assert agent.history == []
    assert not agent.busy

    assert await agent.turn("try again") == "Second time lucky."
    assert [m["role"] for m in agent.history] == ["user", "assistant"]

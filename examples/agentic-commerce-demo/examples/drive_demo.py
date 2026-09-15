# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Drive the family-authority proxy end-to-end against the real wallets.

The scenario: the kid wants to spend **$15**, which is over the $10 solo
limit, so the policy requires a parent's authorization. Acts as the agent
would:

1. discover the gated tool;
2. ask the kid's wallet for a signed request VC (the **kid shell** prompts —
   approve it);
3. try the call with only the request VC — the policy **denies**, and the
   rendered reason says a parent authorization is needed (the reactive
   channel: deny → gather → retry);
4. ask the parent's wallet to authorize that request (the **parent shell**
   prompts — approve it);
5. retry with both credentials — the full chain is satisfied, the call is
   **allowed**, and the downstream debits the balance.

Run the three servers first (see the module header of family_proxy_server.py),
then: ``uv run python examples/drive_demo.py``
"""

from __future__ import annotations

import argparse
import asyncio
import json

from fastmcp import Client

AMOUNT = 15.0
MERCHANT = "acme"


def _rule(title: str) -> None:
    print(f"\n{'─' * 70}\n{title}\n{'─' * 70}")


def _is_bundle(value) -> bool:
    return isinstance(value, dict) and "token" in value


async def _call(client: Client, tool_name: str, arguments: dict):
    """call_tool's own return type is always a plain string (the formatted
    text or JSON-dumped result), never a parsed object — request_action_vc
    and request_authorization_vc are local tools reached through call_tool
    like everything else now, so their JSON result needs decoding here."""
    result = await client.call_tool("call_tool", {"tool_name": tool_name, "arguments": arguments})
    text = result.data if isinstance(result.data, str) else result.content[0].text
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return text


async def drive(url: str) -> None:
    async with Client(url) as client:
        _rule("1. discover the gated tool")
        found = await client.call_tool(
            "search_tools", {"query": "spend money at a merchant"}
        )
        print(found.data)

        await client.call_tool(
            "search_tools", {"query": "request a signed action VC from the kid's wallet"}
        )

        _rule("2. ask the kid's wallet for a $15 request VC")
        print(
            "   ►► ACTION REQUIRED: switch to the KID shell (port 7401) and answer\n"
            "      its 'Approve? [y/N]' prompt. This call blocks until you do.\n"
            "      (If it hangs here, the kid wallet on 7401 isn't running.)"
        )
        request = await _call(
            client,
            "request_action_vc",
            {"action": "spend", "details": {"amount": AMOUNT, "merchant": MERCHANT}},
        )
        if not _is_bundle(request):
            print(f"kid wallet did not return a bundle: {request!r}")
            return
        print("got a signed request VC bundle from the kid wallet.")

        _rule("3. try with only the request VC → policy denies (over the $10 solo tier)")
        denied = await client.call_tool(
            "call_tool",
            {
                "tool_name": "payments__spend",
                "arguments": {
                    "amount": AMOUNT, "merchant": MERCHANT, "requestVC": request
                },
            },
        )
        print(denied.data)

        await client.call_tool(
            "search_tools", {"query": "request a signed authorization VC from the parent's wallet"}
        )

        _rule("4. ask the parent to authorize it")
        print(
            "   ►► ACTION REQUIRED: switch to the PARENT shell (port 7402) and answer\n"
            "      its 'Approve? [y/N]' prompt. This call blocks until you do.\n"
            "      (If it hangs here, the parent wallet on 7402 isn't running — this\n"
            "      is the step the last run stopped at.)"
        )
        authorization = await _call(
            client, "request_authorization_vc", {"request": request, "scope": {}}
        )
        if not _is_bundle(authorization):
            print(f"parent wallet did not return a bundle: {authorization!r}")
            return
        print("got a signed authorization VC bundle from the parent wallet.")

        _rule("5. retry with request + parent authorization → full chain allowed")
        out = await client.call_tool(
            "call_tool",
            {
                "tool_name": "payments__spend",
                "arguments": {
                    "amount": AMOUNT,
                    "merchant": MERCHANT,
                    "requestVC": request,
                    "authorizationVC": authorization,
                },
            },
        )
        print(out.data)


def main() -> None:
    parser = argparse.ArgumentParser(prog="drive_demo")
    parser.add_argument("--url", default="http://127.0.0.1:7400/mcp/")
    args = parser.parse_args()
    asyncio.run(drive(args.url))


if __name__ == "__main__":
    main()

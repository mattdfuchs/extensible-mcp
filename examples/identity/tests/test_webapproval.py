# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""The browser approval surface: a pending sign request is listed, the
human's click resolves it, and an unanswered prompt declines on timeout."""

from __future__ import annotations

import asyncio

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from household_identity.wallet.webapproval import WebApproval


async def test_click_approves_and_resolves():
    wa = WebApproval()
    app = FastAPI()
    wa.mount(app, "kid")
    client = TestClient(app)

    task = asyncio.create_task(wa.approve("sign this?"))
    await asyncio.sleep(0)  # let the prompt register
    [item] = client.get("/approvals").json()
    assert item["message"] == "sign this?"
    assert client.post(f"/approvals/{item['id']}", json={"approve": True}).status_code == 200
    assert await task is True
    assert client.get("/approvals").json() == []  # cleared


async def test_deny_and_unknown_prompt():
    wa = WebApproval()
    app = FastAPI()
    wa.mount(app, "kid")
    client = TestClient(app)

    task = asyncio.create_task(wa.approve("sign this?"))
    await asyncio.sleep(0)
    [item] = client.get("/approvals").json()
    assert client.post(f"/approvals/{item['id']}", json={"approve": False}).status_code == 200
    assert await task is False
    assert client.post("/approvals/999", json={"approve": True}).status_code == 404


async def test_timeout_declines():
    wa = WebApproval(timeout_seconds=0.05)
    assert await wa.approve("anyone there?") is False

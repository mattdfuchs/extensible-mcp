# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Tests for the terminal stdin approval prompt."""

from __future__ import annotations

import builtins

from household_identity.wallet.approval import prompt_terminal


class TestPromptTerminal:
    def test_yes_returns_true(self, monkeypatch, capsys):
        monkeypatch.setattr(builtins, "input", lambda _prompt="": "y")
        assert prompt_terminal("Approve foo?") is True
        assert "Approve foo?" in capsys.readouterr().out

    def test_full_yes_returns_true(self, monkeypatch):
        monkeypatch.setattr(builtins, "input", lambda _prompt="": "YES")
        assert prompt_terminal("msg") is True

    def test_no_returns_false(self, monkeypatch):
        monkeypatch.setattr(builtins, "input", lambda _prompt="": "n")
        assert prompt_terminal("msg") is False

    def test_empty_returns_false(self, monkeypatch):
        monkeypatch.setattr(builtins, "input", lambda _prompt="": "")
        assert prompt_terminal("msg") is False

    def test_eof_returns_false(self, monkeypatch):
        def _eof(_prompt=""):
            raise EOFError

        monkeypatch.setattr(builtins, "input", _eof)
        assert prompt_terminal("msg") is False

# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""`extensible-mcp add-server`, and the SIGHUP reload it triggers.

0.3.0 bound stored tokens to URLs an operator configured, which closed a real
exfiltration path and took the documented "add a token, then `load_mcp_server`
at runtime" flow with it. This is the flow restored from the operator's side,
so the tests are about the properties that make it safe: the token is verified
before anything is written, an existing name is never re-pointed, the token
file stays 0600, and a running proxy picks the server up without a restart.
"""

from __future__ import annotations

import asyncio
import json
import os
import signal
import stat
import sys
from pathlib import Path

import pytest

from extensible_mcp import admin
from extensible_mcp.config import load_config
from extensible_mcp.server import _parse_args, reconcile_servers

from .test_url_auth_integration import (  # reuse the live bearer-checking server
    BearerAuthMiddleware,  # noqa: F401
    TokenStore,  # noqa: F401
    mock_mcp_server,  # noqa: F401
)


def _write_config(tmp_path: Path, **servers) -> Path:
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"mcpServers": servers or {
        "seed": {"command": sys.executable, "args": ["-c", "pass"]}}}, indent=2))
    return path


# -- verification comes first ------------------------------------------------ #

class TestVerification:
    async def test_a_good_url_and_token_verify(self, mock_mcp_server):
        url, _store = mock_mcp_server
        verified = await admin.verify_server("mockauth", url, "correct-token")
        assert "echo" in verified.tool_names

    async def test_a_wrong_token_is_refused_before_anything_is_written(
        self, mock_mcp_server, tmp_path
    ):
        url, _store = mock_mcp_server
        config_path = _write_config(tmp_path)
        before = config_path.read_text()
        with pytest.raises(admin.AdminError) as info:
            await admin.verify_server("mockauth", url, "wrong-token")
        assert "could not use" in str(info.value)
        # The point of verifying first.
        assert config_path.read_text() == before
        assert not (tmp_path / "tokens").exists()

    async def test_an_unreachable_url_names_the_real_failure(self, tmp_path):
        """anyio task groups wrap the cause; an operator needs the leaf."""
        with pytest.raises(admin.AdminError) as info:
            await admin.verify_server("nope", "http://127.0.0.1:1/mcp/", None)
        assert "unhandled errors in a TaskGroup" not in str(info.value)


# -- what gets written ------------------------------------------------------- #

class TestWriting:
    def test_the_server_lands_in_the_config(self, tmp_path):
        config_path = _write_config(tmp_path)
        admin.add_server_to_config(config_path, "notion", "https://notion.example/mcp")
        raw = json.loads(config_path.read_text())
        assert raw["mcpServers"]["notion"] == {"url": "https://notion.example/mcp"}
        assert "seed" in raw["mcpServers"], "must not drop existing servers"

    def test_an_existing_name_is_never_repointed(self, tmp_path):
        """Silently re-pointing a name at another host is the substitution the
        token binding exists to prevent, so it is an error and not an update."""
        config_path = _write_config(tmp_path, notion={"url": "https://real.example/mcp"})
        with pytest.raises(admin.AdminError, match="already in"):
            admin.add_server_to_config(config_path, "notion", "https://attacker.example/mcp")
        assert json.loads(config_path.read_text())["mcpServers"]["notion"] == {
            "url": "https://real.example/mcp"
        }

    def test_the_token_file_is_owner_only(self, tmp_path):
        tokens = tmp_path / "tokens"
        admin.write_token(tokens, "notion", "secret-value")
        assert tokens.read_text().strip() == "notion=secret-value"
        assert stat.S_IMODE(tokens.stat().st_mode) == 0o600

    def test_other_tokens_and_comments_survive(self, tmp_path):
        tokens = tmp_path / "tokens"
        tokens.write_text("# keep me\ngithub=gh-token\nnotion=old\n")
        admin.write_token(tokens, "notion", "new")
        assert tokens.read_text().splitlines() == [
            "# keep me", "github=gh-token", "notion=new"]

    def test_no_temp_file_is_left_behind(self, tmp_path):
        tokens = tmp_path / "tokens"
        admin.write_token(tokens, "a", "1")
        assert [p.name for p in tmp_path.iterdir()] == ["tokens"]


# -- the reload signal ------------------------------------------------------- #

class TestSignalling:
    def test_no_pid_file_is_not_an_error(self, tmp_path):
        """A proxy that is not running is normal: the config is written, and the
        next start picks it up."""
        assert admin.signal_reload(_write_config(tmp_path)) is None

    def test_a_stale_pid_file_is_not_an_error(self, tmp_path):
        config_path = _write_config(tmp_path)
        admin.pid_file_for(config_path).write_text("999999\n")
        assert admin.signal_reload(config_path) is None

    def test_a_garbage_pid_file_is_not_an_error(self, tmp_path):
        config_path = _write_config(tmp_path)
        admin.pid_file_for(config_path).write_text("not-a-pid\n")
        assert admin.signal_reload(config_path) is None

    @pytest.mark.skipif(not hasattr(signal, "SIGHUP"), reason="no SIGHUP on this platform")
    def test_a_live_pid_file_is_signalled(self, tmp_path):
        config_path = _write_config(tmp_path)
        admin.write_pid_file(config_path)
        received: list[int] = []
        previous = signal.signal(signal.SIGHUP, lambda *_: received.append(1))
        try:
            assert admin.signal_reload(config_path) == os.getpid()
            assert received == [1]
        finally:
            signal.signal(signal.SIGHUP, previous)
            admin.remove_pid_file(admin.pid_file_for(config_path))

    def test_a_pid_file_left_by_a_killed_proxy_is_not_signalled(self, tmp_path):
        """The hazard the lock exists for. Python does not run `finally` on
        SIGTERM, so a stale pid file is the *common* case -- and pids get
        reused, so acting on one could SIGHUP an unrelated process, whose
        default action is to die. Here the file names our own live pid and is
        still ignored, because nothing holds the lock."""
        config_path = _write_config(tmp_path)
        pid_file = admin.pid_file_for(config_path)
        pid_file.write_text(f"{os.getpid()}\n")  # a real, live pid — but unlocked

        received: list[int] = []
        previous = signal.signal(signal.SIGHUP, lambda *_: received.append(1))
        try:
            assert admin.signal_reload(config_path) is None
            assert received == [], "signalled a process that is not the proxy"
        finally:
            signal.signal(signal.SIGHUP, previous)

    def test_a_second_proxy_on_one_config_is_refused(self, tmp_path):
        """Two proxies sharing a config would race on the same downstreams and
        leave add-server signalling whichever wrote the file last."""
        config_path = _write_config(tmp_path)
        admin.write_pid_file(config_path)
        try:
            import fcntl  # noqa: F401
        except ImportError:
            pytest.skip("no advisory locking on this platform")
        try:
            with pytest.raises(admin.AdminError, match="already running"):
                admin.write_pid_file(config_path)
        finally:
            admin.remove_pid_file(admin.pid_file_for(config_path))

    def test_a_pid_file_from_another_process_is_not_removed(self, tmp_path):
        config_path = _write_config(tmp_path)
        pid_file = admin.pid_file_for(config_path)
        pid_file.write_text("999999\n")
        admin.remove_pid_file(pid_file)
        assert pid_file.exists(), "a restart's pid file must survive our cleanup"


# -- the reload itself ------------------------------------------------------- #

class TestReconcile:
    async def test_a_new_server_is_connected_and_indexed(self, mock_mcp_server, tmp_path):
        """The whole point: tools become searchable without a restart."""
        url, _store = mock_mcp_server
        from extensible_mcp.client_manager import ClientManager
        from extensible_mcp.types import ServerConfig
        from extensible_mcp.vector_store import VectorStore

        tokens = tmp_path / "tokens"
        admin.write_token(tokens, "mockauth", "correct-token")
        mgr = ClientManager(tokens_file=tokens)
        vs = VectorStore()
        try:
            await mgr.connect_all([ServerConfig(
                name="seed", command=sys.executable,
                args=[str(Path(__file__).parent / "mock_server.py")])])
            ctx = {"client_manager": mgr, "vector_store": vs}

            config_path = _write_config(tmp_path, mockauth={"url": url})
            added, refused = await reconcile_servers(ctx, load_config(config_path))

            assert added == ["mockauth"] and refused == []
            assert "mockauth" in mgr.server_names()
            # Indexed, so search can reach it.
            assert any(
                r.tool.qualified_name == "mockauth__echo"
                for r in vs.search("echo a message back", top_k=10)
            )
        finally:
            await mgr.close_all()

    async def test_reload_is_additive_and_idempotent(self, mock_mcp_server, tmp_path):
        url, _store = mock_mcp_server
        from extensible_mcp.client_manager import ClientManager
        from extensible_mcp.types import ServerConfig
        from extensible_mcp.vector_store import VectorStore

        tokens = tmp_path / "tokens"
        admin.write_token(tokens, "mockauth", "correct-token")
        mgr = ClientManager(tokens_file=tokens)
        try:
            await mgr.connect_all([ServerConfig(
                name="seed", command=sys.executable,
                args=[str(Path(__file__).parent / "mock_server.py")])])
            ctx = {"client_manager": mgr, "vector_store": VectorStore()}
            config_path = _write_config(tmp_path, mockauth={"url": url})
            config = load_config(config_path)

            assert (await reconcile_servers(ctx, config))[0] == ["mockauth"]
            # Second pass: already connected, so nothing happens.
            assert await reconcile_servers(ctx, config) == ([], [])
        finally:
            await mgr.close_all()

    async def test_a_reloaded_server_receives_its_token(self, mock_mcp_server, tmp_path):
        """It has to come through connect_configured, not connect_url: the
        latter is the LLM's path and would refuse to present a credential."""
        url, store = mock_mcp_server
        from extensible_mcp.client_manager import ClientManager
        from extensible_mcp.types import ServerConfig
        from extensible_mcp.vector_store import VectorStore

        tokens = tmp_path / "tokens"
        admin.write_token(tokens, "mockauth", "correct-token")
        mgr = ClientManager(tokens_file=tokens)
        try:
            await mgr.connect_all([ServerConfig(
                name="seed", command=sys.executable,
                args=[str(Path(__file__).parent / "mock_server.py")])])
            ctx = {"client_manager": mgr, "vector_store": VectorStore()}
            config_path = _write_config(tmp_path, mockauth={"url": url})
            await reconcile_servers(ctx, load_config(config_path))
            assert any(a == "Bearer correct-token" for a in store.seen_authorization)

            # And it stays usable, which is what the token being accepted means.
            result = await mgr.call_tool("mockauth__echo", {"message": "hi"})
            assert not result.isError
        finally:
            await mgr.close_all()

    async def test_an_unreachable_server_is_reported_not_raised(self, tmp_path):
        """A reload runs under a signal; one bad entry must not take the proxy
        down or stop the others."""
        from extensible_mcp.client_manager import ClientManager
        from extensible_mcp.types import ServerConfig
        from extensible_mcp.vector_store import VectorStore

        mgr = ClientManager()
        try:
            await mgr.connect_all([ServerConfig(
                name="seed", command=sys.executable,
                args=[str(Path(__file__).parent / "mock_server.py")])])
            ctx = {"client_manager": mgr, "vector_store": VectorStore()}
            config_path = _write_config(
                tmp_path, dead={"url": "http://127.0.0.1:1/mcp/"})
            added, refused = await reconcile_servers(ctx, load_config(config_path))
            assert added == [] and refused == ["dead"]
            assert "seed" in mgr.server_names()
        finally:
            await mgr.close_all()


# -- the CLI surface --------------------------------------------------------- #

class TestArgParsing:
    def test_the_bare_invocation_still_runs_the_server(self):
        """Adding a subcommand must not break `extensible-mcp --config x`."""
        args = _parse_args(["--config", "c.json"])
        assert args.command is None and args.config == "c.json"

    def test_add_server_parses(self):
        args = _parse_args([
            "add-server", "--name", "notion", "--url", "https://n.example/mcp",
            "--token", "t"])
        assert (args.command, args.name, args.url, args.token) == (
            "add-server", "notion", "https://n.example/mcp", "t")

    def test_the_token_may_come_from_stdin(self):
        args = _parse_args([
            "add-server", "--name", "n", "--url", "u", "--token-stdin"])
        assert args.token_stdin is True and args.token is None


class TestTheTokensFileAppearingLater:
    """The bug a live run found that the unit tests had missed.

    `load_config` reports `tokens_file=None` for a file that does not exist, and
    the ClientManager captured that at construction. But creating the tokens
    file is precisely what `add-server` does — so a proxy started before there
    was one reloaded, connected the new server with no credential, and got a
    401. Every earlier test wrote the token file *before* building the manager,
    so none of them could see it.
    """

    async def test_a_proxy_started_without_a_tokens_file_picks_one_up_on_reload(
        self, mock_mcp_server, tmp_path
    ):
        url, store = mock_mcp_server
        from extensible_mcp.client_manager import ClientManager
        from extensible_mcp.types import ServerConfig
        from extensible_mcp.vector_store import VectorStore

        # Started with no tokens file at all, as a fresh install is.
        config_path = _write_config(tmp_path)
        assert load_config(config_path).tokens_file is None
        mgr = ClientManager(tokens_file=load_config(config_path).tokens_file)
        try:
            await mgr.connect_all([ServerConfig(
                name="seed", command=sys.executable,
                args=[str(Path(__file__).parent / "mock_server.py")])])
            ctx = {"client_manager": mgr, "vector_store": VectorStore()}

            # Now the operator runs add-server: token written, config updated.
            admin.write_token(tmp_path / "tokens", "mockauth", "correct-token")
            admin.add_server_to_config(config_path, "mockauth", url)

            added, refused = await reconcile_servers(ctx, load_config(config_path))
            assert added == ["mockauth"], refused
            assert any(a == "Bearer correct-token" for a in store.seen_authorization)
        finally:
            await mgr.close_all()

    async def test_existing_connections_see_the_new_tokens_file_too(
        self, mock_mcp_server, tmp_path
    ):
        """A URL connection resolves the token per call, so it only needs to be
        told where the file is."""
        url, store = mock_mcp_server
        from extensible_mcp.client_manager import ClientManager
        from extensible_mcp.types import ServerConfig

        tokens = tmp_path / "tokens"
        admin.write_token(tokens, "mockauth", "correct-token")
        mgr = ClientManager()  # no tokens file
        try:
            # Connect while the manager knows of no tokens file; the mock server
            # refuses, which is the starting condition.
            with pytest.raises(BaseException):
                await mgr.connect_all([ServerConfig(name="mockauth", url=url)])

            mgr.set_tokens_file(tokens)
            records = await mgr.connect_configured(ServerConfig(name="mockauth", url=url))
            assert any(r.qualified_name == "mockauth__echo" for r in records)
        finally:
            await mgr.close_all()


def test_a_refused_second_proxy_does_not_wipe_the_running_pid(tmp_path):
    """O_TRUNC empties the file at open(), which is before the lock is tested.
    A second proxy about to be refused would blank the first proxy's pid, and
    add-server would then report no proxy running against a live one."""
    try:
        import fcntl  # noqa: F401
    except ImportError:
        pytest.skip("no advisory locking on this platform")

    config_path = _write_config(tmp_path)
    admin.write_pid_file(config_path)
    pid_file = admin.pid_file_for(config_path)
    assert pid_file.read_text().strip() == str(os.getpid())
    try:
        with pytest.raises(admin.AdminError):
            admin.write_pid_file(config_path)
        assert pid_file.read_text().strip() == str(os.getpid()), "pid was wiped"
    finally:
        admin.remove_pid_file(pid_file)

# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""The gate on ``--transport http`` (#11).

There was no transport flag before this, and that absence was accidentally
load-bearing: a shared HTTP deployment could not be misconfigured because it
could not be asked for. Now it can, so the CLI refuses the configurations
that were sound only because one process served one person: no inbound
auth, a process-wide tokens file, and runtime server loading.

The refusals are tested as exits, not as logs: ``main`` returns non-zero
before ``create_server`` is reached.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair, StaticTokenVerifier
from fastmcp.utilities.tests import run_server_async

import extensible_mcp.server as server_mod
from extensible_mcp.config import AuthConfig, Config, ServerConfig, load_config
from extensible_mcp.server import (
    TransportError,
    _parse_args,
    check_http_deployment,
    create_server,
    main,
)

MOCK_SERVER_PATH = str(Path(__file__).parent / "mock_server.py")
ISSUER = "https://idp.example/realms/household"
AUDIENCE = "extensible-mcp"


def _auth(tmp_path: Path) -> AuthConfig:
    pem = tmp_path / "idp.pem"
    pem.write_text(RSAKeyPair.generate().public_key)
    return AuthConfig(issuer=ISSUER, audience=AUDIENCE, public_key_file=pem)


# -- the gate as a function ------------------------------------------------- #

class TestCheckHttpDeployment:
    def test_no_auth_is_refused(self):
        with pytest.raises(TransportError, match="needs an 'auth' block"):
            check_http_deployment(Config())

    def test_auth_requires_the_principal(self, tmp_path):
        assert check_http_deployment(Config(auth=_auth(tmp_path))) is True

    def test_anonymous_on_loopback_is_single_tenant_on_purpose(self):
        for host in ("127.0.0.1", "::1", "localhost"):
            assert check_http_deployment(Config(), allow_anonymous=True, host=host) is False

    def test_anonymous_off_loopback_is_refused(self):
        with pytest.raises(TransportError, match="not loopback"):
            check_http_deployment(Config(), allow_anonymous=True, host="0.0.0.0")

    def test_anonymous_with_auth_says_two_things(self, tmp_path):
        with pytest.raises(TransportError, match="pick one"):
            check_http_deployment(Config(auth=_auth(tmp_path)), allow_anonymous=True)

    @pytest.mark.parametrize("anonymous", [False, True])
    def test_a_tokens_file_is_refused_flat(self, tmp_path, anonymous):
        """One bearer per server per process is one downstream identity for
        every caller. Refused with auth and without: an HTTP listener cannot
        show it serves one person."""
        tokens = tmp_path / "tokens"
        tokens.write_text("mock=secret\n")
        config = Config(tokens_file=tokens, auth=None if anonymous else _auth(tmp_path))
        with pytest.raises(TransportError, match="stdio-only"):
            check_http_deployment(config, allow_anonymous=anonymous)


# -- the CLI ---------------------------------------------------------------- #

def _config_file(tmp_path: Path, **extra) -> Path:
    path = tmp_path / "config.json"
    servers = {"m": {"command": sys.executable, "args": [MOCK_SERVER_PATH]}}
    path.write_text(json.dumps({"mcpServers": servers, **extra}))
    return path


class _FakeServer:
    def __init__(self):
        self.run_kwargs = None

    def run(self, **kwargs):
        self.run_kwargs = kwargs


@pytest.fixture
def started(monkeypatch, tmp_path):
    """Replace create_server with a recorder, so a test can see what main
    would have started with, without starting it."""
    calls: dict = {}
    fake = _FakeServer()

    def fake_create_server(config, **kwargs):
        calls["config"] = config
        calls["kwargs"] = kwargs
        return fake

    monkeypatch.setattr(server_mod, "create_server", fake_create_server)
    monkeypatch.setattr(server_mod.admin, "write_pid_file", lambda p: tmp_path / "pid")
    monkeypatch.setattr(server_mod.admin, "remove_pid_file", lambda p: None)
    calls["server"] = fake
    return calls


@pytest.fixture
def never_started(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("create_server was reached; the gate did not hold")

    monkeypatch.setattr(server_mod, "create_server", refuse)


class TestArgs:
    def test_stdio_is_the_default(self):
        args = _parse_args(["--config", "c.json"])
        assert args.transport == "stdio" and args.allow_anonymous is False

    def test_http_takes_host_and_port(self):
        args = _parse_args(["--transport", "http", "--host", "0.0.0.0", "--port", "9000"])
        assert (args.transport, args.host, args.port) == ("http", "0.0.0.0", 9000)

    def test_help_states_the_constraint(self, capsys):
        with pytest.raises(SystemExit):
            _parse_args(["--help"])
        out = capsys.readouterr().out
        assert "refuses to start" in out and "auth" in out and "tokens file" in out


class TestMainRefuses:
    """Each refusal is an exit before anything is built."""

    def test_http_without_auth(self, tmp_path, never_started, capsys):
        rc = main(["--config", str(_config_file(tmp_path)), "--transport", "http"])
        assert rc == 2
        assert "needs an 'auth' block" in capsys.readouterr().err

    def test_http_with_a_tokens_file(self, tmp_path, never_started, capsys):
        config = _config_file(tmp_path, mcpServers={"m": {"url": "https://m.example/mcp"}})
        (tmp_path / "tokens").write_text("m=secret\n")
        assert load_config(config).tokens_file is not None, "fixture: the file must resolve"
        rc = main(["--config", str(config), "--transport", "http", "--allow-anonymous"])
        assert rc == 2
        assert "stdio-only" in capsys.readouterr().err

    def test_anonymous_off_loopback(self, tmp_path, never_started, capsys):
        rc = main([
            "--config", str(_config_file(tmp_path)),
            "--transport", "http", "--allow-anonymous", "--host", "0.0.0.0",
        ])
        assert rc == 2
        assert "not loopback" in capsys.readouterr().err

    def test_anonymous_means_nothing_on_stdio(self, tmp_path, never_started, capsys):
        rc = main(["--config", str(_config_file(tmp_path)), "--allow-anonymous"])
        assert rc == 2
        assert "only meaningful with --transport http" in capsys.readouterr().err

    def test_auth_without_audience_fails_at_load(self, tmp_path, never_started):
        """The vacuous verifier -- any issuer's token for any audience -- is
        not expressible: the config loader requires both fields."""
        pem = tmp_path / "idp.pem"
        pem.write_text(RSAKeyPair.generate().public_key)
        for missing in ("issuer", "audience"):
            block = {"issuer": ISSUER, "audience": AUDIENCE, "public_key_file": "idp.pem"}
            del block[missing]
            config = _config_file(tmp_path, auth=block)
            with pytest.raises(ValueError, match=f"'{missing}'"):
                main(["--config", str(config), "--transport", "http"])


class TestMainStarts:
    def test_stdio_behaves_exactly_as_before(self, tmp_path, started):
        assert main(["--config", str(_config_file(tmp_path))]) == 0
        assert started["server"].run_kwargs == {}
        assert started["kwargs"]["require_principal"] is None

    def test_http_with_auth_requires_the_principal(self, tmp_path, started):
        pem = tmp_path / "idp.pem"
        pem.write_text(RSAKeyPair.generate().public_key)
        config = _config_file(
            tmp_path, auth={"issuer": ISSUER, "audience": AUDIENCE, "public_key_file": "idp.pem"}
        )
        assert main(["--config", str(config), "--transport", "http", "--port", "8765"]) == 0
        assert started["server"].run_kwargs == {"transport": "http", "host": "127.0.0.1", "port": 8765}
        assert started["kwargs"]["require_principal"] is True

    def test_http_anonymous_is_explicitly_single_tenant(self, tmp_path, started):
        assert main([
            "--config", str(_config_file(tmp_path)), "--transport", "http", "--allow-anonymous",
        ]) == 0
        assert started["server"].run_kwargs["transport"] == "http"
        assert started["kwargs"]["require_principal"] is False


# -- live --------------------------------------------------------------------- #

def _mock_config() -> Config:
    return Config(servers=[ServerConfig(name="mock", command=sys.executable, args=[MOCK_SERVER_PATH])])


_ONE = {"a-token": {"client_id": "c", "scopes": [], "sub": "a", "iss": ISSUER, "roles": []}}


@pytest.mark.asyncio
async def test_load_mcp_server_is_refused_over_http():
    """Refused at the handler, not hidden: a hidden tool is a suggestion."""
    server = create_server(_mock_config(), auth=StaticTokenVerifier(tokens=_ONE))
    async with run_server_async(server) as url:
        async with Client(StreamableHttpTransport(url, auth="a-token")) as client:
            result = await client.call_tool(
                "load_mcp_server", {"server_name": "x", "url": "http://127.0.0.1:1/mcp"}
            )
    text = result.content[0].text
    assert text.startswith("Error:") and "not available over HTTP" in text


@pytest.mark.asyncio
async def test_load_mcp_server_still_reaches_the_pipeline_off_http():
    """The same call in-process (what stdio is) gets past the HTTP refusal and
    on to the load pipeline and connection attempt as before."""
    async with Client(create_server(_mock_config())) as client:
        result = await client.call_tool(
            "load_mcp_server", {"server_name": "x", "url": "http://127.0.0.1:1/mcp"}
        )
    text = result.content[0].text
    assert text.startswith("Error") and "not available over HTTP" not in text


@pytest.mark.asyncio
async def test_a_token_for_another_audience_is_rejected_live():
    """The verifier the config form builds checks the audience, so a token the
    right issuer minted for some other service is refused at the door, with a
    401 before any handler runs. Asserted on the status, since the SDK folds
    an HTTP refusal into a generic client error."""
    import httpx2

    kp = RSAKeyPair.generate()
    verifier = JWTVerifier(public_key=kp.public_key, issuer=ISSUER, audience=AUDIENCE)
    server = create_server(_mock_config(), auth=verifier, require_principal=True)
    ours = kp.create_token(subject="a", issuer=ISSUER, audience=AUDIENCE)
    theirs = kp.create_token(subject="a", issuer=ISSUER, audience="some-other-service")
    async with run_server_async(server) as url:
        async with Client(StreamableHttpTransport(url, auth=ours)) as client:
            found = await client.call_tool("search_tools", {"query": "add numbers", "top_k": 3})
            assert "mock__add_numbers" in found.content[0].text
        async with httpx2.AsyncClient() as http:
            probe = {"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": {}}
            headers = {"Accept": "application/json, text/event-stream"}
            refused = await http.post(
                url, json=probe, headers={**headers, "Authorization": f"Bearer {theirs}"}
            )
            assert refused.status_code == 401
            bare = await http.post(url, json=probe, headers=headers)
            assert bare.status_code == 401

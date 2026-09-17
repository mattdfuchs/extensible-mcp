# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Adding an authenticated server without handing the credential to the model.

`load_mcp_server` lets the LLM name both a server and a URL, and a token is
keyed by name — so a prompt-injected model could point a name that has a token
at a host it controls and be handed the bearer. The proxy closed that by
sending credentials only to URLs an operator configured, which also removed the
documented "drop the token in the tokens file, then load at runtime" flow.

This restores it from the other side. The distinction that makes it safe is
*who possesses the credential*: the bug was the model referencing a secret it
had never seen, and the proxy fetching it on the model's behalf. Here the
operator passes the token in, so only a caller who already holds it can use it
— and the model holds none.

Note this is the opposite direction from moving *signed evidence* by handle
rather than by value, and both are right. Evidence should travel by reference
because the LLM is a lossy courier of bytes it legitimately carries; a
downstream auth token should travel by value because the LLM must never be
able to invoke one it cannot hold.

Deliberately not an MCP tool. A `token` parameter on `load_mcp_server` would
be safe from exfiltration — the model has nothing to pass — but it shares the
endpoint the model drives, and any user who pasted a token into a chat to make
it work would break the rule that tokens never transit the conversation.
"""

from __future__ import annotations

import json
import os
import signal
from dataclasses import dataclass
from pathlib import Path

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

PID_FILENAME = "extensible-mcp.pid"


class AdminError(Exception):
    """Something the operator needs to fix, reported without a traceback."""


@dataclass
class VerifiedServer:
    name: str
    url: str
    tool_names: list[str]


async def verify_server(name: str, url: str, token: str | None) -> VerifiedServer:
    """Connect as an MCP client and list tools, so a bad URL or a wrong token
    fails here rather than at the proxy's next start.

    Verification is the point of the command: writing a token into a file is
    trivial, and finding out hours later that it was wrong is the expensive
    part.

    Built to behave exactly as ``ClientManager`` will, which means **not**
    following redirects. An earlier version did, and so accepted a URL the
    proxy then could not use -- a `/mcp/` that 307s to `/mcp` verified here and
    failed at the proxy, which is worse than not checking, because it reports
    success for something broken. The runtime does not follow redirects either,
    and should not: a redirect carrying an Authorization header is a way to
    hand a bearer somewhere it was not meant to go.
    """
    import httpx

    headers = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        async with httpx.AsyncClient(headers=headers) as http:
            async with streamable_http_client(url, http_client=http) as (r, w, _):
                async with ClientSession(r, w) as session:
                    await session.initialize()
                    listed = await session.list_tools()
    except Exception as e:  # noqa: BLE001 - every failure is the same advice
        detail = _leaf(e)
        hint = (
            "Check the URL, that the server is running, and that the token is "
            "the one it expects."
        )
        if "Redirect" in detail or "307" in detail or "308" in detail:
            # Overwhelmingly a trailing slash, and the message httpx gives names
            # the target, so point straight at it.
            hint = (
                "That URL redirects. Use the URL it redirects to -- usually this "
                "is a trailing slash: try the form without one, or with one, to "
                "match what the server serves. The proxy does not follow "
                "redirects, so the exact URL matters."
            )
        raise AdminError(f"could not use {url} as an MCP server: {detail}\n{hint}") from e
    return VerifiedServer(name=name, url=url, tool_names=[t.name for t in listed.tools])


def _leaf(exc: BaseException) -> str:
    """The innermost message. anyio task groups wrap the real failure."""
    if isinstance(exc, BaseExceptionGroup):
        return "; ".join(_leaf(e) for e in exc.exceptions)
    return str(exc).strip() or type(exc).__name__


def add_server_to_config(config_path: Path, name: str, url: str) -> None:
    """Add ``name`` to the config's ``mcpServers``, refusing to redefine one.

    Rewriting an existing entry is how a name could be re-pointed at another
    host, which is the substitution the token binding exists to prevent -- so
    it is an error here rather than an overwrite.
    """
    raw = json.loads(config_path.read_text())
    servers = raw.setdefault("mcpServers", {})
    if name in servers:
        raise AdminError(
            f"'{name}' is already in {config_path}. Remove it by hand if you "
            "really mean to point that name somewhere else; this command will "
            "not repoint an existing server."
        )
    servers[name] = {"url": url}
    config_path.write_text(json.dumps(raw, indent=2) + "\n")


def write_token(tokens_path: Path, name: str, token: str) -> None:
    """Upsert ``name=token``, leaving every other line untouched.

    Rewritten through a 0600 temp file and replaced atomically: a reader that
    catches the file mid-write would see a truncated token and send it.
    """
    lines: list[str] = []
    replaced = False
    if tokens_path.exists():
        for line in tokens_path.read_text().splitlines():
            key = line.split("=", 1)[0].strip()
            if key == name and not line.strip().startswith("#"):
                lines.append(f"{name}={token}")
                replaced = True
            else:
                lines.append(line)
    if not replaced:
        lines.append(f"{name}={token}")

    tmp = tokens_path.with_name(tokens_path.name + ".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    os.replace(tmp, tokens_path)
    os.chmod(tokens_path, 0o600)


def pid_file_for(config_path: Path) -> Path:
    """Beside the config, so one proxy per config is the unit."""
    return config_path.parent / PID_FILENAME


def _is_locked(pid_file: Path) -> bool:
    """Whether a live process holds the pid file's lock.

    The pid alone is not safe to act on. Python does not run ``finally`` on
    SIGTERM, which is how a daemon is normally stopped, so a stale pid file is
    the common case rather than the exceptional one -- and pids get reused.
    Signalling a recycled pid would send SIGHUP to an unrelated process, whose
    default action is to terminate it.

    An advisory lock answers the question the pid cannot: the running proxy
    holds it for its whole life, and the kernel drops it when that process
    dies, however it died. If we can take the lock, nobody is there.
    """
    try:
        import fcntl
    except ImportError:  # pragma: no cover - Windows
        return True  # cannot tell; fall back to trusting the pid
    try:
        fd = os.open(str(pid_file), os.O_RDWR)
    except OSError:
        return False
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return True  # someone holds it: a live proxy
    else:
        fcntl.flock(fd, fcntl.LOCK_UN)
        return False
    finally:
        os.close(fd)


def signal_reload(config_path: Path) -> int | None:
    """SIGHUP a proxy running against this config. Returns the pid, or None.

    A stale pid file is normal, so it is reported rather than treated as a
    failure: the config and token are already written, and the next start picks
    them up.
    """
    pid_file = pid_file_for(config_path)
    if not pid_file.exists():
        return None
    try:
        pid = int(pid_file.read_text().strip())
    except ValueError:
        return None
    if not hasattr(signal, "SIGHUP"):
        return None
    if not _is_locked(pid_file):
        return None
    try:
        os.kill(pid, signal.SIGHUP)
    except (ProcessLookupError, PermissionError):
        return None
    return pid


# The running proxy's lock fd. Held for the process lifetime: closing it would
# release the lock and make a live proxy look stale.
_pid_lock_fd: int | None = None


def write_pid_file(config_path: Path) -> Path:
    """Record this process's pid and hold an advisory lock on the file."""
    global _pid_lock_fd
    path = pid_file_for(config_path)
    # Open without O_TRUNC and truncate only after the lock is ours. O_TRUNC
    # empties the file at open(), which happens before the lock is tested -- so
    # a second proxy that is about to be refused would first wipe the running
    # proxy's pid, leaving add-server unable to find it.
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT, 0o644)
    try:
        import fcntl

        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except ImportError:  # pragma: no cover - Windows
        pass
    except OSError as e:
        os.close(fd)
        raise AdminError(
            f"another proxy is already running against {config_path} "
            f"(see {path})"
        ) from e
    os.ftruncate(fd, 0)
    os.write(fd, f"{os.getpid()}\n".encode())
    _pid_lock_fd = fd
    return path


def remove_pid_file(path: Path) -> None:
    """Best effort, on the graceful path only. The lock is what actually
    tells a later ``add-server`` whether anyone is there, so a file left by a
    SIGTERM is untidy rather than wrong."""
    global _pid_lock_fd
    if _pid_lock_fd is not None:
        try:
            os.close(_pid_lock_fd)
        except OSError:
            pass
        _pid_lock_fd = None
    try:
        if int(path.read_text().strip()) == os.getpid():
            path.unlink()
    except (OSError, ValueError):
        pass

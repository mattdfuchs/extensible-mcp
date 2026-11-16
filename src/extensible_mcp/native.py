# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""The ``platform`` pseudo-server: a platform's own steps as tools of the proxy.

A workflow or agent platform has steps that never cross MCP -- a shell
command, an HTTP request, a function the developer wrote. The proxy governs
them by giving them names in its own catalogue, as tools of a reserved
server called ``platform``: ``platform__exec``, ``platform__http_request``,
``platform__<name>`` for a declared function. Everything the proxy decides
with is keyed on the server name, so a policy bundle, a role scope, an
access-control pattern and a policy-set route all apply to a native tool
with no second code path.

Two of these tools have the same shape on every platform, and this module
ships their schemas. The distinction that matters to governance is not
local versus external but how legible the effect is from the arguments:

- ``exec`` is **a program with arguments, never a shell.** The schema is an
  ``argv`` array. A platform hands the model a shell string, so a
  ``command`` string is also accepted and normalized here -- tokenized with
  POSIX rules, and refused outright if it carries an operator, redirection,
  substitution, glob or variable reference -- so a policy always reasons
  about one program and its arguments, never about text. The proxy does not
  run it; the platform asks ``POST /decide`` and runs the step itself.
- ``http_request`` is the one native tool the proxy can run
  (:class:`HttpRequestExecutor`): to a host the operator declared, with a
  method and path the host entry allows, carrying a credential the proxy
  holds, following no redirect. The proxy already makes outbound calls to
  configured URLs with configured credentials; this is that path with a
  policy in front of it, and it takes the target API's credential out of the
  platform entirely.

There is deliberately no ``code`` shape. A program is the one argument no
policy can say anything about, and a verdict on one could only say who may
run arbitrary code, which is not governance. A deployment that enforces a
policy turns the platform's code tools off.
"""

from __future__ import annotations

import json
import logging
import shlex
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import httpx

from .credentials import PROXY_ITSELF, CredentialProvider, build_provider
from .types import PLATFORM_SERVER, CredentialConfig, ToolRecord

logger = logging.getLogger(__name__)

EXEC_TOOL = "exec"
HTTP_REQUEST_TOOL = "http_request"

#: Characters that make a command string more than one program and its
#: arguments: pipes and chaining, redirection, substitution, globbing,
#: variable and home expansion, comments, and line breaks. A string carrying
#: any of them is refused before tokenization, since ``shlex`` would quietly
#: turn ``a | b`` into the three arguments ``a``, ``|``, ``b``.
SHELL_OPERATORS = frozenset("|&;<>$`()*?~#\n")

EXEC_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "argv": {
            "type": "array",
            "items": {"type": "string"},
            "minItems": 1,
            "description": (
                "The program and its arguments, one element each; argv[0] is the "
                "program. No shell runs: pipes, redirection, substitution, globs "
                "and variables are refused."
            ),
        },
        "command": {
            "type": "string",
            "description": (
                "A single program with its arguments as one string, tokenized "
                "with POSIX rules into argv. Refused if it carries any shell "
                "operator. Give argv instead where you can."
            ),
        },
        "cwd": {"type": "string", "description": "Working directory."},
        "stdin": {"type": "string", "description": "Text fed to the program's standard input."},
    },
    "additionalProperties": False,
}

HTTP_REQUEST_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "method": {"type": "string", "description": "HTTP method, e.g. GET or POST."},
        "url": {"type": "string", "description": "Absolute URL of the request."},
        "headers": {
            "type": "object",
            "additionalProperties": {"type": "string"},
            "description": "Request headers. Authorization is set by the proxy and may not be given.",
        },
        "query": {
            "type": "object",
            "additionalProperties": {"type": "string"},
            "description": "Query parameters, added to the URL.",
        },
        "body": {
            "description": "Request body: a JSON object or array, sent as JSON, or a string, sent as text.",
        },
    },
    "required": ["method", "url"],
    "additionalProperties": False,
}

SHIPPED_SCHEMAS: dict[str, tuple[str, dict[str, Any]]] = {
    EXEC_TOOL: (
        "Run a program with arguments on the platform. The proxy decides whether "
        "it may run; the platform runs it.",
        EXEC_SCHEMA,
    ),
    HTTP_REQUEST_TOOL: (
        "Make an HTTP request to an external service through the proxy, which "
        "sends it to a declared host with the credential it holds for that host.",
        HTTP_REQUEST_SCHEMA,
    ),
}


class NativeRefusal(Exception):
    """A native call the proxy will not make, with the reason rendered for
    the model. Raised before any filter runs (a command string that is not
    one program) or after the pipeline allowed (a host outside the
    allow-list, a connection that failed); the caller turns it into the
    refusal shape of its entry point."""


@dataclass(frozen=True)
class NativeTool:
    """One declared tool of the ``platform`` server."""

    name: str
    description: str
    input_schema: dict[str, Any]

    @property
    def qualified_name(self) -> str:
        return f"{PLATFORM_SERVER}__{self.name}"

    def record(self) -> ToolRecord:
        return ToolRecord(
            name=self.name,
            qualified_name=self.qualified_name,
            description=self.description,
            input_schema=self.input_schema,
            server_name=PLATFORM_SERVER,
        )


@dataclass(frozen=True)
class HostRule:
    """What the proxy may send to one declared origin.

    ``origin`` is ``scheme://host[:port]``, matched exactly after
    normalization; ``methods`` and ``paths`` (prefixes; empty means any path)
    bound the request; ``headers`` names the request headers a caller may
    set, nothing else being forwarded; ``credential`` names an entry in the
    config's ``credentials`` block, presented as the bearer. The target API's
    secret therefore lives with the proxy and is never seen by the platform
    or the model.
    """

    origin: str
    methods: frozenset[str] = frozenset({"GET"})
    paths: tuple[str, ...] = ()
    headers: frozenset[str] = frozenset()
    credential: str | None = None


@dataclass(frozen=True)
class HttpRequestConfig:
    hosts: dict[str, HostRule] = field(default_factory=dict)
    timeout: float = 30.0
    max_response: int = 1024 * 1024


@dataclass(frozen=True)
class PlatformConfig:
    """The ``platform`` block: which native tools the endpoints may be asked
    about, and whether the proxy runs ``http_request`` itself."""

    tools: dict[str, NativeTool] = field(default_factory=dict)
    http_request: HttpRequestConfig | None = None


def normalize_origin(value: str) -> str:
    """``scheme://host[:port]`` with scheme and host lower-cased and a default
    port dropped, so an operator's spelling and a URL's agree."""
    parts = urlsplit(value if "://" in value else f"https://{value}")
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    if not scheme or not host:
        raise ValueError(f"{value!r} is not an origin of the form scheme://host[:port]")
    port = parts.port
    default = {"http": 80, "https": 443}.get(scheme)
    netloc = host if port is None or port == default else f"{host}:{port}"
    return f"{scheme}://{netloc}"


def normalize_exec_arguments(arguments: dict[str, Any]) -> dict[str, Any]:
    """``argv`` from a ``command`` string, or the arguments unchanged.

    Refuses, before any filter runs, a string that is more than one program
    and its arguments; the rule is named in the refusal so the model can
    give argv instead. A call carrying both forms is refused too, since a
    policy that read one while the platform ran the other would have decided
    about the wrong command.
    """
    if "command" not in arguments:
        return arguments
    command = arguments["command"]
    if "argv" in arguments:
        raise NativeRefusal(
            "platform__exec takes 'argv' or 'command', not both: a policy that "
            "judged one while the platform ran the other would have judged the "
            "wrong command."
        )
    if not isinstance(command, str) or not command.strip():
        raise NativeRefusal("platform__exec 'command' must be a non-empty string.")
    found = sorted(set(command) & SHELL_OPERATORS)
    if found:
        shown = ", ".join(repr(c) for c in found)
        raise NativeRefusal(
            f"platform__exec 'command' carries shell syntax ({shown}). A governed "
            "command is one program and its arguments: no pipes, chaining, "
            "redirection, substitution, globs or variables. Give the program and "
            "each argument as 'argv' instead."
        )
    try:
        argv = shlex.split(command, posix=True)
    except ValueError as e:
        raise NativeRefusal(f"platform__exec 'command' could not be tokenized: {e}.")
    if not argv:
        raise NativeRefusal("platform__exec 'command' names no program.")
    rest = {k: v for k, v in arguments.items() if k != "command"}
    return {"argv": argv, **rest}


class HttpRequestExecutor:
    """Makes ``platform__http_request`` calls the pipeline allowed.

    Every check here runs after the policy has already said yes, and is the
    operator's bound rather than the policy's: the request goes only to a
    declared origin, with an allowed method and path, carrying only the
    headers the host entry permits and the credential the proxy holds for
    it. A redirect is not followed, because following one would let the
    target send the credential to a host the operator never named. The
    response is capped and the credential never appears in a result.
    """

    def __init__(
        self,
        config: HttpRequestConfig,
        credentials: dict[str, CredentialConfig],
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._config = config
        self._transport = transport
        self._providers: dict[str, CredentialProvider] = {}
        for origin, rule in config.hosts.items():
            if rule.credential is None:
                continue
            credential = credentials.get(rule.credential)
            if credential is None:
                raise ValueError(
                    f"platform.http_request host {origin!r} names credential "
                    f"{rule.credential!r}, which is not defined in 'credentials'"
                )
            # One provider per host: the token for one API is not the token
            # for another, so the cache is keyed the way the use is.
            self._providers[origin] = build_provider(credential, audience=None)

    def rule_for(self, url: str) -> tuple[str, HostRule]:
        """The host entry governing ``url``, or a refusal naming the allow-list."""
        try:
            origin = normalize_origin(url)
        except ValueError as e:
            raise NativeRefusal(f"platform__http_request: {e}")
        rule = self._config.hosts.get(origin)
        if rule is None:
            allowed = ", ".join(sorted(self._config.hosts)) or "none"
            raise NativeRefusal(
                f"platform__http_request may not reach {origin}: the proxy sends "
                f"requests only to its declared hosts ({allowed})."
            )
        return origin, rule

    def admit(self, arguments: dict[str, Any]) -> tuple[str, HostRule, str, str, dict[str, str]]:
        """Check an allowed call against the operator's bounds without
        opening a connection. Returns what the request will be made of."""
        method = arguments.get("method")
        url = arguments.get("url")
        if not isinstance(method, str) or not method:
            raise NativeRefusal("platform__http_request needs a 'method'.")
        if not isinstance(url, str) or not url:
            raise NativeRefusal("platform__http_request needs an absolute 'url'.")
        origin, rule = self.rule_for(url)
        method = method.upper()
        if method not in rule.methods:
            raise NativeRefusal(
                f"platform__http_request may not {method} {origin}: the host entry "
                f"allows {', '.join(sorted(rule.methods))}."
            )
        path = urlsplit(url).path or "/"
        if rule.paths and not any(path.startswith(prefix) for prefix in rule.paths):
            raise NativeRefusal(
                f"platform__http_request may not reach {path} on {origin}: the host "
                f"entry allows paths under {', '.join(rule.paths)}."
            )
        headers_in = arguments.get("headers") or {}
        if not isinstance(headers_in, dict):
            raise NativeRefusal("platform__http_request 'headers' must be an object.")
        headers: dict[str, str] = {}
        permitted = {h.lower() for h in rule.headers}
        for name, value in headers_in.items():
            if name.lower() == "authorization":
                raise NativeRefusal(
                    "platform__http_request sets Authorization itself from the "
                    "credential the proxy holds for the host; a caller may not supply one."
                )
            if name.lower() not in permitted:
                raise NativeRefusal(
                    f"platform__http_request may not send header {name!r} to {origin}: "
                    f"the host entry allows {', '.join(sorted(rule.headers)) or 'no headers'}."
                )
            headers[name] = str(value)
        return origin, rule, method, url, headers

    async def call(self, arguments: dict[str, Any]) -> tuple[list[Any], bool, dict[str, Any]]:
        """Make the request. Returns ``(content, is_error, structured)``;
        ``is_error`` only when no response arrived (connection refused,
        timeout) -- a non-2xx status is a result the model reads."""
        import mcp.types as mcp_types

        origin, rule, method, url, headers = self.admit(arguments)
        query = arguments.get("query")
        if query is not None and not isinstance(query, dict):
            raise NativeRefusal("platform__http_request 'query' must be an object.")
        body = arguments.get("body")
        content: bytes | None = None
        if isinstance(body, (dict, list)):
            content = json.dumps(body).encode()
            headers.setdefault("Content-Type", "application/json")
        elif isinstance(body, str):
            content = body.encode()
            headers.setdefault("Content-Type", "text/plain; charset=utf-8")
        elif body is not None:
            raise NativeRefusal("platform__http_request 'body' must be an object, an array or a string.")

        provider = self._providers.get(origin)
        try:
            response = await self._send(provider, method, url, headers, query, content)
        except httpx.TimeoutException:
            raise NativeRefusal(
                f"platform__http_request to {origin} timed out after "
                f"{self._config.timeout:g}s."
            )
        except httpx.HTTPError as e:
            raise NativeRefusal(f"platform__http_request to {origin} failed: {type(e).__name__}.")

        structured = self._result(response)
        return (
            [mcp_types.TextContent(type="text", text=json.dumps(structured))],
            False,
            structured,
        )

    async def _send(
        self,
        provider: CredentialProvider | None,
        method: str,
        url: str,
        headers: dict[str, str],
        query: dict[str, Any] | None,
        content: bytes | None,
    ) -> _Captured:
        async with httpx.AsyncClient(
            follow_redirects=False,
            timeout=self._config.timeout,
            transport=self._transport,
        ) as client:
            response = await self._once(client, provider, method, url, headers, query, content, False)
            if response.status in (401, 403) and provider is not None:
                # One refresh, as the downstream transport does: a second
                # refusal is the two servers disagreeing, which another token
                # will not fix.
                response = await self._once(client, provider, method, url, headers, query, content, True)
            return response

    async def _once(
        self,
        client: httpx.AsyncClient,
        provider: CredentialProvider | None,
        method: str,
        url: str,
        headers: dict[str, str],
        query: dict[str, Any] | None,
        content: bytes | None,
        force_refresh: bool,
    ) -> _Captured:
        sent = dict(headers)
        if provider is not None:
            token = await provider.token(PROXY_ITSELF, force_refresh=force_refresh)
            sent["Authorization"] = f"Bearer {token}"
        async with client.stream(method, url, headers=sent, params=query, content=content) as response:
            cap = self._config.max_response
            chunks: list[bytes] = []
            size = 0
            truncated = False
            async for chunk in response.aiter_bytes():
                if size + len(chunk) > cap:
                    chunks.append(chunk[: cap - size])
                    truncated = True
                    break
                chunks.append(chunk)
                size += len(chunk)
            return _Captured(
                status=response.status_code,
                content_type=response.headers.get("content-type", ""),
                body=b"".join(chunks),
                truncated=truncated,
            )

    @staticmethod
    def _result(response: _Captured) -> dict[str, Any]:
        text = response.body.decode("utf-8", errors="replace")
        body: Any = text
        if not response.truncated and "json" in response.content_type.lower():
            try:
                body = json.loads(text) if text else None
            except ValueError:
                body = text
        return {
            "status": response.status,
            "headers": {"content-type": response.content_type},
            "body": body,
            "truncated": response.truncated,
        }


@dataclass(frozen=True)
class _Captured:
    status: int
    content_type: str
    body: bytes
    truncated: bool


class Platform:
    """The ``platform`` server as the lifespan holds it: its declared tools
    and, when configured, the one executor."""

    def __init__(
        self,
        config: PlatformConfig,
        credentials: dict[str, CredentialConfig],
        *,
        http_transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.tools: dict[str, NativeTool] = dict(config.tools)
        self.http: HttpRequestExecutor | None = (
            HttpRequestExecutor(config.http_request, credentials, transport=http_transport)
            if config.http_request is not None
            else None
        )

    def records(self) -> list[ToolRecord]:
        return [tool.record() for tool in self.tools.values()]

    def prepare(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Normalization that runs before any filter: today, a command
        string into argv."""
        if tool == EXEC_TOOL:
            return normalize_exec_arguments(arguments)
        return arguments

    async def call(self, tool: str, arguments: dict[str, Any]) -> tuple[list[Any], bool, Any]:
        """Dispatch a native call the pipeline allowed, or refuse it: the
        proxy runs ``http_request`` when configured and nothing else."""
        if tool not in self.tools:
            raise NativeRefusal(
                f"Unknown tool '{PLATFORM_SERVER}__{tool}': it is not a declared platform tool."
            )
        if tool == HTTP_REQUEST_TOOL and self.http is not None:
            return await self.http.call(arguments)
        if tool == EXEC_TOOL:
            raise NativeRefusal(
                "The proxy does not run platform__exec. It answers whether the "
                "command may run (POST /decide); the platform runs it."
            )
        raise NativeRefusal(
            f"The proxy does not run {PLATFORM_SERVER}__{tool}. It answers whether "
            "the step may run (POST /decide); the platform runs it."
        )

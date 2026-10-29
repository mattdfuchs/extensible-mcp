# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""The call-path invariants, enumerated rather than described.

Three rules hold the call path together, and until this file all three were
prose -- in CLAUDE.md's "central invariant" section and the README's threat
model. Prose does not fail. The call path is deny-on-objection, so a control
that silently loses its key *permits*: correctness here cannot be established
by careful reading, which is why each rule is a test that fails loudly.

The invariants, one section each:

1. the registered-tool set is closed -- exactly the three meta-tools, ever;
2. every field of a request reaches every filter in its pipeline;
3. a server the selector cannot place is refused, not admitted ungoverned.
"""

from __future__ import annotations

import asyncio
import dataclasses
import sys
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client

from extensible_mcp.config import Config, FiltersConfig
from extensible_mcp.filters import (
    CallFilterPipeline,
    FilterPipeline,
    ResponseFilterPipeline,
    ServerLoadFilterPipeline,
)
from extensible_mcp.routing import BundleRouter
from extensible_mcp.selection import (
    BANNED,
    LayeredBundleSelector,
    provenance_descriptor,
)
from extensible_mcp.server import _admit_servers, create_server
from extensible_mcp.types import (
    CallFilterResult,
    CallRequest,
    CallResponse,
    LocalTool,
    ResponseFilterResult,
    SearchResult,
    ServerConfig,
    ServerLoadRequest,
    ServerLoadResult,
    ToolRecord,
)
from extensible_mcp.types import Principal

MOCK_SERVER_PATH = str(Path(__file__).parent / "mock_server.py")


# --------------------------------------------------------------------------- #
# 1. The registered-tool set is closed.
#
# A tool registered directly on the FastMCP object is reachable by name and
# subject to nothing -- not access control, not a policy bundle, not even the
# rule that a tool must have been surfaced by search_tools, because every
# filter runs inside call_tool_handler and nothing else in the process gates a
# call. That was a live hole until `local_tools` closed it. This section is
# what keeps it closed: the set is asserted to be exactly the three meta-tools,
# so reintroducing a `@server.tool()` after `create_server` returns fails here
# rather than passing review.
# --------------------------------------------------------------------------- #

META_TOOLS = {"search_tools", "call_tool", "load_mcp_server"}


def _config() -> Config:
    """A config with no downstream servers.

    Nothing is connected and no index is built: `list_tools` below reads the
    registry on the returned object without entering the lifespan, which is
    the question this section asks -- what is *registered*, not what a running
    proxy can reach.
    """
    return Config(servers=[], filters=FiltersConfig(similarity_threshold=0.0))


async def _registered_tool_names(server) -> set[str]:
    return {t.name for t in await server.list_tools()}


async def test_registered_tools_are_exactly_the_three_meta_tools():
    server = create_server(_config())
    assert await _registered_tool_names(server) == META_TOOLS


async def test_local_tools_register_no_tool_on_the_server():
    """`local_tools` must stay invisible to the MCP tool list.

    A local tool is reached through `call_tool` -- and so through every
    CallFilter -- precisely because it is *not* registered as a tool of its
    own. If one ever shows up here, it has a second, unfiltered call path.
    """

    async def handler(arguments: dict) -> str:
        return "ok"

    locals_ = [
        LocalTool(
            name=name,
            description=f"local tool {name}",
            input_schema={"type": "object", "properties": {}},
            handler=handler,
        )
        for name in ("approve_payment", "read_wallet")
    ]
    server = create_server(_config(), local_tools=locals_)
    assert await _registered_tool_names(server) == META_TOOLS


async def test_filters_and_bundle_router_register_no_tools():
    """None of the embedding hooks may add a tool.

    The extra_*_filters and bundle_router kwargs are the supported extension
    points; a third party reaching for one of them must not be able to widen
    the reachable surface as a side effect.
    """

    class _PassThroughCallFilter:
        async def check(self, request):
            return CallFilterResult(
                allowed=True,
                tool_name=request.tool_name,
                arguments=request.arguments,
            )

    class _PassThroughSearchFilter:
        def filter(self, results, query):
            return results

    router = BundleRouter(LayeredBundleSelector(), lambda bundle: None)
    server = create_server(
        _config(),
        extra_search_filters=[_PassThroughSearchFilter()],
        extra_call_filters=[_PassThroughCallFilter()],
        bundle_router=router,
    )
    assert await _registered_tool_names(server) == META_TOOLS


async def test_three_meta_tools_are_registered_on_a_live_proxy():
    """The same set, through a client against a connected proxy.

    The registry checks above do not enter the lifespan; this one does, so a
    tool registered from inside it -- at connect time, per downstream server --
    would be caught as well.
    """
    config = Config(
        servers=[
            ServerConfig(name="mock", command=sys.executable, args=[MOCK_SERVER_PATH])
        ],
        filters=FiltersConfig(similarity_threshold=0.0),
    )
    server = create_server(config)
    async with Client(server) as client:
        assert {t.name for t in await client.list_tools()} == META_TOOLS


# --------------------------------------------------------------------------- #
# 2. Every field of a request reaches every filter.
#
# A pipeline that rebuilds its request by naming the fields it knows drops the
# one it does not. On this call path that is not a cosmetic bug: `session_id`
# was added in 0.3.2, dropped by exactly this rebuild, and because a filter
# that sees None falls back to the shared bucket, the loss *permitted*. The
# dedup fix in 0.3.3 lost a field in the other direction and denied, which
# failed safe. Both directions of the bug class have now shipped once.
#
# The structural answer is `dataclasses.replace` at every request/response
# rebuild site (the propagation half of Phase 0, #8). The first test below
# is the declared-field guarantee and guards the 0.3.2 regression. The
# second is the structural one: a field the pipeline was not written to know
# about still reaches the filter. The third is the aliasing half, from the
# 0.3.2 reporter's review: the shared-set bug was one client's object
# reaching another client's filter, which a single request in flight cannot
# see, so two run at once and each filter must have seen its own.
# --------------------------------------------------------------------------- #

_SENTINEL = object()


def _dropped_fields(sent: Any, seen: Any) -> list[str]:
    """Fields of ``sent`` the filter did not see on ``seen``, in order.

    A field is dropped if the object the filter received does not carry it at
    all, or carries something other than what was sent -- which is why every
    field is given a distinguishable value.
    """
    dropped = []
    for f in dataclasses.fields(sent):
        if getattr(seen, f.name, _SENTINEL) != getattr(sent, f.name):
            dropped.append(f.name)
    return dropped


class _RecordingSearchFilter:
    def __init__(self) -> None:
        self.seen: list[tuple[list[SearchResult], str]] = []

    def filter(self, results: list[SearchResult], query: str) -> list[SearchResult]:
        self.seen.append((results, query))
        return results


class _RecordingCallFilter:
    def __init__(self) -> None:
        self.seen: list[CallRequest] = []

    async def check(self, request: CallRequest) -> CallFilterResult:
        self.seen.append(request)
        return CallFilterResult(
            allowed=True, tool_name=request.tool_name, arguments=request.arguments
        )


class _RecordingResponseFilter:
    def __init__(self) -> None:
        self.seen: list[CallResponse] = []

    async def check(self, response: CallResponse) -> ResponseFilterResult:
        self.seen.append(response)
        return ResponseFilterResult(
            allowed=True, content=response.content, is_error=response.is_error
        )


class _RecordingLoadFilter:
    def __init__(self) -> None:
        self.seen: list[ServerLoadRequest] = []

    async def check(self, request: ServerLoadRequest) -> ServerLoadResult:
        self.seen.append(request)
        return ServerLoadResult(allowed=True)


def _principal(label: str) -> Principal:
    """A distinct, frozen Principal per request; `is` is meaningful on it."""
    return Principal(sub=f"sub-{label}", iss="https://idp.example", roles=frozenset({label}))


def _tool_record() -> ToolRecord:
    """A ToolRecord with every field set to something distinguishable."""
    return ToolRecord(
        name="send",
        qualified_name="payments__send",
        description="description-sentinel",
        input_schema={"type": "object", "properties": {"amountCents": {}}},
        server_name="payments",
        embedding_text="embedding-text-sentinel",
    )


async def _run_all_four_pipelines(
    *,
    search_results: list[SearchResult],
    call_request: CallRequest,
    call_response: CallResponse,
    load_request: ServerLoadRequest,
) -> dict[str, list[str]]:
    """Push one fully-populated request through each pipeline, twice-filtered.

    Two recording filters per pipeline, because the invariant is that every
    field reaches *every* filter -- not just the first one, which on some
    pipelines is handed the caller's own object.

    Returns the dropped fields per pipeline, keyed by pipeline class name and
    the filter's position, so a failure names what was lost and where.
    """
    dropped: dict[str, list[str]] = {}

    s1, s2 = _RecordingSearchFilter(), _RecordingSearchFilter()
    FilterPipeline([s1, s2]).apply(search_results, "query-sentinel")
    for i, f in enumerate((s1, s2)):
        seen_results, seen_query = f.seen[0]
        lost = [
            name
            for sent, got in zip(search_results, seen_results, strict=True)
            for name in _dropped_fields(sent, got)
        ]
        if seen_query != "query-sentinel":
            lost.append("query")
        if lost:
            dropped[f"FilterPipeline[{i}]"] = lost

    c1, c2 = _RecordingCallFilter(), _RecordingCallFilter()
    await CallFilterPipeline([c1, c2]).apply(call_request)
    for i, f in enumerate((c1, c2)):
        lost = _dropped_fields(call_request, f.seen[0])
        if lost:
            dropped[f"CallFilterPipeline[{i}]"] = lost

    r1, r2 = _RecordingResponseFilter(), _RecordingResponseFilter()
    await ResponseFilterPipeline([r1, r2]).apply(call_response)
    for i, f in enumerate((r1, r2)):
        lost = _dropped_fields(call_response, f.seen[0])
        if lost:
            dropped[f"ResponseFilterPipeline[{i}]"] = lost

    l1, l2 = _RecordingLoadFilter(), _RecordingLoadFilter()
    await ServerLoadFilterPipeline([l1, l2]).apply(load_request)
    for i, f in enumerate((l1, l2)):
        lost = _dropped_fields(load_request, f.seen[0])
        if lost:
            dropped[f"ServerLoadFilterPipeline[{i}]"] = lost

    return dropped


async def test_declared_request_fields_reach_every_filter():
    """Today's guarantee, for all four pipelines: no declared field is lost.

    This is the 0.3.2 regression's test. It passes now, and it is here so that
    a rebuild site which stops carrying `session_id` (or `arguments`, or
    `is_error`) fails rather than quietly widening what a session-scoped
    filter will allow.
    """
    dropped = await _run_all_four_pipelines(
        search_results=[SearchResult(tool=_tool_record(), score=0.77)],
        call_request=CallRequest(
            tool_name="payments__send",
            arguments={"amountCents": 500},
            server_name="payments",
            session_id="session-sentinel",
            principal=_principal("sentinel"),
        ),
        call_response=CallResponse(
            tool_name="payments__send",
            arguments={"amountCents": 500},
            server_name="payments",
            content=["content-sentinel"],
            is_error=True,
            structured_content={"result": "structured-sentinel"},
            principal=_principal("sentinel"),
        ),
        load_request=ServerLoadRequest(
            server_name="payments", url="https://payments.example/mcp",
            principal=_principal("sentinel"),
        ),
    )
    assert dropped == {}


@dataclasses.dataclass
class _FutureSearchResult(SearchResult):
    future_field: str = "future-sentinel"


@dataclasses.dataclass
class _FutureCallRequest(CallRequest):
    future_field: str = "future-sentinel"


@dataclasses.dataclass
class _FutureCallResponse(CallResponse):
    future_field: str = "future-sentinel"


@dataclasses.dataclass
class _FutureServerLoadRequest(ServerLoadRequest):
    future_field: str = "future-sentinel"


async def test_every_request_field_reaches_every_filter():
    """Field propagation is structural.

    The `future_field` on each subclass stands in for the next field added
    to a request type. (It was named `principal` while that was the next
    field; `principal` has since landed and is covered by the declared-fields
    test above, so the stand-in moved on.) A pipeline that rebuilds by
    enumerating fields cannot carry it; one that uses `dataclasses.replace`
    carries it without being told it exists. Nothing about the field is
    special: the test asks whether the mechanism is structural, and a
    mechanism that must be edited for each new field is a control that
    silently loses its key. This was `xfail(strict=True)` from #1 until the
    rebuild sites moved to `replace`.
    """
    dropped = await _run_all_four_pipelines(
        search_results=[_FutureSearchResult(tool=_tool_record(), score=0.77)],
        call_request=_FutureCallRequest(
            tool_name="payments__send",
            arguments={"amountCents": 500},
            server_name="payments",
            session_id="session-sentinel",
        ),
        call_response=_FutureCallResponse(
            tool_name="payments__send",
            arguments={"amountCents": 500},
            server_name="payments",
            content=["content-sentinel"],
            is_error=True,
            structured_content={"result": "structured-sentinel"},
        ),
        load_request=_FutureServerLoadRequest(
            server_name="payments", url="https://payments.example/mcp"
        ),
    )
    assert dropped == {}


class _Token:
    """A field value with identity and no interning, so `is` means something."""

    def __init__(self, label: str) -> None:
        self.label = label

    def __repr__(self) -> str:
        return f"_Token({self.label!r})"


class _YieldingCallFilter(_RecordingCallFilter):
    async def check(self, request: CallRequest) -> CallFilterResult:
        await asyncio.sleep(0)  # let the other request in flight interleave
        return await super().check(request)


class _YieldingResponseFilter(_RecordingResponseFilter):
    async def check(self, response: CallResponse) -> ResponseFilterResult:
        await asyncio.sleep(0)
        return await super().check(response)


class _YieldingLoadFilter(_RecordingLoadFilter):
    async def check(self, request: ServerLoadRequest) -> ServerLoadResult:
        await asyncio.sleep(0)
        return await super().check(request)


# The pipelines copy the one field a filter may rewrite before the first
# filter runs, so a filter cannot mutate the caller's object in place.
_COPIED_BY_PIPELINE = frozenset({"arguments", "content"})


def _aliased_fields(own: Any, other: Any, seen: Any) -> list[str]:
    """Fields of ``seen`` that are not ``own``'s, or are ``other``'s.

    Every field is given a value distinguishable *between* the two requests
    and carrying identity, so this catches both a field that leaked across
    requests and one that was rebuilt from the wrong source. The two fields
    a filter may rewrite -- `arguments` on a request, `content` on a
    response -- are deliberately copied by the pipeline before the first
    filter sees them, so for those equality to own and non-identity to other
    is the whole claim; for every other field the object the filter saw must
    be own's.
    """
    bad = []
    for f in dataclasses.fields(own):
        got = getattr(seen, f.name, _SENTINEL)
        theirs = getattr(other, f.name)
        if got is theirs or got != getattr(own, f.name):
            bad.append(f.name)
        elif f.name not in _COPIED_BY_PIPELINE and got is not getattr(own, f.name):
            bad.append(f.name)
    return bad


async def test_two_requests_in_flight_each_reach_their_own_filters():
    """The aliasing half: two requests at once, and each filter saw its own.

    The 0.3.2 bug was aliasing, not loss -- one client's discovery set
    reaching another client's filter -- and a field aliased to an *equal*
    object passes a presence-and-value check on a single request. So two
    requests go through the same pipelines concurrently, with filters that
    yield between them, and every field each filter saw must be its own
    request's object and not the other's. Over the three request-carrying
    pipelines, with the future field present on each.
    """
    def call_request(label: str) -> CallRequest:
        return _FutureCallRequest(
            tool_name=f"payments__send_{label}",
            arguments={"amountCents": _Token(f"amount-{label}")},
            server_name=f"payments-{label}",
            session_id=f"session-{label}",
            principal=_principal(label),
            future_field=_Token(f"future-{label}"),
        )

    def call_response(label: str) -> CallResponse:
        return _FutureCallResponse(
            tool_name=f"payments__send_{label}",
            arguments={"amountCents": _Token(f"amount-{label}")},
            server_name=f"payments-{label}",
            content=[_Token(f"content-{label}")],
            is_error=(label == "a"),
            structured_content={"result": _Token(f"structured-{label}")},
            principal=_principal(label),
            future_field=_Token(f"future-{label}"),
        )

    def load_request(label: str) -> ServerLoadRequest:
        return _FutureServerLoadRequest(
            server_name=f"payments-{label}",
            url=f"https://payments-{label}.example/mcp",
            principal=_principal(label),
            future_field=_Token(f"future-{label}"),
        )

    aliased: dict[str, list[str]] = {}

    c1, c2 = _YieldingCallFilter(), _YieldingCallFilter()
    pipeline = CallFilterPipeline([c1, c2])
    ra, rb = call_request("a"), call_request("b")
    await asyncio.gather(pipeline.apply(ra), pipeline.apply(rb))
    for i, f in enumerate((c1, c2)):
        by_name = {seen.tool_name: seen for seen in f.seen}
        assert set(by_name) == {ra.tool_name, rb.tool_name}
        for own, other in ((ra, rb), (rb, ra)):
            bad = _aliased_fields(own, other, by_name[own.tool_name])
            if bad:
                aliased[f"CallFilterPipeline[{i}]:{own.tool_name}"] = bad

    r1, r2 = _YieldingResponseFilter(), _YieldingResponseFilter()
    pipeline = ResponseFilterPipeline([r1, r2])
    pa, pb = call_response("a"), call_response("b")
    await asyncio.gather(pipeline.apply(pa), pipeline.apply(pb))
    for i, f in enumerate((r1, r2)):
        by_name = {seen.tool_name: seen for seen in f.seen}
        assert set(by_name) == {pa.tool_name, pb.tool_name}
        for own, other in ((pa, pb), (pb, pa)):
            bad = _aliased_fields(own, other, by_name[own.tool_name])
            if bad:
                aliased[f"ResponseFilterPipeline[{i}]:{own.tool_name}"] = bad

    l1, l2 = _YieldingLoadFilter(), _YieldingLoadFilter()
    pipeline = ServerLoadFilterPipeline([l1, l2])
    la, lb = load_request("a"), load_request("b")
    await asyncio.gather(pipeline.apply(la), pipeline.apply(lb))
    for i, f in enumerate((l1, l2)):
        by_name = {seen.server_name: seen for seen in f.seen}
        assert set(by_name) == {la.server_name, lb.server_name}
        for own, other in ((la, lb), (lb, la)):
            bad = _aliased_fields(own, other, by_name[own.server_name])
            if bad:
                aliased[f"ServerLoadFilterPipeline[{i}]:{own.server_name}"] = bad

    assert aliased == {}


# --------------------------------------------------------------------------- #
# 3. A server the selector cannot place is refused.
#
# Bundle selection is fail-closed by construction: both terminals of the
# literal-map/classifier chain end in a denial. What makes that load-bearing is
# the other half -- at call time the router *passes through* a call whose
# server it holds no filter for, because an ungoverned server is a legitimate
# configuration. So admission is the only thing standing between "no bundle
# could be chosen for this server" and "this server's tools are callable with
# no policy at all". A refusal that admitted the server anyway would not read
# as a failure anywhere: the calls would simply succeed.
#
# Two ways to end up unplaceable, and both are refusals here: the selector
# cannot name a bundle, or it names one the deployment cannot build a filter
# for (`filter_factory` returning None).
# --------------------------------------------------------------------------- #

PLACED_URL = "https://payments.example/mcp"
UNPLACEABLE_URL = "https://weather.example/mcp"


class _StubPolicyFilter:
    """Stands in for a WasmPolicyFilter: the router only needs `bundle` at
    admission and `check` at call time."""

    def __init__(self, bundle: str) -> None:
        self.bundle = bundle

    async def check(self, request: CallRequest) -> CallFilterResult:
        return CallFilterResult(
            allowed=True, tool_name=request.tool_name, arguments=request.arguments
        )


class _PlacingClassifier:
    """A classifier that places every descriptor, so a refusal in a test using
    it can only have come from the layer above."""

    def __init__(self, bundle: str = "family_spend") -> None:
        self.bundle = bundle
        self.calls: list[dict[str, Any]] = []

    def decide(self, descriptor: dict[str, Any]) -> str:
        self.calls.append(descriptor)
        return self.bundle


def _descriptor(url: str = PLACED_URL) -> dict[str, Any]:
    return provenance_descriptor(
        origin_server="payments", url=url, config_trust_tier="prod"
    )


def test_selector_with_nothing_to_place_a_descriptor_refuses():
    """No map entry and no classifier is a refusal, not a pass."""
    result = LayeredBundleSelector().select(_descriptor())
    assert not result.allowed and result.route is None


def test_banned_map_entry_does_not_fall_through_to_a_classifier():
    """`banned` is terminal: the layer below must not rescue it."""
    classifier = _PlacingClassifier()
    # Positive control: on its own, the classifier does place this descriptor.
    assert LayeredBundleSelector(classifier=classifier).select(_descriptor()).allowed

    banned = LayeredBundleSelector({PLACED_URL: BANNED}, classifier)
    result = banned.select(_descriptor())
    assert not result.allowed and result.route is None
    assert len(classifier.calls) == 1  # the ban short-circuited, asked nobody


def test_router_refuses_a_server_the_selector_cannot_place():
    asked: list[str] = []

    def factory(bundle: str):
        asked.append(bundle)
        return _StubPolicyFilter(bundle)

    router = BundleRouter(LayeredBundleSelector(), factory)
    result = router.admit(
        server_name="weather", url=UNPLACEABLE_URL, how_loaded="static"
    )
    assert not result.allowed
    assert not router.governs("weather")
    assert router.bundle_for("weather") is None
    assert asked == []  # nothing was selected, so nothing was built


async def test_filter_factory_returning_none_refuses_rather_than_admitting():
    """A named-but-unavailable bundle refuses the server.

    This is the case that cannot be allowed to degrade quietly: the bundle
    *was* selected, so the server is one the deployment means to govern, and
    the only reason there is no filter is that the deployment could not build
    one. The second half of the test shows what admitting it anyway would
    cost -- the router has no filter for that server, so every call to it
    passes through untouched.
    """
    router = BundleRouter(
        LayeredBundleSelector({PLACED_URL: "family_spend"}), lambda bundle: None
    )
    result = router.admit(
        server_name="payments", url=PLACED_URL, how_loaded="static"
    )
    assert not result.allowed
    assert "unavailable" in result.reason
    assert not router.governs("payments")

    arguments = {"amountCents": 500, "merchant": "acme"}
    passthrough = await router.check(
        CallRequest(
            tool_name="payments__send", arguments=arguments, server_name="payments"
        )
    )
    assert passthrough.allowed and passthrough.arguments == arguments


def test_admit_servers_leaves_out_every_refused_server():
    """The load-time helper that turns a refusal into "not connected"."""

    def factory(bundle: str):
        return _StubPolicyFilter(bundle) if bundle == "family_spend" else None

    router = BundleRouter(
        LayeredBundleSelector(
            {PLACED_URL: "family_spend", "https://sandbox.example/mcp": "readonly"}
        ),
        factory,
    )
    servers = [
        ServerConfig(name="payments", url=PLACED_URL),
        ServerConfig(name="weather", url=UNPLACEABLE_URL),  # unplaceable
        ServerConfig(name="sandbox", url="https://sandbox.example/mcp"),  # no filter
    ]
    assert {s.name for s in _admit_servers(router, servers)} == {"payments"}


async def test_refused_server_is_never_connected_or_callable():
    """End to end: a refused server's tools do not exist as far as the LLM is
    concerned -- not surfaced by search_tools, and not callable.

    Two identical downstream servers under one router, one placed and one not,
    so the assertion is about the refusal and not about a proxy that failed to
    start. The map keys on the admitted server name because both of these are
    stdio and so have no URL to key on.
    """
    config = Config(
        servers=[
            ServerConfig(name="placed", command=sys.executable, args=[MOCK_SERVER_PATH]),
            ServerConfig(name="refused", command=sys.executable, args=[MOCK_SERVER_PATH]),
        ],
        filters=FiltersConfig(similarity_threshold=0.0),
    )
    router = BundleRouter(
        LayeredBundleSelector({"placed": "family_spend"}, map_key="origin_server"),
        lambda bundle: _StubPolicyFilter(bundle),
    )
    server = create_server(config, bundle_router=router)
    async with Client(server) as client:
        search = await client.call_tool(
            "search_tools", {"query": "add numbers", "top_k": 10}
        )
        text = search.content[0].text
        assert "placed__add_numbers" in text  # the admitted server still works
        assert "refused__add_numbers" not in text

        call = await client.call_tool(
            "call_tool",
            {"tool_name": "refused__add_numbers", "arguments": {"a": 1, "b": 2}},
        )
        assert "not been discovered" in call.content[0].text.lower()


# --------------------------------------------------------------------------- #
# Composition: scoping sits outside the single-use guard.
#
# A route's chain is `RouteScoped(SingleUse(Policy))`. The order of the two
# wrappers is not structural -- a chain is registered per server type, and
# nothing refuses the inverted one -- and getting it wrong fails silently:
# `SingleUse(RouteScoped(Policy))` would see a stray credential on an
# informational call, get a pass-through verdict from the scoping wrapper
# (which never ran the policy), and mark the evidence spent. Nothing errors.
# The next legitimate call carrying that evidence is refused. This test is
# the assertion that silent failure would break, so it is what guards the
# composition until a constraint language can.
# --------------------------------------------------------------------------- #


def _single_use_minimal_spend(key):
    from extensible_mcp.bundle import PolicyBundle
    from extensible_mcp.declared_bundles import credential_jti
    from extensible_mcp.replay import SingleUseEvidenceFilter
    from extensible_mcp.wasm_filter import WasmPolicyFilter
    from tests import vc_helpers as vc

    bundle = PolicyBundle.load(Path(__file__).parent / "fixtures" / "minimal_spend", name="spend")
    policy = WasmPolicyFilter(bundle, config={"requesterJwk": vc.public_jwk(key)})
    return bundle, SingleUseEvidenceFilter(
        policy, credential_fields=("requestVC",), extract_id=credential_jti
    )


def _calls_sharing_one_credential(key):
    from tests import vc_helpers as vc

    args = {"amountCents": 500, "merchant": "acme"}
    credential = vc.request_vc(args=args, key=key, jti="urn:composition-1")
    informational = CallRequest(
        tool_name="payments__balance",
        arguments={"requestVC": credential},  # stray: balance takes none
        server_name="payments",
    )
    gated = CallRequest(
        tool_name="payments__send",
        arguments={**args, "requestVC": credential},
        server_name="payments",
    )
    return informational, gated


async def test_an_informational_call_with_a_stray_credential_does_not_spend_it():
    from extensible_mcp.policyset import Route, RouteScopedFilter
    from tests import vc_helpers as vc

    key = vc.new_key()
    bundle, guarded = _single_use_minimal_spend(key)
    route = Route(name="payments-send", server_type="spend", tools=frozenset({"send"}))
    chain = RouteScopedFilter(route, guarded, bundle.credential_fields())
    informational, gated = _calls_sharing_one_credential(key)

    passed = await chain.check(informational)
    assert passed.allowed and passed.arguments == {}  # stripped, never judged

    allowed = await chain.check(gated)
    assert allowed.allowed, allowed.reason  # the evidence is still spendable
    assert allowed.arguments == {"amountCents": 500, "merchant": "acme"}

    replay = await chain.check(gated)
    assert not replay.allowed and "already been used" in replay.reason


async def test_the_inverted_composition_is_the_silent_failure_this_guards():
    """Negative control: with the guard outside the scoping, the stray
    credential on `balance` is spent by a call the policy never saw, and the
    legitimate `send` that follows is refused. Nothing errored on the way."""
    from extensible_mcp.policyset import Route, RouteScopedFilter
    from extensible_mcp.declared_bundles import credential_jti
    from extensible_mcp.replay import SingleUseEvidenceFilter
    from tests import vc_helpers as vc

    key = vc.new_key()
    bundle, guarded = _single_use_minimal_spend(key)
    route = Route(name="payments-send", server_type="spend", tools=frozenset({"send"}))
    inverted = SingleUseEvidenceFilter(
        RouteScopedFilter(route, guarded._inner, bundle.credential_fields()),
        credential_fields=("requestVC",),
        extract_id=credential_jti,
    )
    informational, gated = _calls_sharing_one_credential(key)

    passed = await inverted.check(informational)
    assert passed.allowed  # looks fine

    burned = await inverted.check(gated)
    assert not burned.allowed and "already been used" in burned.reason

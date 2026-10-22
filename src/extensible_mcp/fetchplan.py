# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Assemble a policy's closed input by walking a fetch plan the bundle supplies.

A bundle's policy is *closed*: it reads a fixed set of top-level input fields,
and the companion ``fetchplan.json`` says where each one comes from — its
source ``kind`` plus, for ``wallet`` lookups, a subject drawn from an
earlier-assembled field. This module walks that plan in order and dispatches
each entry to a registered resolver. It never interprets the policy; the
resolvers are the only deployment-specific part.

The plan format, ``$input`` parameter substitution, in-order processing, and
fail-closed semantics mirror the executor a policy-authoring toolchain would
use to test its own bundles offline; this module's one deliberate departure
is that resolvers here are **async** (a wallet/DID lookup is network I/O), and
the deployment supplies real resolvers rather than test mocks.

Fail-closed: a resolver that cannot produce a required value raises
``FetchError``; the caller treats an un-assembled input as a denial rather than
guessing.

Source-kind → field, for the family-spend example:

- ``call``   — the LLM supplied it on the tool call (action content, signed VCs)
- ``config`` — a deployment constant (trust root)
- ``clock``  — the current time
- ``wallet`` — an attestation the proxy fetches by subject DID (membership)
- ``derive`` — a field computed from earlier ones by one primitive (a hash, a
  signature check folded over candidate keys), for a policy language that
  cannot evaluate the primitive itself

``derive`` is the one kind that computes rather than fetches, and the shape it
is allowed to take is a security property: a verification primitive may only be
*folded* over candidates and *project* a witness, never applied bare to return a
verdict, because a verdict no longer carries the relation the rule has to keep.
:class:`DeriveResolver` and :func:`validate_derive_plan` say why at length.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

from .wasm_policy import (
    HostBuiltinError,
    _b64url_bytes,
    _b64url_encode_no_pad,
    _key_from_did_key,
    _sha256,
    _verify_ed25519_raw,
    _verify_eddsa,
    make_verify_webauthn,
)

logger = logging.getLogger("extensible_mcp.fetchplan")

# An async lookup of an attestation (e.g. a membership VC) by subject DID.
WalletLookup = Callable[[str], Awaitable[Any]]


class FetchError(Exception):
    """A required input field could not be resolved; the call fails closed."""


@dataclass
class FetchContext:
    """The deployment-supplied inputs the resolvers draw from.

    - ``envelope``: the call-sourced fields (``call``) — what the LLM provided
      on the tool call: the action, its arguments, and any signed VC bundles.
    - ``config``: deployment constants (``config``) — e.g. the trust root.
    - ``now``: current time in epoch seconds (``clock``).
    - ``wallet``: async lookup ``subject DID -> attestation`` (``wallet``). A
      deployment swaps in a DID-web / wallet client behind this one callable.
    """

    envelope: dict[str, Any] = field(default_factory=dict)
    config: dict[str, Any] = field(default_factory=dict)
    now: int = 0
    wallet: WalletLookup | None = None


class Resolver(Protocol):
    async def resolve(
        self,
        name: str,
        params: dict[str, Any],
        assembled: dict[str, Any],
        ctx: FetchContext,
    ) -> Any: ...


class CallResolver:
    """``call``: a field the LLM supplied on the tool call."""

    async def resolve(self, name, params, assembled, ctx):
        if name not in ctx.envelope:
            raise FetchError(f"tool call has no field {name!r}")
        return ctx.envelope[name]


class ConfigResolver:
    """``config``: a deployment constant."""

    async def resolve(self, name, params, assembled, ctx):
        if name not in ctx.config:
            raise FetchError(f"no deployment config for {name!r}")
        return ctx.config[name]


class ClockResolver:
    """``clock``: the current time."""

    async def resolve(self, name, params, assembled, ctx):
        return ctx.now


class WalletResolver:
    """``wallet``: an attestation fetched by subject DID.

    The subject comes from a ``$input`` parameter (e.g. ``requestVC.claims.iss``),
    already substituted from an earlier-assembled field. A missing attestation
    fails closed — it is fetched authoritatively, so "no credential for this
    subject" is a denial, not an empty default.
    """

    async def resolve(self, name, params, assembled, ctx):
        subject = params.get("subject")
        if subject is None:
            raise FetchError(f"wallet source for {name!r} has no subject")
        if ctx.wallet is None:
            raise FetchError(f"no wallet lookup configured for {name!r}")
        result = await ctx.wallet(subject)
        if result is None:
            raise FetchError(f"no credential for subject {subject!r}")
        return result


# --------------------------------------------------------------------------- #
# ``derive``: hoisting a primitive ahead of the policy without booleanizing it
# --------------------------------------------------------------------------- #

DERIVE_KIND = "derive"

# Primitives that take a **key** operand and answer a verification question.
#
# This classification is **proxy-owned**, deliberately. A bundle declares which
# primitive names it uses (see :func:`declared_primitives`) because the atom
# registry of a policy-authoring toolchain grows, and a list agreed in prose
# diverges from an emitter reading a registry at the first new primitive. The
# *class* must not travel the same way: the folded-only rule below works because
# the unsafe shape is unexpressible, and that survives only while the component
# that refuses to run the unsafe form is the one holding the classification. A
# bundle that declared ``verify_eddsa`` as key-free -- a generator bug is enough
# -- and then applied it bare would get a bare boolean back from a load that
# passed its own check.
KEY_CONSUMING_PRIMITIVES = frozenset(
    {"verify_eddsa", "verify_ed25519_raw", "verify_webauthn"}
)

# Primitives that *produce* a key rather than consuming one. ``key_from_did_key``
# turns a ``did:key`` identifier into the Ed25519 JWK it encodes, and is legal
# only inside ``$apply`` -- a derived key emitted as its own field floats free of
# the DID it came from, so the rule would check ``verify(jws, signerKey)`` and,
# separately, ``signerDid in trustedDids``, with nothing relating the two. A
# trusted DID presented alongside an attacker's key would pass.
KEY_PRODUCING_PRIMITIVES = frozenset({"key_from_did_key"})

_DERIVE_SOURCE_KEYS = frozenset({"kind", "fn", "args", "over", "project"})
_APPLY_KEYS = frozenset({"fn", "args"})
_ARG_MARKERS = frozenset({"$input", "$item", "$apply"})


class DeriveUndefined(FetchError):
    """A ``derive`` primitive answered ``None``: its operand was evidence it
    could not read (an unparseable invoice, a malformed base64url string), so
    the derived value is *undefined* -- the same word, and the same effect,
    as Rego's ``json.unmarshal`` on garbage. :meth:`FetchExecutor.assemble`
    omits the field rather than writing ``null``, and anything reading it is
    omitted in turn. Distinct from a :class:`FetchError` raised by a
    primitive, which is a system fault and fails the assembly closed."""


class DerivePlanError(ValueError):
    """A ``derive`` entry the proxy refuses to run, raised at bundle load.

    Load time, not evaluation time: these are shapes whose *existence* is the
    fault (a bare signature check, a hoisted key, an unsatisfiable primitive),
    and a bundle that carries one must never reach a call.
    """


def _parse_json(value: Any) -> Any:
    """``parse_json(string) -> object``, the derive twin of Rego's
    ``json.unmarshal`` / the CEL engine's ``parse_json``.

    A non-string operand is a plan fault (``HostBuiltinError``, fail closed).
    Unparseable *content* is not: the string is LLM-relayed evidence (a
    merchant's canonical invoice), so it yields ``None``, which the resolver
    turns into :class:`DeriveUndefined` -- the field is omitted, the rule
    denies on the relation it could not satisfy, with its authored sentence,
    and tiers that never read the field are untouched. That is the verdict
    OPA's ``json.unmarshal`` gives the Rego twin, reproduced rather than
    inherited: this is a Python reimplementation of an OPA native, not the
    engine's own code (see :func:`default_primitives`).
    """
    if not isinstance(value, str):
        raise HostBuiltinError(
            f"parse_json expects a string, got {type(value).__name__}"
        )
    try:
        return json.loads(value)
    except ValueError:
        logger.debug("fetchplan: parse_json could not parse its operand")
        return None


def _base64url_decode(value: Any) -> str | None:
    """``base64url_decode(string) -> string``, the derive twin of Rego's
    ``base64url.decode``. Malformed content is evidence, so ``None`` and the
    field is undefined (see :func:`_parse_json`); a non-string operand is a
    plan fault. A reimplementation of an OPA native, as the other is."""
    if not isinstance(value, str):
        raise HostBuiltinError(
            f"base64url_decode expects a string, got {type(value).__name__}"
        )
    try:
        return _b64url_bytes(value).decode()
    except (ValueError, UnicodeDecodeError):
        logger.debug("fetchplan: base64url_decode could not decode its operand")
        return None


def default_primitives(
    *, webauthn_rp_id: str | None = None
) -> dict[str, Callable[..., Any]]:
    """The primitive vocabulary a ``derive`` entry may name.

    **Five of the seven are the same implementations the two policy engines
    run as host built-ins** (:func:`~extensible_mcp.wasm_policy.default_builtins`,
    :func:`~extensible_mcp.cel_policy.default_cel_functions`) under the
    toolchain's atom names -- ``sha256``, ``verify_eddsa``,
    ``verify_ed25519_raw``, ``key_from_did_key``, ``base64url_encode_no_pad``,
    plus ``verify_webauthn`` when configured: one Ed25519 path, one WebAuthn
    path, one ``did:key`` decoder, whether the check runs inside the policy or
    ahead of it. For those the contract carries over by construction:
    ``False`` for an evidence problem, ``HostBuiltinError`` for a system fault.

    **The other two are not.** ``parse_json`` and ``base64url_decode`` are
    Python reimplementations of OPA natives (``json.unmarshal``,
    ``base64url.decode``) that a Rego bundle compiles into its wasm and never
    asks the host for. Their agreement with the engine is established by
    test, not inherited, and what is matched deliberately is the *undefined*
    domain: OPA leaves both undefined on content they cannot read, so here
    they answer ``None`` and the resolver omits the derived field
    (:class:`DeriveUndefined`) instead of writing ``null``.

    The CEL engine's twins of those two are different again, for a reason
    worth knowing at the seam: they return a CEL *error value*
    (:func:`~extensible_mcp.cel_policy.undefined_evidence`) rather than
    ``None``, because cel-python threads an error value through the
    expression the way Rego threads undefined through a rule body, and a
    ``None`` would not. So the three spellings of one fact -- undefined,
    error value, omitted field -- are each what the consuming evaluator can
    act on, and each denies through the relation that read it.

    ``verify_webauthn`` is registered only when a relying-party id is
    configured, so a bundle declaring it without one fails at load rather than
    denying quietly at the first call.
    """
    primitives: dict[str, Callable[..., Any]] = {
        "sha256": _sha256,
        "parse_json": _parse_json,
        "base64url_decode": _base64url_decode,
        "base64url_encode_no_pad": _b64url_encode_no_pad,
        "verify_eddsa": _verify_eddsa,
        "verify_ed25519_raw": _verify_ed25519_raw,
        "key_from_did_key": _key_from_did_key,
    }
    if webauthn_rp_id is not None:
        primitives["verify_webauthn"] = make_verify_webauthn(webauthn_rp_id)
    return primitives


class DeriveResolver:
    """``derive``: a field computed by applying one primitive to resolved
    arguments, so a policy language that cannot evaluate a signature check
    still decides on the *relation* rather than on someone else's verdict.

    Two forms, and the difference between them is the whole point:

    - **bare** -- one primitive applied to its arguments, the result stored::

        {"field": "requestVcDigest",
         "source": {"kind": "derive", "fn": "sha256",
                    "args": [{"$input": "requestVcJws"}]}}

    - **folded** -- the primitive applied once per candidate, and the
      ``project``-ed field of every candidate it returned ``true`` for
      collected into a set::

        {"field": "invoiceSignerIds",
         "source": {"kind": "derive", "fn": "verify_ed25519_raw",
                    "over": {"$input": "trustedMerchants"},
                    "args": [{"$input": "invoiceCanonical"},
                             {"$input": "invoiceSignature"},
                             {"$item": "key"}],
                    "project": "merchantId"}}

      The rule then keeps the relation -- *the merchant the invoice claims is
      the merchant whose key signed it* -- which a booleanized
      ``invoiceSignatureOK: true`` has consumed both terms of, and under which
      an invoice signed by ``m1`` claiming ``m2`` is allowed.

      ``over`` is a ``$input`` reference to an assembled list, or a literal
      list whose elements may themselves carry ``$input`` references. The
      second is the single-key verification -- one credential, one issuer,
      one key, and so no candidate *list* anywhere to reference::

        "over": [{"key": {"$input": "requesterMembership.adminKey"}}]

      A one-element fold is not a boolean in disguise: it keeps *which* key
      as a term the rule names, so a host that supplied a different key from
      the one the rule checks against fails the relation.

    An argument may itself be ``{"$apply": {"fn": ..., "args": [...]}}``: one
    inner primitive, nested one level, so a key-producing primitive is hoisted
    *as a unit* with the verification that consumes its output and the witness
    is the DID whose derived key verified, never the key.

    Filter-and-project is the only combinator, deliberately: a deployment-
    registered composite would move the quantifier's decision procedure into
    deployment code.

    **A verification that does not match is not an error.** It yields an empty
    set and raises nothing: a ``FetchError`` here would surface as "Policy
    input could not be assembled", conflating a forged credential with an
    unreachable wallet and losing the guidance channel for exactly the checks
    that most need explaining. The rule denies, with its authored sentence.
    """

    def __init__(self, primitives: dict[str, Callable[..., Any]] | None = None) -> None:
        self.primitives = dict(
            default_primitives() if primitives is None else primitives
        )

    async def resolve(self, name, params, assembled, ctx):
        fn_name = params["fn"]
        fn = self._primitive(name, fn_name)
        if params["folded"]:
            return self._fold(name, fn_name, fn, params)
        # Belt and braces: the bundle carrying this plan was refused at load
        # (see validate_derive_plan), so a bare key-consuming primitive here
        # means the plan did not come through PolicyBundle.load at all.
        if fn_name in KEY_CONSUMING_PRIMITIVES or fn_name in KEY_PRODUCING_PRIMITIVES:
            raise FetchError(
                f"derive field {name!r}: {fn_name!r} may not be applied bare"
            )
        value = self._call(name, fn_name, fn, [self._arg(name, a, None) for a in params["args"]])
        if value is None:
            raise DeriveUndefined(
                f"derive field {name!r}: {fn_name!r} could not read its operand"
            )
        return value

    # -- the two forms ------------------------------------------------------ #

    def _fold(self, name, fn_name, fn, params):
        candidates = params["over"]
        if not isinstance(candidates, list):
            raise FetchError(
                f"derive field {name!r}: 'over' resolved to "
                f"{type(candidates).__name__}, not a list of candidates"
            )
        witnesses = []
        for item in candidates:
            try:
                args = [self._arg(name, a, item) for a in params["args"]]
            except DeriveUndefined:
                # An undefined argument for *this* candidate: it is no
                # witness, and the fold goes on. The rule then checks
                # membership in what was collected, so a fold that collects
                # nothing denies -- undefined fails closed through the
                # relation, as it does inside a Rego comprehension.
                continue
            if self._call(name, fn_name, fn, args) is True:
                witnesses.append(self._project(name, item, params["project"]))
        return witnesses

    def _arg(self, name, spec, item):
        """One resolved argument: a value, the current element's field, or the
        result of the nested ``$apply`` primitive."""
        if "$value" in spec:
            return spec["$value"]
        if "$item" in spec:
            if item is None:
                raise FetchError(
                    f"derive field {name!r}: '$item' outside a folded entry"
                )
            return self._project(name, item, spec["$item"])
        inner = spec["$apply"]
        fn_name = inner["fn"]
        fn = self._primitive(name, fn_name)
        if fn_name in KEY_CONSUMING_PRIMITIVES:
            raise FetchError(
                f"derive field {name!r}: {fn_name!r} consumes a key and may not "
                "be nested inside '$apply'"
            )
        value = self._call(
            name, fn_name, fn, [self._arg(name, a, item) for a in inner["args"]]
        )
        if value is None:
            # Undefined does not travel into another primitive as ``None``
            # (which the outer one would refuse as a type fault); the
            # application it feeds is undefined too.
            raise DeriveUndefined(
                f"derive field {name!r}: '$apply' {fn_name!r} could not read its operand"
            )
        return value

    # -- helpers ------------------------------------------------------------ #

    def _primitive(self, name, fn_name):
        fn = self.primitives.get(fn_name)
        if fn is None:
            raise FetchError(
                f"derive field {name!r} names primitive {fn_name!r}, which has "
                "no registered implementation"
            )
        return fn

    def _call(self, name, fn_name, fn, args):
        """Invoke a primitive. ``False`` is a verification's verdict and
        travels onward; ``None`` is a parse that could not read its evidence
        and becomes :class:`DeriveUndefined` at the call site (a bare entry
        is omitted, a ``$apply`` makes its consumer undefined, a fold skips
        the candidate); anything *raised* is a system fault and fails
        closed."""
        try:
            return fn(*args)
        except Exception as e:  # noqa: BLE001 - HostBuiltinError and friends
            raise FetchError(
                f"derive field {name!r}: primitive {fn_name!r} could not be "
                f"evaluated: {e}"
            ) from e

    @staticmethod
    def _project(name, container, path):
        """A field of the current element -- the witness a folded entry emits,
        and what ``{"$item": "key"}`` reads. An empty path is the element
        itself. A candidate missing the field is a malformed candidate list
        (config- or wallet-sourced, never LLM-supplied), so fail closed."""
        if not path:
            return container
        cur = container
        for step in path.split("."):
            if not isinstance(cur, dict) or step not in cur:
                raise FetchError(
                    f"derive field {name!r}: candidate has no field {path!r}"
                )
            cur = cur[step]
        return cur


# --------------------------------------------------------------------------- #
# Load-time validation of ``derive`` entries
# --------------------------------------------------------------------------- #


def declared_primitives(plan: dict[str, Any]) -> dict[str, str | None]:
    """The primitive vocabulary the plan declares, as ``name -> declared class``
    (``None`` when the declaration is a bare name).

    ``fetchplan.json`` carries it as a top-level ``primitives``, either as a
    list of names or as an object whose values may record the toolchain's own
    idea of each primitive's class::

        "primitives": {"sha256": {"class": "pure"},
                       "verify_ed25519_raw": {"class": "key-consuming"}}

    The declared class is **advisory**: the proxy enforces its own
    (:data:`KEY_CONSUMING_PRIMITIVES`) and only logs a disagreement. A plan
    with no ``primitives`` block declares nothing, which is why every existing
    bundle keeps loading -- and why a plan using ``derive`` without one is
    refused.
    """
    block = plan.get("primitives")
    if block is None:
        return {}
    if isinstance(block, list):
        if not all(isinstance(n, str) for n in block):
            raise DerivePlanError("fetch plan 'primitives' list holds a non-name")
        return {n: None for n in block}
    if isinstance(block, dict):
        declared: dict[str, str | None] = {}
        for prim, decl in block.items():
            if not isinstance(prim, str):
                raise DerivePlanError("fetch plan 'primitives' holds a non-name key")
            if isinstance(decl, dict):
                cls = decl.get("class")
                declared[prim] = cls if isinstance(cls, str) else None
            elif isinstance(decl, str):
                declared[prim] = decl
            else:
                declared[prim] = None
        return declared
    raise DerivePlanError(
        f"fetch plan 'primitives' must be a list or an object, got "
        f"{type(block).__name__}"
    )


def _validate_unique_fields(plan: dict[str, Any]) -> None:
    """Refuse a plan in which two entries name the same ``field``, naming the
    field and both source kinds. Kind-agnostic on purpose: a ``call``/``call``
    pair collapses in ``assemble`` exactly as a ``derive``/``derive`` pair
    does; ``derive`` merely makes the collision easy to generate, because its
    field names are computed rather than written."""
    seen: dict[str, str] = {}
    for entry in plan.get("entries") or []:
        field = entry.get("field")
        kind = (entry.get("source") or {}).get("kind")
        if not isinstance(field, str):
            continue
        if field in seen:
            raise DerivePlanError(
                f"fetch plan names field {field!r} twice (a {seen[field]!r} "
                f"entry and a {kind!r} entry); the later one would silently "
                f"overwrite the earlier in the assembled input"
            )
        seen[field] = str(kind)


def validate_derive_plan(
    plan: dict[str, Any], *, primitives: dict[str, Callable[..., Any]] | None = None
) -> None:
    """Refuse, at load, a fetch plan the proxy must not assemble from. Raises
    :class:`DerivePlanError`. The first check is kind-agnostic; the rest
    concern ``derive`` entries, and a plan with none passes them whatever
    vocabulary it declares.

    What is refused, and why each is a load-time question rather than an
    evaluation-time one:

    - two entries that name the same ``field``, of any source kinds.
      :meth:`FetchExecutor.assemble` walks entries in order into one map, so
      the last writer wins and the rule reads a value computed for different
      arguments -- the plan validates, the manifest accepts one property, the
      policy evaluates cleanly, and the verdict answers a question nobody
      asked. The toolchain shipped exactly this (six folds over one shared
      candidate domain all named ``trustRootJwkKeyWitnesses``, so five
      leaves checked the wrong credential's signature) and fixed its
      generator; this is the independent guard on the consuming side;
    - a primitive a ``derive`` entry **invokes** that the proxy cannot
      satisfy, or one it invokes without declaring -- the same discipline as
      an unregistered host built-in, which fails when the policy is loaded and
      not at the first call that needs it;
    - a **key-consuming** primitive applied bare, whatever the bundle declares
      about its class: there is no bare-boolean form of verification in this
      format at all, so a single-trust-root deployment writes a one-element
      candidate list and the rule checks membership;
    - a **key-producing** primitive as a top-level ``fn``: a hoisted key is
      unbound from the identifier it came from;
    - ``$apply`` nested more than one level, rejected rather than supported
      speculatively;
    - ``$apply`` or ``$item`` inside a literal ``over`` element. ``$item``
      names the element being defined; ``$apply`` would be invoked per
      candidate on a path :func:`_referenced_primitives` does not walk, so a
      primitive with no implementation would pass validation and fail on the
      first real call -- the load-time-versus-call-time class this check
      exists to remove. Apply the primitive in ``args`` instead.

    What is **not** refused: a declared primitive no ``derive`` entry
    references. The ``primitives`` block is a declaration of the plan's
    vocabulary, not a request for the derive registry -- a bundle whose policy
    calls ``verify_webauthn`` as a host built-in declares it while deriving
    nothing, and the two engines share one ``fetchplan.json``, so the block can
    only carry the union of what the policy reaches. Requiring every declared
    name of the *derive* registry refused such a bundle from a deployment that
    had configured the engine correctly. The engine asks the other question and
    asks it first: :meth:`OpaWasmPolicy._verify_builtins_available` fails closed
    on a built-in the policy actually calls, parsed out of the wasm, before this
    runs. So an unimplemented declaration is logged, not raised.
    """
    _validate_unique_fields(plan)
    declared = declared_primitives(plan)
    available = default_primitives() if primitives is None else primitives
    for prim in sorted(declared):
        claimed = declared[prim]
        if claimed is not None:
            proxy_class = (
                "key-consuming"
                if prim in KEY_CONSUMING_PRIMITIVES
                else "key-producing"
                if prim in KEY_PRODUCING_PRIMITIVES
                else "pure"
            )
            if claimed != proxy_class:
                # Advisory only: the proxy's own classification is what the
                # entry checks below are decided on.
                logger.warning(
                    "fetchplan: bundle declares primitive %r as %r; the proxy "
                    "classifies it as %r and enforces that",
                    prim, claimed, proxy_class,
                )
    for entry in plan.get("entries") or []:
        source = entry.get("source") or {}
        if source.get("kind") == DERIVE_KIND:
            _validate_derive_entry(entry.get("field"), source, declared)
    referenced = _referenced_primitives(plan)
    for prim in sorted(referenced):
        if prim not in available:
            raise DerivePlanError(
                f"fetch plan derives with primitive {prim!r}, which the proxy "
                f"has no implementation for; have {sorted(available)}"
            )
    for prim in sorted(set(declared) - referenced):
        if prim not in available:
            logger.warning(
                "fetchplan: bundle declares primitive %r, which the proxy has "
                "no derive implementation for; no 'derive' entry invokes it, so "
                "the declaration states the plan's vocabulary and the load "
                "stands. A deployment that means to derive with it is missing "
                "configuration (e.g. a WebAuthn relying-party id); a policy "
                "that calls it as a host built-in is refused by the engine's "
                "own check, which runs first",
                prim,
            )


def _referenced_primitives(plan: dict[str, Any]) -> set[str]:
    """The primitives a ``derive`` entry actually invokes: a top-level ``fn``
    or an ``$apply.fn``.

    Tolerant of shapes :func:`_validate_derive_entry` has already refused (a
    non-string ``fn``, a malformed ``$apply``) -- it reads names, it does not
    judge them.
    """
    referenced: set[str] = set()
    for entry in plan.get("entries") or []:
        source = entry.get("source") or {}
        if not isinstance(source, dict) or source.get("kind") != DERIVE_KIND:
            continue
        fn = source.get("fn")
        if isinstance(fn, str) and fn:
            referenced.add(fn)
        referenced |= _applied_primitives(source.get("args"))
    return referenced


def _applied_primitives(args: Any) -> set[str]:
    """The ``$apply.fn`` names among an argument list, at any nesting."""
    referenced: set[str] = set()
    if not isinstance(args, list):
        return referenced
    for arg in args:
        if not isinstance(arg, dict):
            continue
        inner = arg.get("$apply")
        if not isinstance(inner, dict):
            continue
        fn = inner.get("fn")
        if isinstance(fn, str) and fn:
            referenced.add(fn)
        referenced |= _applied_primitives(inner.get("args"))
    return referenced


def _validate_derive_entry(
    field: Any, source: dict[str, Any], declared: dict[str, str | None]
) -> None:
    where = f"derive entry {field!r}"
    unknown = set(source) - _DERIVE_SOURCE_KEYS
    if unknown:
        raise DerivePlanError(f"{where}: unknown source key(s) {sorted(unknown)}")
    fn = source.get("fn")
    if not isinstance(fn, str) or not fn:
        raise DerivePlanError(f"{where}: 'fn' must name a primitive")
    _require_declared(where, fn, declared)
    args = source.get("args", [])
    if not isinstance(args, list):
        raise DerivePlanError(f"{where}: 'args' must be a list")
    folded = "over" in source

    if fn in KEY_PRODUCING_PRIMITIVES:
        raise DerivePlanError(
            f"{where}: {fn!r} produces a key and may appear only inside "
            "'$apply' -- a derived key emitted as its own field is unbound "
            "from the identifier it came from"
        )
    if fn in KEY_CONSUMING_PRIMITIVES and not folded:
        raise DerivePlanError(
            f"{where}: {fn!r} consumes a key and may appear only in a folded "
            "entry ('over' + 'project'); the format has no bare-boolean form "
            "of verification, because a verdict no longer carries the relation"
        )
    if folded:
        project = source.get("project")
        if not isinstance(project, str) or not project:
            raise DerivePlanError(
                f"{where}: a folded entry must 'project' a witness field from "
                "each candidate"
            )
        over = source["over"]
        if not (isinstance(over, dict) and set(over) == {"$input"}) and not isinstance(
            over, list
        ):
            raise DerivePlanError(
                f"{where}: 'over' must be a '$input' reference or a literal list"
            )
        if isinstance(over, list):
            for candidate in over:
                _validate_candidate(where, candidate)
    elif "project" in source:
        raise DerivePlanError(f"{where}: 'project' without 'over'")

    for arg in args:
        _validate_derive_arg(where, arg, declared, folded=folded, nested=False)


def _validate_candidate(where: str, node: Any) -> None:
    """A literal ``over`` element may carry ``$input`` leaves, at any depth,
    and no other marker. Walks objects and lists so the shape the resolver
    will resolve is the shape that was checked."""
    if isinstance(node, dict):
        markers = [k for k in node if isinstance(k, str) and k.startswith("$")]
        if markers:
            if len(node) > 1:
                raise DerivePlanError(
                    f"{where}: an 'over' element carries more than one key: "
                    f"{sorted(node)}"
                )
            marker = markers[0]
            if marker == "$input":
                if not isinstance(node[marker], str) or not node[marker]:
                    raise DerivePlanError(f"{where}: '$input' must be a field path")
                return
            if marker == "$apply":
                raise DerivePlanError(
                    f"{where}: '$apply' has no meaning inside an 'over' element; "
                    "apply the primitive in 'args'"
                )
            if marker == "$item":
                raise DerivePlanError(
                    f"{where}: '$item' has no meaning inside an 'over' element "
                    "-- it names the element being defined"
                )
            raise DerivePlanError(f"{where}: unknown argument marker {marker!r}")
        for value in node.values():
            _validate_candidate(where, value)
    elif isinstance(node, list):
        for value in node:
            _validate_candidate(where, value)


def _validate_derive_arg(
    where: str,
    arg: Any,
    declared: dict[str, str | None],
    *,
    folded: bool,
    nested: bool,
) -> None:
    if not isinstance(arg, dict):
        return  # a literal
    markers = [k for k in arg if isinstance(k, str) and k.startswith("$")]
    if not markers:
        return  # a literal object
    if len(arg) > 1:
        raise DerivePlanError(
            f"{where}: an argument carries more than one key: {sorted(arg)}"
        )
    marker = markers[0]
    if marker not in _ARG_MARKERS:
        raise DerivePlanError(f"{where}: unknown argument marker {marker!r}")
    if marker == "$input":
        if not isinstance(arg[marker], str) or not arg[marker]:
            raise DerivePlanError(f"{where}: '$input' must be a field path")
        return
    if marker == "$item":
        if not folded:
            raise DerivePlanError(
                f"{where}: '$item' has no meaning outside a folded entry"
            )
        if not isinstance(arg[marker], str):
            raise DerivePlanError(f"{where}: '$item' must be a field path")
        return
    # $apply
    if nested:
        raise DerivePlanError(
            f"{where}: '$apply' nests one level only"
        )
    inner = arg[marker]
    if not isinstance(inner, dict):
        raise DerivePlanError(f"{where}: '$apply' must be an object")
    unknown = set(inner) - _APPLY_KEYS
    if unknown:
        raise DerivePlanError(f"{where}: unknown '$apply' key(s) {sorted(unknown)}")
    inner_fn = inner.get("fn")
    if not isinstance(inner_fn, str) or not inner_fn:
        raise DerivePlanError(f"{where}: '$apply' must name a primitive")
    _require_declared(where, inner_fn, declared)
    if inner_fn in KEY_CONSUMING_PRIMITIVES:
        raise DerivePlanError(
            f"{where}: {inner_fn!r} consumes a key; nesting it inside '$apply' "
            "booleanizes the check it is supposed to keep"
        )
    inner_args = inner.get("args", [])
    if not isinstance(inner_args, list):
        raise DerivePlanError(f"{where}: '$apply' 'args' must be a list")
    for inner_arg in inner_args:
        _validate_derive_arg(where, inner_arg, declared, folded=folded, nested=True)


def _require_declared(
    where: str, fn: str, declared: dict[str, str | None]
) -> None:
    if fn not in declared:
        raise DerivePlanError(
            f"{where}: primitive {fn!r} is not declared in the fetch plan's "
            "'primitives' vocabulary"
        )


def default_resolvers(
    *, primitives: dict[str, Callable[..., Any]] | None = None
) -> dict[str, Resolver]:
    """The shipped resolvers. ``primitives`` overrides the ``derive`` vocabulary
    — e.g. ``default_primitives(webauthn_rp_id=...)`` for a deployment whose
    bundles derive passkey witnesses."""
    return {
        "call": CallResolver(),
        "config": ConfigResolver(),
        "clock": ClockResolver(),
        "wallet": WalletResolver(),
        DERIVE_KIND: DeriveResolver(primitives),
    }


class FetchExecutor:
    """Assemble the closed policy input by walking the fetch plan."""

    def __init__(self, resolvers: dict[str, Resolver] | None = None) -> None:
        self.resolvers = resolvers if resolvers is not None else default_resolvers()

    async def assemble(
        self, plan: dict[str, Any], ctx: FetchContext
    ) -> dict[str, Any]:
        """Process plan entries in order, dispatching by source kind and
        substituting ``$input`` params from already-assembled fields. Returns
        the closed input document.

        **Guard-aware.** A call field whose guard marks it not-``always``
        required (a conditional credential, e.g. an authorization VC needed only
        above a threshold) is *omitted* when absent, rather than failing closed —
        and any field whose ``$input`` params reference an omitted field is
        omitted too. The policy then sees those fields as undefined and denies
        the paths that need them, while paths that don't (the solo tier) still
        evaluate. An absent *required* field still fails closed.

        **Undefined-aware.** A ``derive`` entry whose primitive could not read
        its evidence (:class:`DeriveUndefined`) is omitted the same way, never
        written as ``null``: ``null`` is a *defined* value -- truthy as a bare
        Rego term, present to a Cedar ``has`` -- and would let a check pass
        that its Rego twin leaves undefined. Omission is what the three
        engines agree on, including on a tier the call does not reach, where
        garbage in an unneeded credential must not turn an allow into a
        denial.
        """
        assembled: dict[str, Any] = {}
        omitted: set[str] = set()
        for entry in plan["entries"]:
            name = entry["field"]
            source = entry["source"]
            kind = source["kind"]
            resolver = self.resolvers.get(kind)
            if resolver is None:
                raise FetchError(f"no resolver registered for source kind {kind!r}")

            guard = entry.get("guard")
            optional = guard is not None and not guard.get("always", True)

            # Params may navigate into an earlier field that was omitted (an
            # absent optional credential); then this field is not needed either.
            # A ``derive`` entry is guard-aware the same way, and for the same
            # reason: its arguments are ``$input`` references, so one pointing
            # at an omitted credential omits the derived field too.
            try:
                if kind == DERIVE_KIND:
                    params = self._resolve_derive_source(name, source, assembled)
                else:
                    params = self._resolve_params(source.get("params", {}), assembled)
            except FetchError:
                logger.debug("fetchplan: omitting %r (depends on an omitted field)", name)
                omitted.add(name)
                continue

            try:
                assembled[name] = await resolver.resolve(name, params, assembled, ctx)
            except DeriveUndefined as e:
                logger.debug("fetchplan: omitting %r (undefined: %s)", name, e)
                omitted.add(name)
                continue
            except FetchError:
                if optional:
                    logger.debug("fetchplan: omitting absent optional field %r", name)
                    omitted.add(name)
                    continue
                raise
        return assembled

    def _resolve_params(
        self, params: dict[str, Any], assembled: dict[str, Any]
    ) -> dict[str, Any]:
        resolved: dict[str, Any] = {}
        for key, val in params.items():
            if isinstance(val, dict) and "$input" in val:
                resolved[key] = self._navigate(assembled, val["$input"])
            else:
                resolved[key] = val
        return resolved

    def _resolve_derive_source(
        self, name: str, source: dict[str, Any], assembled: dict[str, Any]
    ) -> dict[str, Any]:
        """Resolve a ``derive`` source's ``$input`` references against the
        fields assembled so far, leaving ``$item`` and ``$apply`` for the
        resolver to evaluate per candidate.

        Done here, in the param phase, so an argument reading an omitted
        optional credential raises :class:`FetchError` and the derived field is
        omitted rather than failing the whole assembly. A literal ``over``
        list is walked the same way, for the same reason.
        """
        spec: dict[str, Any] = {
            "fn": source.get("fn"),
            "args": [self._resolve_arg(a, assembled) for a in source.get("args", [])],
            "folded": "over" in source,
            "project": source.get("project"),
        }
        if spec["folded"]:
            over = source["over"]
            if isinstance(over, list):
                # A literal candidate list. ``$input`` inside an element means
                # what it means one key over in ``args``, so it resolves here
                # and ``$item`` projects the resolved value -- the resolver
                # must never see a marker where it expects a key.
                spec["over"] = [self._resolve_candidate(c, assembled) for c in over]
            else:
                resolved = self._resolve_arg(over, assembled)
                if "$value" not in resolved:
                    raise FetchError(
                        f"derive field {name!r}: 'over' must be a '$input' "
                        "reference or a literal list"
                    )
                spec["over"] = resolved["$value"]
        return spec

    def _resolve_candidate(self, node: Any, assembled: dict[str, Any]) -> Any:
        """One literal ``over`` element with its ``$input`` leaves resolved,
        at any depth. ``$apply`` and ``$item`` are refused at load, so a marked
        object here is an ``$input`` reference."""
        if isinstance(node, dict):
            if "$input" in node:
                return self._navigate(assembled, node["$input"])
            return {k: self._resolve_candidate(v, assembled) for k, v in node.items()}
        if isinstance(node, list):
            return [self._resolve_candidate(v, assembled) for v in node]
        return node

    def _resolve_arg(self, arg: Any, assembled: dict[str, Any]) -> dict[str, Any]:
        if isinstance(arg, dict):
            if "$input" in arg:
                return {"$value": self._navigate(assembled, arg["$input"])}
            if "$item" in arg:
                return {"$item": arg["$item"]}
            if "$apply" in arg:
                inner = arg["$apply"]
                return {
                    "$apply": {
                        "fn": inner.get("fn"),
                        "args": [
                            self._resolve_arg(a, assembled)
                            for a in inner.get("args", [])
                        ],
                    }
                }
        return {"$value": arg}

    @staticmethod
    def _navigate(doc: Any, path: str) -> Any:
        cur = doc
        for step in path.split("."):
            if not isinstance(cur, dict) or step not in cur:
                raise FetchError(f"fetch param path {path!r} not yet assembled")
            cur = cur[step]
        return cur

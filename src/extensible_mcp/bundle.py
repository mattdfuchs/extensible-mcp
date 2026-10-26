# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""A policy bundle: the set of artifacts, supplied by an external
policy-authoring toolchain, that govern one tool.

A bundle is a directory the proxy consumes verbatim:

- the enforced rules — ``policy.wasm`` (OPA/Rego, loaded into an
  :class:`~extensible_mcp.wasm_policy.OpaWasmPolicy`), ``checks.cel.json``
  (CEL, loaded into a :class:`~extensible_mcp.cel_policy.CelPolicy`) *or*
  ``policy.cedar`` with its ``expected_ids.json`` (Cedar, loaded into a
  :class:`~extensible_mcp.cedar_policy.CedarPolicy`) — the bundle format is
  engine-plural: see :mod:`extensible_mcp.policy_engine`. A conforming
  toolchain may target any of them.
- ``manifest.json``  — JSON Schema of the closed input (type defs + validation)
- ``fetchplan.json`` — where each input field comes from (``call`` / ``config``
  / ``clock`` / ``wallet`` / ``derive``)
- ``guidance.json``  — the human/LLM-facing layer (optional; a bundle that
  doesn't ship it renders from sentences written in the policy file —
  CEL ``{"expr", "sentence"}``, Cedar ``@sentence``, Rego ``deny_reason`` —
  or, failing those, with a plain denial message)

This module is the runtime view of a bundle. The ``allow`` / ``deny_reason``
entrypoints and the call-field partition are derived from the artifacts, so the
filter never hard-codes a policy's shape — any toolchain that emits a
conforming directory works, with no proxy-side changes.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from .fetchplan import validate_derive_plan
from .policy_engine import PolicyEngine, inline_guidance
from .wasm_policy import OpaWasmPolicy

# Reserved call-field names that are not LLM-supplied *credentials*: the action
# identifier and the tool's own native arguments. Every other ``call`` field is
# a credential the augmenter surfaces for the LLM to supply.
_TOOL_FIELD = "tool"
_ARGUMENTS_FIELD = "arguments"


@dataclass
class PolicyBundle:
    """One loaded policy bundle, ready to assemble-and-evaluate against.

    ``policy`` is a :class:`~extensible_mcp.policy_engine.PolicyEngine` — the
    bundle format is engine-plural: :func:`load` picks the implementation by
    what the directory contains (``policy.wasm`` → OPA/Rego,
    ``checks.cel.json`` → CEL, ``policy.cedar`` → Cedar) unless its
    ``engine`` argument forces one, and nothing past this field knows which
    one it holds."""

    name: str
    package: str
    policy: PolicyEngine
    manifest: dict[str, Any]
    fetchplan: dict[str, Any]
    guidance: dict[str, Any] | None = None

    @classmethod
    def load(
        cls,
        directory: str | Path,
        *,
        name: str | None = None,
        builtins: dict[str, Any] | None = None,
        engine: Literal["rego", "cel", "cedar"] | None = None,
        primitives: dict[str, Any] | None = None,
    ) -> "PolicyBundle":
        """Load a bundle directory. ``builtins`` overrides the default host
        built-ins — e.g. ``default_builtins(webauthn_rp_id=...)`` for a policy
        that verifies passkey assertions; a policy needing an unregistered
        built-in fails here at load, not at evaluation. Ignored for a CEL
        bundle (pass CEL functions via :func:`~extensible_mcp.cel_policy.CelPolicy`
        directly if a deployment needs a non-default set).

        ``engine`` forces which :class:`~extensible_mcp.policy_engine.PolicyEngine`
        implementation to load, overriding the default of picking by which
        artifact is present (``checks.cel.json``, then ``policy.cedar``, then
        ``policy.wasm``). Raises :class:`FileNotFoundError` if the forced
        engine's artifact is missing — a directory carrying more than one
        artifact (e.g. a shadow-comparison fixture) needs this to load a
        non-default one; it is never inferred silently. A Cedar bundle is
        also refused here, as :class:`~extensible_mcp.cedar_policy.CedarPolicyError`,
        when its policy set does not carry exactly the forbids its
        ``expected_ids.json`` lists: forbid-only means an incomplete set
        allows what the source policy denies.

        ``primitives`` overrides the vocabulary a ``derive`` fetch-plan entry
        may name — ``default_primitives(webauthn_rp_id=...)`` for a deployment
        whose plans fold a passkey check over enrolled keys. The fetch plan's
        ``derive`` entries are validated here, at load: a bare key-consuming
        primitive, a hoisted key, or an ``fn`` this proxy cannot satisfy raises
        :class:`~extensible_mcp.fetchplan.DerivePlanError` before the bundle
        can govern a call — the discipline an unregistered host built-in
        already gets, for the same reason. The proxy owns which primitives
        consume a key, whatever the bundle declares about them."""
        d = Path(directory)
        cel_path = d / "checks.cel.json"
        cedar_path = d / "policy.cedar"
        wasm_path = d / "policy.wasm"
        artifacts = {"cel": cel_path, "cedar": cedar_path, "rego": wasm_path}
        if engine is not None and not artifacts[engine].exists():
            raise FileNotFoundError(
                f"engine={engine!r} requested but {artifacts[engine]} does not exist"
            )
        if engine is None:
            engine = (
                "cel" if cel_path.exists()
                else "cedar" if cedar_path.exists()
                else "rego"
            )
        if engine == "cel":
            from .cel_policy import CelPolicy

            policy: PolicyEngine = CelPolicy(cel_path)
            package = json.loads(cel_path.read_text())["package"]
        elif engine == "cedar":
            from .cedar_policy import CedarPolicy

            # Cedar has no package construct and the bundle declares none; the
            # directory name labels the entrypoints, which is all a package
            # does for a bundle whose denials render through guidance.
            policy = CedarPolicy(cedar_path, package=d.name)
            package = d.name
        else:
            policy = OpaWasmPolicy(wasm_path, builtins=builtins)
            package = _derive_package(policy)
        manifest = json.loads((d / "manifest.json").read_text())
        fetchplan = json.loads((d / "fetchplan.json").read_text())
        if engine == "cedar":
            from .cedar_policy import refuse_reserved_plan_fields

            refuse_reserved_plan_fields(fetchplan, d / "fetchplan.json")
        # A plan whose derived fields are shaped wrong is a bundle that must
        # never reach a call, so this is a load-time refusal, not a runtime one.
        validate_derive_plan(fetchplan, primitives=primitives)
        guidance_path = d / "guidance.json"
        guidance = (
            json.loads(guidance_path.read_text()) if guidance_path.exists() else None
        )
        if guidance is None:
            guidance = _synthesize_guidance(policy, fetchplan)
        return cls(
            name=name or d.name,
            package=package,
            policy=policy,
            manifest=manifest,
            fetchplan=fetchplan,
            guidance=guidance,
        )

    # -- entrypoints -------------------------------------------------------- #

    @property
    def allow_entrypoint(self) -> str:
        return f"{self.package}/allow"

    @property
    def deny_reason_entrypoint(self) -> str:
        return f"{self.package}/deny_reason"

    def has_deny_reason(self) -> bool:
        return self.deny_reason_entrypoint in self.policy.entrypoints()

    @property
    def failed_checks_entrypoint(self) -> str:
        return f"{self.package}/failed_checks"

    def has_failed_checks(self) -> bool:
        """Whether the policy emits runtime failed-check ids; some
        toolchains/older artifacts carry only the English ``deny_reason`` set."""
        return self.failed_checks_entrypoint in self.policy.entrypoints()

    # -- manifest validation -------------------------------------------------- #

    def validate_input(self, assembled: dict[str, Any]) -> list[str]:
        """Validate an assembled input against the manifest (JSON Schema).

        Returns ``"<path>: <message>"`` strings, empty when the input
        conforms. The manifest's root ``required`` is guard-aware,
        so an input legitimately missing a conditional credential validates;
        a present-but-malformed one does not, and ``additionalProperties:
        false`` rejects fields the policy does not read.

        Raises on a missing ``jsonschema`` dependency or a manifest that is
        not itself a valid schema — both deployment faults the caller treats
        as fail-closed, never as a policy decision.
        """
        validator = getattr(self, "_validator", None)
        if validator is None:
            try:
                import jsonschema
            except ImportError as e:  # pragma: no cover - exercised via env
                raise ImportError(
                    "Manifest validation requires 'jsonschema'. Install it "
                    "with: pip install 'extensible-mcp[wasm]'"
                ) from e
            cls = jsonschema.validators.validator_for(self.manifest)
            cls.check_schema(self.manifest)
            validator = self._validator = cls(self.manifest)
        return [
            f"{'/'.join(str(p) for p in err.absolute_path) or '<input>'}: {err.message}"
            for err in validator.iter_errors(assembled)
        ]

    # -- call-field partition ----------------------------------------------- #

    def call_fields(self) -> list[str]:
        """Input fields the LLM supplies on the call (``call`` source)."""
        return [
            e["field"]
            for e in self.fetchplan["entries"]
            if e["source"]["kind"] == _TOOL_FIELD_KIND
        ]

    def credential_fields(self) -> list[str]:
        """Call fields that are LLM-supplied credentials — every ``call`` field
        except the action identifier and the native arguments. These are the
        parameters the schema augmenter injects (e.g. ``requestVC``)."""
        return [
            f for f in self.call_fields() if f not in (_TOOL_FIELD, _ARGUMENTS_FIELD)
        ]

    # -- call credentials (derived issuer roles + dependency edges) ----------- #

    def call_credentials(self) -> list[dict[str, Any]]:
        """The guidance's per-credential records — ``{field, issuer_role,
        role_checks, depends_on}``. Empty for older or simpler guidance;
        roles/edges are fail-soft derivations, so absence means vaguer
        guidance, never a wrong assertion."""
        if not self.guidance:
            return []
        return list(self.guidance.get("call_credentials") or [])

    def issuer_role(self, field: str) -> str | None:
        """The role that signs a credential (``"kid"``/``"parent"``) — the
        policy's enforced tag, which is also the key a deployment's
        ``IssuerRegistry`` maps to a concrete wallet."""
        for c in self.call_credentials():
            if c.get("field") == field:
                return c.get("issuer_role")
        return None

    def credential_dependencies(self, field: str) -> list[str]:
        """The fields this credential signs over — obtain those first."""
        for c in self.call_credentials():
            if c.get("field") == field:
                return [
                    d["field"] for d in c.get("depends_on") or [] if d.get("field")
                ]
        return []

    def issuer_roles(self) -> set[str]:
        """Every issuer role the bundle names — the set a deployment checks
        against its ``IssuerRegistry`` at admission, so a governed tool never
        advertises a credential nobody can sign."""
        return {
            role for c in self.call_credentials() if (role := c.get("issuer_role"))
        }

    # -- call-field guards (when a credential is required) ------------------- #

    def field_guard(self, field: str) -> dict[str, Any] | None:
        """The guard on a call field — ``{always, required_in_tiers,
        deciding_checks, ...}`` — or ``None`` if the fetch plan carries none
        (older artifacts) or the field is not a call field."""
        for e in self.fetchplan["entries"]:
            if e["field"] == field:
                return e.get("guard")
        return None

    def is_always_required(self, field: str) -> bool:
        """Whether a credential is required on every path. Defaults to ``True``
        when no guard is present, so guard-less artifacts treat all credentials
        as mandatory (the conservative, pre-guard behaviour)."""
        guard = self.field_guard(field)
        return True if guard is None else bool(guard.get("always", True))

    def deciding_sentences(self, field: str) -> list[str]:
        """The authored sentences of the checks that decide a conditional
        credential's requirement (resolved from ``guidance.json`` by id).
        Empty when the field is unconditional or guidance is absent."""
        guard = self.field_guard(field)
        if not guard:
            return []
        sentences = []
        for check_id in guard.get("deciding_checks", []):
            sentence = self.check_sentence(check_id)
            if sentence:
                sentences.append(sentence)
        return sentences

    # -- guidance lookups --------------------------------------------------- #

    def check_sentence(self, check_id: str) -> str | None:
        """Look up a named check's authored sentence by id
        (``full_chain.arguments.amount_cents_above``)."""
        if not self.guidance:
            return None
        for tier in self.guidance.get("tiers", []):
            for check in tier.get("checks", []):
                if check.get("id") == check_id:
                    return check.get("sentence")
        return None

    def definition(self, name: str) -> dict[str, Any] | None:
        """A named type from the manifest's ``definitions`` block."""
        return self.manifest.get("definitions", {}).get(name)

    def field_schema(self, field: str) -> dict[str, Any] | None:
        """The JSON Schema a fetch-plan call entry declares for a field,
        with a top-level ``$ref`` into the manifest resolved one level."""
        for e in self.fetchplan["entries"]:
            if e["field"] == field:
                schema = e.get("schema")
                if isinstance(schema, dict) and "$ref" in schema:
                    ref = schema["$ref"].rsplit("/", 1)[-1]
                    return self.definition(ref) or schema
                return schema
        return None


_TOOL_FIELD_KIND = "call"

#: The guard keys a shipped ``guidance.json`` carries per call field; copied
#: from the fetch plan when guidance is synthesised, so the renderer can still
#: name an absent credential by tier.
_GUARD_KEYS = ("field", "always", "required_in_tiers", "deciding_checks")


def _synthesize_guidance(
    policy: PolicyEngine, fetchplan: dict[str, Any]
) -> dict[str, Any] | None:
    """Guidance for a bundle that ships none, from the sentences its policy
    file carries — the hand-author's form. The engine supplies the tiers and
    sentences (:func:`~extensible_mcp.policy_engine.inline_guidance`); the
    call guards come from the fetch plan's ``call`` entries, which is where a
    shipped guidance file's ``call_guards`` originate too. ``None`` when the
    engine offers nothing, and the denial falls back to the policy's own
    ``deny_reason`` strings or the bare message, as before."""
    inline = inline_guidance(policy)
    if not inline:
        return None
    guards = []
    for e in fetchplan.get("entries") or []:
        guard = e.get("guard")
        if e.get("source", {}).get("kind") == _TOOL_FIELD_KIND and isinstance(guard, dict):
            guards.append({"field": e["field"], **{k: guard[k] for k in _GUARD_KEYS[1:] if k in guard}})
    return {**inline, "call_guards": guards, "synthesized_from": "inline"}


def _derive_package(policy: OpaWasmPolicy) -> str:
    """Recover the policy package from the module's entrypoints.

    Entrypoints are full paths like ``policybundle/examples/family_spend/allow``;
    the package is that minus the trailing ``/allow``.
    """
    for ep in policy.entrypoints():
        if ep.endswith("/allow"):
            return ep[: -len("/allow")]
    raise ValueError(
        f"bundle policy exposes no '/allow' entrypoint; have {policy.entrypoints()}"
    )

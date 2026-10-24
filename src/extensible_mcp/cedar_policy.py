# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Cedar: the third :class:`~extensible_mcp.policy_engine.PolicyEngine` over
the same bundle format.

A Cedar bundle carries ``policy.cedar`` and ``expected_ids.json`` beside the
engine-independent ``manifest.json`` / ``fetchplan.json`` / ``guidance.json``.
Three facts about Cedar shape this module, and each one becomes a check the
loader or the query path performs rather than a convention a reviewer has to
remember:

1. **Cedar has no host-function extension point**, by design — a user-defined
   function would destroy the decidability that makes Cedar analysable. A
   cryptographic leaf therefore cannot run *inside* the policy the way the
   Rego and CEL engines run it as a host builtin. The fetch plan computes a
   **witness set** with a ``derive`` entry instead, and the rule tests a
   relation over it (``context.requestVCJwsTrustRootJwkKeyWitnesses.contains(
   context.trustRootJwk)`` rather than ``signed_by(...)``). The proxy's half
   of that bargain is the *derivation contract*: the fold collects exactly
   the candidates the primitive answered ``True`` for. A witness set that is
   too **large** makes a forbid fail to fire, so over-inclusion fails open;
   the bundle's ``contract.json`` names each such obligation.

2. **The policy set is forbid-only over a base permit**: one forbid per
   reason leaf, annotated ``@id("<check id>")`` with the same id the guidance
   joins on, plus one forbid per tier annotated ``@assembly("<tier>")`` for
   that tier's own incompleteness. An **empty** policy set therefore allows
   everything, so a load that finds fewer forbids than ``expected_ids.json``
   lists is refused — that is a silent permit, not a partial policy. The
   ``@assembly`` forbid carries no ``@id`` on purpose: it is not a reason the
   guidance has a sentence for, so a fired one is dropped from
   ``failed_checks`` and the renderer explains the absent credential from
   the guard metadata instead, as it already does for the other engines.

3. **Cedar skips a policy whose condition raises**, and in a forbid-only set a
   skipped forbid is a permit. So an evaluation diagnostic is a *fault* here,
   never a denial with noise. The supplier proves every emitted condition
   safe against ``manifest.json``'s shape, and the filter validates the
   assembled input against that manifest before evaluation; a diagnostic
   means one of those two did not hold, and the call fails closed.

Everything evidential travels in ``context``. The principal, action and
resource are fixed labels (:data:`REQUEST_HEAD`), no entity store is passed,
and no emitted policy tests ``principal in``; the empty-store hazard is
unreachable by construction, which leaves the empty-*policy-set* hazard for
the completeness check above.
"""

from __future__ import annotations

import json
import logging
from collections import Counter
from pathlib import Path
from typing import Any

from .wasm_policy import PolicyEvaluationError

logger = logging.getLogger(__name__)

_MISSING_DEPS_MSG = (
    "The Cedar policy engine requires 'cedarpy'. "
    "Install it with: pip install 'extensible-mcp[cedar]'"
)

POLICY_FILE = "policy.cedar"
EXPECTED_IDS_FILE = "expected_ids.json"

#: The one request head every bundle is evaluated under. The emitted policies
#: never test these, so they are labels, not inputs.
REQUEST_HEAD: dict[str, str] = {
    "principal": 'Caller::"caller"',
    "action": 'Action::"call"',
    "resource": 'Tool::"governed"',
}

#: Cedar's JSON reader treats an object with one of these keys as an entity
#: reference or an extension value rather than as a record. The assembled
#: input is data; a key with this prefix anywhere in it is refused.
RESERVED_KEY_PREFIX = "__"


class CedarPolicyError(ValueError):
    """A Cedar bundle this proxy refuses to load.

    Raised for a policy set that does not parse, that uses templates, or that
    does not carry exactly the forbids ``expected_ids.json`` says it must —
    each of which is a bundle that could allow a call the source policy
    denies, so none of them may govern one.
    """


class CedarPolicy:
    """One loaded Cedar bundle, ready to query.

    Implements the :class:`~extensible_mcp.policy_engine.PolicyEngine` Protocol
    with the same ``entrypoints()`` / ``query()`` shape as the other two
    engines, so :mod:`extensible_mcp.wasm_filter` cannot tell them apart.
    Exposes ``<package>/allow`` and ``<package>/failed_checks``; like a CEL
    bundle it has no English ``deny_reason`` — denials render through the
    guidance layer.
    """

    def __init__(
        self,
        policy_path: str | Path,
        *,
        expected_ids_path: str | Path | None = None,
        package: str | None = None,
    ) -> None:
        try:
            import cedarpy
        except ImportError as e:  # pragma: no cover - exercised via env
            raise ImportError(_MISSING_DEPS_MSG) from e
        self._cedarpy = cedarpy

        policy_path = Path(policy_path)
        expected_path = (
            Path(expected_ids_path)
            if expected_ids_path is not None
            else policy_path.with_name(EXPECTED_IDS_FILE)
        )
        if not expected_path.exists():
            raise CedarPolicyError(
                f"{policy_path} has no {EXPECTED_IDS_FILE} beside it. A forbid-only "
                "policy set cannot be checked complete without one, and an "
                "incomplete one allows everything."
            )
        self._package = package or policy_path.parent.name
        self._expected_ids, self._expected_tiers = _read_expected(expected_path)

        text = policy_path.read_text()
        self._check_complete(_parse_policies(cedarpy, text, policy_path))
        # Parsed once here; `is_authorized` accepts the PolicySet directly, so a
        # 100 KB emitted policy is not re-parsed on every call.
        self._policies = cedarpy.PolicySet.from_str(text)

    # -- what the loader verified ---------------------------------------- #

    @property
    def expected_ids(self) -> frozenset[str]:
        """The check ids ``expected_ids.json`` lists, each found as an ``@id`` forbid."""
        return self._expected_ids

    @property
    def assembly_tiers(self) -> frozenset[str]:
        """The tiers ``expected_ids.json`` lists, each found as an ``@assembly`` forbid."""
        return self._expected_tiers

    # -- PolicyEngine Protocol ------------------------------------------- #

    def entrypoints(self) -> list[str]:
        return [f"{self._package}/allow", f"{self._package}/failed_checks"]

    def query(self, input_obj: Any, entrypoint: str) -> Any:
        if entrypoint not in self.entrypoints():
            raise PolicyEvaluationError(
                f"unknown entrypoint {entrypoint!r}; have {self.entrypoints()}"
            )
        if not isinstance(input_obj, dict):
            raise PolicyEvaluationError(
                f"Cedar input must be an object, got {type(input_obj).__name__}"
            )
        reserved = _reserved_key(input_obj)
        if reserved is not None:
            raise PolicyEvaluationError(
                f"input carries the key {reserved}, whose {RESERVED_KEY_PREFIX!r} "
                "prefix Cedar reads as an entity reference or extension value "
                "rather than as data"
            )

        result = self._cedarpy.is_authorized(
            {**REQUEST_HEAD, "context": input_obj}, self._policies, []
        )
        diagnostics = result.diagnostics
        errors = list(diagnostics.errors)
        decision = result.decision
        if errors or decision not in (
            self._cedarpy.Decision.Allow,
            self._cedarpy.Decision.Deny,
        ):
            # A condition that raised was skipped, and a skipped forbid is a
            # permit: whatever the decision says, it was not reached over the
            # whole policy set. Fail closed as a fault, not as a denial.
            raise PolicyEvaluationError(
                f"Cedar reported {len(errors)} evaluation diagnostic(s) "
                f"(decision {decision.value!r}); a skipped forbid is a permit, "
                f"so this is a fault: {errors[0] if errors else 'no decision'}"
            )
        allowed = decision == self._cedarpy.Decision.Allow
        if entrypoint.endswith("/allow"):
            return [{"result": allowed}]
        if allowed:
            return [{"result": []}]
        # Each fired forbid is a reason; the `@id` annotation is the check id
        # the guidance joins on. A reason with no `@id` is an `@assembly`
        # forbid: dropped, never replaced by Cedar's positional `policyN`
        # label, which would join to nothing and render as the placeholder.
        by_reason = dict(diagnostics.id_annotations_by_reason or {})
        ids = sorted({by_reason[r] for r in diagnostics.reasons if r in by_reason})
        return [{"result": ids}]

    # -- load-time completeness ------------------------------------------- #

    def _check_complete(self, policies: list[tuple[str, dict[str, Any]]]) -> None:
        found_ids: Counter[str] = Counter()
        found_tiers: Counter[str] = Counter()
        permits = 0
        for effect, annotations in policies:
            check_id = annotations.get("id")
            tier = annotations.get("assembly")
            if effect == "permit":
                if check_id is not None or tier is not None:
                    raise CedarPolicyError(
                        "a permit carries @id/@assembly; only a forbid is a reason"
                    )
                permits += 1
                continue
            if check_id is not None and tier is not None:
                raise CedarPolicyError(
                    f"forbid {check_id!r} carries both @id and @assembly"
                )
            if check_id is not None:
                found_ids[check_id] += 1
            elif tier is not None:
                found_tiers[tier] += 1
            else:
                raise CedarPolicyError(
                    "a forbid carries neither @id nor @assembly, so it could fire "
                    "with no reason the guidance can render"
                )
        if permits == 0:
            raise CedarPolicyError(
                "no permit: a forbid-only set with no base permit denies every call"
            )
        duplicates = sorted(k for k, n in found_ids.items() if n > 1)
        if duplicates:
            raise CedarPolicyError(f"@id annotated on more than one forbid: {duplicates}")
        duplicates = sorted(k for k, n in found_tiers.items() if n > 1)
        if duplicates:
            raise CedarPolicyError(
                f"@assembly annotated on more than one forbid: {duplicates}"
            )
        missing = sorted(self._expected_ids - set(found_ids))
        unexpected = sorted(set(found_ids) - self._expected_ids)
        if missing or unexpected:
            raise CedarPolicyError(
                f"policy set does not carry exactly the forbids {EXPECTED_IDS_FILE} "
                f"lists: missing {missing}, unexpected {unexpected}. A forbid-only "
                "set that half-loads is a silent permit, not a partial policy."
            )
        missing = sorted(self._expected_tiers - set(found_tiers))
        unexpected = sorted(set(found_tiers) - self._expected_tiers)
        if missing or unexpected:
            raise CedarPolicyError(
                f"policy set does not carry one @assembly forbid per tier in "
                f"{EXPECTED_IDS_FILE}: missing {missing}, unexpected {unexpected}. "
                "Without it a tier whose inputs are all absent is allowed."
            )


def _read_expected(path: Path) -> tuple[frozenset[str], frozenset[str]]:
    spec = json.loads(path.read_text())
    ids = spec.get("ids")
    tiers = spec.get("tiers")
    if not isinstance(ids, list) or not ids or not all(isinstance(i, str) for i in ids):
        raise CedarPolicyError(f"{path}: 'ids' must be a non-empty list of check ids")
    if len(set(ids)) != len(ids):
        raise CedarPolicyError(f"{path}: 'ids' lists a check id twice")
    if not isinstance(tiers, list) or not tiers:
        raise CedarPolicyError(f"{path}: 'tiers' must be a non-empty list")
    names: list[str] = []
    per_tier: set[str] = set()
    for t in tiers:
        if not isinstance(t, dict) or not isinstance(t.get("tier"), str):
            raise CedarPolicyError(f"{path}: each tier needs a string 'tier' name")
        names.append(t["tier"])
        per_tier.update(t.get("ids") or [])
    if len(set(names)) != len(names):
        raise CedarPolicyError(f"{path}: a tier is listed twice")
    if per_tier != set(ids):
        raise CedarPolicyError(
            f"{path}: the per-tier ids and the flat 'ids' list disagree"
        )
    return frozenset(ids), frozenset(names)


def _parse_policies(cedarpy: Any, text: str, path: Path) -> list[tuple[str, dict[str, Any]]]:
    """Every static policy as ``(effect, annotations)``, via Cedar's own parser."""
    try:
        parsed = json.loads(cedarpy.policies_to_json_str(text))
    except ValueError as e:
        raise CedarPolicyError(f"{path} does not parse as Cedar: {e}") from e
    if parsed.get("templates") or parsed.get("templateLinks"):
        raise CedarPolicyError(
            f"{path} uses policy templates; a bundle is static policies only"
        )
    out: list[tuple[str, dict[str, Any]]] = []
    for policy in (parsed.get("staticPolicies") or {}).values():
        out.append((policy.get("effect"), dict(policy.get("annotations") or {})))
    return out


def _reserved_key(value: Any, path: str = "input") -> str | None:
    if isinstance(value, dict):
        for k, v in value.items():
            here = f"{path}.{k}"
            if isinstance(k, str) and k.startswith(RESERVED_KEY_PREFIX):
                return here
            found = _reserved_key(v, here)
            if found is not None:
                return found
    elif isinstance(value, list):
        for i, v in enumerate(value):
            found = _reserved_key(v, f"{path}[{i}]")
            if found is not None:
                return found
    return None

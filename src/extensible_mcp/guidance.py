# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""The "why it failed" renderer: failed-check ids × guidance → the denial.

The runtime half is the policy's ``failed_checks`` entrypoint — a flat set of
tier-local check ids (``"t1.c5"``). The static half is the bundle's
``guidance.json``: the tier structure with per-check ``{id, sentence,
remedy_class}``, the call-field guards, and ``call_credentials`` (issuer
roles). This module joins the two into the disjunctive denial message, per
four properties the design deliberately holds to:

1. the runtime value is a *set* of failed checks — when the policy denies,
   every tier failed, possibly at several checks;
2. ids are opaque join keys, looked up in the guidance and never parsed;
3. a failure the guidance cannot name renders as a placeholder — vague,
   never wrong (an unnamed/quantifier-body check emits no id at all);
4. the message preserves the tier disjunction ("satisfy one of these
   paths") — the flat union of every tier's failures is self-contradictory.

An *absent* conditional credential emits no failed ids either — its checks'
conditions are undefined, so their rule bodies never fire. The renderer
covers that gap from the guard metadata: a tier that requires a call
credential the input did not carry gets a "provide ⟨field⟩, signed by the
⟨role⟩" line. This is the rendering-layer fix for a wording bluntness that
would otherwise conflate "absent" with "invalid".

``remedy_class`` drives the one typed branch (two values, ratified): a path
can be opened by re-prompting iff every failed check on it is
``re-promptable``; the denial is retryable iff some path can be opened. An
unknown remedy is treated as ``re-promptable`` — a futile retry is simply
denied again, while a wrong "do not retry" abandons a satisfiable call.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

_RE_PROMPTABLE = "re-promptable"

_PLACEHOLDER_PATH = "other conditions on this path were not met"
_PLACEHOLDER_CHECK = "an unnamed condition was not met"
_RETRY_HINT = "Gather the missing evidence or adjust the call, then retry."
_TERMINAL_HINT = (
    "No path can be satisfied by adjusting the call or gathering evidence; "
    "do not retry."
)


def render_denial(
    guidance: dict[str, Any] | None,
    failed_ids: Iterable[str],
    *,
    absent_fields: Iterable[str] = (),
) -> str | None:
    """The disjunctive denial message, or ``None`` when guidance cannot
    improve on the policy's own ``deny_reason`` strings.

    ``failed_ids`` is the ``failed_checks`` result; ``absent_fields`` are the
    bundle's credential fields the assembled input did not carry (their
    checks fire no ids). Returns ``None`` when there is no tier structure or
    nothing at all to say — the caller falls back to the English join.
    """
    failed = set(failed_ids)
    absent = set(absent_fields)
    tiers = (guidance or {}).get("tiers") or []
    if not tiers or not (failed or absent):
        return None

    guards = {g.get("field"): g for g in (guidance or {}).get("call_guards") or []}
    roles = {
        c.get("field"): c.get("issuer_role")
        for c in (guidance or {}).get("call_credentials") or []
    }

    def absent_lines(tier_id: Any) -> list[str]:
        lines = []
        for field in sorted(absent):
            guard = guards.get(field)
            if guard and tier_id in (guard.get("required_in_tiers") or []):
                role = roles.get(field)
                signer = f", signed by the {role}," if role else ""
                lines.append(f"provide `{field}`{signer} which was not supplied")
        return lines

    named_ids = {c.get("id") for t in tiers for c in t.get("checks", [])}
    path_lines: list[str] = []
    any_openable = False

    for i, tier in enumerate(tiers):
        failed_here = [c for c in tier.get("checks", []) if c.get("id") in failed]
        needs = absent_lines(tier.get("tier", i))
        needs += [c.get("sentence") or _PLACEHOLDER_CHECK for c in failed_here]
        # A path opens under re-prompting only if every failed check on it
        # does; a tier whose failures are all unnamed stays presumed-openable.
        openable = all(
            c.get("remedy_class", _RE_PROMPTABLE) == _RE_PROMPTABLE
            for c in failed_here
        )
        any_openable = any_openable or openable
        body = "; ".join(needs) if needs else _PLACEHOLDER_PATH
        path_lines.append(f"- Path {i + 1}: {body}.")

    lines = [
        "Tool call denied by policy: no allowed path was satisfied. "
        "To succeed, satisfy every condition of one of these paths:",
        *path_lines,
    ]
    if failed - named_ids:
        lines.append("Other unnamed conditions also failed.")
    lines.append(_RETRY_HINT if any_openable else _TERMINAL_HINT)
    return "\n".join(lines)

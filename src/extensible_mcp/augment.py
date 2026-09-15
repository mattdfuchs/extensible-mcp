# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Search-side augmentation: tell the LLM which credentials a governed tool
needs.

When ``search_tools`` surfaces a tool governed by a policy bundle, the LLM must
be told to supply the bundle's credential fields (e.g. ``requestVC``) — and
*when*, since some are required only on certain paths (e.g. an authorization VC
only above a spend threshold). :class:`BundleAugmenter` is a ``ToolFilter`` that,
per result, looks up the governing bundle (via the :class:`BundleRouter` the call
path already uses) and rewrites the surfaced tool definition:

- injects each credential field into the tool's input schema, typed from the
  bundle's manifest; an always-required credential is marked ``required``, a
  conditional one is optional;
- extends the description with a generated "what you need" note — the
  *scaffolding* ("always / if … also", the dependency ordering) is the
  proxy's; the *meaningful words* (the named-check sentences, issuer roles,
  credential names) come from the bundle's ``guidance.json``.

Credentials are listed in **dependency order** (a credential that signs over
another comes after it), each annotated with its **issuer role** — the
policy's enforced tag ("a parent must sign"), which the deployment's
``IssuerRegistry`` maps to a concrete wallet. Roles and edges are fail-soft
derivations from the bundle's own authoring toolchain: when a guidance file
predates them the note is merely vaguer, never wrong.

This is the proactive half of the message-is-the-interface design: the
enforcement path re-checks everything regardless, so a tool that misreads this
guidance is denied, not a security hole.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from collections.abc import Callable

from .bundle import PolicyBundle
from .routing import BundleRouter
from .types import SearchResult, ToolRecord


def _vc_bundle_phrase(role: str | None) -> str:
    wallet = f"the {role}'s wallet" if role else "the appropriate wallet"
    return (
        "A signed verifiable-credential bundle ({token, membership}) "
        f"obtained from {wallet}."
    )


def _unqualified_action(tool_name: str) -> str:
    return tool_name.split("__", 1)[1] if "__" in tool_name else tool_name


class BundleAugmenter:
    """A ``ToolFilter`` that surfaces a governed tool's required credentials.

    ``tool_action`` must match the call filter's mapping (the policy's
    ``input.tool``): the note tells the LLM the exact action identifier to
    put in the signed request, because the policy binds on it and the LLM
    cannot guess it — each wrong guess costs a human wallet approval.

    ``wire_schemas`` (field → JSON Schema) overrides the injected schema for
    a credential field. The manifest's shape is what the *policy* reads; when
    the call path runs a translating adapter (e.g. ``WalletBundleAdapter``
    turning ``{token, membership}`` into ``{jws, claims}``), the LLM must be
    shown the **wire** shape it actually sends — advertising the policy shape
    misleads it into "fixing" a working call.
    """

    def __init__(
        self,
        router: BundleRouter,
        *,
        tool_action: Callable[[str], str] = _unqualified_action,
        wire_schemas: dict[str, dict[str, Any]] | None = None,
    ) -> None:
        self._router = router
        self._tool_action = tool_action
        self._wire_schemas = dict(wire_schemas or {})

    def filter(self, results: list[SearchResult], query: str) -> list[SearchResult]:
        out: list[SearchResult] = []
        for r in results:
            bundle = self._router.bundle_for(r.tool.server_name)
            if bundle is None or not bundle.credential_fields():
                out.append(r)
                continue
            out.append(SearchResult(tool=self._augment(r.tool, bundle), score=r.score))
        return out

    # -- augmentation ------------------------------------------------------- #

    def _augment(self, tool: ToolRecord, bundle: PolicyBundle) -> ToolRecord:
        schema = deepcopy(tool.input_schema) if tool.input_schema else {"type": "object"}
        properties: dict[str, Any] = schema.setdefault("properties", {})
        required: list[str] = schema.setdefault("required", [])

        for field in self._dependency_order(bundle):
            properties[field] = self._credential_schema(field, bundle)
            if bundle.is_always_required(field) and field not in required:
                required.append(field)

        return ToolRecord(
            name=tool.name,
            qualified_name=tool.qualified_name,
            description=self._augment_description(
                tool.description, bundle, action=self._tool_action(tool.qualified_name)
            ),
            input_schema=schema,
            server_name=tool.server_name,
            # Keep the original embedding text: augmentation is presentation,
            # it must not change how the tool is found.
            embedding_text=tool.embedding_text,
        )

    def _dependency_order(self, bundle: PolicyBundle) -> list[str]:
        """Credential fields with each one's dependencies before it (a
        credential signs over what it depends on, so that must exist first).
        Fail-soft: an edge to a non-credential field is ignored, and a cycle —
        which a well-formed bundle's dependency edges should never contain —
        degrades to the given order."""
        fields = bundle.credential_fields()
        ordered: list[str] = []
        visiting: set[str] = set()

        def visit(field: str) -> None:
            if field in ordered or field in visiting:
                return
            visiting.add(field)
            for dep in bundle.credential_dependencies(field):
                if dep in fields:
                    visit(dep)
            visiting.discard(field)
            ordered.append(field)

        for field in fields:
            visit(field)
        return ordered

    def _credential_schema(self, field: str, bundle: PolicyBundle) -> dict[str, Any]:
        base = self._wire_schemas.get(field) or bundle.field_schema(field)
        schema = deepcopy(base) if isinstance(base, dict) else {"type": "object"}
        note = self._requirement_phrase(field, bundle)
        existing = schema.get("description")
        schema["description"] = f"{existing} {note}".strip() if existing else note
        return schema

    def _requirement_phrase(self, field: str, bundle: PolicyBundle) -> str:
        phrase = _vc_bundle_phrase(bundle.issuer_role(field))
        if bundle.is_always_required(field):
            return f"Required: {phrase}"
        deciding = bundle.deciding_sentences(field)
        when = "; ".join(deciding) if deciding else "certain conditions hold"
        return f"Required only when {when}. {phrase}"

    def _augment_description(
        self, description: str, bundle: PolicyBundle, *, action: str
    ) -> str:
        lines = ["", "This tool is policy-governed and requires signed credentials:"]
        for field in self._dependency_order(bundle):
            role = bundle.issuer_role(field)
            signed = f", signed by the {role}," if role else ""
            if bundle.is_always_required(field):
                head = f"- Always provide `{field}`{signed}".rstrip(",")
            else:
                deciding = bundle.deciding_sentences(field)
                when = "; ".join(deciding) if deciding else "the policy's conditions hold"
                head = f"- Provide `{field}`{signed} when {when}"
            deps = [d for d in bundle.credential_dependencies(field)
                    if d in bundle.credential_fields()]
            if deps:
                listed = ", ".join(f"`{d}`" for d in deps)
                head += f"; obtain {listed} first — this credential signs over it"
            lines.append(head + ".")
        lines.append(
            f'The policy evaluates this tool\'s action as `"{action}"` — when '
            "requesting a credential, name the action exactly so (the signed "
            f'request\'s type/action field must equal `"{action}"`, not the '
            "qualified tool name)."
        )
        lines.append(
            "Calls missing a required credential are denied; the denial says "
            "what is still needed."
        )
        return description + "\n".join(lines)

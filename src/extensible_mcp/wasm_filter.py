# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""A call filter that enforces a supplied policy bundle.

For each call it: splits the arguments into the tool's native arguments and the
LLM-supplied credential fields; assembles the policy's closed input via the
bundle's fetch plan (resolving config / clock / wallet itself); evaluates the
``allow`` rule; and either passes the call through with the credential fields
stripped, or denies with the policy's reason. Engine errors fail closed.

The credential→requirement *conditionality* (e.g. an authorization VC needed
only above a threshold) is governed by the policy itself: a credential a call
does not need is never read, so a placeholder/absent value for it is harmless.
The fetch plan's own guards (``always: false`` on a conditional field) let the
executor omit a genuinely absent optional credential rather than failing
closed on it — see :mod:`extensible_mcp.fetchplan`; a field the plan marks
unconditional still fails closed if missing.

The action binding is security-relevant: the policy checks
``requestVC.claims.action == input.tool`` and
``requestVC.claims.arguments == input.arguments`` — i.e. the signed request
must match the call actually being made. ``input.tool`` and ``input.arguments``
are therefore the proxy's *authoritative* view (the real tool and native args),
not values taken from the credential.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from typing import Any

from .bundle import PolicyBundle
from .didweb import DidWebResolver
from .fetchplan import FetchContext, FetchError, FetchExecutor, WalletLookup
from .guidance import render_denial
from .types import CallFilterResult, CallRequest
from .wallet_bundle import WalletBundleAdapter, WalletBundleError, make_membership_lookup
from .wasm_policy import PolicyEvaluationError

logger = logging.getLogger("extensible_mcp.wasm_filter")


def _validation_failure(errors: list[str]) -> str:
    shown = "; ".join(errors[:3])
    more = f" (+{len(errors) - 3} more)" if len(errors) > 3 else ""
    return (
        "Policy allowed the call, but its input failed manifest validation "
        f"(failing closed): {shown}{more}"
    )


def policy_deny_reason(bundle: PolicyBundle, assembled: dict[str, Any]) -> str:
    """Build a denial message from a bundle's failure rules.

    Preferred channel: the runtime ``failed_checks`` id set joined with the
    bundle's guidance into the disjunctive per-path message (with absent
    conditional credentials named from the guard metadata). Fallback — an
    artifact without the entrypoint or guidance, or a denial with nothing
    renderable — is the flat join of the English ``deny_reason`` set.
    """
    default = "Tool call denied by policy."
    rendered = _rendered_denial(bundle, assembled)
    if rendered is not None:
        return rendered
    if not bundle.has_deny_reason():
        return default
    try:
        out = bundle.policy.query(assembled, bundle.deny_reason_entrypoint)
    except PolicyEvaluationError:
        return default
    reasons = out[0]["result"] if out and "result" in out[0] else []
    if not reasons:
        return default
    return "Tool call denied by policy: " + "; ".join(sorted(reasons)) + "."


def _rendered_denial(bundle: PolicyBundle, assembled: dict[str, Any]) -> str | None:
    if not bundle.has_failed_checks():
        return None
    try:
        out = bundle.policy.query(assembled, bundle.failed_checks_entrypoint)
    except PolicyEvaluationError:
        return None
    ids = out[0]["result"] if out and "result" in out[0] else []
    # A credential the input did not carry fires no ids (its conditions are
    # undefined); the renderer names it from the guards instead.
    absent = [f for f in bundle.credential_fields() if f not in assembled]
    return render_denial(bundle.guidance, ids, absent_fields=absent)


def _unqualified_action(tool_name: str) -> str:
    """Default ``input.tool``: the tool name without its ``{server}__`` prefix.

    The signed request's ``action`` must equal this, so the convention has to
    match what the wallet signs. Override via ``tool_action`` when a deployment
    binds on the qualified name or another identifier.
    """
    return tool_name.split("__", 1)[1] if "__" in tool_name else tool_name


class WasmPolicyFilter:
    """Enforce a single policy bundle on the call path (a ``CallFilter``).

    Manifest validation (on by default) gates the **allow** path: an input
    that fails the manifest never forwards even when the policy allows it —
    the defense-in-depth case being a field no rule reads (e.g. an extra
    native argument the signed request does not bind), which
    ``additionalProperties: false`` rejects. Denials are *not* short-
    circuited by validation: the policy evaluates regardless, so its rendered
    denial (the guidance channel) is what the LLM sees, with validation
    errors logged rather than masking it.
    """

    def __init__(
        self,
        bundle: PolicyBundle,
        *,
        config: dict[str, Any],
        wallet_lookup: WalletLookup | None = None,
        clock: Callable[[], int] | None = None,
        tool_action: Callable[[str], str] = _unqualified_action,
        executor: FetchExecutor | None = None,
        validate_input: bool = True,
    ) -> None:
        self.bundle = bundle
        self._config = dict(config)
        self._wallet = wallet_lookup
        self._clock = clock or (lambda: int(time.time()))
        self._tool_action = tool_action
        self._executor = executor or FetchExecutor()
        self._validate = validate_input

    async def check(self, request: CallRequest) -> CallFilterResult:
        credential_fields = self.bundle.credential_fields()
        native_args = {
            k: v for k, v in request.arguments.items() if k not in credential_fields
        }

        envelope: dict[str, Any] = {
            "tool": self._tool_action(request.tool_name),
            "arguments": native_args,
        }
        for field in credential_fields:
            if field in request.arguments:
                envelope[field] = request.arguments[field]

        ctx = FetchContext(
            envelope=envelope,
            config=self._config,
            now=self._clock(),
            wallet=self._wallet,
        )

        # Stripping the credential fields is correct whatever the verdict: the
        # downstream tool only ever wants its native arguments.
        deny = lambda reason: CallFilterResult(  # noqa: E731
            allowed=False,
            reason=reason,
            tool_name=request.tool_name,
            arguments=native_args,
        )

        try:
            assembled = await self._executor.assemble(self.bundle.fetchplan, ctx)
        except FetchError as e:
            return deny(f"Policy input could not be assembled: {e}")

        validation_errors = []
        if self._validate:
            try:
                validation_errors = self.bundle.validate_input(assembled)
            except Exception as e:  # noqa: BLE001 - deployment fault, fail closed
                return deny(f"Policy input could not be validated (failing closed): {e}")

        try:
            result = self.bundle.policy.query(assembled, self.bundle.allow_entrypoint)
        except PolicyEvaluationError as e:
            # Engine/config fault — fail closed, surfaced as an error not a
            # silent policy "deny".
            return deny(f"Policy could not be evaluated (failing closed): {e}")

        if result and result[0].get("result") is True:
            if validation_errors:
                logger.warning(
                    "manifest validation failed on allowed call %r: %s",
                    request.tool_name, validation_errors,
                )
                return deny(_validation_failure(validation_errors))
            return CallFilterResult(
                allowed=True,
                tool_name=request.tool_name,
                arguments=native_args,
            )

        if validation_errors:
            logger.info(
                "manifest validation errors on denied call %r: %s",
                request.tool_name, validation_errors,
            )
        return deny(self._deny_reason(assembled))

    def _deny_reason(self, assembled: dict[str, Any]) -> str:
        return policy_deny_reason(self.bundle, assembled)


class VCPolicyFilter:
    """Production VC enforcement on the call path (a ``CallFilter``).

    Composes the wallet-bundle adapter, the did:web resolver, and the policy
    bundle: for each call it adapts the `{token, membership}` bundles into the
    policy's input shape, resolves each membership's admin key via did:web,
    assembles the closed input (guard-aware — an absent optional authorization
    is omitted, so the solo tier still evaluates), and evaluates ``allow``.

    On allow, the call is forwarded with the credential bundles stripped and the
    tool's *original* native arguments preserved (the cents-normalization is for
    the policy only; the downstream tool sees what the LLM sent). Engine/config
    faults fail closed.

    Manifest validation (on by default) gates the allow path only — see
    :class:`WasmPolicyFilter`. Ordering matters here: the resolver deliberately
    attaches ``adminKey = None`` for an untrusted issuer so the *policy* can
    deny with its chain-of-trust reason; validation must not preempt that
    denial with a type error.
    """

    def __init__(
        self,
        bundle: PolicyBundle,
        *,
        adapter: WalletBundleAdapter,
        resolver: DidWebResolver,
        trusted_admin_dids: list[str],
        clock: Callable[[], int] | None = None,
        executor: FetchExecutor | None = None,
        validate_input: bool = True,
        extra_config: dict[str, Any] | None = None,
        wallet_fallback: WalletLookup | None = None,
    ) -> None:
        """``extra_config`` supplies additional ``config``-sourced fetch-plan
        fields beyond ``trustedAdminDids`` (e.g. the WebAuthn bundle's
        ``webauthnOrigin``). ``wallet_fallback`` answers ``wallet``-sourced
        lookups the harvested memberships cannot — e.g. a passkey enrollment
        keyed by ``credentialId`` — and must return the envelope complete
        (``adminKey`` attached), since it bypasses the membership resolver."""
        self.bundle = bundle
        self._adapter = adapter
        self._resolver = resolver
        self._trusted = list(trusted_admin_dids)
        self._clock = clock or (lambda: int(time.time()))
        self._executor = executor or FetchExecutor()
        self._validate = validate_input
        self._extra_config = dict(extra_config or {})
        self._wallet_fallback = wallet_fallback

    async def check(self, request: CallRequest) -> CallFilterResult:
        # Downstream gets the original native args (un-normalized), minus the
        # credential bundles — the cents form is a policy-only view.
        credential_fields = {
            self._adapter.request_field,
            self._adapter.authorization_field,
        }
        downstream_args = {
            k: v for k, v in request.arguments.items() if k not in credential_fields
        }

        def deny(reason: str) -> CallFilterResult:
            return CallFilterResult(
                allowed=False,
                reason=reason,
                tool_name=request.tool_name,
                arguments=downstream_args,
            )

        try:
            adapted = self._adapter.adapt(request)
        except WalletBundleError as e:
            return deny(f"A supplied credential is malformed: {e}")

        membership_lookup = make_membership_lookup(adapted.memberships, self._resolver)
        fallback = self._wallet_fallback

        async def wallet_lookup(subject: str):
            found = await membership_lookup(subject)
            if found is None and fallback is not None:
                return await fallback(subject)
            return found

        ctx = FetchContext(
            envelope=adapted.envelope,
            config={**self._extra_config, "trustedAdminDids": self._trusted},
            now=self._clock(),
            wallet=wallet_lookup,
        )

        try:
            assembled = await self._executor.assemble(self.bundle.fetchplan, ctx)
        except FetchError as e:
            return deny(f"Policy input could not be assembled: {e}")

        validation_errors = []
        if self._validate:
            try:
                validation_errors = self.bundle.validate_input(assembled)
            except Exception as e:  # noqa: BLE001 - deployment fault, fail closed
                return deny(f"Policy input could not be validated (failing closed): {e}")

        try:
            result = self.bundle.policy.query(assembled, self.bundle.allow_entrypoint)
        except PolicyEvaluationError as e:
            return deny(f"Policy could not be evaluated (failing closed): {e}")

        if result and result[0].get("result") is True:
            if validation_errors:
                logger.warning(
                    "manifest validation failed on allowed call %r: %s",
                    request.tool_name, validation_errors,
                )
                return deny(_validation_failure(validation_errors))
            return CallFilterResult(
                allowed=True,
                tool_name=request.tool_name,
                arguments=downstream_args,
            )
        if validation_errors:
            logger.info(
                "manifest validation errors on denied call %r: %s",
                request.tool_name, validation_errors,
            )
        return deny(policy_deny_reason(self.bundle, assembled))

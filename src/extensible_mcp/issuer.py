# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Issuer registry: which wallet fulfils which role (the zero-trust seam).

A policy names a *role* ("a parent must sign"); the proxy decides which concrete
wallet is that role. This generalizes the fork's two hard-coded positional URLs
(`originator_wallet_url` / `approver_wallet_url`) into a role-keyed table, so a
deployment can have more than two parties.

The registry is acquisition-side routing — used when the LLM asks the proxy to
obtain a signature for a given role. It is deployment config, never derived from
anything a tool reports.

The role *names* come from the policy side: a bundle's ``guidance.json``
derives each credential's ``issuer_role`` from the enforced role tag
(``PolicyBundle.issuer_roles()``), so the registry keys on exactly the
strings the policy enforces. At admission a deployment checks
``registry.missing_roles(bundle.issuer_roles())`` — a governed tool must
never advertise a credential nobody can sign (fail closed, like an
unavailable bundle).
"""

from __future__ import annotations

from collections.abc import Iterable


class IssuerRegistry:
    """Maps a role name to the wallet endpoint that signs for it."""

    def __init__(self, wallets: dict[str, str]) -> None:
        self._wallets = dict(wallets)

    def url_for(self, role: str) -> str | None:
        """The wallet URL for a role, or ``None`` if no wallet serves it."""
        return self._wallets.get(role)

    def roles(self) -> list[str]:
        return list(self._wallets)

    def missing_roles(self, roles: Iterable[str]) -> list[str]:
        """The roles among ``roles`` that no wallet serves — the
        admission-time check against a bundle's ``issuer_roles()``."""
        return sorted({r for r in roles if r not in self._wallets})

    def __contains__(self, role: str) -> bool:
        return role in self._wallets

    @classmethod
    def from_positional(
        cls,
        *,
        originator_url: str,
        approver_url: str,
        originator_role: str = "kid",
        approver_role: str = "parent",
    ) -> "IssuerRegistry":
        """Build from the fork's two positional wallet URLs — a migration shim
        so existing `VCConfig` (originator/approver URLs) maps onto the
        role-keyed table without a config rewrite."""
        return cls({originator_role: originator_url, approver_role: approver_url})

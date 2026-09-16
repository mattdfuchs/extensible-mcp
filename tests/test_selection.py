# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Tests for stage-one bundle selection: the literal-map / Rego-classifier
layering, against a real compiled classifier wasm."""

from __future__ import annotations

from pathlib import Path

import pytest

from extensible_mcp.selection import (
    BANNED,
    LayeredBundleSelector,
    RegoClassifier,
    provenance_descriptor,
)

CLASSIFIER_WASM = (
    Path(__file__).parent / "fixtures" / "classifier" / "policy.wasm"
)


@pytest.fixture(scope="module")
def classifier():
    return RegoClassifier(CLASSIFIER_WASM)


def _desc(server: str, *, tier: str = "prod", url: str | None = None):
    return provenance_descriptor(
        origin_server=server,
        url=url or f"https://{server}.example",
        config_trust_tier=tier,
    )


# -- the classifier backend (matches the committed policy.rego) ------------- #


def test_classifier_routes_payments_to_family_spend(classifier):
    assert classifier.decide(_desc("payments")) == "family_spend"


def test_classifier_routes_sandbox_to_readonly(classifier):
    assert classifier.decide(_desc("other", tier="sandbox")) == "readonly"


def test_classifier_defaults_to_deny_all(classifier):
    assert classifier.decide(_desc("unknown", tier="prod")) == "deny_all"


# -- the layered selector ---------------------------------------------------- #


def test_classifier_only_selects(classifier):
    sel = LayeredBundleSelector(classifier=classifier)
    r = sel.select(_desc("payments"))
    assert r.bundle == "family_spend" and r.source == "classifier" and r.allowed


def test_classifier_deny_is_not_allowed(classifier):
    sel = LayeredBundleSelector(classifier=classifier)
    r = sel.select(_desc("unknown"))
    assert r.bundle is None and r.source == "classifier" and not r.allowed


def test_map_override_wins_over_classifier(classifier):
    # classifier would say family_spend, but the operator pins this URL.
    url = "https://payments.example"
    sel = LayeredBundleSelector({url: "readonly"}, classifier)
    r = sel.select(_desc("payments", url=url))
    assert r.bundle == "readonly" and r.source == "map"


def test_map_banned_does_not_fall_through(classifier):
    url = "https://payments.example"
    sel = LayeredBundleSelector({url: "banned"}, classifier)
    r = sel.select(_desc("payments", url=url))
    # would have classified to family_spend, but the ban is authoritative
    assert r.bundle is None and r.source == "map" and not r.allowed


def test_map_miss_falls_through_to_classifier(classifier):
    sel = LayeredBundleSelector({"https://other.example": "banned"}, classifier)
    r = sel.select(_desc("payments"))  # different url -> map miss -> classify
    assert r.bundle == "family_spend" and r.source == "classifier"


def test_map_miss_no_classifier_fails_closed():
    sel = LayeredBundleSelector({"https://x.example": "family_spend"})
    r = sel.select(_desc("payments"))
    assert r.bundle is None and r.source == "default" and not r.allowed


def test_map_hit_no_classifier_still_works():
    url = "https://payments.example"
    sel = LayeredBundleSelector({url: "family_spend"})
    r = sel.select(_desc("payments", url=url))
    assert r.bundle == "family_spend" and r.source == "map"


def test_descriptor_is_proxy_constructed():
    # The descriptor carries proxy-controlled facts, not tool metadata.
    d = provenance_descriptor(
        origin_server="payments", url="https://p.example", config_trust_tier="prod"
    )
    assert d["origin_server"] == "payments" and "tool" not in d


class TestKeyNormalization:
    """The literal map is an exact-string lookup on a URL, so spellings of
    one endpoint that differ only in case or a trailing slash used to miss a
    `banned` entry entirely and fall through to the classifier."""

    @pytest.mark.parametrize(
        "spelling",
        [
            "https://evil.example/mcp",
            "https://evil.example/mcp/",
            "https://Evil.Example/mcp",
            "HTTPS://evil.example/mcp/",
        ],
    )
    def test_banned_entry_catches_equivalent_spellings(self, spelling):
        sel = LayeredBundleSelector({"https://evil.example/mcp": BANNED})
        result = sel.select({"url": spelling})
        assert result.bundle is None
        assert result.source == "map"

    def test_non_url_keys_are_left_alone(self):
        sel = LayeredBundleSelector({"Payments": "family_spend"}, map_key="name")
        assert sel.select({"name": "Payments"}).bundle == "family_spend"
        assert sel.select({"name": "payments"}).bundle is None

    def test_path_case_is_preserved(self):
        """Only scheme and host are case-insensitive; a path is not."""
        sel = LayeredBundleSelector({"https://a.example/MCP": "b"})
        assert sel.select({"url": "https://a.example/MCP"}).bundle == "b"
        assert sel.select({"url": "https://a.example/mcp"}).bundle is None

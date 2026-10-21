# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""The fixture corpus as a set of pinned facts, so an adoption is checked
rather than eyeballed.

Every policy bundle under ``tests/fixtures/`` is either *adopted* -- supplied
by the external toolchain and re-pinned verbatim, with a ``guidance_digest``
that names the artifact -- or *teaching* -- hand-authored for this repo and
relabelled by hand to the same id scheme. This module pins, for both kinds,
what a re-pin can silently break: the id scheme and counts, that no check
lost its sentence, that every cross-reference between the bundle's own
files resolves, that a Rego bundle and its CEL twin really are the same
bundle in two notations, and that nothing from the supplier's namespace
leaked into a public artifact.

The twin relation is CEL-specific on purpose. A Cedar bundle over the same
rule set is a *second* bundle -- the hoist changes its closed input, so its
manifest and fetch plan must differ -- and a check written as "every engine
has a bundle for every rule set" would either demand Cedar fixtures that
have no reason to exist or quietly accept a byte-differing pair as a twin.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"

ID_SCHEME = "named-split"
PLACEHOLDER = "an unnamed condition was not met"

# bundle -> (total ids, authored sentences, mechanical "required: ..." sentences).
# The adopted rows are the toolchain's own table for the split (93 -> 126
# upstream; the three Rego bundles here plus the one CEL twin). The teaching
# rows are this repo's, authored here.
EXPECTED_COUNTS = {
    "family_spend_prod": (32, 16, 16),
    "family_spend_webauthn": (30, 15, 15),
    "family_spend_invoice": (32, 23, 9),
    "cel_family_spend_invoice": (32, 23, 9),
    "family_spend": (29, 16, 13),
    "cel_family_spend": (29, 16, 13),
}
ADOPTED = {"family_spend_prod", "family_spend_webauthn", "family_spend_invoice",
           "cel_family_spend_invoice"}
TEACHING = {"family_spend", "cel_family_spend"}
REGO_BUNDLES = {"family_spend", "family_spend_prod", "family_spend_webauthn",
                "family_spend_invoice"}
CEL_BUNDLES = {"cel_family_spend", "cel_family_spend_invoice"}

# Rego bundle -> its CEL twin, or the reason it has none. A missing twin that
# is not listed here fails the pairing test rather than vanishing from it.
CEL_TWIN = {
    "family_spend": "cel_family_spend",
    "family_spend_invoice": "cel_family_spend_invoice",
    "family_spend_webauthn": None,  # Rego-only upstream: no CEL artifact ships
    "family_spend_prod": None,      # ships upstream, adoption tracked as #18
}

# Two shapes stay welded by rule and must still be single checks: a crypto
# application already inside a quantifier is not lifted out, and a
# single-literal body inlines to itself.
STILL_WELDED = {
    "family_spend_invoice": ["solo.invoice.signed_by_trusted_merchant",
                             "dual.invoice.signed_by_trusted_merchant"],
    "cel_family_spend_invoice": ["solo.invoice.signed_by_trusted_merchant",
                                 "dual.invoice.signed_by_trusted_merchant"],
    "family_spend_prod": ["full_chain.authorization_vc.hash_binds"],
}


def _guidance(bundle: str) -> dict:
    return json.loads((FIXTURES / bundle / "guidance.json").read_text())


def _ids(guidance: dict) -> list[str]:
    return [c["id"] for tier in guidance["tiers"] for c in tier["checks"]]


@pytest.mark.parametrize("bundle", sorted(EXPECTED_COUNTS))
def test_id_scheme_and_counts(bundle):
    g = _guidance(bundle)
    assert g["id_scheme"] == ID_SCHEME
    ids = _ids(g)
    assert len(ids) == len(set(ids)), "duplicate check id"
    sentences = [c["sentence"] for tier in g["tiers"] for c in tier["checks"]]
    mechanical = sum(1 for s in sentences if s.startswith("required: "))
    assert (len(ids), len(ids) - mechanical, mechanical) == EXPECTED_COUNTS[bundle]


@pytest.mark.parametrize("bundle", sorted(EXPECTED_COUNTS))
def test_every_check_has_a_sentence_and_none_is_the_placeholder(bundle):
    """The condition this repo attached to accepting the split: every check
    carries a sentence, no bundle gained a placeholder."""
    for tier in _guidance(bundle)["tiers"]:
        for c in tier["checks"]:
            assert c.get("sentence"), c["id"]
            assert c["sentence"] != PLACEHOLDER, c["id"]
            assert c.get("remedy_class"), c["id"]


@pytest.mark.parametrize("bundle", sorted(ADOPTED))
def test_adopted_bundle_carries_a_digest(bundle):
    """The scheme tag names a scheme, not an artifact -- two commits with the
    same tag can differ by a sentence. The digest is the line to compare."""
    d = _guidance(bundle)["guidance_digest"]
    assert re.fullmatch(r"[0-9a-f]{16}", d["value"])
    assert d["alg"] == "fnv1a64"


@pytest.mark.parametrize("bundle", sorted(TEACHING))
def test_teaching_bundle_carries_no_digest(bundle):
    """A digest names a supplier artifact; a hand-authored bundle is not one."""
    assert "guidance_digest" not in _guidance(bundle)


@pytest.mark.parametrize("bundle", sorted(EXPECTED_COUNTS))
def test_deciding_checks_resolve(bundle):
    """A stale ``deciding_checks`` silently breaks the absent-field branch of
    ``render_denial``, so this is asserted rather than eyeballed."""
    ids = set(_ids(_guidance(bundle)))
    plan = json.loads((FIXTURES / bundle / "fetchplan.json").read_text())
    seen = 0
    for entry in plan["entries"]:
        for cid in (entry.get("guard") or {}).get("deciding_checks") or []:
            assert cid in ids, (entry["field"], cid)
            seen += 1
    assert seen, "expected at least one guarded entry"


@pytest.mark.parametrize("bundle", sorted(REGO_BUNDLES))
def test_rego_failed_checks_cover_exactly_the_guidance_ids(bundle):
    """The wasm is built from this source, so the source is the join to pin:
    every id guidance can render is one the policy can emit, and vice versa."""
    rego = (FIXTURES / bundle / "policy.rego").read_text()
    emitted = set(re.findall(r'failed_checks contains "([^"]+)"', rego))
    assert emitted == set(_ids(_guidance(bundle)))


@pytest.mark.parametrize("bundle", sorted(CEL_BUNDLES))
def test_cel_tiers_match_guidance_exactly(bundle):
    checks = json.loads((FIXTURES / bundle / "checks.cel.json").read_text())
    cel_ids = [cid for tier in checks["tiers"] for cid in tier["checks"]]
    assert cel_ids == _ids(_guidance(bundle)), "same ids, same order"
    assert set(checks["checks"]) == set(cel_ids)
    for cid in checks.get("guards") or {}:
        assert cid in checks["checks"], cid


@pytest.mark.parametrize("bundle", sorted(STILL_WELDED))
def test_still_welded_shapes_are_single_checks(bundle):
    ids = _ids(_guidance(bundle))
    for cid in STILL_WELDED[bundle]:
        assert cid in ids, cid
        assert not any(i.startswith(cid + ".") for i in ids), cid


@pytest.mark.parametrize("rego", sorted(CEL_TWIN))
def test_cel_twin_is_the_same_bundle_in_another_notation(rego):
    """For every Rego bundle, either a CEL twin exists and the three
    engine-independent files are byte-identical, or the bundle is listed
    Rego-only with a reason. A missing twin fails here; it does not vanish."""
    cel = CEL_TWIN[rego]
    if cel is None:
        assert not (FIXTURES / f"cel_{rego}").exists(), (
            f"cel_{rego} exists on disk but is listed Rego-only"
        )
        return
    for name in ("manifest.json", "fetchplan.json", "guidance.json"):
        assert (FIXTURES / rego / name).read_bytes() == (FIXTURES / cel / name).read_bytes(), name


def test_every_bundle_on_disk_is_accounted_for():
    """A fixture directory nobody listed is a fixture nobody is checking: every
    directory with a ``guidance.json`` is a bundle and must be in the table,
    and every fixture directory of any kind documents its own provenance."""
    on_disk = {p.parent.name for p in FIXTURES.glob("*/guidance.json")}
    assert on_disk == set(EXPECTED_COUNTS)
    for d in FIXTURES.iterdir():
        if d.is_dir():
            assert (d / "PROVENANCE.md").is_file(), d.name


def test_no_supplier_namespace_leaks_into_a_public_artifact():
    """The one allowed match is the challenge pre-image's version tag, which
    is an opaque wire constant shared with the approval page."""
    hits = []
    for path in FIXTURES.rglob("*"):
        if path.is_file() and path.suffix != ".wasm":
            for n, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
                if "lego" in line.lower() and "legov1" not in line:
                    hits.append(f"{path.relative_to(FIXTURES)}:{n}")
    assert hits == []

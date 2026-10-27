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
    "cedar_family_spend": (29, 16, 13),
    # The adopted Cedar policy re-shaped by this repo: permit decides, forbid explains.
    "cedar_family_spend_compact": (29, 16, 13),
    # The smallest bundle, three ways: the README's authoring walk-through.
    "minimal_spend": (5, 2, 3),
    "cel_minimal_spend": (5, 2, 3),
    "cedar_minimal_spend": (5, 2, 3),
}
ADOPTED = {"family_spend_prod", "family_spend_webauthn", "family_spend_invoice",
           "cel_family_spend_invoice"}
# cedar_family_spend's rules are supplied, but its guidance is this repo's
# own teaching file, so it carries no digest either.
TEACHING = {"family_spend", "cel_family_spend", "cedar_family_spend",
            "cedar_family_spend_compact",
            "minimal_spend", "cel_minimal_spend", "cedar_minimal_spend"}
REGO_BUNDLES = {"family_spend", "family_spend_prod", "family_spend_webauthn",
                "family_spend_invoice", "minimal_spend"}
CEL_BUNDLES = {"cel_family_spend", "cel_family_spend_invoice", "cel_minimal_spend"}

# Rego bundle -> its CEL twin, or the reason it has none. A missing twin that
# is not listed here fails the pairing test rather than vanishing from it.
CEL_TWIN = {
    "family_spend": "cel_family_spend",
    "minimal_spend": "cel_minimal_spend",
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


def _fnv1a64(data: bytes) -> int:
    h = 0xCBF29CE484222325
    for b in data:
        h = ((h ^ b) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


def _compact(value) -> str:
    """The supplier's compact JSON rendering of a hole's source value."""
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def _hole_source(source) -> str:
    # A single-key object (``$input`` / ``const`` / ``unresolved``) is split
    # into key and compact value, so the projection carries no opinion about
    # how an object serialises.
    if isinstance(source, dict) and len(source) == 1:
        ((key, value),) = source.items()
        return f"{key}\t{_compact(value)}"
    return _compact(source)


def _csv(items) -> str:
    return ",".join(str(x) for x in items)


def _digest_lines(guidance: dict) -> list[str]:
    """The supplier's line projection of a guidance file: one tab-separated
    record per line, in the file's own order, covering every field except
    the digest itself. Parsed content, not bytes, so key order and
    whitespace do not move it."""
    lines = ["scheme\t" + guidance["id_scheme"], "goal\t" + guidance["goal"]]
    for tier in guidance["tiers"]:
        lines.append(f"tier\t{tier['tier']}")
        for c in tier["checks"]:
            lines.append(
                f"check\t{c['id']}\t{c['sentence']}\t{c['condition']}\t{c['remedy_class']}"
            )
            for h in c.get("holes", []):
                lines.append(
                    f"hole\t{h['marker']}\t{h['param']}\t{h.get('format', '')}"
                    f"\t{_hole_source(h['source'])}"
                )
    for g in guidance.get("call_guards", []):
        always = "true" if g["always"] else "false"
        lines.append(
            f"guard\t{g['field']}\t{always}\t{_csv(g['required_in_tiers'])}"
            f"\t{_csv(g['deciding_checks'])}"
        )
    for cred in guidance.get("call_credentials", []):
        lines.append(
            f"cred\t{cred['field']}\t{cred.get('issuer_role', '')}"
            f"\t{_csv(cred['role_checks'])}"
        )
        for edge in cred.get("depends_on", []):
            lines.append(
                f"edge\t{cred['field']}\t{edge['field']}\t{_csv(edge['binding_checks'])}"
            )
    return lines


def guidance_digest(guidance: dict) -> str:
    """Recompute a guidance file's ``guidance_digest`` from its content."""
    payload = ("\n".join(_digest_lines(guidance)) + "\n").encode("utf-8")
    return format(_fnv1a64(payload), "016x")


@pytest.mark.parametrize("bundle", sorted(EXPECTED_COUNTS))
def test_fetch_plan_names_each_field_once(bundle):
    """Two entries naming one field collapse in ``assemble`` to the last
    writer, and the load now refuses that (#31). Pinned on the corpus as well
    as on synthetic plans, since the one time it shipped it was generated."""
    plan = json.loads((FIXTURES / bundle / "fetchplan.json").read_text())
    fields = [e["field"] for e in plan["entries"]]
    assert len(fields) == len(set(fields)), sorted(
        f for f in set(fields) if fields.count(f) > 1
    )


@pytest.mark.parametrize("bundle", sorted(ADOPTED))
def test_adopted_bundle_digest_is_recomputable(bundle):
    """The scheme tag names a scheme, not an artifact -- two commits with the
    same tag can differ by a sentence. The digest is the line to compare, so
    it has to be a fact about the content rather than a label on it: the
    supplier publishes the projection it is taken over, and this recomputes
    it. A re-pin that changes rendered guidance now has to change the
    recorded value too, and one that does not reproduces it exactly."""
    d = _guidance(bundle)["guidance_digest"]
    assert d["alg"] == "fnv1a64"
    assert re.fullmatch(r"[0-9a-f]{16}", d["value"])
    assert guidance_digest(_guidance(bundle)) == d["value"]


@pytest.mark.parametrize("bundle", sorted(ADOPTED))
def test_provenance_quotes_the_recorded_digest(bundle):
    """The provenance note is where a human compares a re-pin; it must quote
    the same value the file carries."""
    value = _guidance(bundle)["guidance_digest"]["value"]
    assert value in (FIXTURES / bundle / "PROVENANCE.md").read_text()


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
    conditional = 0
    for entry in plan["entries"]:
        guard = entry.get("guard") or {}
        conditional += not guard.get("always", True)
        for cid in guard.get("deciding_checks") or []:
            assert cid in ids, (entry["field"], cid)
            seen += 1
    # A conditional credential must say which checks decide it; a bundle
    # whose every field is always required (the minimal trio) has none to say.
    if conditional:
        assert seen, "a conditional field with no deciding_checks"


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


# Rego bundle -> its Cedar twin, or the reason it has none. A Cedar bundle's
# manifest and fetch plan cannot be byte-identical to the Rego bundle's —
# every hoisted crypto leaf reads a derived field no other engine needs — so
# the pairing asserts the differences are exactly the ones Cedar forces.
# A Rego bundle may have one Cedar twin per policy-set shape; each is held
# to the same relation to the Rego bundle.
CEDAR_TWIN = {
    "family_spend": ["cedar_family_spend", "cedar_family_spend_compact"],
    "minimal_spend": ["cedar_minimal_spend"],
    "family_spend_prod": None,      # ships upstream; needs #27's `concat` as a derive primitive
    "family_spend_webauthn": None,  # ships upstream; needs #27 and `verify_webauthn` registered
    "family_spend_invoice": None,   # ships upstream; needs `verify_webauthn` registered
}


def _cedar_pairs():
    for rego, twins in sorted(CEDAR_TWIN.items()):
        if twins is None:
            yield rego, None
        else:
            for cedar in twins:
                yield rego, cedar


@pytest.mark.parametrize("rego,cedar", list(_cedar_pairs()))
def test_cedar_twin_differs_from_the_rego_bundle_only_where_cedar_forces_it(rego, cedar):
    if cedar is None:
        assert not (FIXTURES / f"cedar_{rego}").exists(), (
            f"cedar_{rego} exists on disk but is listed as having no twin"
        )
        return
    r, c = FIXTURES / rego, FIXTURES / cedar
    # Guidance is the one artifact that crosses the hoist untouched.
    assert (r / "guidance.json").read_bytes() == (c / "guidance.json").read_bytes()

    rm = json.loads((r / "manifest.json").read_text())
    cm = json.loads((c / "manifest.json").read_text())
    derived = cm["derived_fields"]
    assert set(cm["properties"]) == set(rm["properties"]) | set(derived)
    for name in rm["properties"]:
        assert cm["properties"][name] == rm["properties"][name], name
    assert not set(derived) & set(cm["required"]), (
        "a derived field is absent when its primitive matched nothing; never required"
    )
    assert set(cm["required"]) <= set(rm["required"])
    assert set(cm["definitions"]) == set(rm["definitions"])

    rp = json.loads((r / "fetchplan.json").read_text())
    cp = json.loads((c / "fetchplan.json").read_text())
    shared = len(rp["entries"])
    assert cp["entries"][:shared] == rp["entries"], "the shared plan, verbatim, first"
    appended = cp["entries"][shared:]
    assert all(e["source"]["kind"] == "derive" for e in appended)
    assert {e["field"] for e in appended} == set(derived)
    assert set(cp["primitives"]) == {e["source"]["fn"] for e in appended}, (
        "a Cedar plan declares exactly what it derives"
    )

    # expected_ids.json, where the shape needs one, names the guidance's ids,
    # tier by tier, and no others. A permit-decides twin may ship without it;
    # the loader then reads the same structure off the @tier permits, and it
    # must still be the guidance's.
    g = _guidance(cedar)
    if (c / "expected_ids.json").exists():
        expected = json.loads((c / "expected_ids.json").read_text())
        assert set(expected["ids"]) == set(_ids(g))
        assert [set(t["ids"]) for t in expected["tiers"]] == [
            {ch["id"] for ch in t["checks"]} for t in g["tiers"]
        ]
    else:
        policy = PolicyBundle.load(c).policy
        assert policy.shape == "permit-decides", "only that shape may omit the file"
        assert policy.expected_ids == set(_ids(g))
        assert [{ch["id"] for ch in t["checks"]} for t in policy.inline_guidance()["tiers"]] == [
            {ch["id"] for ch in t["checks"]} for t in g["tiers"]
        ]


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


# -- the corpus loads quietly in its intended configuration ------------------ #
#
# Every adopted fetch plan declares the bundle's primitive vocabulary, and
# three of them declare ``verify_webauthn`` without deriving anything -- the
# correct steady state for an engine that runs crypto in-policy. The derive
# registry has to be configured alongside the engine (``primitives=`` beside
# ``builtins=``), or the load warns about missing configuration on a
# deployment that has none missing. A warning that fires when all is well is
# one people learn to ignore, so the quiet path is pinned.

import logging

from extensible_mcp.bundle import PolicyBundle
from extensible_mcp.fetchplan import default_primitives
from extensible_mcp.wasm_policy import default_builtins

RP_ID = "approval.example"

LOAD_CONFIG = {
    "family_spend": {},
    "cel_family_spend": {},
    "cedar_family_spend": {},
    "cedar_family_spend_compact": {},
    "minimal_spend": {},
    "cel_minimal_spend": {},
    "cedar_minimal_spend": {},
    "family_spend_prod": {},
    "family_spend_webauthn": {"builtins": default_builtins(webauthn_rp_id=RP_ID),
                              "primitives": default_primitives(webauthn_rp_id=RP_ID)},
    "family_spend_invoice": {"builtins": default_builtins(webauthn_rp_id=RP_ID),
                             "primitives": default_primitives(webauthn_rp_id=RP_ID)},
    "cel_family_spend_invoice": {"primitives": default_primitives(webauthn_rp_id=RP_ID)},
}


@pytest.mark.parametrize("bundle", sorted(LOAD_CONFIG))
def test_bundle_loads_with_no_fetchplan_warning_in_its_intended_configuration(bundle, caplog):
    with caplog.at_level(logging.WARNING, logger="extensible_mcp.fetchplan"):
        PolicyBundle.load(FIXTURES / bundle, name=bundle, **LOAD_CONFIG[bundle])
    assert [r.getMessage() for r in caplog.records
            if r.name == "extensible_mcp.fetchplan"] == []


@pytest.mark.parametrize("bundle", sorted(LOAD_CONFIG))
def test_inline_sentences_do_not_drift_from_the_guidance(bundle):
    """A bundle may carry its sentences both inline (CEL ``{"expr",
    "sentence"}``, Cedar ``@sentence``) and in ``guidance.json``. The file
    wins when present, so a drift between the two would be invisible at run
    time; it is pinned here instead, per id, for every bundle that has any."""
    b = PolicyBundle.load(FIXTURES / bundle, name=bundle, **LOAD_CONFIG[bundle])
    inline = getattr(b.policy, "inline_sentences", {})
    by_id = {c["id"]: c["sentence"] for t in _guidance(bundle)["tiers"] for c in t["checks"]}
    for cid, sentence in inline.items():
        assert by_id.get(cid) == sentence, (bundle, cid)


def test_the_warning_still_fires_when_the_registry_is_not_configured(caplog):
    """The quiet path above is quiet because the registry is configured, not
    because the warning is gone: the engine alone leaves ``verify_webauthn``
    declared and unregistered, and that is reported."""
    with caplog.at_level(logging.WARNING, logger="extensible_mcp.fetchplan"):
        PolicyBundle.load(FIXTURES / "family_spend_webauthn", name="w",
                          builtins=default_builtins(webauthn_rp_id=RP_ID))
    messages = [r.getMessage() for r in caplog.records if r.name == "extensible_mcp.fetchplan"]
    assert len(messages) == 1
    assert "verify_webauthn" in messages[0]

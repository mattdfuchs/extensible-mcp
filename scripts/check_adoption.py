#!/usr/bin/env python3
# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Enumerate the upstream toolchain's bundles against ``tests/fixtures/``.

Run by hand, with the upstream tree checked out locally::

    uv run python scripts/check_adoption.py /path/to/upstream

The upstream tree is not available in CI, and a test that skips when it is
absent passes vacuously, which is the thing this check exists to avoid. So
this is a script: it fails loudly, when someone runs it, on a bundle
upstream ships that this repo has neither adopted nor decided not to.

A *bundle* is a directory carrying a ``guidance.json``, the same definition
``tests/test_fixture_corpus.py`` uses. Upstream ``rego/<name>`` pairs with
the local ``<name>``, and ``cel/<name>`` with ``cel_<name>``. A local
directory whose ``PROVENANCE.md`` says it is not derived from any external
toolchain is this repo's own hand-authored bundle, and is never counted as
an adoption of an upstream one that happens to share its name.

Every bundle on either side lands in exactly one of three lists:

- **adopted**: upstream and local both exist and local is not hand-authored.
  The two ``guidance_digest`` values are compared, and so are the three
  engine-independent files byte for byte, so a pin that upstream has moved
  past is reported rather than looking current.
- **not adopted**: upstream ships it; this repo has nothing for it, or only
  a hand-authored bundle of the same name. Fails the run unless the bundle
  is in :data:`NOT_ADOPTED_BY_DECISION` with the reason.
- **local only**: a local bundle no upstream ``rego/`` or ``cel/`` directory
  pairs with -- hand-authored teaching bundles, and the Cedar bundles, which
  are a second bundle over a rule set rather than a twin of one and are
  held to their own relation in ``test_fixture_corpus.py``.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

FIXTURES = Path(__file__).resolve().parent.parent / "tests" / "fixtures"
UPSTREAM_KINDS = ("rego", "cel")
ENGINE_INDEPENDENT = ("manifest.json", "fetchplan.json", "guidance.json")
HAND_AUTHORED_MARKER = "Not derived from any external toolchain"

# Upstream bundles this repo has decided not to adopt, with the reason. An
# entry here is a decision, not a deferral: a bundle merely not yet adopted
# should fail this check until it is adopted or an issue decides otherwise.
NOT_ADOPTED_BY_DECISION = {
    "rego/rebac": (
        "not a proxy filter: a design-demonstration example exercising an "
        "external-relations source kind, one of several such examples"
    ),
    "rego/family_spend": (
        "the local family_spend is this repo's hand-authored teaching bundle, "
        "not this artifact; the README's authoring walk-through is written "
        "against it"
    ),
    "cel/family_spend": (
        "the local cel_family_spend is this repo's hand-authored teaching "
        "bundle, not this artifact; see rego/family_spend"
    ),
}


def local_name(kind: str, name: str) -> str:
    return name if kind == "rego" else f"{kind}_{name}"


def is_bundle(directory: Path) -> bool:
    return (directory / "guidance.json").is_file()


def is_hand_authored(directory: Path) -> bool:
    provenance = directory / "PROVENANCE.md"
    return provenance.is_file() and HAND_AUTHORED_MARKER in provenance.read_text()


def digest_of(directory: Path) -> str | None:
    guidance = json.loads((directory / "guidance.json").read_text())
    return (guidance.get("guidance_digest") or {}).get("value")


def compare_adoption(upstream: Path, local: Path) -> str:
    """One line on how the adopted fixture stands against upstream now."""
    notes = []
    up_digest, local_digest = digest_of(upstream), digest_of(local)
    if up_digest == local_digest:
        notes.append(f"digest {local_digest}")
    else:
        notes.append(f"DIGEST MOVED upstream={up_digest} local={local_digest}")
    differing = [
        name for name in ENGINE_INDEPENDENT
        if (upstream / name).read_bytes() != (local / name).read_bytes()
    ]
    if differing:
        notes.append("differs in " + ", ".join(differing))
    else:
        notes.append("engine-independent files verbatim")
    return "; ".join(notes)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("upstream", type=Path,
                        help="root of the upstream toolchain's checkout")
    args = parser.parse_args(argv)
    upstream_root: Path = args.upstream.resolve()
    if not upstream_root.is_dir():
        parser.error(f"not a directory: {upstream_root}")

    adopted: list[str] = []
    not_adopted: list[str] = []
    undecided = 0
    paired_locals: set[str] = set()

    for kind in UPSTREAM_KINDS:
        kind_dir = upstream_root / kind
        if not kind_dir.is_dir():
            continue
        for directory in sorted(kind_dir.iterdir()):
            if not directory.is_dir() or not is_bundle(directory):
                continue
            key = f"{kind}/{directory.name}"
            local = FIXTURES / local_name(kind, directory.name)
            if local.is_dir() and is_bundle(local) and not is_hand_authored(local):
                paired_locals.add(local.name)
                adopted.append(f"{key} -> {local.name}: {compare_adoption(directory, local)}")
            elif key in NOT_ADOPTED_BY_DECISION:
                not_adopted.append(f"{key}: by decision -- {NOT_ADOPTED_BY_DECISION[key]}")
            else:
                undecided += 1
                not_adopted.append(f"{key}: NO LOCAL BUNDLE AND NO RECORDED DECISION")

    local_only = []
    for directory in sorted(FIXTURES.iterdir()):
        if not directory.is_dir() or not is_bundle(directory) or directory.name in paired_locals:
            continue
        origin = "hand-authored" if is_hand_authored(directory) else "no upstream rego/ or cel/ pairing"
        local_only.append(f"{directory.name}: {origin}")

    for title, rows in (("adopted", adopted), ("not adopted", not_adopted),
                        ("local only", local_only)):
        print(f"{title} ({len(rows)})")
        for row in rows:
            print(f"  {row}")

    stale = [row for row in NOT_ADOPTED_BY_DECISION
             if not (upstream_root / row / "guidance.json").is_file()]
    if stale:
        print("decisions naming a bundle upstream no longer ships: " + ", ".join(stale))

    if undecided:
        sys.stdout.flush()
        print(f"{undecided} upstream bundle(s) neither adopted nor decided against.",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

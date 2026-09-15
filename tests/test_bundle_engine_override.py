# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""PolicyBundle.load()'s ``engine`` override: forcing a choice instead of
inferring one from which artifact the directory happens to contain."""

from __future__ import annotations

from pathlib import Path

import pytest

from extensible_mcp.bundle import PolicyBundle
from extensible_mcp.cel_policy import CelPolicy
from extensible_mcp.wasm_policy import OpaWasmPolicy

REGO_DIR = Path(__file__).parent / "fixtures" / "family_spend"
CEL_DIR = Path(__file__).parent / "fixtures" / "cel_family_spend"


def test_engine_none_infers_from_artifact_presence():
    assert isinstance(PolicyBundle.load(REGO_DIR).policy, OpaWasmPolicy)
    assert isinstance(PolicyBundle.load(CEL_DIR).policy, CelPolicy)


def test_engine_rego_forces_wasm_policy():
    bundle = PolicyBundle.load(REGO_DIR, engine="rego")
    assert isinstance(bundle.policy, OpaWasmPolicy)


def test_engine_cel_forces_cel_policy():
    bundle = PolicyBundle.load(CEL_DIR, engine="cel")
    assert isinstance(bundle.policy, CelPolicy)


def test_engine_cel_without_artifact_raises():
    with pytest.raises(FileNotFoundError, match="checks.cel.json"):
        PolicyBundle.load(REGO_DIR, engine="cel")


def test_engine_rego_without_artifact_raises():
    with pytest.raises(FileNotFoundError, match="policy.wasm"):
        PolicyBundle.load(CEL_DIR, engine="rego")

# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""A second :class:`~extensible_mcp.policy_engine.PolicyEngine`: CEL-authored
policy bundles evaluated in-process via ``cel-python``.

Design and the empirical semantic-parity mapping against the OPA/Rego engine
are in NOTES.md ("CEL as a Second Policy Engine"). The one rule that mapping
concluded, stated here because it is the load-bearing correctness property:

**Any exception during evaluation — a structural CEL fault (missing field,
type mismatch) or a raised** ``HostBuiltinError`` **from a registered
builtin — is fail-closed, unconditionally, with no inspection of the
exception's type.** ``cel-python`` does not reliably wrap a custom
function's raised exception in ``CELEvalError`` (confirmed empirically: it
can propagate raw), so classifying by *what* was raised is unsound. Only a
clean, non-exceptional boolean return is a legitimate pass/fail signal — an
evidentiary denial must be an explicit ``false`` the bundle author wrote
(via ``has()`` guards), never an artifact of the runtime raising.

``checks.cel.json`` (the bundle's CEL artifact) shape::

    {"engine": "cel-v1",
     "package": "<entrypoint prefix>",
     "tiers": [{"tier": 0, "checks": ["t0.c0", ...]}, ...],
     "checks": {"t0.c0": "<CEL expression, authored positively>", ...}}

Checks are authored positively (must evaluate ``true`` to pass) — the
opposite polarity from Rego bundles' failure-form ``condition`` strings in
``guidance.json``. This has no effect on :func:`extensible_mcp.guidance.render_denial`,
which never reads ``condition``, only ``sentence``/``remedy_class``/``id``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from .wasm_policy import (
    HostBuiltinError,
    PolicyEvaluationError,
    _b64url_bytes,
    _b64url_encode_no_pad,
    _key_from_did_key,
    _sha256,
    _verify_eddsa,
    _verify_ed25519_raw,
)

_MISSING_DEPS_MSG = (
    "The CEL policy engine requires 'cel-python'. "
    "Install it with: pip install 'extensible-mcp[cel]'"
)


# --------------------------------------------------------------------------- #
# Default CEL functions — thin celtypes adapters over the *same* plain-Python
# crypto builtins the OPA engine uses. Same contracts, same exception types:
# False/None for an evidence problem, HostBuiltinError for a system fault.
# --------------------------------------------------------------------------- #


def default_cel_functions(*, webauthn_rp_id: str | None = None) -> dict[str, Callable[..., Any]]:
    from celpy import celtypes

    def _py(v: Any) -> Any:
        """Unwrap a celtypes value to a plain Python object (str/dict/list/
        bool/int/None) for handoff to the shared builtin functions."""
        if isinstance(v, celtypes.NullType) or v is None:
            return None
        if isinstance(v, celtypes.MapType):
            return {_py(k): _py(val) for k, val in v.items()}
        if isinstance(v, celtypes.ListType):
            return [_py(x) for x in v]
        if isinstance(v, celtypes.BoolType):  # BoolType subclasses int, not bool
            return bool(v)
        if isinstance(v, celtypes.StringType):
            return str(v)
        if isinstance(v, celtypes.IntType):
            return int(v)
        if isinstance(v, celtypes.DoubleType):
            return float(v)
        return v

    def verify_eddsa(jws: Any, jwk: Any) -> "celtypes.BoolType":
        return celtypes.BoolType(_verify_eddsa(_py(jws), _py(jwk)))

    def key_from_did_key(did: Any) -> Any:
        key = _key_from_did_key(_py(did))
        return celtypes.NullType() if key is None else celtypes.MapType(
            {celtypes.StringType(k): celtypes.StringType(v) for k, v in key.items()}
        )

    def sha256(value: Any) -> "celtypes.StringType":
        return celtypes.StringType(_sha256(_py(value)))

    def base64url_encode_no_pad(value: Any) -> "celtypes.StringType":
        return celtypes.StringType(_b64url_encode_no_pad(_py(value)))

    def verify_ed25519_raw(message: Any, sig: Any, key: Any) -> "celtypes.BoolType":
        return celtypes.BoolType(_verify_ed25519_raw(_py(message), _py(sig), _py(key)))

    def parse_json(value: Any) -> Any:
        """CEL twin of Rego's ``json.unmarshal`` — needed because a bundle
        parses signed evidence (an invoice, a WebAuthn clientDataJSON)
        *inside* the policy rather than having the proxy parse it first,
        which would sever the parsed fields from the signature that covers
        the original bytes."""
        import celpy

        return celpy.json_to_cel(json.loads(str(_py(value))))

    def base64url_decode(value: Any) -> "celtypes.StringType":
        """CEL twin of Rego's ``base64url.decode``."""
        return celtypes.StringType(_b64url_bytes(str(_py(value))).decode())

    functions: dict[str, Callable[..., Any]] = {
        "verify_eddsa": verify_eddsa,
        "key_from_did_key": key_from_did_key,
        "sha256": sha256,
        "base64url_encode_no_pad": base64url_encode_no_pad,
        "verify_ed25519_raw": verify_ed25519_raw,
        "parse_json": parse_json,
        "base64url_decode": base64url_decode,
    }
    if webauthn_rp_id is not None:
        from .wasm_policy import make_verify_webauthn

        _verify_webauthn = make_verify_webauthn(webauthn_rp_id)

        def verify_webauthn(auth_data: Any, cd: Any, sig: Any, jwk: Any) -> "celtypes.BoolType":
            return celtypes.BoolType(_verify_webauthn(_py(auth_data), _py(cd), _py(sig), _py(jwk)))

        functions["verify_webauthn"] = verify_webauthn
    return functions


class CelPolicy:
    """Loads one CEL-authored bundle (``checks.cel.json``) and evaluates it
    in-process. Implements the :class:`~extensible_mcp.policy_engine.PolicyEngine`
    Protocol: same ``entrypoints()``/``query()`` shape as ``OpaWasmPolicy``,
    so :mod:`wasm_filter` cannot tell the two apart."""

    def __init__(
        self,
        checks_path: str | Path,
        *,
        functions: dict[str, Callable[..., Any]] | None = None,
    ) -> None:
        try:
            import celpy
        except ImportError as e:  # pragma: no cover - exercised via env
            raise ImportError(_MISSING_DEPS_MSG) from e

        spec = json.loads(Path(checks_path).read_text())
        self._package: str = spec["package"]
        self._tiers: list[dict[str, Any]] = spec["tiers"]
        self._guards: dict[str, list[str]] = spec.get("guards") or {}
        self._functions = dict(functions or default_cel_functions())

        env = celpy.Environment()
        self._programs: dict[str, Any] = {}
        for check_id, expr in spec["checks"].items():
            ast = env.compile(expr)
            self._programs[check_id] = env.program(ast, functions=self._functions)
        self._celpy = celpy

    # -- PolicyEngine Protocol ------------------------------------------- #

    def entrypoints(self) -> list[str]:
        return [f"{self._package}/allow", f"{self._package}/failed_checks"]

    def query(self, input_obj: Any, entrypoint: str) -> Any:
        if entrypoint not in self.entrypoints():
            raise PolicyEvaluationError(
                f"unknown entrypoint {entrypoint!r}; have {self.entrypoints()}"
            )
        results = self._evaluate_all(input_obj)
        allowed = any(
            all(results[cid] for cid in tier["checks"])
            for tier in self._tiers
        )
        if entrypoint.endswith("/allow"):
            return [{"result": allowed}]
        # allow ⟺ failed_checks == [] is a structural Rego invariant (every
        # failed_checks rule there requires `not allow`) -- preserve it here
        # too, rather than reporting a tier's locally-false, globally-moot
        # checks (e.g. tier 1's own bounds) when some other tier already
        # allowed the call.
        if allowed:
            return [{"result": []}]
        failed = [cid for cid, passed in results.items() if not passed]
        # A check written `has(f) && <cond>` evaluates cleanly to False when
        # `f` is a genuinely absent optional field -- correct for the AND-fold
        # `allow` needs, but a false positive as a *reported* failure reason
        # (the check didn't fail, it was never applicable). `guards` names,
        # per check id, which top-level fields must be present for a `false`
        # to mean a real failure; drop ids where any guarded field is absent
        # -- the renderer's own absent-field fallback names the credential
        # instead. Mirrors Rego's `undefined` (no id) for the same case.
        if self._guards and isinstance(input_obj, dict):
            failed = [
                cid for cid in failed
                if not (set(self._guards.get(cid, ())) - set(input_obj))
            ]
        return [{"result": sorted(failed)}]

    # -- evaluation ------------------------------------------------------- #

    def _evaluate_all(self, input_obj: Any) -> dict[str, bool]:
        """Evaluate every named check once. Any exception at all — a
        structural CEL fault or a raised HostBuiltinError from a builtin —
        aborts the whole query as PolicyEvaluationError (fail-closed, no
        partial result); see the module docstring for why type-sniffing the
        exception is unsound and was deliberately not attempted."""
        activation = self._celpy.json_to_cel({"input": input_obj})
        out: dict[str, bool] = {}
        for check_id, program in self._programs.items():
            try:
                result = program.evaluate(activation)
            except Exception as e:  # noqa: BLE001 - deliberately unconditional, see docstring
                raise PolicyEvaluationError(
                    f"check {check_id!r} could not be evaluated (failing closed): {e}"
                ) from e
            out[check_id] = bool(result)
        return out

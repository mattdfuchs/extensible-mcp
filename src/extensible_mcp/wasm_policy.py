# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""In-process evaluation of OPA-compiled (WASM) Rego policies.

A policy-authoring toolchain compiles a policy to a ``.wasm`` module via
``opa build -t wasm``. The crypto built-ins a credential policy needs —
``io.jwt.verify_*``, ``crypto.sha256`` — are *not* bundled into that module;
OPA emits them as host-provided imports. This module loads the wasm via
``wasmtime`` and supplies those built-ins from Python, so the whole policy
(signature checks included) runs in-process with no external OPA binary.

The load-bearing distinction: a built-in must separate *verification failed*
— a legitimate ``false`` the policy reads as a denial — from *the built-in
itself erroring* (malformed JWK, unsupported algorithm). The former returns
``False``; the latter raises ``HostBuiltinError``, which surfaces as
``PolicyEvaluationError`` and must be treated as fail-closed, never as a
quiet policy "deny".

``wasmtime`` and ``joserfc`` are optional; install via ``pip install
extensible-mcp[wasm]`` (or ``uv sync --group dev``).
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any

logger = logging.getLogger("extensible_mcp.wasm_policy")

# base58btc alphabet (Bitcoin / multibase 'z').
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
# Multicodec varint prefix for an Ed25519 public key (0xed -> varint 0xed 0x01).
_ED25519_MULTICODEC = b"\xed\x01"

_MISSING_DEPS_MSG = (
    "The WASM policy engine requires 'wasmtime' and 'joserfc'. "
    "Install them with: pip install 'extensible-mcp[wasm]'"
)


class PolicyEvaluationError(Exception):
    """A policy could not be evaluated (wasm trap, or a host built-in errored).

    This is distinct from a clean ``allow = false`` denial. Callers must treat
    it as fail-closed: deny the call, but surface it as an error, not as a
    policy decision.
    """


class HostBuiltinError(Exception):
    """Raised by a host built-in when it cannot produce a result.

    A *malformed* input (bad JWK, unknown algorithm) is an error, not a
    ``false`` answer — raising this keeps "the credential's signature did not
    verify" (a denial) distinct from "we could not check the signature at all"
    (fail closed).
    """


# --------------------------------------------------------------------------- #
# Default crypto host built-ins
# --------------------------------------------------------------------------- #


def _sha256(value: Any) -> str:
    """OPA ``crypto.sha256(string) -> hex string``."""
    if not isinstance(value, str):
        raise HostBuiltinError(f"crypto.sha256 expects a string, got {type(value).__name__}")
    return hashlib.sha256(value.encode()).hexdigest()


def _verify_eddsa(jws: Any, jwk: Any) -> bool:
    """OPA ``io.jwt.verify_eddsa(jws, jwk) -> bool``: verify an EdDSA-signed
    compact JWS against a JWK.

    The ``jwk`` operand reaches this builtin from two kinds of source, handled
    by shape:

    - a **JWK string** — deployment config (the trust root). If it is present
      but unparseable that is a *system* fault → ``HostBuiltinError`` (fail
      closed); a broken verifier must never read as a quiet "deny".
    - a **JWK object** — produced in-policy by ``key_from_did_key`` from a
      credential's ``did:key``. Used as-is.
    - **``None``** — no usable key for this signer (a malformed ``did:key``
      yields ``None``, or config is simply absent). Without a key the signature
      cannot be checked, so this is a ``False`` denial, *not* fail-closed —
      which also means a bad ``did:key`` in one tier never traps evaluation of
      another tier.

    ``jws`` is **LLM-supplied evidence**: anything wrong with it (missing,
    malformed, bad signature) is just a ``False`` denial.
    """
    from joserfc import jws as joserfc_jws
    from joserfc.jwk import OKPKey

    if jwk is None:
        return False  # no key to verify against → deny (not a system fault)
    if isinstance(jwk, dict):
        key_data: Any = jwk  # an in-policy did:key-derived JWK
    elif isinstance(jwk, str):
        try:
            key_data = json.loads(jwk)
        except Exception as e:  # noqa: BLE001 - corrupt config string is fail-closed
            raise HostBuiltinError(f"io.jwt.verify_eddsa: unparseable JWK: {e}") from e
    else:
        raise HostBuiltinError(
            f"io.jwt.verify_eddsa: JWK must be object, string, or null, "
            f"got {type(jwk).__name__}"
        )
    try:
        key = OKPKey.import_key(key_data)
    except Exception as e:  # noqa: BLE001
        raise HostBuiltinError(f"io.jwt.verify_eddsa: invalid JWK: {e}") from e

    # Evidence — any problem is a denial, not an error.
    if not isinstance(jws, str):
        return False
    try:
        # Accept both header names for the same signature scheme: the
        # curve-specific RFC 9864 name ("Ed25519") the identity layer signs
        # with, and the older generic "EdDSA" name (RFC 8037; stock OPA's
        # own `io.jwt.verify_eddsa` docs use it, so a bundle's own test
        # signers commonly do too). Same key, same bytes verified — the
        # header name is deployment convention, not a trust boundary, so
        # rejecting one silently was a needless interop failure with no
        # diagnostic beyond "signature is invalid".
        joserfc_jws.deserialize_compact(jws, key, algorithms=["Ed25519", "EdDSA"])
        return True
    except Exception:  # noqa: BLE001 - bad signature or malformed token → deny
        return False


def _b58decode(s: str) -> bytes:
    """Decode a base58btc string to bytes."""
    num = 0
    for ch in s:
        num = num * 58 + _B58.index(ch)  # ValueError on a non-alphabet char
    body = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + body


def _key_from_did_key(did: Any) -> dict[str, Any] | None:
    """Derive an Ed25519 JWK from a ``did:key`` (host builtin ``key_from_did_key``).

    Returns a JWK object on success, or ``None`` for any malformed/non-Ed25519
    input — a missing key, not an error, so a bad ``did:key`` degrades to a
    signature-verification denial rather than trapping the policy. Pure: no I/O.
    """
    if not isinstance(did, str) or not did.startswith("did:key:z"):
        logger.warning("key_from_did_key: not a base58btc did:key: %r", did)
        return None
    try:
        raw = _b58decode(did[len("did:key:z"):])
    except ValueError:
        logger.warning("key_from_did_key: invalid base58 in %r", did)
        return None
    if raw[:2] != _ED25519_MULTICODEC or len(raw) != 2 + 32:
        logger.warning("key_from_did_key: not an Ed25519 multicodec key: %r", did)
        return None
    x = base64.urlsafe_b64encode(raw[2:]).rstrip(b"=").decode()
    return {"kty": "OKP", "crv": "Ed25519", "x": x}


def _b64url_bytes(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64url_encode_no_pad(value: Any) -> str:
    """OPA ``base64url.encode_no_pad(string) -> string``.

    A standard OPA builtin, but the wasm compiler does not inline it — the
    module imports it from the host (like the SDK-provided builtins), so the
    proxy supplies it. Pure; a non-string operand is a type fault."""
    if not isinstance(value, str):
        raise HostBuiltinError(
            f"base64url.encode_no_pad expects a string, got {type(value).__name__}"
        )
    return base64.urlsafe_b64encode(value.encode()).rstrip(b"=").decode()


def _verify_ed25519_raw(message: Any, sig_b64url: Any, key_b64url: Any) -> bool:
    """Host builtin ``verify_ed25519_raw(message, sig, key) -> bool``.

    Verifies a raw Ed25519 signature over ``message`` — the exact string the
    signer produced and signed, never re-canonicalized in-policy (the
    wire-form principle, applied to a merchant's invoice) — where ``sig`` and
    ``key`` are base64url-encoded *raw* bytes, not a JOSE/JWK object. That's
    the shape an external counterparty's Ed25519 keypair naturally has (a
    merchant isn't a did:key/did:web member of the trust network), which is
    why this is a distinct builtin from ``io.jwt.verify_eddsa`` rather than a
    JWK-wrapping shim.

    ``key_b64url`` is deployment config — a trusted-merchant public key looked
    up by the caller's own policy before this builtin ever runs. Malformed
    config is a system fault: ``HostBuiltinError``, fail closed. ``None``
    (e.g. an absent lookup key evaluated defensively) is a clean denial, not
    an error — matching ``_verify_eddsa``'s treatment of a missing JWK.
    ``message``/``sig_b64url`` are LLM-relayed evidence: anything wrong with
    them is just a ``False`` denial, never fail-closed.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    if key_b64url is None:
        return False
    if not isinstance(key_b64url, str):
        raise HostBuiltinError(
            f"verify_ed25519_raw: key must be a base64url string, "
            f"got {type(key_b64url).__name__}"
        )
    try:
        public_key = Ed25519PublicKey.from_public_bytes(_b64url_bytes(key_b64url))
    except Exception as e:  # noqa: BLE001 - malformed configured key is a system fault
        raise HostBuiltinError(f"verify_ed25519_raw: invalid public key: {e}") from e

    if not isinstance(message, str) or not isinstance(sig_b64url, str):
        return False
    try:
        signature = _b64url_bytes(sig_b64url)
    except Exception:  # noqa: BLE001 - malformed evidence -> deny, not fail-closed
        return False
    try:
        public_key.verify(signature, message.encode())
    except InvalidSignature:
        return False
    return True


def make_verify_webauthn(rp_id: str) -> Callable[..., Any]:
    """Build the ``verify_webauthn(authData, clientDataJSON, sig, jwk) -> bool``
    host builtin for one relying party.

    The wasm ABI caps host builtins at four arguments, so the
    relying-party id is *proxy configuration* baked in here rather than a
    policy input. The builtin checks the ES256/P-256 signature over
    ``authenticatorData ‖ SHA-256(clientDataJSON)``, the rpId hash, the
    user-present and user-verified flags, and ``clientData.type ==
    "webauthn.get"`` — and deliberately **not** the challenge or the origin:
    both live in the policy (``spend_challenge_binds`` / the
    ``webauthn_verified`` template), so the faithfulness theorem covers "the
    signature is over the exact action".

    Every operand is evidence — the assertion fields come off the approval
    page and the JWK rides in the admin-signed enrollment credential (whose
    own signature ``enrolled_as`` checks separately) — so anything malformed
    is a ``False`` denial, never fail-closed. The one deployment fault, a
    missing rpId, is rejected here at configuration time.
    """
    if not rp_id or not isinstance(rp_id, str):
        raise ValueError("verify_webauthn requires a non-empty relying-party id")
    rp_id_hash = hashlib.sha256(rp_id.encode()).digest()

    def _verify_webauthn(auth_data: Any, client_data_json: Any, sig: Any, jwk: Any) -> bool:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec

        if isinstance(jwk, str):
            try:
                jwk = json.loads(jwk)
            except ValueError:
                return False
        if not isinstance(jwk, dict) or jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
            return False
        if not all(isinstance(v, str) for v in (auth_data, client_data_json, sig)):
            return False
        try:
            x = _b64url_bytes(jwk["x"])
            y = _b64url_bytes(jwk["y"])
            ad = _b64url_bytes(auth_data)
            cd = _b64url_bytes(client_data_json)
            signature = _b64url_bytes(sig)
        except (KeyError, ValueError):
            return False
        try:
            key = ec.EllipticCurvePublicNumbers(
                int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()
            ).public_key()
        except ValueError:
            return False

        try:
            client_data = json.loads(cd)
        except ValueError:
            return False
        if not isinstance(client_data, dict) or client_data.get("type") != "webauthn.get":
            return False
        # authData: rpIdHash(32) + flags(1) + signCount(4); UP=0x01, UV=0x04.
        if len(ad) < 37 or ad[:32] != rp_id_hash:
            return False
        if not (ad[32] & 0x01) or not (ad[32] & 0x04):
            return False
        try:
            key.verify(
                signature, ad + hashlib.sha256(cd).digest(), ec.ECDSA(hashes.SHA256())
            )
        except InvalidSignature:
            return False
        return True

    return _verify_webauthn


def default_builtins(*, webauthn_rp_id: str | None = None) -> dict[str, Callable[..., Any]]:
    """The crypto built-ins a credential policy expects from its host.

    ``key_from_did_key`` is included for the production multi-key policy (it
    derives a verifier key from a credential's ``did:key``); policies that don't
    use it simply never call it. ``verify_webauthn`` is registered only when a
    relying-party id is configured — loading a WebAuthn policy without one
    fails at load time (the builtin-availability check), not as a quiet deny.
    """
    builtins: dict[str, Callable[..., Any]] = {
        "crypto.sha256": _sha256,
        "io.jwt.verify_eddsa": _verify_eddsa,
        "key_from_did_key": _key_from_did_key,
        "base64url.encode_no_pad": _b64url_encode_no_pad,
        "verify_ed25519_raw": _verify_ed25519_raw,
    }
    if webauthn_rp_id is not None:
        builtins["verify_webauthn"] = make_verify_webauthn(webauthn_rp_id)
    return builtins


# --------------------------------------------------------------------------- #
# OPA-WASM ABI harness
# --------------------------------------------------------------------------- #


class OpaWasmPolicy:
    """Loads one OPA-compiled policy module and evaluates it in-process.

    The module is instantiated once; each :meth:`query` runs a fresh evaluation
    context, so a single instance is reusable across calls. Not thread-safe — a
    wasm ``Store`` is single-threaded; use one instance per worker.
    """

    def __init__(
        self,
        wasm_path: str | Path,
        *,
        builtins: dict[str, Callable[..., Any]] | None = None,
    ) -> None:
        try:
            import wasmtime
        except ImportError as e:  # pragma: no cover - exercised via env
            raise ImportError(_MISSING_DEPS_MSG) from e

        self._wasmtime = wasmtime
        self._impls: dict[str, Callable[..., Any]] = (
            default_builtins() if builtins is None else dict(builtins)
        )
        # Set when a host built-in raises, so a wasm trap can be re-surfaced
        # with the real cause rather than an opaque trap message.
        self._pending_error: HostBuiltinError | None = None

        self._store = wasmtime.Store()
        module = wasmtime.Module.from_file(self._store.engine, str(wasm_path))
        self._memory = wasmtime.Memory(
            self._store,
            next(i.type for i in module.imports if i.name == "memory"),
        )
        self._instance = wasmtime.Instance(
            self._store, module, self._build_imports(module)
        )

        # builtin-name -> integer id the module dispatches on, and the
        # entrypoint-path -> id map.
        self._builtin_ids = {
            v: k for k, v in self._dump(self._exp("builtins")(self._store)).items()
        }
        self._entrypoints: dict[str, int] = self._dump(
            self._exp("entrypoints")(self._store)
        )
        self._verify_builtins_available()

    # -- exports / memory helpers ------------------------------------------- #

    def _exp(self, name: str):
        return self._instance.exports(self._store)[name]

    def _read_cstr(self, addr: int) -> str:
        data = self._memory.read(self._store, addr, self._memory.data_len(self._store))
        return data[: data.index(0)].decode()

    def _dump(self, value_addr: int) -> Any:
        """Marshal an OPA value address out to a Python object."""
        return json.loads(self._read_cstr(self._exp("opa_json_dump")(self._store, value_addr)))

    def _load(self, obj: Any) -> int:
        """Marshal a Python object into an OPA value, returning its address."""
        raw = json.dumps(obj).encode()
        ptr = self._exp("opa_malloc")(self._store, len(raw))
        self._memory.write(self._store, raw, ptr)
        return self._exp("opa_json_parse")(self._store, ptr, len(raw))

    # -- host imports ------------------------------------------------------- #

    def _build_imports(self, module) -> list:
        wasmtime = self._wasmtime
        i32 = wasmtime.ValType.i32()

        def ft(n_args: int) -> "wasmtime.FuncType":
            return wasmtime.FuncType([i32] * n_args, [i32])

        def make_dispatch(n_operands: int):
            # opa_builtinN(builtin_id, ctx, *operand_addrs) -> result_addr
            def dispatch(builtin_id: int, _ctx: int, *operand_addrs: int) -> int:
                name = self._builtin_ids.get(builtin_id, f"<id {builtin_id}>")
                impl = self._impls.get(name)
                if impl is None:
                    self._pending_error = HostBuiltinError(
                        f"policy needs unregistered built-in {name!r}"
                    )
                    raise self._pending_error
                args = [self._dump(a) for a in operand_addrs[:n_operands]]
                try:
                    result = impl(*args)
                except HostBuiltinError as e:
                    self._pending_error = e
                    raise
                except Exception as e:  # noqa: BLE001 - normalize to fail-closed
                    self._pending_error = HostBuiltinError(
                        f"built-in {name!r} raised: {e}"
                    )
                    raise self._pending_error from e
                return self._load(result)

            return dispatch

        def opa_abort(addr: int) -> None:
            msg = self._read_cstr(addr)
            self._pending_error = HostBuiltinError(f"opa_abort: {msg}")
            raise self._pending_error

        by_name: dict[str, Any] = {
            "memory": self._memory,
            "opa_abort": wasmtime.Func(
                self._store, wasmtime.FuncType([i32], []), opa_abort
            ),
        }
        for n in range(5):
            by_name[f"opa_builtin{n}"] = wasmtime.Func(
                self._store, ft(n + 2), make_dispatch(n)
            )
        # Preserve the module's declared import order.
        return [by_name[imp.name] for imp in module.imports]

    # -- public API --------------------------------------------------------- #

    def entrypoints(self) -> list[str]:
        """The rule paths this module exposes (e.g. ``pkg/allow``)."""
        return list(self._entrypoints)

    def query(self, input_obj: Any, entrypoint: str) -> Any:
        """Evaluate ``entrypoint`` against ``input_obj``; return the result.

        The return value is OPA's result-set shape, e.g. ``[{"result": true}]``
        for a defined boolean rule, or ``[]`` when the rule is undefined.

        Raises :class:`PolicyEvaluationError` on a wasm trap or a host built-in
        error (fail-closed), with the underlying cause attached.
        """
        if entrypoint not in self._entrypoints:
            raise PolicyEvaluationError(
                f"unknown entrypoint {entrypoint!r}; have {self.entrypoints()}"
            )

        self._pending_error = None
        store = self._store
        try:
            ctx = self._exp("opa_eval_ctx_new")(store)
            self._exp("opa_eval_ctx_set_data")(store, ctx, self._load({}))
            self._exp("opa_eval_ctx_set_input")(store, ctx, self._load(input_obj))
            self._exp("opa_eval_ctx_set_entrypoint")(
                store, ctx, self._entrypoints[entrypoint]
            )
            rc = self._exp("eval")(store, ctx)
        except Exception as e:  # noqa: BLE001 - wasm traps land here
            if self._pending_error is not None:
                raise PolicyEvaluationError(str(self._pending_error)) from self._pending_error
            raise PolicyEvaluationError(f"wasm evaluation trapped: {e}") from e

        if rc != 0:
            raise PolicyEvaluationError(f"opa eval returned non-zero status {rc}")
        return self._dump(self._exp("opa_eval_ctx_get_result")(store, ctx))

    def _verify_builtins_available(self) -> None:
        missing = [name for name in self._builtin_ids.values() if name not in self._impls]
        if missing:
            raise PolicyEvaluationError(
                f"policy needs host built-ins with no registered impl: {sorted(missing)}"
            )

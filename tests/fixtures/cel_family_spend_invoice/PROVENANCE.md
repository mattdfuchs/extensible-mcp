# Fixture provenance — cel_family_spend_invoice (CEL twin, invoice-bound leg)

Supplied by an external policy-authoring toolchain — the CEL twin of
`family_spend_invoice`, emitted from the same common core rather than
translated from the Rego bundle. Because both artifacts are generated,
their agreement on every test scenario in `tests/test_invoice_policy.py`
(parametrized to run against both engines) isn't two authors corroborating
each other. What it does check is that two quite different runtimes — a
WASM module and in-process CEL evaluation — reach the same decision
through the same host builtins, and that the check ids, which come from
separate expansions that neither language validates, still line up. All of
it against this repo's own engines rather than a harness belonging to the
supplier.

This is the first CEL bundle in this repo governing a production-shaped
(not teaching) policy — see `cel_family_spend`'s own PROVENANCE.md for the
hand-authored teaching bundle this is not related to.

- Package: `policybundle.examples.family_spend_invoice` — anonymized for
  this public release, matching `family_spend_invoice`'s own package name
  (both bundles' entrypoints resolve under the same logical name; only
  the `/`-vs-`.` separator differs, an artifact of how OPA's `-e` compile
  flags vs. a plain JSON `"package"` field each spell the same path)
- Entrypoints: `allow`, `failed_checks` — **no `deny_reason`**; CEL
  bundles in this repo never expose one (see `cel_policy.CelPolicy.entrypoints()`)
- Required two new host functions this repo's CEL engine did not have
  before adopting this bundle: `parse_json` (CEL twin of Rego's
  `json.unmarshal`) and `base64url_decode` (twin of `base64url.decode`).
  Needed because the invoice and a WebAuthn `clientDataJSON` are parsed
  *inside* the policy — parsing them outside and passing fields in would
  sever them from the signatures that cover the original bytes. Both are
  now in `cel_policy.default_cel_functions` unconditionally (no
  capability flag), so any bundle can use them.
- `guards` (`checks.cel.json`'s own field, distinct from the Rego
  bundle's `fetchplan.json` guard entries but serving the same purpose)
  correctly excludes the parent-leg checks when `parentApproval`/
  `parentEnrollment` are genuinely absent below the $10 threshold —
  verified in `test_invoice_policy.py::test_dual_tier_denies_without_parent`.
- **Cross-engine divergence, not a defect in this bundle:** on a
  genuinely missing *unconditionally-required* field (e.g. `childApproval`
  absent entirely, an out-of-contract input the proxy's own fetch-plan
  assembly would never produce), this CEL bundle raises
  `PolicyEvaluationError` — this repo's own CEL engine is fail-closed by
  design on any exception, with no attempt to distinguish "a structural
  fault" from "an evidentiary denial." The Rego twin evaluates around the
  same missing field via Rego's undefined-propagation and returns a
  `failed_checks` set without raising. See `family_spend_invoice`'s own
  PROVENANCE.md for the fuller note; pinned down by
  `test_engines_diverge_on_a_genuinely_missing_required_field`.

## Rebuild

Nothing to build — `checks.cel.json` is plain, interpreted CEL source;
there is no compile step. If replacing this fixture with a newer version
from the supplier, verify byte-for-byte against `test_invoice_policy.py`
before and after, same discipline as every other supplied bundle here.

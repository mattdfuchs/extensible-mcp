# Fixture provenance — cedar_approval (Cedar, entity attributes on the resource)

A document-finalize rule: the requester is one of the document's required
approvers, the document is in review, and every required approver has
approved. Three conditions, no evidence, no tiers but one. It is in the
corpus for one reason: it is the first supplied bundle whose fetch plan
carries an **`entities` block**, so it is the fixture that pins the loader's
reading of that block — the resource is a `Document` whose attributes are
the input's `status`, `requiredApprovers` and `currentApprovals`, moved out
of `context` and read as `resource.status`, `resource.currentApprovals
.containsAll(resource.requiredApprovers)`.

**Supplied by an external policy-authoring toolchain**, emitted from its own
`approval` core in the permit-decides shape at upstream commit `64c41c5`,
where it is the toolchain's port of a public Cedar benchmark scenario
(`approval_chain_workflow`, requirement 3) and not a proxy deliverable: a
closed input of four `call`-sourced fields, one of which, `principal`, is
the requester's id *as the call supplies it*. In the proxy's threat model a
call-sourced identity is the model naming itself, which is why the bundle is
adopted as a **loader-grammar fixture** and nothing more — it is never
attached to a server in any example. `cedar_family_hierarchy` is the fixture
that shows a principal reached the proxy's way, through a `caller`-sourced
entry. Generator-internal names were anonymized as for every supplied bundle;
nothing executable changed. Digest of the **unedited** `policy.cedar` as
published:

```
sha256  63154b03b44a084abd88cda494c7891b8a2172a0a42d397a3fba6d654aeab0ca
bytes   4,055
```

| file | origin |
|---|---|
| `policy.cedar` | supplied: 1 `@tier` permit, 3 `@id` forbids, 1 `@assembly` forbid; `resource.<f>` reads under `resource has f` guards |
| `expected_ids.json` | supplied: the 3 ids and 1 tier, `"shape": "permit-decides"` |
| `contract.json` | supplied: no derivation obligations (nothing is a verification), the certificate's nine hypotheses with an owner each, `typed` empty |
| `manifest.json` | supplied: four required fields, closed |
| `fetchplan.json` | supplied: four `call` entries, and the `entities` block — `principal` is `Caller::"<caller.sub>"` (anonymous here, since no entry is named `caller`), `resource` is `Document::"<package>"` with the three attributes |
| `schema.json` | supplied: derived from the manifest and the block — `Document` carries the three attributes, `Caller` none, the one action's context is `principal` plus the optional `probe` |
| `guidance.json` | supplied; `guidance_digest.value = "c68cd58bb37bbdb9"` |

`tests/test_cedar_store.py` runs the supplier's own scenario table against
this bundle through the loader and holds the decisions and the fired ids to
the supplier's: the store the proxy forms from the block is the one the
supplier's differential formed from the same block. The schema is validated
against at load and never passed to `is_authorized`.

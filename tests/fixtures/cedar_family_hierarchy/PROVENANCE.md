# Fixture provenance — cedar_family_hierarchy (Cedar, the entity store and `in`)

Not derived from any external toolchain. Hand-authored directly for this
repository: the first bundle in the corpus whose policy tests hierarchy
membership, and the one that shows where every edge in the proxy's entity
store comes from. A parent in the household may spend up to $50 on a server
the deployment places in its organization — six conditions, one tier, in
the permit-decides shape of `../cedar_minimal_spend`.

**The three edges, from the three sources a fetch plan has.** Cedar's `in`
is a lookup in the subject's closed ancestor set; the proxy forms that set
from the plan. `fetchplan.json`'s `entities` block names three *membership
fields*, each a list of entity references, and the loader makes them the
principal's and the resource's parents before `is_authorized`:

| edge | field | source | why that type name |
|---|---|---|---|
| `principal in IdpRole::"parent"` | `callerIdpRoles` | `derive`: `entity_refs("IdpRole", caller.roles)` over the `caller` entry's roles claim | the IdP's word about the principal, under a type that says so — lexically apart from any admin-vouched role in the evidence |
| `resource in Org::"acme"` | `serverOrgs` | `config`: the operator's list of `Org` references | the deployment's word about its own server, written once per bundle |
| `principal in Family::"household"` | `callerFamilies` | `derive`: `verify_eddsa` folded over the trust root's key, projecting a `Family` reference | the edge exists only if the membership credential's signature verified against the key the deployment trusts |

Nothing enters the store undeclared, and each edge's provenance is the plan
entry that produced it. The `entity_refs` primitive takes its type as a
plan literal, never from data, so no input can pick the relation it joins.

**The schema is the contract on `in`.** `schema.json` declares `Caller
memberOf [IdpRole, Family]` and `Server memberOf [Org]` and nothing else.
The loader validates `policy.cedar` against it at load (Cedar's own
validator, as a hard gate) and refuses an `in` over any relation the schema
does not declare — Cedar would type such a test as `false` and report
nothing. A bundle without a schema has every `in` refused outright, as every
Cedar bundle did before this one.

| file | origin |
|---|---|
| `policy.cedar` | hand-written: 1 `@tier` permit, 6 `@id` forbids with `@sentence`, 1 `@assembly` forbid |
| `manifest.json` | hand-written; `IdpRole`, `Family` and `Org` are closed Draft-7 definitions of the entity-reference shape `{"type": {"const": …}, "id"}`; the two derived fields are in `properties` and never `required` |
| `fetchplan.json` | hand-written: three `call` entries, two `config`, one `clock`, one `caller` (`fields: [sub, roles]`), two `derive`, the `primitives` block, and the `entities` block with its three `memberships` |
| `schema.json` | hand-written: the manifest in Cedar's schema notation, with the two `memberOfTypes` declarations |
| `guidance.json` | hand-written, the same sentences the `@sentence` annotations carry; `tests/test_fixture_corpus.py` holds the two identical |

`tests/test_cedar_store.py` runs the scenarios: every edge present allows;
each edge absent — the child role, another organization, a credential a
stranger signed — denies with its own sentence; a membership that names
someone other than the caller, an expired one and an amount over the cap
each deny with theirs; and a `config` value that is not a list of references
is a fault, not a denial, because the declared store could not be formed.

## Rebuild

Nothing to build — `policy.cedar` is interpreted source. A new relation
means a `memberOfTypes` entry in `schema.json`, a membership field in the
manifest and plan, and a `memberships` entry in the block; the loader
refuses the policy that tests it until all three are there.

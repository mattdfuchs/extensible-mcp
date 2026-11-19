# Fixture provenance — cedar_channel (Cedar, entity references and the principal as a value)

A channel's delete-message rule: the requester is the channel's owner, or
one of its moderators — `resource.owner == principal ||
resource.moderators.contains(principal)`, the public benchmark's reference
policy word for word up to the order of `==`'s operands. One condition. It
is in the corpus because it is the first supplied bundle that uses the two
things the `entities` block adds beyond attributes: **entity references as
values** (`owner` is a `User`, `moderators` a set of them, written in the
manifest as the closed record `{"type": "User", "id": …}` and listed in the
block's `references`, so the loader wraps each in Cedar's `__entity` escape
— by the block, never by looking at a value's shape), and **the request's
principal formed from an input field** (`"id": {"from": "input", "field":
"principal"}`: the field *is* the principal, leaves `context`, and the
policy's presence guard for it is `principal is User`).

**Supplied by an external policy-authoring toolchain**, emitted from its own
`channel` core in the permit-decides shape at upstream commit `64c41c5`,
where it is the toolchain's port of a public Cedar benchmark scenario
(`group_chat_moderator`, requirement 3) and not a proxy deliverable: every
field, the principal included, is `call`-sourced. As with `cedar_approval`,
a call-sourced identity is outside the proxy's threat model, so this is a
**loader-grammar fixture** and is never attached to a server in any example;
`cedar_family_hierarchy` reaches its principal through a `caller`-sourced
entry. Generator-internal names were anonymized as for every supplied
bundle; nothing executable changed. Digest of the **unedited** `policy.cedar`
as published:

```
sha256  0aba21cf41cc7554cd796a195f0214093d705bf90046183bfac868928b66af2c
bytes   3,532
```

| file | origin |
|---|---|
| `policy.cedar` | supplied: 1 `@tier` permit, 1 `@id` forbid, 1 `@assembly` forbid; `principal is User` as the principal's presence guard |
| `expected_ids.json` | supplied: the 1 id and 1 tier, `"shape": "permit-decides"` |
| `contract.json` | supplied: no derivation obligations, the certificate's nine hypotheses, `typed` empty |
| `manifest.json` | supplied: three required fields, `User` as a closed Draft-7 definition with `"type": {"const": "User"}` |
| `fetchplan.json` | supplied: three `call` entries, and the `entities` block with `references` for all three and the principal's id from the input |
| `schema.json` | supplied: `Channel = {owner: User, moderators: Set<User>}`, `User` with no attributes, the one action's context only the optional `probe` |
| `guidance.json` | supplied; `guidance_digest.value = "61d1888303dd18c7"` |

`tests/test_cedar_store.py` runs the supplier's scenario table — owner,
moderator, both, neither, an unmoderated channel, reference keys in either
order — through the loader, and pins the measurement that decides the
loader's duty: without the `__entity` escape Cedar reads the bare record as
a record and the owner is denied.

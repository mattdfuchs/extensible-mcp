# What this realm file leaves out, and why

`household-realm.json` was **written by hand**, not produced by `kc.sh export`
and not by the admin console's partial export either. It contains the parts
the [recipe](README.md) teaches and nothing else.

That matters mostly for the next person to regenerate it. A full export is
more complete, which here is the wrong direction: it would re-add every item
below without saying so, and the diff would be large enough that nobody would
notice. **If you regenerate, diff against this list first.**

The `secrets` CI job (gitleaks, see [`.gitleaks.toml`](../../../../.gitleaks.toml))
scans this file like any other. Nothing below is allowlisted, because nothing
below is in the file — an allowlisted secret in a scanned file is a worse
position than a file with nothing to allowlist. If a regeneration trips that
job, the fix is to take the secret out, never to add an entry.

## 1. The realm's signing keys — never exported

An export can carry the realm's `components`, including `rsa-generated` and
`hmac-generated` providers with their private key material. This file has no
`components` block at all, so Keycloak generates a fresh key set at import.
Confirmed on 26.8.1: after importing this file, the realm has an ACTIVE RS256
signing key that the file did not supply.

This is not only hygiene. **A committed signing key is shared by every clone.**
A token minted in one person's demo would validate in everyone else's, which
makes a committed key a correctness problem for anyone using the demo to reason
about tokens — not just a leak.

## 2. The client secret — made not to exist

`approval-page` is a public client with S256 PKCE, so there is no
`"secret"` field to strip and none to replace with a placeholder either. The
alternative for a non-browser client is private-key JWT, where the realm JSON
would carry the client's **public** JWK — also not a secret. Either way the
answer is a client that has no secret, not a secret kept somewhere else.

A regenerated export of a *confidential* client will contain a real
`"secret"`. That is the one change in this file that must never be committed.

## 3. User credentials — moot, and still checked

The recipe is WebAuthn-passwordless, so there is no password material to
export. `parent` and `child` are present with roles, profile fields and a
`webauthn-register-passwordless` required action, and with **no `credentials`
array**. Confirmed on 26.8.1: both users import with zero credentials.

Enrolling the first passkey is therefore a manual step, described in the
recipe. That is the cost of not committing a password, and it is worth it.

## 4. Other things an export adds that are not secrets

Left out to keep the file reviewable, since every line in it is a line
somebody has to read:

- **`id` fields.** An export stamps UUIDs on the realm, clients, roles, flows
  and mappers. Letting Keycloak assign them keeps the file free of identifiers
  that mean nothing outside one server's database.
- **`smtpServer`.** Not needed by the demo, and a populated one carries a
  password.
- **`keycloakVersion`** and the full default sets of client scopes, built-in
  clients (`account`, `broker`, `realm-management`, `security-admin-console`),
  built-in authentication flows, default required actions and client profiles
  or policies. Keycloak creates all of these at import. Importing a custom
  `browserFlow` does not suppress the built-in flows; verified on 26.8.1.
- **`identityProviders`, `organizations`, `groups`, `clientScopes`.** Empty
  here; a real deployment's export would carry its own.

## 5. What is deliberately in the file

So a regeneration does not drop them as "demo noise":

- `scopeMappings` granting `approval-page` the `parent` and `child` roles.
  With `fullScopeAllowed: false` and no scope mapping, the role mapper emits
  nothing — the claim just is not there. See the recipe.
- `authenticatorConfig: amr-webauthn-passwordless`, with a **positive**
  `default.reference.maxAge`. The default is `0`, which drops the `amr` value
  silently.
- The `oidc-audience-mapper` with `included.custom.audience`. Without it there
  is no `aud` claim at all.
- Profile fields on both users, so `VERIFY_PROFILE` does not block the first
  login.

# Keycloak recipe: a committed realm, no secrets in it

The demo does not run Keycloak. It ships a realm you can import into one,
curated so that "point the passkey page at a real identity provider" can
become a configuration step rather than a rewrite — which is the reason
[`oauth.py`](../../src/extensible_mcp_vc/oauth.py) implements authorization
code + PKCE and not a password check.

**The code consumes it.** With `APPROVAL_ISSUER` set, the approval service
runs in external-issuer mode: discovery, the realm's JWKS, RS256, verified by
the same `JWTVerifier` the proxy's `auth` block builds; the page's sign-in
goes to Keycloak and the code exchange is forwarded. The realm and the
verifier are pinned from one contract: `tests/test_keycloak_realm.py` holds
this file to the claims the recipe promises, and `tests/test_external_issuer.py`
mints tokens of exactly that shape and checks the service accepts them. See
[Point the demo at it](#point-the-demo-at-it).

Keycloak is the enterprise answer here: self-hosted, no account needed by
anyone cloning the repo, dynamic client registration, identity brokering,
step-up. It is **not** the home answer — the home shape is one proxy per
person on loopback, with identity as a `config` fact rather than a token.

[`household-realm.json`](household-realm.json) is the artifact. It is
**secret-free by construction**, not secret-free by externalising its secrets
to a `.env`; see [REALM-CURATION.md](REALM-CURATION.md) for what was left out
and why, so a later regeneration does not quietly put it back. The `secrets`
CI job is a backstop for this file, not the plan.

## Pinned version

Everything below was verified against **`quay.io/keycloak/keycloak:26.8.1`**
(released 2026-10-13), by importing the committed file into that image and
reading back what the server made of it. Where this document states what a
mapper emits, that claim came from a decoded access token, not from the docs.

A later Keycloak may rename a config key or change a default. Re-run the
checks in [Re-verifying after a version bump](#re-verifying-after-a-version-bump)
before changing the pin.

## Import it

```sh
docker run --rm -p 8080:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  -v "$PWD/examples/agentic-commerce-demo/deploy/keycloak:/opt/keycloak/data/import:ro" \
  quay.io/keycloak/keycloak:26.8.1 start-dev --import-realm
```

As a compose fragment, to sit alongside the two demo services — kept here
rather than in `docker-compose.yml` on purpose, because the demo's default
`up` should not start an identity provider nobody asked for:

```yaml
  # Optional: docker compose -f docker-compose.yml -f docker-compose.keycloak.yml up
  keycloak:
    image: quay.io/keycloak/keycloak:26.8.1
    command: ["start-dev", "--import-realm"]
    environment:
      # Dev-mode bootstrap admin. A real deployment uses `start`, a database,
      # and an admin created out of band.
      KC_BOOTSTRAP_ADMIN_USERNAME: admin
      KC_BOOTSTRAP_ADMIN_PASSWORD: admin
    volumes:
      - ./keycloak:/opt/keycloak/data/import:ro
    ports:
      - "127.0.0.1:8080:8080"
```

The values the demo takes: issuer `http://localhost:8080/realms/household`;
for the passkey page, client `approval-page` and audience `approval-service`;
for the chat console, client `family-console` and audience `family-proxy`,
which is what the family proxy verifies. One client per browser surface and
one audience per resource server, so a token for the page is never a token
for the proxy. The clients and audiences are the code's own constants; only
the issuer is configuration.

## Point the demo at it

[`docker-compose.keycloak.yml`](../docker-compose.keycloak.yml) is the
fragment above plus the family container's environment, so the demo and the
provider come up together:

```sh
docker compose -f examples/agentic-commerce-demo/deploy/docker-compose.yml \
               -f examples/agentic-commerce-demo/deploy/docker-compose.keycloak.yml up --build
```

What the fragment sets, and why each line is there:

- `APPROVAL_ISSUER=http://localhost:8080/realms/household` on the family
  container: what the realm's tokens name in `iss`, and where the browser is
  sent to sign in.
- `APPROVAL_ISSUER_INTERNAL=http://keycloak:8080/realms/household`: where the
  *service* reaches Keycloak, from inside the compose network. Discovery, the
  JWKS and the token endpoint are fetched there; the URLs Keycloak publishes
  are rewritten from the public issuer onto this base for the service's own
  requests only, and the browser-facing authorize URL is left as published.
- `KC_HOSTNAME=http://localhost:8080` on Keycloak: makes it name the public
  issuer in tokens and in discovery whichever host the request arrived on.
  Without it the discovery document fetched at `keycloak:8080` names
  `keycloak:8080` as the issuer, the service refuses it as a mismatch, and
  tokens would carry the wrong `iss` too.
- The service's `APPROVAL_REQUIRED_AMR` is left at its default, `hwk`: a
  sign-in that did not use the passwordless flow cannot enrol a passkey.
- The same two variables put the **family proxy** on the provider: it
  waits for discovery at startup, verifies the console's bearer for the
  `family-proxy` audience against the realm's keys, requires a principal on
  every call, and scopes the catalogue by role (both roles see everything;
  neither may load a server at runtime). And they put the **console** on
  it: the chat page signs you in at Keycloak and the console holds one MCP
  session per signed-in person, presenting that person's token, so the
  proxy's principal is the person at the console.
- **First boot binds the memberships.** With the issuer set, `setup.py`
  writes each member's pinned account at the provider —
  `{"idp": <issuer>, "account": <the realm's user id>}` — into the
  membership credential the admin signs. The production bundles'
  `account_bound` check then requires the console session to be the member
  whose wallet signed the request. A workspace created *without* the issuer
  has unbound memberships, which bind nobody under a principal: run
  `docker compose down -v` before switching modes.

Then, once:

1. Open `http://localhost:8080` (admin / admin), realm `household`, and
   register a passkey for `parent` and for `child` as
   [The users, and the enrolment step you have to do by hand](#the-users-and-the-enrolment-step-you-have-to-do-by-hand)
   describes; the realm ships the users with no credential.
2. Open `http://localhost:7500`. The page sends you to Keycloak; sign in with
   the passkey; you come back signed in as that user, and **Enrol** mints the
   admin-signed enrollment under the role the token carries. A user holding
   both roles is asked which one to enrol under.
3. Open `http://localhost:7300`. The console sends you to Keycloak too (its
   own client); sign in as `child`, and every call the assistant makes
   carries your token: the proxy knows who it is representing, the wallet
   that signs the request must be bound to your account, and a request the
   assistant steers at the other member's wallet is denied with the binding
   sentence. The business shape in one sign-in: the organization's
   identity provider, its proxy, its passkey authority, the merchant on the
   other side.

`docker compose logs family` prints `[approval] sign-in via external issuer`
instead of the local passwords, which do not apply in this mode.

The opt-in test runs the service's provider client against the live
container, rewrite included, and is skipped without the variable:

```sh
KEYCLOAK_URL=http://127.0.0.1:8080 uv run --package extensible-mcp-vc \
  pytest examples/agentic-commerce-demo/tests/test_external_issuer.py -k pinned_keycloak
```

**The file name is load-bearing.** A directory import requires
`<realm>-realm.json`; with any other name 26.8.1 refuses to start with
`File name / realm name mismatch`. That is why this file is
`household-realm.json` and not `realm.json`.

**Mount it read-only.** Keycloak writes nothing here, and `:ro` keeps an
import from being the thing that edits the file you committed.

## What the realm carries, and what silently breaks without it

### The audience mapper — assert this one first

Keycloak does **not** put your resource server in `aud`. This is the usual
trip hazard, and it does not fail loudly: tokens are issued, they look
right, and the resource server rejects every one of them.

Measured on 26.8.1, with two otherwise-identical clients in one realm:

| client | `aud` in the access token |
|---|---|
| with `oidc-audience-mapper` | `approval-service` |
| without it | **the claim is absent entirely** |

(Both clients had `fullScopeAllowed: false`, as the committed one does. A
client whose scope pulls in other clients' roles gets an `aud` listing *those*
clients — which is still not your resource server.)

So a verifier that checks the audience — as `oauth.py`'s `verify_token` does,
and as anything replacing it should — fails closed on every token from a
realm missing this mapper. The mapper is `oidc-audience-mapper` with
`included.custom.audience` set to the resource's own name:

```json
{
  "name": "approval-service-audience",
  "protocolMapper": "oidc-audience-mapper",
  "config": {
    "included.custom.audience": "approval-service",
    "access.token.claim": "true"
  }
}
```

`included.custom.audience` is a free string; `included.client.audience` picks
another *client* in the realm instead. The audience here is a resource name
rather than a client, so the custom form is the right one, and the committed
file sets only that one.

### The role mapper, and the scope mapping it needs

The role vocabulary is ours, not Keycloak's: `parent` and `child`, the same
two the demo's own
[`DemoUserStore`](../../src/extensible_mcp_vc/oauth.py) issues. They are realm
roles, emitted into a `roles` claim by `oidc-usermodel-realm-role-mapper`.

**A mapper alone emits nothing.** The client sets
`"fullScopeAllowed": false` — least privilege, and the right default — which
means the client's scope has to *contain* a role before any mapper can put it
in a token. Without the realm-level `scopeMappings` entry, measured on
26.8.1, the `roles` claim and Keycloak's own `realm_access` are both simply
missing, exactly as if the mapper were not there:

```json
"scopeMappings": [
  { "client": "approval-page", "roles": ["parent", "child"] }
]
```

The claim is multivalued — a JSON array, because a Keycloak user can hold
both roles. The demo's internal token shape carries a single `role` string
instead, so a verifier reading Keycloak tokens reads `roles` as a list and
decides what one principal with two roles means. That is a deployment
decision and the realm file does not make it.

### The AMR mapper

`AmrProtocolMapper` (`oidc-amr-mapper`) is built in, and **not automatic** in
two separate ways:

1. The mapper has to be added to the client. The committed file adds it.
2. **The AMR values are configured per authenticator execution**, as an
   authenticator config on the execution, not on the mapper.
   `AmrUtils.getAuthenticationExecutionReferences` returns nothing for an
   execution with no config, so the strings are ours to choose — the same
   "vocabulary is yours" property the role mapper has:

   ```json
   "authenticatorConfig": [
     { "alias": "amr-webauthn-passwordless",
       "config": { "default.reference.value": "hwk",
                   "default.reference.maxAge": "900" } }
   ]
   ```

`hwk` is RFC 8176's proof-of-possession of a hardware-secured key, which is
what a platform authenticator with user verification required actually
demonstrates. `swk` would be the honest value for a software passkey synced
across devices, and `user`, `pin` and `mfa` are the other registered values in
reach. Nothing in Keycloak checks the string against the registry.

**`default.reference.maxAge` is not optional.** `AmrUtils.isAmrValid` tests
`authTime + maxAge >= now`, and the default when the key is absent is `"0"` —
which makes the factor expire the instant it is used, so the value silently
drops out of the claim. A positive value is what makes the claim appear at
all. It also means Keycloak expires *individual factors*, which is stronger
than a session-level `auth_time`: at 900 seconds the passkey leg stops
counting a quarter-hour after it happened, whatever the session does.

Measured on 26.8.1, with the committed mapper and config: `amr` is
`["hwk"]`.

### The WebAuthn-passwordless execution

`browserFlow` is bound by alias to `webauthn-passwordless-browser`:

- `auth-cookie` (ALTERNATIVE) — an existing session still works
- a subflow (ALTERNATIVE) of `auth-username-form` (REQUIRED) then
  `webauthn-authenticator-passwordless` (REQUIRED)

There is no password leg, and the realm's passwordless policy requires user
verification and a resident key, with `platform` attachment (Touch ID, Windows
Hello) and `localhost` as the RP ID — the same hostname rule the demo's own
passkey page has, since WebAuthn binds a credential to its origin.

Importing a custom flow does **not** suppress the built-in ones: after import,
26.8.1 has `browser`, `direct grant`, `registration`, `reset credentials`,
`clients`, `first broker login` and `docker auth` alongside ours, and the
other realm bindings still point at them. Only `browserFlow` is overridden.

### The users, and the enrolment step you have to do by hand

`parent` and `child` are present with their roles, and with **no credentials
at all** — the import leaves them with zero (confirmed against
`/admin/realms/household/users/{id}/credentials`), and
`webauthn-register-passwordless` as a required action.

A user with no credential cannot start a passwordless login, so somebody has
to enrol the first passkey. That is deliberate: the alternative is a
committed password. Use the admin console — Users → *parent* → Credentials →
Credential Reset → `webauthn-register-passwordless` → Send/Copy link — and
open the link in the browser holding the authenticator. The realm also carries
profile fields for both users, because `VERIFY_PROFILE` is a default required
action and a user without a first name, last name and email cannot complete a
login until it is satisfied.

## Client authentication: public with PKCE

`approval-page` is a **public** client — `publicClient: true`, S256 PKCE
required via `pkce.code.challenge.method`, standard flow only, direct access
grants off. A public client has no secret to commit, which is the whole point;
PKCE is what replaces one for a browser surface that cannot keep a secret
anyway.

The other secret-free option is private-key JWT (`client-jwt`), where the
realm JSON carries only the client's **public** JWK. That fits a service
client rather than a browser page, and it is the shape to adopt here if and
when a private-key-JWT provider lands on the proxy side. Both are secret-free;
neither needs a `client-secret` in this file.

## On `${ENV_VAR}` placeholders — verified, and still not used

The recipe depends on no substitution feature, because it has nothing to
substitute. The verification was done anyway, so that the fallback is a
measured statement rather than folklore. On **26.8.1**, standalone
(`start-dev --import-realm`, directory import — no operator involved):

| form in the realm JSON | what the server stored |
|---|---|
| `${DEMO_PROBE_VALUE}`, variable set | the value — substitution **does** happen |
| `${DEMO_NOT_SET_ANYWHERE}` | the literal `${DEMO_NOT_SET_ANYWHERE}`, no error |
| `${PATH}` | the server's own `PATH` |
| `${${INDIRECT}}` | resolved through the indirection |
| `${env:VAR}` | the literal string `VAR` |
| `${env.VAR}` | unsubstituted |
| `${VAR:-fallback}` | `-fallback`, i.e. `:` introduces the default, not `:-` |

Substituted in realm attributes, client attributes and client description
alike. So the plain `${VAR}` form works on the Quarkus distribution and not
only under the Kubernetes operator — which the docs do not say either way, and
which is why this was measured rather than asserted.

Three reasons the recipe still does not use it:

- **It reads any environment variable**, not only the ones you meant: `${PATH}`
  resolving proves the operator docs' warning applies to the standalone
  distribution too. A realm document is then a read primitive over the
  server's environment.
- **CVE-2025-9162** is an injection flaw in exactly this substitution path —
  a realm document processed through placeholder replacement pulling
  environment values (including database credentials) into stored
  configuration. It was reported against the operator's `KeycloakRealmImport`;
  the substitution code lives in the realm-import path. On 26.8.1 the
  indirection form above still resolved, so do not read "patched" into this
  table.
- **A typo fails open and silent.** An unset variable is stored verbatim, so a
  misspelled placeholder ships the literal `${...}` as a configuration value
  with no warning at import.

If some future addition genuinely cannot be made secret-free, the fallback is
`.env` plus an entrypoint that runs `envsubst` over a copy of the JSON before
Keycloak boots — an explicit, named substitution of named variables, written
down in the entrypoint where it can be reviewed. Not this feature.

## Re-verifying after a version bump

`tests/test_keycloak_realm.py` (in the demo suite) asserts the file's shape
and that this document's claims match it — no container, so it catches a
realm edit that drifts from the docs, not a Keycloak behaviour change. For the
behaviour, re-run the three measurements against the new image:

1. **It imports.** Mount this directory and look for `Realm 'household'
   imported` plus `Import finished successfully`, with no `ERROR` line.
2. **Keys are fresh and the config stuck.** `GET /admin/realms/household/keys`
   shows an ACTIVE RS256 signing key the file did not provide; the
   `webauthn-authenticator-passwordless` execution still carries the
   `amr-webauthn-passwordless` config.
3. **The claims come out.** Derive a throwaway realm from this file that
   changes *only* what a token needs without a browser — a password
   credential, a direct-grant flow carrying the same authenticator config —
   and decode an access token. On 26.8.1 that yields
   `aud=approval-service`, `roles=["parent"]`, `amr=["hwk"]`. Keep the
   derived realm out of the repo; it has a password in it, which is the
   reason it is derived rather than committed.

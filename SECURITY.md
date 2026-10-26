# Security Policy

## Reporting a Vulnerability

If you believe you have found a security vulnerability in extensible-mcp, please report it privately rather than opening a public issue.

**Preferred:** use GitHub's [private vulnerability reporting](https://github.com/mattdfuchs/extensible-mcp/security/advisories/new) for this repository.

**Alternate:** email `mattdfuchs@gmail.com` with the subject line starting `[extensible-mcp security]`.

I will acknowledge receipt within a few days and follow up with a triage assessment. Please give a reasonable amount of time for a fix to land before public disclosure; coordinated disclosure is appreciated.

## Scope

In scope:

- Vulnerabilities in the proxy itself: filter bypasses, secret leakage into the LLM's context, ways to call tools that should have been blocked, ways to load servers that `load_control` should have rejected.
- Credential-handling regressions: tokens, client secrets or signing keys appearing in logs, in chat transcripts, or in error messages surfaced to the LLM.
- Bypasses of the structurally-enforced "the LLM can only call tools it has surfaced via `search_tools`" property. The set is scoped per MCP session; on a transport without sessions (stdio) a process serves one client and the scope is the process.
- Denial-of-service issues that an attacker (e.g., via a prompt-injected tool description) can trigger against the proxy itself.

Out of scope:

- Vulnerabilities in downstream MCP servers — report those to the relevant upstream project.
- Issues that require a malicious local config file to be loaded — the threat model assumes the config file is trusted.
- Issues that require a malicious downstream server to already be configured. The proxy's `load_control` filter is for this; vulnerabilities in `load_control` itself are in scope.
- Issues in dependencies (Rego, FastEmbed, fastmcp, etc.) — report those to the relevant upstream.

## Not claimed

Worth stating so it is clear what is a finding and what is a known limit.

**The proxy does not authenticate its caller.** It has no notion of which user
a session acts for. A session is identified — `CallRequest.session_id`, which
is what scopes the discovery set — but that says which connection a call came
from, not who authorized it. Access control, `load_control` and the tool
catalogue are therefore deployment-wide rather than per-principal: every
session connected to a proxy is subject to the same rules, because the proxy
cannot tell them apart.

Where a principal *is* established, it is established by evidence rather than
by the connection: a policy bundle verifies signed credentials naming the
requester and, above a threshold, an approver. That answers *who asked for
this specific action*, which is a different question from *who is on the other
end of this session*. Reports that the second question is unanswered are
accurate and already known; a design for it is being worked on. Reports that
the first is answerable without valid evidence are very much in scope.

**"Signature checks run inside the policy" is a claim about the engine, not
about the bundle format.** It holds unconditionally for two of the three
engines that ship: the Rego/wasm engine is given crypto builtins as host
imports, and the CEL engine evaluates its checks over the same closed input, so
in both cases a credential is verified *within* the rules that decide the call.
The third, Cedar — whose bundles an external policy-authoring toolchain emits —
is different, because Cedar has no crypto: the verifications are **hoisted** —
performed by the host ahead of the policy, which then decides over the
resulting witness set. For that target the sentence above is false, and this is
the narrowing rather than a retraction.

What transfers across the hoist is asymmetric, and the asymmetry is the point:

- **Deny-soundness transfers unconditionally.** A denial from the Cedar target
  is a real denial whatever witness set the host supplied.
- **Deny-completeness does not.** It holds only under the derivation contract —
  the obligation that the witness set the host derives is exactly the set the
  source policy would have established. A witness set that is too *large* makes
  a forbid fail to fire, so the Cedar target can **allow** where the source
  policy denies. **Over-inclusion fails open.**

Such a bundle is therefore *certified modulo the derivation contract*. There is
no such thing here as a "verified Cedar policy", and a report that treats the
certificate as covering the hoisted step is reading a conditional result as an
unconditional one. The hoisted applications are **trusted, and a new surface**:
this is the one place the Cedar target is weaker than the Rego and CEL engines,
where the check runs inside the policy and there is nothing to trust ahead of
it. A defect in a hoisted application is in scope as a finding.

Two structural consequences, in scope for reports:

- A Cedar bundle in the **forbid-only** shape — the one the external
  toolchain emits — carries an unconditional base permit and emits **no
  entity hierarchy**, so an **empty policy set allows everything**. There
  is no deny-by-default to fall back on. What stands between a failed load
  and a silent permit is therefore the load-time check that every expected
  rule `@id` is present. A way to load such a bundle with rules missing, or
  to make that check pass without them, is a bypass and a finding.
- A Cedar bundle in the **permit-decides** shape — the one a hand author
  should write — is decided by one `@tier` permit per tier, with the
  forbids guarded behind a `probe` key the proxy injects only to explain a
  denial. An empty set denies. The shape is declared in `expected_ids.json`,
  never inferred, and the guards are checked on every call rather than at
  load, because cedarpy exposes a policy's effect and annotations but not
  its condition. A way to make a forbid decide in the decision pass, a
  permit match in the probe pass, or a bundle evaluate in a shape other
  than the one it declares, is a finding.

**The proxy does not prevent a client from reaching other servers.** It governs
what passes through it. A client that can connect elsewhere — another MCP server
in its own configuration, a stdio server that needs no credential, or a shell —
is outside the proxy's reach by construction, and no credential the proxy
withholds changes that: withholding a token does not deny access to something
that never asked for one.

Sole-path is therefore a deployment property rather than an enforced one. It is
achieved by network egress control and by the operator holding the downstream
credentials — `client_manager` presents a token only to a URL an operator
configured for that name, so a server that requires auth is not reachable by a
client that has never seen its token. The containerized demo shows the intended
shape: the downstream org publishes no ports and is reachable only over the
compose network. A deployment that skips that work has skipped something, and a
report assuming the proxy supplies it unaided is a known limit rather than a
finding.

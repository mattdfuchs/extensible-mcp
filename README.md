# extensible-mcp

extensible-mcp is a proxy that sits between an LLM and the universe of MCP servers, providing on-demand tool retrieval and a deterministic enforcement point for access control. Tool definitions don't need to live in the prompt, sensitive credentials don't need to live in the LLM's context, and security policies are evaluated by code rather than by the model.

## Why: Security

LLMs cannot be trusted to manage their own security. They hallucinate, they have no reliable line between "instruction" and "data," and they can be manipulated by anything they read — a tool result, a scraped web page, an email, a message from another agent. Any claim an LLM makes about what a user wants, or what a counterparty has agreed to, has to be treated as hearsay: unverifiable on its own, and worthless as authorization for a sensitive action. Enforcement has to live outside the model, in deterministic code the model cannot talk its way around, and secrets have to stay out of its context entirely — that premise is argued in full under [Threat Model](#threat-model) below.

extensible-mcp is built as that enforcement point. Every operation between the LLM and the outside world — which servers it can load, which tools it can find, which calls actually go through, what comes back — passes through a filter pipeline evaluated by code, never by the model. And where a decision needs to rest on more than the model's say-so, the policy-bundle engine requires cryptographically signed evidence — a Verifiable Credential, a WebAuthn passkey assertion — in place of a claim the LLM typed.

### The Order Pizza demo: Zero Trust, fully elaborated

Two things in this repo carry that idea. A [**policy bundle**](#policy-bundles) is how a policy over signed evidence is written and attached to the filter pipeline — a manifest, a fetch plan, human-facing guidance, and the rules themselves in Rego compiled to WASM, in CEL, or in Cedar. The **Order Pizza** demo ([`examples/agentic-commerce-demo/`](examples/agentic-commerce-demo/)) is that machinery worked all the way through: a full elaboration of what Zero Trust looks like once every party's word has to be backed by a signature.

Our Zero Trust posture assumes any statement an agent makes about a user's intent — an agent that is subject to hallucination and prompt injection — is hearsay. User intent can only be asserted, in a non-repudiable way, by a signed statement the LLM could not have produced itself. We get that from the W3C's **Verifiable Credentials** framework: a statement wrapped in a signed envelope, where the signature is the signer vouching for it.

The demo has three parties making statements of intent, each one a signed credential:

1. **The child**, ordering a pizza — without this, the agent might just place the order because the child usually does around this time.
2. **The parent**, approving the order, for the same reason.
3. **The pizza shop**, giving a guaranteed, binding price.

In the flow: the child asks to buy pizza, either a slice ($4) or a full pizza (over $10). The agent talks to the pizza shop's own agent to arrange the sale — and because that agent's price comes back as a signed claim bound by its shop's own policy floor, it cannot be talked into an unauthorized discount. (Compare the real 2023 incident where a car dealership's chatbot could be talked into "agreeing" to sell a truck for $1 — an agent's word was never a signature. This demo makes that failure mode structurally impossible, not just discouraged.) The agent then pings the child for a passkey signature on the request, and — for orders over $10 — the parent too.

Only once every required signature is present does the call to order pizza satisfy the approval service's policy. On full approval, the order settles through a payment rail — an in-memory mock by default, or real Stripe test-mode charges if you configure your own key — and the pizza shop hands back its own signed commitment to fulfill.

See [`examples/agentic-commerce-demo/deploy/`](examples/agentic-commerce-demo/deploy/) to run it yourself: it's fully containerized down to a browser chat window, a live log, and a 2-window passkey approval page.

## Why: Extensibility

Connecting an LLM client to a set of MCP servers is normally a startup-time decision: list servers in a config, launch the client, hope you guessed right. There's no clean way to add a server mid-conversation, or to have the LLM itself reach for a capability that wasn't pre-configured.

Even once servers are connected, the LLM client is handed a flat list of every tool from every server, injected wholesale into the context window. As the number of servers grows, this causes token bloat, degraded model performance, and hard context-limit failures — even when most tools aren't relevant to the current turn.

And there's no standard control plane. If you want to block dangerous operations, enforce argument-shape policies, or gate which servers an LLM is allowed to connect to in the first place, you have to build that into each client or each server individually.

extensible-mcp sits between the LLM and your MCP servers and addresses all three:

1. **Dynamic server loading** — Connect to MCP servers at startup from config, or at runtime by URL. The LLM can pull in entirely new servers and their capabilities from across the network on demand, without restarting the client.
2. **RAG-based tool search and retrieval** — Tool definitions are embedded into a vector index. The LLM searches semantically with `search_tools(query)` and pulls back only the matches it needs, instead of every tool definition occupying space in every prompt.
3. **Pluggable filter pipelines** — Every operation (search, call, server load) passes through a filter chain. The proxy enforces one structural guarantee: the LLM can only call tools it has previously surfaced via `search_tools`. Beyond that, the filter logic is yours: ship-with reference filters cover access control, Rego policy evaluation, and server-load whitelisting; bring your own for argument validation, audit logging, signed-claim verification, or anything else.

```
LLM  <-->  extensible-mcp  <-->  MCP Server(s)
              |
              +-- search_tools(query)         → vector search over indexed tools
              +-- call_tool(name, args)        → proxied to the right server
              +-- load_mcp_server(name, url)   → connect a new server at runtime
```

## How It Works

The proxy exposes three meta-tools to the LLM:

- **`search_tools(query)`** — Describe what you want to do in natural language. The proxy embeds the query with [all-MiniLM-L6-v2](https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2), runs cosine similarity against the tool index, and returns matching definitions.
- **`call_tool(tool_name, arguments)`** — Invoke a tool by the name `search_tools` returned: qualified for a downstream tool (e.g. `github__create_issue`), bare for one of the proxy's own local tools. The proxy routes the call accordingly.
- **`load_mcp_server(server_name, url)`** — Connect to a new remote MCP server at runtime. Its tools are indexed immediately and become available for search and invocation.

Retrieval is model-driven: the LLM decides when to search and crafts its own queries, so there's no wasted retrieval on turns where no tools are needed.

## Status

The base proxy is working: dynamic server loading, RAG-based tool retrieval, an extensible filter pipeline, and downstream authentication (credentials the proxy acquires by OAuth grant, or a legacy tokens file, either way kept out of the LLM's context) all ship today. The pipeline enforces one structural guarantee — the LLM can only call tools it has discovered via `search_tools` — and ships reference filters for access control, Rego policy evaluation, and server-load whitelisting that you can use as-is, configure, or replace with your own. The example configs work against the official GitHub MCP server.

Beyond that base, an in-process **policy-bundle engine** enforces signed-evidence policies on the call path: a policy (compiled to OPA/Rego-WASM, authored directly in CEL, or emitted as Cedar) evaluates a closed input assembled from the call's arguments, deployment config, and resolved evidence — a Verifiable Credential, a WebAuthn passkey assertion, a merchant's raw signature over the exact bytes it signed — each verified field-by-field against the actual call, never taken on the LLM's word. The engine is deliberately plural: `manifest.json`/`fetchplan.json`/the human-facing guidance layer are the same regardless of which engine evaluates the policy, and Rego, CEL and Cedar backends ship as proof. See [`project-overview.md`](project-overview.md) for the architecture, module by module.

The line from here to [Policy as Code, Policy as Type (Fuchs, 2025)](https://arxiv.org/abs/2506.01446) — which treats a policy as a dependent type whose properties can be mathematically proven rather than just tested — is now concrete rather than aspirational: the bundle format supports a policy derived that way, without the proxy needing to know or care. The core package's suite is 750 tests; the two example packages add 133 and 51.

## Threat Model

The [Why: Security](#why-security) section above states the premise: LLMs cannot be trusted to manage their own security, so enforcement has to live outside the model. This section argues it in full. LLMs are open to prompt injection attacks from any material they ingest, they can be influenced by material in their training set in non-obvious ways, including treating data as instructions, they hallucinate, they can forget instructions, and any information passed to them must be considered compromised. Any serious attempt to enforce rules must live outside the LLM in code not subject to all these weaknesses.

This premise is not new; it is **zero trust** applied to the LLM. Zero trust — the principle that no actor is trusted by virtue of where it sits, and that every action is authenticated and authorized on its own merits — is the default posture of modern service-based architecture (Saltzer and Schroeder's *least privilege* and *complete mediation*, 1975; the de-perimeterization movement; Kindervag's coining of the term at Forrester, 2010; Google's BeyondCorp; NIST's Zero Trust Architecture, SP 800-207, 2020). Its standard shape — a policy decision point kept separate from a policy enforcement point, deciding per request — is the shape of this proxy. The one addition is to place the LLM agent itself on the untrusted side of the boundary: not because its identity is in doubt, but because its judgment can be manipulated by what it reads, so authenticating it is not enough. Enforcement lives in deterministic code, and — in the policy-bundle engine described under Status — trusts only evidence the LLM cannot forge.

The pipeline allows for control at all points of contact between the LLM and the external world:
- At server loading time, we can filter and prohibit the agent from loading untrusted servers. Beyond just the tools, the server and tool descriptions can contain prompt injection attacks. 
- At search time, we can, again, hide dangerous or untrusted tools. In the current release, we include a sample filter to hide any tool containing "delete"; not only can't such a tool be called, it can't be found.
- At call time, further policies can prevent illegitimate use of an allowed tool. In the sample code we prevent the closing of an issue, but allow other uses of the same tool to allow updating issues.
- At response time, filters can inspect or rewrite tool results on their way back to the LLM — useful for redacting secrets that leak back from a buggy server, flagging or scrubbing prompt-injection content in scraped pages or email bodies, truncating large responses, or audit logging. Tool results are an injection surface every bit as real as tool descriptions; the response pipeline is where you handle it.
- The LLM cannot call any tools it didn't find during search. This ensures the LLM calls only tools in the protected set and is not vulnerable to attempts to call outside the protected envelope.
- We do not pass secrets (in particular, downstream credentials) to the LLM. The proxy holds them itself — acquired by an OAuth grant, or read from a file the model cannot see — and presents them in HTTP Authorization headers. The LLM can prompt the user to fix a credential when it appears to have expired, but it never sees one.

The discovery rule is scoped per MCP session: what one conversation surfaced is not callable by another. On a transport without sessions (stdio) a process serves a single client, so the scope is the process. This was not always so — until 0.3.2 the set was process-wide, which on an HTTP transport meant a tool surfaced by any session was callable by every session. It was reported as a bypass and it was one.

A sharper limit remains, and it is a property of the design rather than a bug: **the proxy does not know who a session acts for.** A session is distinguishable, which is what makes the scoping above possible, but it carries no principal. So access control, `load_control` and the tool catalogue are deployment-wide — every session is subject to the same rules, because there is nothing to tell them apart by. Where a principal is established at all, it is established by signed evidence the policy verifies, which answers *who asked for this action* rather than *who is on the other end of this connection*.

Of course, we can only apply these protections within the context of the LLM itself. We cannot protect against:
- Security flaws in the user's configuration, 
- The behavior of downstream servers (although limiting to trusted servers can mitigate that), 
- Policies that trust unverified LLM claims (such as whether the user has agreed to some action) 
- Otherwise ineffective policies (for example, our simple Rego script prohibits one action, but allows all others).

It's tempting to use required argument values as a way to extend policies, such as requiring ```confirmation: 'CONFIRM_DELETE'``` before a delete proceeds. We considered this and discarded it: an LLM that can be prompt-injected into deleting a file can also be prompt-injected into supplying the confirmation string. The user's acquiescence is unproven. The mechanism prevents accidents but not adversaries. The policy-bundle engine (see Status) addresses this pattern with signed claims — evidence whose validity depends on a channel the LLM cannot influence, verified field-by-field against the actual call rather than taken on the LLM's word.

This becomes especially acute as agents communicate with other agents. A2A, for example, has the receiving agent process every message through an LLM, making every counterparty message a potential prompt injection vector. An LLM's judgment about what its negotiating partner has agreed to is structurally unsafe; the same signed-evidence architecture that addresses single-agent authorization is even more necessary in multi-agent settings.

Signed claims as parameters — values that provably come from a valid source, such as the user or another party, and cannot have been forged by the LLM — are how the policy-bundle engine (see Status) closes this gap. Examples of the underlying evidence include Duo or CIBA push approvals, W3C Verifiable Credentials, SD-JWT, WebAuthn/passkey assertions, or DocuSign-grade envelopes.

Concretely, this works in three parts:
- Before handing a governed tool's definition to the LLM, the search-side augmenter marks which parameters must be signed, and by whom.
- That requirement forces the LLM to retrieve valid claims for those parameters, from the user or from other parties. The signing requirement prevents the LLM from spoofing.
- At tool call time, the policy validates the signed parameters — field-by-field against the actual call — as part of the allow decision.

This addresses the unverified claims issue and can also be used to strengthen the guarantee that an MCP Server is permitted. Verified claims are now key to agentic commerce, but the requirement will hold for many non-commercial operations, such as deleting files.

The `rego_policy` config option (see **Rego policies** below) is the simple case: one `.rego` file, no signed evidence, no bundle. It's a separate, lighter-weight mechanism from the policy-bundle engine described under Status — reach for `rego_policy` for a quick argument-shape rule, and the bundle engine when the decision needs to rest on verified, signed evidence rather than the raw arguments alone. Neither is privileged by the pipeline; a custom `CallFilter` can replace either.

### Where this sits relative to the agent protocols

A growing set of protocols governs agent-mediated commerce — AP2, ACP, UCP, Visa's TAP, Mastercard's Verifiable Intent. They standardize the boundary *between* organizations: how a signed instruction travels from an agent to a merchant to a payment network, and what evidence survives into a dispute.

They carry a delegation. They do not decide one. That distinction is invisible in consumer commerce, where the principal is a person spending their own money and authority follows from identity: it's Alice's card, Alice signed, done. Inside an organization it is the whole problem. Knowing *which* employee's key signed tells you nothing about whether that employee could commit the company to a $40,000 purchase. Signing authority is a policy — delegated limits, role thresholds, separation of duties, dual control above a bar — and it lives inside the organization, unverifiable from the far side of any boundary. What a counterparty can check is that a key belonging to your organization was used. Whether the party that invoked it was entitled to is a question only you can answer, and it has to be answered before the signature exists.

It is not only a commerce question. *Did this employee ask to share this document with this partner? Did this clinician request this patient's X-rays? Did the homeowner schedule this service call, before the smart home opens the door?* Same shape, no payment anywhere in it — and no cart, mandate, or payment credential can express any of them.

Here we can separate "*may*" from "*did*". A general-purpose policy model such as Zanzibar can answer if an actor *may* perform an act. That is a different question from the one here, and the two compose rather than compete. Consider the sharing case: a prompt-injected agent asks to share a document with an outside company, and the employee genuinely does hold share rights. A relationship check returns allow, and it is *right* — the permission was real. What was forged was the request. Relationship-based access control decides whether a principal **may** act; it assumes the caller is not lying about what the principal asked for.

The door case adds one more wrinkle worth naming: what has to be proven there was authorized earlier, not approved just now. Some acts rest on a standing authorization — a service call booked last Tuesday — rather than a tap on a phone at the moment of action. Both are evidence; they differ in when the human was in the loop, and a policy has to be able to ask for either.

The relationship model's assumption that the request is genuine, and the commerce protocols' assumption that the sender had authority, are the same gap seen from two sides, and neither survives a prompt-injectable intermediary. This project closes it inside the organization, before the act, in deterministic code the agent cannot talk its way around, resting on evidence the agent cannot itself produce, as required by the evaluating policy. What happens after — carrying the result across a boundary as an AP2 mandate, checking a relationship store for permission — composes on top. This is what stands behind the signature, not a replacement for the protocols that transport it.

## Setup

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/getting-started/installation/).

```bash
# Clone and install
git clone https://github.com/mattdfuchs/extensible-mcp.git
cd extensible-mcp
uv sync

# Create a config file
cp config.example.json config.json
# Edit config.json with your MCP servers
```

`config.example.json` is intentionally a minimal starter — see the Configuration section below for the full set of options (URL servers, `rego_policy`, `load_control`, etc.).

**What `uv sync` installs, and what it leaves out.** Bare `uv sync` gets you the proxy and nothing else: no test dependencies, none of the three policy engines (they are [optional extras](#policy-bundles)), and neither example package — the two under `examples/` are separate workspace members, not part of the root install. Three rungs, widest last:

| Command | Adds |
|---|---|
| `uv sync` | the proxy itself |
| `uv sync --group dev` | pytest, plus the engine extras (`wasm`, `rego`, `cel`, `cedar`) and `oauth` |
| `uv sync --all-packages --all-extras --group dev` | the `examples/` workspace members and their extras too |

Use the middle one to work on the proxy, the last one to run every suite in the repo. To install a single engine without the rest, name its extra: `uv sync --extra wasm`.

If your config references `$VAR_NAME`-style values (e.g. `"GITHUB_PERSONAL_ACCESS_TOKEN": "$GITHUB_PERSONAL_ACCESS_TOKEN"` in a stdio server's `env` block), drop a `.env` file in the same directory as the loaded config or export the variables in your shell — the proxy resolves dotenv first, then `os.environ`. The `.env` lookup is per-config-directory, so a `.env` at the repo root won't apply to configs loaded from elsewhere.

## Configuration

The config file uses the same `mcpServers` format as Claude Desktop, plus an optional `filters` section. Servers can be local (stdio via `command`) or remote (Streamable HTTP via `url`):

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
    },
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_PERSONAL_ACCESS_TOKEN": "<your-token>"
      }
    },
    "remote-tools": {
      "url": "https://example.com/mcp"
    }
  },
  "filters": {
    "similarity_threshold": 0.3,
    "access_control": {
      "deny": ["github__delete_repo"],
      "deny_patterns": ["*__drop_*", "*__delete_*"],
      "allow_servers": ["filesystem", "github"]
    },
    "load_control": {
      "deny_url_patterns": ["http://*"],
      "allow_url_patterns": ["https://github.com/*", "https://internal.corp/*"]
    }
  }
}
```

### Authentication

Many MCP servers require credentials. How the proxy supplies one depends on how the downstream server is reached, and in every case the credential stays out of the LLM's context: the model never sees a token, a client secret or a key, and the proxy's system instructions tell it never to ask for one in the conversation.

**Stdio servers** (launched as child processes via `command`) — pass credentials through the `env` block in `mcpServers`, the same way you would for any MCP server. The GitHub example in [`examples/`](examples/) uses this pattern with `$GITHUB_PERSONAL_ACCESS_TOKEN` resolved from a `.env` file or the proxy's environment.

**URL servers** (Streamable HTTP via `url`) — the proxy authenticates itself to an OAuth authorization server and is handed a short-lived access token, which lives only in memory. Declare the client identity once under `credentials`, then reference it by name from each server:

```json
{
  "credentials": {
    "corp-as": {
      "grant": "private_key_jwt",
      "token_endpoint": "https://as.example.com/oauth/token",
      "client_id": "extensible-mcp-proxy",
      "private_key_file": "keys/proxy-signing.pem"
    },
    "legacy-as": {
      "grant": "client_credentials",
      "token_endpoint": "https://legacy.example.com/oauth/token",
      "client_id": "extensible-mcp-proxy",
      "client_secret_env": "LEGACY_CLIENT_SECRET"
    }
  },
  "mcpServers": {
    "payments": {
      "url": "https://payments.example.com/mcp",
      "credential": "corp-as",
      "scope": "payments.invoke",
      "audience": "https://payments.example.com"
    }
  }
}
```

Two grants ship. Both are the OAuth 2.0 `client_credentials` grant at the token endpoint; they differ in how the proxy proves it is the client:

- `private_key_jwt` (RFC 7523) signs a short-lived assertion with a private key the authorization server never sees, so nothing replayable is transmitted or logged. It needs the `oauth` extra: `pip install "extensible-mcp[oauth]"`.
- `client_credentials` sends a client secret, read from the environment variable named by `client_secret_env`. There is deliberately no `client_secret` field: the config file is one people commit and share, so a config carrying one is refused at load.

`scope` and `audience` belong to the server rather than the credential, because one OAuth client legitimately serves many resources. Relative paths such as `private_key_file` resolve against the config file's directory. The token is attached per request and refreshed in place when the downstream answers 401, so expiry is handled without a restart and without anyone editing a file.

What this earns is *no replayable secret at rest*, not *no secret at rest*: `private_key_jwt` still keeps a private key on disk. A workload identity — a platform-attested, short-lived token exchanged at the authorization server — is the step past that, and is deliberately not built in, because every form of it is deployment-specific. The seam is there for it: a `CredentialProvider` is an object that returns a token, so "read the projected service-account token and exchange it" is another provider, written without touching the proxy.

**No identity provider is required.** Nothing in the proxy needs Keycloak, Okta, Entra or any other authorization server unless you add a `credentials` entry pointing at one. A deployment of stdio servers, or of URL servers that need no credential, runs with none. (The Order Pizza demo's passkey page has its own built-in sign-in and does not use an external provider either.)

**The tokens file.** Before 0.3.5 the only path for a URL server was a `tokens` file next to the config — one `server_name=value` line per server, `#` for comments, surrounding quotes stripped — sent as `Authorization: Bearer <token>`. It remains supported: the proxy reads it if it exists (or at the path in `EXTENSIBLE_MCP_TOKENS_FILE`, for keeping it somewhere a filesystem tool cannot reach), reads it fresh on every connection so a rotated line takes effect without a restart, and logs a note once per process when it is used, naming the grant path as the alternative. It will be removed in a later release, once a runnable example of the grant path ships alongside the demo — not before. The reason to move when that comes is that a bearer token on disk is a long-lived credential that stays valid until someone notices it has leaked, where a grant-acquired token is short-lived and never written anywhere. A server uses one path or the other: naming a `credential` for a server that also has a tokens-file line is refused at load, rather than settled by a silent precedence rule. Across servers the two can be mixed.

**A credential is only presented to a URL you configured.** A credential is keyed by server name, but the URL a connection goes to is chosen by whoever opened it — and for a runtime `load_mcp_server`, that is the LLM. So a credential is presented only when the connection's URL matches the one named for that server in the config file. A prompt-injected model calling `load_mcp_server("notion", "https://attacker.example/mcp")` gets no credential: the connection is attempted anonymously and, against a server that requires auth, simply fails. This means a server that needs a credential must be in your config, not discovered at runtime.

**Adding an authenticated server without restarting.** That rule would otherwise make "get a credential, start using it" a restart, so a running proxy reloads its server list on `SIGHUP`: add the server (and, for the grant path, its `credentials` entry) to the config and signal the process, and it connects and indexes the new tools in place. For the bearer-token path the proxy also ships an operator command:

```bash
# --token-stdin keeps the secret out of your shell history and the process list
echo -n "$TOKEN" | extensible-mcp add-server --name notion --url https://notion.example/mcp --token-stdin
```

It connects to the URL as an MCP client with that token and lists its tools, and *only if that works* writes the server into your config and the token into the tokens file (`0600`), then sends `SIGHUP` to a proxy already running against that config. If no proxy is running, the files are still written and the next start picks them up. It writes a bearer token to the tokens file, and says so when it does; a credential acquired by grant is configured by hand as above.

Verification matches the runtime exactly, including not following redirects — so a URL that redirects is reported here, with the URL to use instead, rather than passing the check and failing later at the proxy.

It is a CLI command rather than an argument on `load_mcp_server` on purpose. The flaw it works around was the model *referencing a credential it had never seen*; passing the token in inverts that, so only a caller who already holds it can use it, and the model holds none. Putting a `token` parameter on the meta-tool would be safe from exfiltration for the same reason, but it shares the surface the model drives, and any user who pasted a token into a chat to make it work would break the rule that credentials never transit the conversation.

An existing server name is never re-pointed: repointing a name at another host is the substitution the URL binding exists to prevent, so the command refuses and tells you to edit the config by hand if you really mean it.

**Credential expiry.** If a downstream call returns 401/403 (or an error message containing "unauthorized"/"forbidden") and the proxy cannot recover by acquiring a fresh token, it translates the failure into a clear error to the LLM naming the server and reporting how long the credential has been unchanged. The proxy's system instructions tell the LLM to ask the user to fix the credential and retry — never to request one in the conversation. Credentials stay out of the chat transcript by design.

### Filter pipelines

Four independent pipelines — search, call (request), response, and server-load — each pass through an ordered chain of filters before (or in the response case, after) the operation runs. The proxy enforces one structural guarantee: **the LLM can only call tools it has previously surfaced via `search_tools`.** That gate is built into the call pipeline, and nothing reaching a tool through `call_tool` can get around it.

The qualifier carries the claim. What cannot be bypassed is the call path, not the process: a tool registered directly on the `FastMCP` object is reachable by its own name and crosses no pipeline at all — not this gate, not access control, not a policy bundle. That is why a tool the proxy itself provides is passed in as `local_tools` on `create_server` and dispatched through `call_tool` like any other, and why decorating `@server.tool()` after `create_server` returns puts the hole back. Embedding the proxy means keeping every tool on the call path.

Beyond the discovery gate, the filter logic is yours to define. The filters described below ship as reference implementations and are configured via the JSON config; for anything beyond them, write your own — see [Writing a custom filter](#writing-a-custom-filter).

**Search filters** — applied to `search_tools` results before they're returned to the LLM.

| Field | Description |
|---|---|
| `similarity_threshold` | Minimum cosine similarity score (default: `0.3`) |
| `access_control.deny` | Exact qualified tool names to hide (e.g. `github__delete_repo`) |
| `access_control.deny_patterns` | Glob patterns to hide (e.g. `*__delete_*`) |
| `access_control.allow_servers` | If non-empty, only tools from these servers appear in results |

**Call filters** — applied to `call_tool` invocations before they're proxied downstream.

| Field | Description |
|---|---|
| `access_control.*` | Same deny/allow rules as search — blocks calls even if the LLM knows the tool name |

**Rego policies** — for fine-grained call-time policy evaluation, you can point to a `.rego` file:

```json
{
  "filters": {
    "rego_policy": "policies/deny_dangerous.rego"
  }
}
```

The policy receives this input on every `call_tool` invocation:

```json
{
  "tool_name": "github__delete_repo",
  "arguments": {"repo": "my-org/my-repo"},
  "server_name": "github"
}
```

The policy must define `allow` (boolean). Optionally define `deny_reason` (string) for a custom error message. See [`examples/deny_dangerous.rego`](examples/deny_dangerous.rego) for a working example. Relative paths in the config are resolved relative to the config file's directory.

Rego policy evaluation uses [`regopy`](https://pypi.org/project/regopy/), which ships as the `rego` extra: `pip install "extensible-mcp[rego]"`, or `uv sync --extra rego` in a checkout. The policy-bundle engines are extras too — `wasm` for OPA-compiled policies, `cel` for CEL, `cedar` for Cedar — since each pulls dependencies not everyone needs. A checkout's `--group dev` installs all of them.

**Response filters** — applied to tool results on their way back from the downstream server, before the LLM sees them. No reference filters ship by default; the pipeline is empty unless you wire in your own. Useful for redacting secrets that leak back from a buggy server, scrubbing or flagging prompt-injection patterns in scraped content, truncating large responses, or audit logging. See [Writing a custom filter](#writing-a-custom-filter) for the Protocol shape.

**Server load filters** — applied to `load_mcp_server` requests before any connection is made.

| Field | Description |
|---|---|
| `load_control.deny_names` | Exact server names to block |
| `load_control.deny_name_patterns` | Glob patterns on server names (e.g. `evil_*`) |
| `load_control.deny_url_patterns` | Glob patterns on URLs (e.g. `http://*` to require HTTPS) |
| `load_control.allow_url_patterns` | If non-empty, only URLs matching at least one pattern are allowed (whitelist) |

Without `load_control`, an LLM could be prompt-injected into connecting to a malicious server. Use `allow_url_patterns` to whitelist trusted domains and `deny_url_patterns` to block insecure protocols.

### Policy bundles

`rego_policy` above decides on the raw arguments alone. When the decision has to rest on signed evidence instead — a Verifiable Credential, a passkey assertion — use a **policy bundle**: a directory of four files, three of which are engine-independent.

| File | What it is |
|---|---|
| `manifest.json` | JSON Schema for the policy's whole input object. Names the input contract, declares which fields are required, and closes it with `additionalProperties: false`. |
| `fetchplan.json` | Where each input field comes from. One entry per field, with `source.kind` of `call` (from the tool call), `config` (from deployment config), `clock` (current time), `wallet` (fetched by a lookup you supply, parameterized by other input fields), or `derive` (computed from earlier fields by one primitive, for a policy language that cannot evaluate the primitive itself). A `derive` entry that verifies a signature may only be *folded* over candidate keys and *project* a witness — never applied bare to yield a verdict, because a verdict no longer carries the relation the rule has to keep. |
| `guidance.json` | A sentence for each condition the policy can fail, so a denial renders as an explanation — for a human, or for the LLM, telling it what evidence is still missing — instead of a bare `false`. Optional: a hand-written bundle may keep its sentences in the policy file instead (a CEL check written as `{"expr", "sentence"}`, a Cedar `@sentence` annotation, a Rego `deny_reason` rule), and the loader synthesises this layer from them. |
| `policy.wasm`, `checks.cel.json` *or* `policy.cedar` + `expected_ids.json` | The rules themselves, in whichever engine you prefer. A Cedar bundle also lists the policy ids its loader must find, because a forbid-only policy set that half-loads allows everything. |

All three engines are optional extras, because each pulls dependencies not every deployment wants: `pip install "extensible-mcp[wasm]"` for the OPA/WASM one, `[cel]` for CEL, `[cedar]` for Cedar. They are imported lazily, so `PolicyBundle.load` is where a base install discovers it is missing one.

The engines are interchangeable over the same guidance. Rego and CEL also share the manifest and fetch plan byte for byte; a Cedar bundle's differ only where Cedar forces it, described below. A Rego policy is compiled to WASM:

```bash
opa build -t wasm -e mypolicy/allow -e mypolicy/failed_checks \
  -e mypolicy/deny_reason policy.rego
# add --capabilities capabilities.json when the policy calls a host builtin
# beyond OPA's defaults (e.g. signature verification)
```

A CEL policy skips the compile step: `checks.cel.json` carries the expressions directly.

A Cedar policy is interpreted too, but Cedar has no host-function extension point — by design, since one would destroy the decidability that makes Cedar analysable — so a signature check cannot run *inside* the policy. Each cryptographic leaf instead becomes a `derive` entry in the fetch plan, a witness set the rule tests a relation over, which is why a Cedar bundle's manifest and fetch plan carry fields the Rego and CEL twins never need. A check id reaches a denial only as a `forbid` annotated `@id` with the guidance's check id, plus one `@assembly` forbid per tier for its own incompleteness, and the loader accepts two policy-set shapes, declared in `expected_ids.json` and never inferred. In the **forbid-only** shape, which the generated bundles use, an unconditional base `permit` carries nothing and every leaf forbid restates the negation of every other tier, so an empty set allows everything and a bundle that carries fewer forbids than the file lists is refused rather than loaded as a permit. In the **permit-decides** shape, which a hand author should use, one `permit` per tier annotated `@tier` carries that tier's conjunction once and each forbid carries only its own condition; the proxy evaluates twice, a decision pass with no `probe` key in which the forbids are inert and an empty set denies, and on a denial a probe pass with `probe: true` in which the permits are inert and the fired forbids are the failed checks. The guards are checked on every call, since cedarpy exposes a policy's effect and annotations but not its condition, and `probe` is reserved. The proxy's half of the hoist bargain is the derivation contract: the fold collects exactly the candidates the primitive verified, because a witness set that is too large makes a forbid fail to fire. A Cedar bundle is therefore *certified modulo its derivation contract*, which is a weaker claim than the other two engines can make, and the bundle's own `contract.json` says so.

**What each engine accepts.** The bundle format, not the language, sets the contract, and the three engines are not equally open. Stated plainly, so the claim is no wider than the loader:

| Engine | What a bundle may contain | What the proxy imposes |
|---|---|---|
| Rego | Any program `opa build -t wasm` compiles, exposing `<package>/allow`; `failed_checks` and `deny_reason` optional | Host builtins beyond OPA's own must be ones the proxy registers; an unregistered one fails at load |
| CEL | Any boolean CEL expression, one per check | The file format is this project's: a package, tiers, and a map from check id to expression; allow is the disjunction over tiers of each tier's conjunction. One tier with one check holds any policy CEL can express. Functions limited to the registered set |
| Cedar | Conditions over `context`, in one of two declared shapes | One `@id` forbid per check, one `@assembly` forbid per tier, an `expected_ids.json` that must match exactly, no templates; either a base permit with forbid-only leaves, or one `@tier` permit per tier with probe-guarded forbids; a fixed synthetic principal, action and resource, and an empty entity store. A Cedar policy written over real principals and entity hierarchies cannot be loaded today |

So Rego support is support for Rego; CEL support is CEL expressions in a wrapper of this project's design; and Cedar support, as of this release, is Cedar as the condition language of a bundle, in a shape a hand author can read and write. What remains for a later release is mapping Cedar's principal, action and resource onto the proxy's own, once it has a verified principal.

Any artifact can be hand-authored — several bundles under [`tests/fixtures/`](tests/fixtures/) are. The certified ones are instead **generated from a common core**, so the Rego, CEL and Cedar twins agree by construction rather than by someone keeping three files in sync. Running all three against the same inputs then tests what generation can't guarantee on its own: that three quite different runtimes — a WASM module under wasmtime, CEL expressions evaluated in-process, and Cedar's engine over host-derived witness sets — reach the same decision, and report the same failed checks, from the same signed evidence.

One consequence worth knowing when reading a bundle: the check identifiers threading a denial back to the condition that produced it are opaque join keys between the rules and `guidance.json`, and nothing in the proxy parses one. They are named, but they are still an artifact of generation. Render denials through `guidance.json`; don't build against the identifiers themselves.

Attach a loaded bundle as a call filter:

```python
from extensible_mcp import PolicyBundle, WasmPolicyFilter
from extensible_mcp.server import create_server

bundle = PolicyBundle.load("policies/spend-bundle", name="spend")
policy_filter = WasmPolicyFilter(
    bundle,
    config={"trustRootDID": "did:web:example.com", "trustRootJwk": jwk},
    wallet_lookup=my_lookup,   # serves the fetch plan's `wallet` sources
)
server = create_server(config, extra_call_filters=[policy_filter])
```

The filter assembles the policy's input from the fetch plan, evaluates it, and on a denial returns the rendered guidance rather than the raw check ids. Note what it does with the call's arguments: any field the fetch plan sources from `call` other than `tool` and `arguments` is a **credential field** — it's pulled out of the arguments, fed to the policy, and *not* forwarded downstream. The downstream tool sees only its own native arguments, never the evidence that authorized them. To govern bundles per downstream server rather than pipeline-wide, pass `bundle_router` to `create_server` instead.

**Evidence is single-use, and the policy cannot make it so.** A policy over signed evidence is a pure function of that evidence and the call, so the same credentials re-sent with the same arguments decide the same way: every signature still verifies, every binding still holds, and the action happens again. One human approval, unlimited identical calls. Spending the evidence is state the policy does not have, so it lives in a filter — wrap the policy filter in `SingleUseEvidenceFilter`, which keys on the credential's own `jti`:

```python
from extensible_mcp import SingleUseEvidenceFilter

guarded = SingleUseEvidenceFilter(policy_filter, credential_fields=("requestVC",))
```

The `jti` sits inside the signed payload, so a caller cannot vary it without invalidating the signature — which is what makes it usable as a replay key, and what a challenge derived purely from the terms lacks. It wraps rather than follows the policy filter for two reasons: the policy filter strips credential fields from the arguments it passes on, so a later filter never sees them; and evidence must be spent only when the call was actually authorized, or a call the policy refuses would burn the human's approval. The store is in memory and per process — a deployment needing replay protection across restarts or several proxies should supply its own.

Eleven worked bundles live under [`tests/fixtures/`](tests/fixtures/), each with a `PROVENANCE.md` recording where it came from and what it is: ten call-gate policies across the three engines, from the minimal trio walked through below up to an invoice-settlement policy, plus `classifier/` — a selection classifier, which decides *which* bundle governs a server rather than whether a call is allowed. A twelfth directory, `undefined_shapes/`, is not a bundle: it is a table of Rego expression shapes, measured alongside their CEL twins, pinning how each engine treats an undefined operand. [`project-overview.md`](project-overview.md) covers the modules involved.

#### Authoring a bundle

The smallest bundle in the corpus is the place to start: [`tests/fixtures/minimal_spend/`](tests/fixtures/minimal_spend/), with its CEL twin [`cel_minimal_spend/`](tests/fixtures/cel_minimal_spend/) and Cedar twin [`cedar_minimal_spend/`](tests/fixtures/cedar_minimal_spend/). One tier, one signed request, one spending cap: a call to `send` is allowed when a request credential, signed by the one key the deployment trusts, is current, names this tool and these exact arguments, and asks for at most $10. Five conditions, and every file fits on a screen.

**The three engine-independent files.** `manifest.json` is the JSON Schema of the policy's whole input, closed with `additionalProperties: false`. Five fields: the `tool` being called, its `arguments`, the `requestVC` credential as `{jws, claims}`, the trusted `requesterJwk`, and `now`. Everything the rules can read is named here, and nothing else reaches them.

`fetchplan.json` says where each field comes from, one entry per field:

```json
{"field": "tool",         "source": {"kind": "call"},   "schema": {"type": "string"},                     "guard": {"always": true, "required_in_tiers": [0], ...}}
{"field": "arguments",    "source": {"kind": "call"},   "schema": {"$ref": "#/definitions/SpendRequest"}, "guard": {...}}
{"field": "requestVC",    "source": {"kind": "call"},   "schema": {"$ref": "#/definitions/RequestVC"},    "guard": {...}}
{"field": "requesterJwk", "source": {"kind": "config"}, "schema": {"type": "string"}}
{"field": "now",          "source": {"kind": "clock"},  "schema": {"$ref": "#/definitions/Timestamp"}}
```

Three fields come from the call. Of those, `requestVC` is a credential field, because it is neither `tool` nor `arguments`: the search-side augmenter advertises it on the tool's schema, and the filter strips it before forwarding. `requesterJwk` is a deployment fact handed to the filter as `config`, and `now` is the proxy's clock, so the policy never reads the wall clock itself. A `call` entry's `guard` says which tiers require it; here every field is always required, so a call that omits the credential is refused before the rules run.

`guidance.json` gives each condition an id and a sentence:

```json
{"id": "solo.request_vc.signed_by",           "sentence": "a credential signature is invalid",             "remedy_class": "re-promptable", ...}
{"id": "solo.arguments.amount_cents_at_most", "sentence": "required: input.arguments.amountCents <= 1000", "remedy_class": "re-promptable", ...}
```

The id is the join key between the rules and this file; `remedy_class` tells the renderer whether re-prompting could open the path. These three files are identical for the Rego and CEL twins, byte for byte, and the Cedar twin differs in exactly one place, shown below.

**Where the text lives.** Someone writing rules by hand puts the sentence beside the rule, and each engine has a place for it: a CEL check written as `{"expr": ..., "sentence": ...}` instead of the bare expression, a `@sentence("...")` annotation on a Cedar `@id` forbid, a Rego `deny_reason` rule. Leave `guidance.json` out and the loader synthesises it from those — tiers from the file, call guards from the fetch plan — so the denial renders exactly as it would have; a check with no sentence renders as `required: <expression>` (CEL) or `required: <id>` (Cedar). The three twins below carry their sentences both ways, so either file can be read alone, and the corpus test holds the two identical. `guidance.json` remains the richer layer — call guards, issuer roles, what the search-side augmenter advertises — and is what a generated bundle ships; when present it wins.

**The rules, three ways.** Rego, in `policy.rego`:

```rego
allow if {
	signed_by(input.requestVC.jws, input.requesterJwk)
	within_window(input.requestVC.claims.nbf, input.requestVC.claims.exp, input.now)
	input.requestVC.claims.action == input.tool
	input.requestVC.claims.arguments == input.arguments
	input.arguments.amountCents <= 1000
}

failed_checks contains "solo.arguments.amount_cents_at_most" if {
	not allow
	input.arguments.amountCents > 1000
}
```

`signed_by` calls `io.jwt.verify_eddsa`, a host builtin the proxy supplies to the WASM module, so the signature is checked inside the policy. One `failed_checks` rule per condition reports its id on a denial, and one `deny_reason` rule per condition carries its sentence — Rego's inline form of the text, read only when there is no guidance. Compiled with:

```bash
P=policybundle/examples/minimal_spend
opa build -t wasm -e $P/allow -e $P/failed_checks -e $P/deny_reason policy.rego
```

CEL, in `checks.cel.json`, is a map from id to one expression, plus the tier each id belongs to, with no compile step. A check's value is the expression, or an object carrying the expression and its sentence:

```json
"solo.request_vc.signed_by":           {"expr": "verify_eddsa(input.requestVC.jws, input.requesterJwk)",
                                        "sentence": "a credential signature is invalid"},
"solo.arguments.amount_cents_at_most": {"expr": "input.arguments.amountCents <= 1000",
                                        "sentence": "required: input.arguments.amountCents <= 1000"}
```

A tier allows when every one of its checks is true; the ids of the checks that were not are the failed checks.

Cedar, in `policy.cedar`. Cedar cannot call a host function, so the signature check moves out of the policy and into the fetch plan: the Cedar twin's `fetchplan.json` is the shared plan plus one `derive` entry, and its manifest gains the one field that entry produces.

```json
{"field": "requestVCJwsRequesterJwkKeyWitnesses",
 "source": {"kind": "derive", "fn": "verify_eddsa",
            "args": [{"$input": "requestVC.jws"}, {"$item": "key"}],
            "over":  [{"key": {"$input": "requesterJwk"}}],
            "project": "key"}}
```

Read it as: fold `verify_eddsa(jws, key)` over the candidate keys — here, the one trusted key — and project the keys that verified. The result is a witness set the rule tests a relation over, never a bare boolean; a key that failed to verify is simply not in it. The policy is in the permit-decides shape: one `permit` per tier, annotated `@tier`, carries the tier's conditions once, and one `forbid` per condition carries only that condition and the id it reports under:

```
@tier("solo")
permit (principal, action, resource)
when {
  !(context has probe) &&
  context has requestVCJwsRequesterJwkKeyWitnesses && context has requesterJwk &&
  context.requestVCJwsRequesterJwkKeyWitnesses.contains(context.requesterJwk) &&
  context has requestVC && context.requestVC has claims &&
  context.requestVC.claims has nbf && context.requestVC.claims has exp && context has now &&
  context.requestVC.claims.nbf <= context.now && context.now <= context.requestVC.claims.exp &&
  context.requestVC.claims has action && context has tool &&
  context.requestVC.claims.action == context.tool &&
  context.requestVC.claims has arguments && context has arguments &&
  context.requestVC.claims.arguments == context.arguments &&
  context.arguments has amountCents &&
  context.arguments.amountCents <= 1000
};

@id("solo.arguments.amount_cents_at_most")
@sentence("required: input.arguments.amountCents <= 1000")
forbid (principal, action, resource)
when {
  context has probe &&
  context has arguments && context.arguments has amountCents &&
  !(context.arguments.amountCents <= 1000)
};
```

`@sentence` is the text a denial renders for that forbid when the bundle ships no guidance; the evaluator never reads it. The `probe` guards are the mechanism. The proxy evaluates the file twice. In the **decision pass** the context has no `probe` key, so every forbid is inert, the permit decides, and an input that matches no permit is denied: an empty policy set denies. On a denial the proxy runs a **probe pass** with `probe: true`, in which the permit is inert and the forbids that fire are the failed checks. One `@assembly("solo")` forbid, carrying no `@id` and probe-guarded like the rest, fires when the tier's inputs are incomplete, so the renderer can say which credential was absent. `expected_ids.json` declares the shape and lists the five ids and the one tier; the loader refuses a policy set that does not carry exactly those forbids and exactly one `@tier` permit per tier, and since cedarpy exposes a policy's effect and annotations but not its condition, the guards are checked on every call: a forbid that fires in the decision pass, or a permit that matches in the probe pass, is a fault. `probe` is reserved, as an input key and as a fetch-plan field.

The other shape the loader accepts, **forbid-only**, is what the generated bundles use: an unconditional base `permit` and leaf forbids that each restate the negation of every other tier, so that a solo leaf cannot fire on a call the full chain allows. Cedar has no way to factor that repetition, which is why a hand author should write the shape above; [`tests/fixtures/cedar_family_spend_compact/`](tests/fixtures/cedar_family_spend_compact/) is the adopted two-tier policy re-shaped that way, a quarter of the bytes, and decides identically on every differential scenario.

**What a denial looks like.** A $50 call carrying a valid $50 request fails one condition. All three engines report the same id, and it renders through the guidance as:

```
Tool call denied by policy: no allowed path was satisfied. To succeed, satisfy every condition of one of these paths:
- Path 1: required: input.arguments.amountCents <= 1000.
Gather the missing evidence or adjust the call, then retry.
```

That text is asserted byte for byte in [`tests/test_minimal_bundle_differential.py`](tests/test_minimal_bundle_differential.py), which runs every scenario — allowed under the cap, and one denial per condition — through the real filter on all three twins and holds them to one verdict and one set of ids. To write your own, copy the trio, rename the package, and change the conditions; [`tests/test_fixture_corpus.py`](tests/test_fixture_corpus.py) states what every bundle in the corpus has to keep in step.

### Writing a custom filter

The reference filters described above are starting points, not the limit of what the pipeline can do. Filters are plain Python objects implementing one of four Protocols:

- **`ToolFilter`** — `filter(results: list[SearchResult], query: str) -> list[SearchResult]`. Applied to `search_tools` results.
- **`CallFilter`** — `async check(request: CallRequest) -> CallFilterResult`. Applied to `call_tool` invocations before they're proxied downstream.
- **`ResponseFilter`** — `async check(response: CallResponse) -> ResponseFilterResult`. Applied to tool results on their way back to the LLM. Filters can inspect, modify, or replace the content; subsequent filters see the modified content.
- **`ServerLoadFilter`** — `async check(request: ServerLoadRequest) -> ServerLoadResult`. Applied to `load_mcp_server` requests.

A custom call filter that audits every invocation:

```python
from extensible_mcp import CallFilter, CallRequest, CallFilterResult

class AuditLogFilter:
    async def check(self, request: CallRequest) -> CallFilterResult:
        log_to_my_system(request.tool_name, request.arguments, request.server_name)
        return CallFilterResult(
            allowed=True,
            tool_name=request.tool_name,
            arguments=request.arguments,
        )
```

Wire it in by writing your own entry point — `create_server` accepts `extra_search_filters`, `extra_call_filters`, `extra_response_filters`, and `extra_load_filters`, plus `bundle_router` (per-server policy bundles, see [Policy bundles](#policy-bundles)) and `local_tools` (below):

```python
from extensible_mcp.config import find_config_path, load_config
from extensible_mcp.server import create_server
from myorg.filters import AuditLogFilter

config = load_config(find_config_path(None))
server = create_server(config, extra_call_filters=[AuditLogFilter()])
server.run()
```

Custom filters run after the built-in reference filters in each pipeline. To deny a call, return `CallFilterResult(allowed=False, reason="...", tool_name=..., arguments=...)`. The discovered-tools guarantee runs before any custom call filter and is always enforced regardless of your filter set.

### Adding your own tools

Some capabilities belong to the proxy itself rather than to any downstream server — requesting a signed credential, filing evidence, anything that needs the proxy's own state or network position. Pass them to `create_server` as `local_tools`:

```python
from extensible_mcp import LocalTool

async def handler(arguments: dict) -> dict:
    return {"ok": True, "echoed": arguments["message"]}

echo = LocalTool(
    name="echo_message",
    description="Echo a message back. Reached like any other tool.",
    input_schema={
        "type": "object",
        "properties": {"message": {"type": "string"}},
        "required": ["message"],
    },
    handler=handler,
)

server = create_server(config, local_tools=[echo])
```

A local tool is indexed into the same vector store, discovered by the same `search_tools`, and invoked through the same `call_tool` as a downstream tool — so the same call pipeline gates it, discovery guarantee included. The name carries no `__`, since that separator is reserved for the `{server}__{tool}` downstream namespace; `access_control.allow_servers` therefore doesn't apply to local tools, while `deny` and `deny_patterns` still match them by name.

Note what this deliberately does *not* offer: a way to register a tool that sidesteps the pipeline. Registering a tool directly on the returned `FastMCP` object would do exactly that — it would be reachable by name over plain MCP, with no filter, no policy, and no discovery gate — which is why the proxy's own capabilities go through `local_tools` instead. Whether a tool's code happens to run in-process is not a reason to trust it more.

### Config resolution order

1. `--config` CLI flag
2. `EXTENSIBLE_MCP_CONFIG` environment variable
3. `~/Library/Application Support/extensible-mcp/config.json` (macOS)
4. `~/.config/extensible-mcp/config.json`
5. `./config.json`

## Usage

```bash
# Run the server
uv run extensible-mcp

# Or with an explicit config path
uv run extensible-mcp --config /path/to/config.json
```

The proxy runs as a stdio-based MCP server. Connect to it from any MCP client the same way you would connect to any other MCP server.

## Examples

The [`examples/`](examples/) directory has ready-to-use configs for proxying GitHub's official MCP server through extensible-mcp, with two layers of security in the filter pipeline: a glob deny pattern (`*__delete_*`) that blocks all delete operations, and a Rego policy that blocks closing issues based on argument shape.

- **Claude Desktop** — [`examples/claude-desktop-config.json`](examples/claude-desktop-config.json)
- **OpenClaw** — [`examples/openclaw-config.json`](examples/openclaw-config.json)

See [`examples/README.md`](examples/README.md) for setup instructions and suggested prompts to try.

The larger, end-to-end Order Pizza commerce demo described under
[Why: Security](#why-security) lives in
[`examples/agentic-commerce-demo/`](examples/agentic-commerce-demo/),
backed by the identity/wallet package in
[`examples/identity/`](examples/identity/) — both are workspace members of
this repo; see their own READMEs for setup, or
[`deploy/`](examples/agentic-commerce-demo/deploy/) to run it
containerized, needing nothing on the host beyond Docker, a browser, and an
`ANTHROPIC_API_KEY` (the chat window runs its own agent loop).

## Development

```bash
# Install with dev dependencies (see Setup for what each rung adds)
uv sync --group dev

# Run tests
uv run pytest

# Run a single test file
uv run pytest tests/test_filters.py -v
```

`uv run pytest` runs the proxy's own suite. The two `examples/` packages have
their own, which need the wider install — see
[CONTRIBUTING.md](CONTRIBUTING.md#running-tests) for all three.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the workspace layout, dev
setup, and test commands. See [`CHANGELOG.md`](CHANGELOG.md) for what's
changed release by release.

## License

Apache License 2.0 — see [LICENSE](LICENSE).

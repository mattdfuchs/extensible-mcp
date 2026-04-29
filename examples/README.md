# Examples

These examples show how to use extensible-mcp as a proxy in front of GitHub's official MCP server, with two layers of access control:

1. A glob deny pattern (`*__delete_*`) that blocks any tool with "delete" in its name.
2. A Rego policy (`deny_close_issue.rego`) that blocks the specific argument shape `github__issue_write` with `state == "closed"`.

Together they demonstrate the two enforcement points in the filter pipeline. The deny pattern hides any matching tool from `search_tools` results so the LLM never sees it, and also rejects direct calls — so an attacker who learns a tool name like `github__delete_repository` from a prompt injection or prior conversation still can't invoke it. The Rego policy works at call time only, but enforces fine-grained, argument-aware rules that pure name-matching can't express.

## Setup

1. **Get a GitHub PAT.** Create one at https://github.com/settings/personal-access-tokens/new with `repo` scope.

2. **Provide the token via environment.** `github-proxy-config.json` references the token as `$GITHUB_PERSONAL_ACCESS_TOKEN`, which the proxy resolves at startup. Pick one:
   - Copy `.env.example` to `.env` in this directory and paste your PAT in, or
   - Export `GITHUB_PERSONAL_ACCESS_TOKEN=ghp_...` in the shell that launches the proxy.

   `.env` is gitignored; do not commit your token.

3. **Update paths.** In the client config you choose below, replace `/path/to/extensible-mcp` with the actual path to this repo.

## Proxy config: `github-proxy-config.json`

This is the extensible-mcp config. It connects to GitHub's MCP server via Docker, blocks all delete operations via a glob deny pattern, and applies a Rego policy that blocks closing issues:

```json
{
  "mcpServers": {
    "github": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-e", "GITHUB_PERSONAL_ACCESS_TOKEN",
        "ghcr.io/github/github-mcp-server"
      ],
      "env": {
        "GITHUB_PERSONAL_ACCESS_TOKEN": "$GITHUB_PERSONAL_ACCESS_TOKEN"
      }
    }
  },
  "filters": {
    "similarity_threshold": 0.3,
    "access_control": {
      "deny_patterns": ["*__delete_*"]
    },
    "rego_policy": "deny_close_issue.rego"
  }
}
```

The `$GITHUB_PERSONAL_ACCESS_TOKEN` reference is resolved at startup from a `.env` file in this directory or from the proxy's environment (see Setup above).

Try it: ask the LLM to search for tools related to "delete a branch" — `search_tools` will return nothing, because the deny pattern hides matching tools from search results before the LLM ever sees them.

## Claude Desktop: `claude-desktop-config.json`

Copy into `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS):

```json
{
  "mcpServers": {
    "extensible-mcp": {
      "command": "uv",
      "args": [
        "run",
        "--directory", "/path/to/extensible-mcp",
        "extensible-mcp",
        "--config", "/path/to/extensible-mcp/examples/github-proxy-config.json"
      ]
    }
  }
}
```

## OpenClaw: `openclaw-config.json`

Add via the OpenClaw CLI:

```bash
openclaw mcp set extensible-mcp '{
  "command": "uv",
  "args": [
    "run",
    "--directory", "/path/to/extensible-mcp",
    "extensible-mcp",
    "--config", "/path/to/extensible-mcp/examples/github-proxy-config.json"
  ]
}'
```

Or merge `openclaw-config.json` into your OpenClaw config file.

## What to try

Pick a repository you own and have push access to — the demo will create a real issue there. Substitute it for `<your-username>/<your-test-repo>` below.

1. **Search works normally:** "Search for tools related to managing GitHub issues"
2. **Call works normally:** "Create an issue on `<your-username>/<your-test-repo>` titled 'Test issue' with body 'This is a test issue'"
3. **Delete is blocked:** "Delete the branch 'old-feature' from `<your-username>/<your-test-repo>`"
4. **Closing the issue is blocked by Rego:** "Close the test issue you just created"
5. **Load a remote MCP server at runtime:** add a line like `myserver=<token>` to `examples/tokens`, then ask the LLM: "Load an MCP server named 'myserver' at `<https://your-mcp-url>`. Then search its tools and try one."

In case 3, the deny pattern hides any matching tool from `search_tools` results, so the LLM searches for delete tools, finds nothing, and reports it can't perform the operation. (Direct calls to a known delete tool name would also be rejected, but the demo's flow never reaches the call step because the tool is never surfaced.) In case 4, `github__issue_write` itself isn't blocked — the LLM finds it via search and attempts the call — but the Rego policy inspects the arguments and refuses when `state == "closed"`. The two cases illustrate the two enforcement points: search-time and call-time.

Case 5 demonstrates dynamic server loading and credential separation. The LLM invokes `load_mcp_server`, the proxy connects via Streamable HTTP, attaches the token from `examples/tokens` as an `Authorization: Bearer` header, and indexes the new server's tools — all without the token ever appearing in the conversation. Rotate by overwriting the line in `tokens`; the next connection picks it up.

Note: this example config doesn't set `load_control`, so the proxy will accept any URL the LLM is asked to load. For real use, add `load_control.allow_url_patterns` to your config to whitelist trusted hosts — otherwise a prompt-injected LLM could be tricked into connecting to a malicious server.

**Clean up afterwards.** Because case 4 demonstrates a deliberate block, the LLM cannot close the test issue for you. Close it manually via the GitHub UI when you're done.

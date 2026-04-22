# Examples

These examples show how to use extensible-mcp as a proxy in front of GitHub's official MCP server, with access control that blocks any tool with "delete" in its name.

This demonstrates the call filter pipeline: even if an LLM learns a tool name like `github__delete_repository` from a prompt injection or prior conversation, the proxy rejects the call. The deny pattern `*__delete_*` applies to all tools — including any added in future GitHub MCP server updates — without needing to enumerate them.

## Setup

1. **Get a GitHub PAT.** Create one at https://github.com/settings/personal-access-tokens/new with `repo` scope.

2. **Edit the proxy config.** In `github-proxy-config.json`, replace `<your-token>` with your PAT.

3. **Update paths.** In the client config you choose below, replace `/path/to/extensible-mcp` with the actual path to this repo.

## Proxy config: `github-proxy-config.json`

This is the extensible-mcp config. It connects to GitHub's MCP server via Docker and blocks all delete operations:

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
        "GITHUB_PERSONAL_ACCESS_TOKEN": "<your-token>"
      }
    }
  },
  "filters": {
    "similarity_threshold": 0.3,
    "access_control": {
      "deny_patterns": ["*__delete_*"]
    }
  }
}
```

Try it: ask the LLM to search for tools related to "delete a branch" — it will find them via `search_tools`, but any attempt to call them via `call_tool` will be rejected by the proxy.

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

Once connected, try these prompts to see the proxy in action:

1. **Search works normally:** "Search for tools related to managing GitHub issues"
2. **Call works normally:** "Create an issue on mattdfuchs/extensible-mcp titled 'Test issue'"
3. **Delete is blocked:** "Delete the branch 'old-feature' from mattdfuchs/extensible-mcp"

In case 3, the LLM will find delete-related tools via search, but the proxy will reject the `call_tool` invocation with an access control error — even though the tool is visible in search results.

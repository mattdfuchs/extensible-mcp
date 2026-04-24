# extensible-mcp

A programmable proxy layer for MCP that adds dynamic tool discovery, RAG-based tool retrieval, and pluggable filter pipelines.

## Why

MCP gives every tool-providing server the same interface, but the LLM client is left to deal with the consequences: a flat list of every tool from every server, injected wholesale into the context window. As the number of servers grows, this causes token bloat, degraded model performance, and hard context-limit failures — even when most tools aren't relevant to the current turn.

Beyond scale, there's no standard control plane. If you want to block dangerous operations, enforce argument policies, or gate which servers an LLM can connect to, you have to build that into each client or each server individually.

extensible-mcp sits between the LLM and your MCP servers and solves three problems at once:

1. **Dynamic tool discovery** — Connect to MCP servers at startup from config, or at runtime by URL. The LLM can pull in new capabilities from across the network on demand.
2. **RAG-based tool retrieval** — Tool definitions are embedded into a vector index and retrieved by semantic search, not dumped into the prompt. The model sees only what's relevant.
3. **Pluggable filter pipelines** — Every operation (search, call, server load) passes through a configurable filter chain. Use it for access control, argument validation, security policies, logging, or custom transformations.

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
- **`call_tool(tool_name, arguments)`** — Invoke a tool by its qualified name (e.g. `github__create_issue`). The proxy routes the call to the correct downstream server.
- **`load_mcp_server(server_name, url)`** — Connect to a new remote MCP server at runtime. Its tools are indexed immediately and become available for search and invocation.

Retrieval is model-driven: the LLM decides when to search and crafts its own queries, so there's no wasted retrieval on turns where no tools are needed.

## Setup

Requires Python 3.10+.

```bash
# Clone and install
git clone https://github.com/mattdfuchs/extensible-mcp.git
cd extensible-mcp
uv sync

# Create a config file
cp config.example.json config.json
# Edit config.json with your MCP servers
```

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

### Filter pipelines

Every request flows through a filter pipeline before it's executed. There are three independent pipelines, one per operation. Filters implement simple protocols (`ToolFilter`, `CallFilter`, `ServerLoadFilter`), so you can add your own — the built-in filters described below are just the ones that ship out of the box:

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

Tools must be discovered via `search_tools` before they can be called. This is always active and prevents the LLM from calling tools it hasn't searched for first.

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

Rego support requires the optional `regopy` dependency:

```bash
uv sync --group rego
```

**Server load filters** — applied to `load_mcp_server` requests before any connection is made.

| Field | Description |
|---|---|
| `load_control.deny_names` | Exact server names to block |
| `load_control.deny_name_patterns` | Glob patterns on server names (e.g. `evil_*`) |
| `load_control.deny_url_patterns` | Glob patterns on URLs (e.g. `http://*` to require HTTPS) |
| `load_control.allow_url_patterns` | If non-empty, only URLs matching at least one pattern are allowed (whitelist) |

Without `load_control`, an LLM could be prompt-injected into connecting to a malicious server. Use `allow_url_patterns` to whitelist trusted domains and `deny_url_patterns` to block insecure protocols.

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

The [`examples/`](examples/) directory has ready-to-use configs for proxying GitHub's official MCP server through extensible-mcp, with all delete operations blocked via `*__delete_*`:

- **Claude Desktop** — [`examples/claude-desktop-config.json`](examples/claude-desktop-config.json)
- **OpenClaw** — [`examples/openclaw-config.json`](examples/openclaw-config.json)

See [`examples/README.md`](examples/README.md) for setup instructions and suggested prompts to try.

## Development

```bash
# Install with dev dependencies
uv sync --group dev

# Run tests
uv run pytest

# Run a single test file
uv run pytest tests/test_filters.py -v
```

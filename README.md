# extensible-mcp

An MCP proxy that replaces static tool definitions with semantic search.

## Problem

As the number of MCP servers grows, so does the number of tool definitions injected into the LLM's context window. This wastes tokens, degrades performance, and hits context limits — even when most tools aren't relevant to the current task.

## How It Works

extensible-mcp sits between an LLM and your MCP servers. Instead of forwarding all tool definitions, it exposes just two meta-tools:

- **`search_tools(query)`** — Describe what you want to do in natural language. Returns matching tool definitions ranked by semantic similarity.
- **`call_tool(tool_name, arguments)`** — Invoke a tool from the search results by its qualified name (e.g. `github__create_issue`).

On startup, the proxy connects to all configured MCP servers, indexes their tools into an in-memory vector store (using [all-MiniLM-L6-v2](https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2)), and serves search queries via cosine similarity.

```
LLM  <-->  extensible-mcp (search_tools / call_tool)  <-->  MCP Server(s)
```

The model decides when to search for tools and crafts its own search queries, keeping retrieval model-driven rather than automatic.

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

The config file uses the same `mcpServers` format as Claude Desktop, plus an optional `filters` section:

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
    }
  },
  "filters": {
    "similarity_threshold": 0.3,
    "access_control": {
      "deny": ["github__delete_repo"],
      "deny_patterns": ["*__drop_*", "*__delete_*"],
      "allow_servers": ["filesystem", "github"]
    }
  }
}
```

### Filter options

| Field | Description |
|---|---|
| `similarity_threshold` | Minimum cosine similarity score to include a tool in results (default: `0.3`) |
| `access_control.deny` | Exact qualified tool names to block (e.g. `github__delete_repo`) |
| `access_control.deny_patterns` | Glob patterns to block (e.g. `*__delete_*`) |
| `access_control.allow_servers` | If non-empty, only tools from these servers are allowed |

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

## Development

```bash
# Install with dev dependencies
uv sync --group dev

# Run tests
uv run pytest

# Run a single test file
uv run pytest tests/test_filters.py -v
```

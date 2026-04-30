# Security Policy

## Reporting a Vulnerability

If you believe you have found a security vulnerability in extensible-mcp, please report it privately rather than opening a public issue.

**Preferred:** use GitHub's [private vulnerability reporting](https://github.com/mattdfuchs/extensible-mcp/security/advisories/new) for this repository.

**Alternate:** email `mattdfuchs@gmail.com` with the subject line starting `[extensible-mcp security]`.

I will acknowledge receipt within a few days and follow up with a triage assessment. Please give a reasonable amount of time for a fix to land before public disclosure; coordinated disclosure is appreciated.

## Scope

In scope:

- Vulnerabilities in the proxy itself: filter bypasses, secret leakage into the LLM's context, ways to call tools that should have been blocked, ways to load servers that `load_control` should have rejected.
- Token-handling regressions: tokens appearing in logs, in chat transcripts, or in error messages surfaced to the LLM.
- Bypasses of the structurally-enforced "the LLM can only call tools it has surfaced via `search_tools`" property.
- Denial-of-service issues that an attacker (e.g., via a prompt-injected tool description) can trigger against the proxy itself.

Out of scope:

- Vulnerabilities in downstream MCP servers — report those to the relevant upstream project.
- Issues that require a malicious local config file to be loaded — the threat model assumes the config file is trusted.
- Issues that require a malicious downstream server to already be configured. The proxy's `load_control` filter is for this; vulnerabilities in `load_control` itself are in scope.
- Issues in dependencies (Rego, FastEmbed, fastmcp, etc.) — report those to the relevant upstream.

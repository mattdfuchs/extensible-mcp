# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""A fake downstream MCP server with known tools for testing."""

from fastmcp import FastMCP

mock_mcp = FastMCP("mock-server")


@mock_mcp.tool(name="add_numbers", description="Add two numbers together")
def add_numbers(a: int, b: int) -> int:
    """Add two numbers and return the result."""
    return a + b


@mock_mcp.tool(name="send_email", description="Send an email to a recipient")
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email message."""
    return f"Email sent to {to}: {subject}"


@mock_mcp.tool(
    name="search_files", description="Search for files matching a pattern in a directory"
)
def search_files(pattern: str, directory: str = "/") -> list[str]:
    """Search for files by glob pattern."""
    return [f"{directory}/match1.txt", f"{directory}/match2.txt"]


@mock_mcp.tool(name="delete_files", description="Delete files matching a pattern")
def delete_files(pattern: str) -> str:
    """Delete files (dangerous operation)."""
    return f"Deleted files matching {pattern}"


if __name__ == "__main__":
    mock_mcp.run()

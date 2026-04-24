package extensible_mcp

default allow = true

allow = false {
    input.tool_name == "github__issue_write"
    input.arguments.state == "closed"
}

deny_reason = "Closing issues is not allowed" {
    input.tool_name == "github__issue_write"
    input.arguments.state == "closed"
}

package extensible_mcp

default allow = true

allow = false {
    contains(input.tool_name, "delete")
}

allow = false {
    contains(input.tool_name, "drop")
}

deny_reason = "Tool name contains a dangerous operation (delete/drop)" {
    contains(input.tool_name, "delete")
}

deny_reason = "Tool name contains a dangerous operation (delete/drop)" {
    contains(input.tool_name, "drop")
}

package test_policy

default allow = true

allow = false {
    contains(input.tool_name, "delete")
}

deny_reason = "delete operations are not allowed" {
    contains(input.tool_name, "delete")
}

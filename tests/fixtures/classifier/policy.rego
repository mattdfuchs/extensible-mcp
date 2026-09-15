# Hand-authored directly for this repository. Not derived from any external
# toolchain -- see PROVENANCE.md. A Descriptor -> decision policy: no crypto
# host builtins, so it needs no capabilities.json to build.
package policybundle.examples.classifier

default decision := "deny_all"

decision := "family_spend" if {
	input.origin_server == "payments"
}

decision := "readonly" if {
	not input.origin_server == "payments"
	input.config_trust_tier == "sandbox"
}

# Hand-authored for this repository. Not derived from any external toolchain
# -- see PROVENANCE.md. The smallest policy bundle in the corpus: one signed
# request, one spending cap. Its CEL twin (../cel_minimal_spend) and Cedar
# twin (../cedar_minimal_spend) decide the same five conditions, and
# tests/test_minimal_bundle_differential.py holds the three to one verdict.
package policybundle.examples.minimal_spend

default allow := false

# The request is signed by the key the deployment trusts, is current, names
# this tool and these exact arguments, and the amount is at or under the cap.
allow if {
	signed_by(input.requestVC.jws, input.requesterJwk)
	within_window(input.requestVC.claims.nbf, input.requestVC.claims.exp, input.now)
	input.requestVC.claims.action == input.tool
	input.requestVC.claims.arguments == input.arguments
	input.arguments.amountCents <= 1000
}

within_window(nbf, exp, now) if {
	nbf <= now
	now <= exp
}

# The signature check runs inside the policy: `io.jwt.verify_eddsa` is a
# host builtin the proxy supplies to the WASM module.
signed_by(jws, jwk) if {
	io.jwt.verify_eddsa(jws, jwk)
}

# One id per failable condition, reported only on a denial. The ids are the
# join keys guidance.json renders a sentence for; nothing parses them.
failed_checks contains "solo.request_vc.signed_by" if {
	not allow
	not signed_by(input.requestVC.jws, input.requesterJwk)
}

failed_checks contains "solo.request_vc.within_window" if {
	not allow
	not within_window(input.requestVC.claims.nbf, input.requestVC.claims.exp, input.now)
}

failed_checks contains "solo.request_vc.action_matches" if {
	not allow
	input.requestVC.claims.action != input.tool
}

failed_checks contains "solo.request_vc.arguments_matches" if {
	not allow
	input.requestVC.claims.arguments != input.arguments
}

failed_checks contains "solo.arguments.amount_cents_at_most" if {
	not allow
	input.arguments.amountCents > 1000
}

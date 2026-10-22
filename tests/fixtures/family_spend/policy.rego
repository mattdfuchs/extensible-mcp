# Hand-authored directly for this repository. Not derived from any external
# toolchain -- see PROVENANCE.md. Mirrors the CEL sibling bundle
# (../cel_family_spend/checks.cel.json) check-for-check, so the two prove the
# same PolicyBundle format runs against either engine.
package policybundle.examples.family_spend

default allow := false

allow if {
	common_checks
	solo_allowed
}

allow if {
	common_checks
	full_chain_allowed
}

common_checks if {
	signed_by(input.requestVC.jws, input.trustRootJwk)
	within_window(input.requestVC.claims.nbf, input.requestVC.claims.exp, input.now)
	input.requestVC.claims.action == input.tool
	input.requestVC.claims.arguments == input.arguments
	member_of(input.requesterMembership, input.trustRootDID, input.now, input.trustRootJwk)
	input.requesterMembership.claims.sub == input.requestVC.claims.iss
	input.requesterMembership.claims.role == "kid"
}

solo_allowed if {
	input.arguments.amountCents <= 1000
}

full_chain_allowed if {
	1000 < input.arguments.amountCents
	input.arguments.amountCents <= 20000
	signed_by(input.authorizationVC.jws, input.trustRootJwk)
	within_window(input.authorizationVC.claims.nbf, input.authorizationVC.claims.exp, input.now)
	bound_to(input.requestVC, input.authorizationVC)
	member_of(input.approverMembership, input.trustRootDID, input.now, input.trustRootJwk)
	input.approverMembership.claims.sub == input.authorizationVC.claims.iss
	input.approverMembership.claims.role == "parent"
}

within_window(nbf, exp, now) if {
	nbf <= now
	now <= exp
}

member_of(m, trust_root, now, trust_root_jwk) if {
	m.claims.iss == trust_root
	within_window(m.claims.nbf, m.claims.exp, now)
	signed_by(m.jws, trust_root_jwk)
}

bound_to(req, auth) if {
	req.claims.jti == auth.claims.jti
	auth.claims.requestHash == crypto.sha256(req.jws)
}

signed_by(jws, jwk) if {
	io.jwt.verify_eddsa(jws, jwk)
}

deny_reason contains "a credential signature is invalid" if {
	not allow
	not signed_by(input.requestVC.jws, input.trustRootJwk)
}

deny_reason contains "a credential is outside its validity window" if {
	not allow
	not within_window(input.requestVC.claims.nbf, input.requestVC.claims.exp, input.now)
}

deny_reason contains "required: input.requestVC.claims.action == input.tool" if {
	not allow
	input.requestVC.claims.action != input.tool
}

deny_reason contains "required: input.requestVC.claims.arguments == input.arguments" if {
	not allow
	input.requestVC.claims.arguments != input.arguments
}

deny_reason contains "the membership credential was not issued by the trust root" if {
	not allow
	input.requesterMembership.claims.iss != input.trustRootDID
}

deny_reason contains "a credential is outside its validity window" if {
	not allow
	not within_window(input.requesterMembership.claims.nbf, input.requesterMembership.claims.exp, input.now)
}

deny_reason contains "a credential signature is invalid" if {
	not allow
	not signed_by(input.requesterMembership.jws, input.trustRootJwk)
}

deny_reason contains "required: input.requesterMembership.claims.sub == input.requestVC.claims.iss" if {
	not allow
	input.requesterMembership.claims.sub != input.requestVC.claims.iss
}

deny_reason contains "required: input.requesterMembership.claims.role == \"kid\"" if {
	not allow
	input.requesterMembership.claims.role != "kid"
}

deny_reason contains "required: input.arguments.amountCents <= 1000" if {
	not allow
	input.arguments.amountCents > 1000
}

deny_reason contains "required: 1000 < input.arguments.amountCents" if {
	not allow
	1000 >= input.arguments.amountCents
}

deny_reason contains "required: input.arguments.amountCents <= 20000" if {
	not allow
	input.arguments.amountCents > 20000
}

deny_reason contains "a credential signature is invalid" if {
	not allow
	not signed_by(input.authorizationVC.jws, input.trustRootJwk)
}

deny_reason contains "a credential is outside its validity window" if {
	not allow
	not within_window(input.authorizationVC.claims.nbf, input.authorizationVC.claims.exp, input.now)
}

deny_reason contains "the authorization is not bound to this request" if {
	not allow
	not bound_to(input.requestVC, input.authorizationVC)
}

deny_reason contains "the membership credential was not issued by the trust root" if {
	not allow
	input.approverMembership.claims.iss != input.trustRootDID
}

deny_reason contains "a credential is outside its validity window" if {
	not allow
	not within_window(input.approverMembership.claims.nbf, input.approverMembership.claims.exp, input.now)
}

deny_reason contains "a credential signature is invalid" if {
	not allow
	not signed_by(input.approverMembership.jws, input.trustRootJwk)
}

deny_reason contains "required: input.approverMembership.claims.sub == input.authorizationVC.claims.iss" if {
	not allow
	input.approverMembership.claims.sub != input.authorizationVC.claims.iss
}

deny_reason contains "required: input.approverMembership.claims.role == \"parent\"" if {
	not allow
	input.approverMembership.claims.role != "parent"
}

failed_checks contains "solo.request_vc.signed_by" if {
	not allow
	not signed_by(input.requestVC.jws, input.trustRootJwk)
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

failed_checks contains "solo.requester_membership.iss_matches" if {
	not allow
	input.requesterMembership.claims.iss != input.trustRootDID
}

failed_checks contains "solo.requester_membership.within_window" if {
	not allow
	not within_window(input.requesterMembership.claims.nbf, input.requesterMembership.claims.exp, input.now)
}

failed_checks contains "solo.requester_membership.signed_by" if {
	not allow
	not signed_by(input.requesterMembership.jws, input.trustRootJwk)
}

failed_checks contains "solo.requester_membership.sub_matches" if {
	not allow
	input.requesterMembership.claims.sub != input.requestVC.claims.iss
}

failed_checks contains "solo.requester_membership.role_matches" if {
	not allow
	input.requesterMembership.claims.role != "kid"
}

failed_checks contains "solo.arguments.amount_cents_at_most" if {
	not allow
	input.arguments.amountCents > 1000
}

failed_checks contains "full_chain.request_vc.signed_by" if {
	not allow
	not signed_by(input.requestVC.jws, input.trustRootJwk)
}

failed_checks contains "full_chain.request_vc.within_window" if {
	not allow
	not within_window(input.requestVC.claims.nbf, input.requestVC.claims.exp, input.now)
}

failed_checks contains "full_chain.request_vc.action_matches" if {
	not allow
	input.requestVC.claims.action != input.tool
}

failed_checks contains "full_chain.request_vc.arguments_matches" if {
	not allow
	input.requestVC.claims.arguments != input.arguments
}

failed_checks contains "full_chain.requester_membership.iss_matches" if {
	not allow
	input.requesterMembership.claims.iss != input.trustRootDID
}

failed_checks contains "full_chain.requester_membership.within_window" if {
	not allow
	not within_window(input.requesterMembership.claims.nbf, input.requesterMembership.claims.exp, input.now)
}

failed_checks contains "full_chain.requester_membership.signed_by" if {
	not allow
	not signed_by(input.requesterMembership.jws, input.trustRootJwk)
}

failed_checks contains "full_chain.requester_membership.sub_matches" if {
	not allow
	input.requesterMembership.claims.sub != input.requestVC.claims.iss
}

failed_checks contains "full_chain.requester_membership.role_matches" if {
	not allow
	input.requesterMembership.claims.role != "kid"
}

failed_checks contains "full_chain.arguments.amount_cents_above" if {
	not allow
	1000 >= input.arguments.amountCents
}

failed_checks contains "full_chain.arguments.amount_cents_at_most" if {
	not allow
	input.arguments.amountCents > 20000
}

failed_checks contains "full_chain.authorization_vc.signed_by" if {
	not allow
	not signed_by(input.authorizationVC.jws, input.trustRootJwk)
}

failed_checks contains "full_chain.authorization_vc.within_window" if {
	not allow
	not within_window(input.authorizationVC.claims.nbf, input.authorizationVC.claims.exp, input.now)
}

failed_checks contains "full_chain.request_vc.bound_to" if {
	not allow
	not bound_to(input.requestVC, input.authorizationVC)
}

failed_checks contains "full_chain.approver_membership.iss_matches" if {
	not allow
	input.approverMembership.claims.iss != input.trustRootDID
}

failed_checks contains "full_chain.approver_membership.within_window" if {
	not allow
	not within_window(input.approverMembership.claims.nbf, input.approverMembership.claims.exp, input.now)
}

failed_checks contains "full_chain.approver_membership.signed_by" if {
	not allow
	not signed_by(input.approverMembership.jws, input.trustRootJwk)
}

failed_checks contains "full_chain.approver_membership.sub_matches" if {
	not allow
	input.approverMembership.claims.sub != input.authorizationVC.claims.iss
}

failed_checks contains "full_chain.approver_membership.role_matches" if {
	not allow
	input.approverMembership.claims.role != "parent"
}

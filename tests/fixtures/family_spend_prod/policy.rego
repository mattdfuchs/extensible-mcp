# Generated policy — do not edit by hand.
# METADATA
# schemas:
#   - input: schema
package policybundle.examples.family_spend_prod

default allow := false

allow if {
	prod_common_checks
	prod_solo
}

allow if {
	prod_common_checks
	prod_full_chain
}

prod_common_checks if {
	signed_by_did_key(input.requestVC.jws, input.requestVC.claims.iss)
	within_window(input.requestVC.claims.nbf, input.requestVC.claims.exp, input.now)
	input.requestVC.claims.vc.credentialSubject.requests.type == input.tool
	input.requestVC.claims.vc.credentialSubject.requests.amountCents == input.arguments.amountCents
	input.requestVC.claims.vc.credentialSubject.requests.merchant == input.arguments.merchant
	member_of(input.requesterMembership, input.requestVC.claims.iss, input.trustedAdminDids, input.now)
	account_bound(input.requesterMembership)
	input.requesterMembership.claims.vc.credentialSubject.role == "child"
}

prod_solo if {
	input.requestVC.claims.vc.credentialSubject.requests.amountCents <= 1000
}

prod_full_chain if {
	1000 < input.requestVC.claims.vc.credentialSubject.requests.amountCents
	input.requestVC.claims.vc.credentialSubject.requests.amountCents <= 20000
	signed_by_did_key(input.authorizationVC.jws, input.authorizationVC.claims.iss)
	within_window(input.authorizationVC.claims.nbf, input.authorizationVC.claims.exp, input.now)
	input.authorizationVC.claims.vc.credentialSubject.authorizes_request == input.requestVC.claims.jti
	hash_binds(input.authorizationVC.claims.vc.credentialSubject.request_hash, input.requestVC.jws)
	member_of(input.approverMembership, input.authorizationVC.claims.iss, input.trustedAdminDids, input.now)
	input.approverMembership.claims.vc.credentialSubject.role == "parent"
}

within_window(nbf, exp, now) if {
	nbf <= now
	now < exp
}

member_of(m, signer_iss, trusted, now) if {
	issued_by_trusted_admin(m, trusted)
	signed_by_key(m.jws, m.adminKey)
	m.claims.sub == signer_iss
	within_window(m.claims.nbf, m.claims.exp, now)
}

account_bound(m) if {
	not input.callerAccount
}

account_bound(m) if {
	m.claims.sub == input.callerAccount
}

account_bound(m) if {
	some a in m.claims.vc.credentialSubject.accounts
	a.idp == input.callerIdp
	a.account == input.callerAccount
}

issued_by_trusted_admin(m, trusted) if {
	some d in trusted
	m.claims.iss == d
}

hash_binds(rh, jws) if {
	rh == concat("", ["sha256:", crypto.sha256(jws)])
}

signed_by_did_key(jws, did) if {
	io.jwt.verify_eddsa(jws, key_from_did_key(did))
}

signed_by_key(jws, jwk) if {
	io.jwt.verify_eddsa(jws, jwk)
}

failed_checks contains "solo.request_vc.signed_by_did_key" if {
	not allow
	not signed_by_did_key(input.requestVC.jws, input.requestVC.claims.iss)
}

failed_checks contains "solo.request_vc.within_window" if {
	not allow
	not within_window(input.requestVC.claims.nbf, input.requestVC.claims.exp, input.now)
}

failed_checks contains "solo.request_vc.type_matches" if {
	not allow
	input.requestVC.claims.vc.credentialSubject.requests.type != input.tool
}

failed_checks contains "solo.request_vc.amount_cents_matches" if {
	not allow
	input.requestVC.claims.vc.credentialSubject.requests.amountCents != input.arguments.amountCents
}

failed_checks contains "solo.request_vc.merchant_matches" if {
	not allow
	input.requestVC.claims.vc.credentialSubject.requests.merchant != input.arguments.merchant
}

failed_checks contains "solo.requester_membership.issued_by_trusted_admin" if {
	not allow
	not issued_by_trusted_admin(input.requesterMembership, input.trustedAdminDids)
}

failed_checks contains "solo.requester_membership.signed_by_key" if {
	not allow
	not signed_by_key(input.requesterMembership.jws, input.requesterMembership.adminKey)
}

failed_checks contains "solo.requester_membership.sub_matches" if {
	not allow
	input.requesterMembership.claims.sub != input.requestVC.claims.iss
}

failed_checks contains "solo.requester_membership.within_window" if {
	not allow
	not within_window(input.requesterMembership.claims.nbf, input.requesterMembership.claims.exp, input.now)
}

failed_checks contains "solo.requester_membership.account_bound" if {
	not allow
	not account_bound(input.requesterMembership)
}

failed_checks contains "solo.requester_membership.role_matches" if {
	not allow
	input.requesterMembership.claims.vc.credentialSubject.role != "child"
}

failed_checks contains "solo.request_vc.amount_cents_at_most" if {
	not allow
	input.requestVC.claims.vc.credentialSubject.requests.amountCents > 1000
}

failed_checks contains "full_chain.request_vc.signed_by_did_key" if {
	not allow
	not signed_by_did_key(input.requestVC.jws, input.requestVC.claims.iss)
}

failed_checks contains "full_chain.request_vc.within_window" if {
	not allow
	not within_window(input.requestVC.claims.nbf, input.requestVC.claims.exp, input.now)
}

failed_checks contains "full_chain.request_vc.type_matches" if {
	not allow
	input.requestVC.claims.vc.credentialSubject.requests.type != input.tool
}

failed_checks contains "full_chain.request_vc.amount_cents_matches" if {
	not allow
	input.requestVC.claims.vc.credentialSubject.requests.amountCents != input.arguments.amountCents
}

failed_checks contains "full_chain.request_vc.merchant_matches" if {
	not allow
	input.requestVC.claims.vc.credentialSubject.requests.merchant != input.arguments.merchant
}

failed_checks contains "full_chain.requester_membership.issued_by_trusted_admin" if {
	not allow
	not issued_by_trusted_admin(input.requesterMembership, input.trustedAdminDids)
}

failed_checks contains "full_chain.requester_membership.signed_by_key" if {
	not allow
	not signed_by_key(input.requesterMembership.jws, input.requesterMembership.adminKey)
}

failed_checks contains "full_chain.requester_membership.sub_matches" if {
	not allow
	input.requesterMembership.claims.sub != input.requestVC.claims.iss
}

failed_checks contains "full_chain.requester_membership.within_window" if {
	not allow
	not within_window(input.requesterMembership.claims.nbf, input.requesterMembership.claims.exp, input.now)
}

failed_checks contains "full_chain.requester_membership.account_bound" if {
	not allow
	not account_bound(input.requesterMembership)
}

failed_checks contains "full_chain.requester_membership.role_matches" if {
	not allow
	input.requesterMembership.claims.vc.credentialSubject.role != "child"
}

failed_checks contains "full_chain.request_vc.amount_cents_above" if {
	not allow
	1000 >= input.requestVC.claims.vc.credentialSubject.requests.amountCents
}

failed_checks contains "full_chain.request_vc.amount_cents_at_most" if {
	not allow
	input.requestVC.claims.vc.credentialSubject.requests.amountCents > 20000
}

failed_checks contains "full_chain.authorization_vc.signed_by_did_key" if {
	not allow
	not signed_by_did_key(input.authorizationVC.jws, input.authorizationVC.claims.iss)
}

failed_checks contains "full_chain.authorization_vc.within_window" if {
	not allow
	not within_window(input.authorizationVC.claims.nbf, input.authorizationVC.claims.exp, input.now)
}

failed_checks contains "full_chain.authorization_vc.authorizes_request_matches" if {
	not allow
	input.authorizationVC.claims.vc.credentialSubject.authorizes_request != input.requestVC.claims.jti
}

failed_checks contains "full_chain.authorization_vc.hash_binds" if {
	not allow
	not hash_binds(input.authorizationVC.claims.vc.credentialSubject.request_hash, input.requestVC.jws)
}

failed_checks contains "full_chain.approver_membership.issued_by_trusted_admin" if {
	not allow
	not issued_by_trusted_admin(input.approverMembership, input.trustedAdminDids)
}

failed_checks contains "full_chain.approver_membership.signed_by_key" if {
	not allow
	not signed_by_key(input.approverMembership.jws, input.approverMembership.adminKey)
}

failed_checks contains "full_chain.approver_membership.sub_matches" if {
	not allow
	input.approverMembership.claims.sub != input.authorizationVC.claims.iss
}

failed_checks contains "full_chain.approver_membership.within_window" if {
	not allow
	not within_window(input.approverMembership.claims.nbf, input.approverMembership.claims.exp, input.now)
}

failed_checks contains "full_chain.approver_membership.role_matches" if {
	not allow
	input.approverMembership.claims.vc.credentialSubject.role != "parent"
}


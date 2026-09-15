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
	some d in trusted
	m.claims.iss == d
	signed_by_key(m.jws, m.adminKey)
	m.claims.sub == signer_iss
	within_window(m.claims.nbf, m.claims.exp, now)
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

deny_reason contains "a credential signature is invalid" if {
	not allow
	not signed_by_did_key(input.requestVC.jws, input.requestVC.claims.iss)
}

deny_reason contains "a credential is outside its validity window" if {
	not allow
	not within_window(input.requestVC.claims.nbf, input.requestVC.claims.exp, input.now)
}

deny_reason contains "required: input.requestVC.claims.vc.credentialSubject.requests.type == input.tool" if {
	not allow
	input.requestVC.claims.vc.credentialSubject.requests.type != input.tool
}

deny_reason contains "required: input.requestVC.claims.vc.credentialSubject.requests.amountCents == input.arguments.amountCents" if {
	not allow
	input.requestVC.claims.vc.credentialSubject.requests.amountCents != input.arguments.amountCents
}

deny_reason contains "required: input.requestVC.claims.vc.credentialSubject.requests.merchant == input.arguments.merchant" if {
	not allow
	input.requestVC.claims.vc.credentialSubject.requests.merchant != input.arguments.merchant
}

deny_reason contains "a membership credential does not chain to a trusted admin" if {
	not allow
	not member_of(input.requesterMembership, input.requestVC.claims.iss, input.trustedAdminDids, input.now)
}

deny_reason contains "required: input.requesterMembership.claims.vc.credentialSubject.role == \"child\"" if {
	not allow
	input.requesterMembership.claims.vc.credentialSubject.role != "child"
}

deny_reason contains "required: input.requestVC.claims.vc.credentialSubject.requests.amountCents <= 1000" if {
	not allow
	input.requestVC.claims.vc.credentialSubject.requests.amountCents > 1000
}

deny_reason contains "required: 1000 < input.requestVC.claims.vc.credentialSubject.requests.amountCents" if {
	not allow
	1000 >= input.requestVC.claims.vc.credentialSubject.requests.amountCents
}

deny_reason contains "required: input.requestVC.claims.vc.credentialSubject.requests.amountCents <= 20000" if {
	not allow
	input.requestVC.claims.vc.credentialSubject.requests.amountCents > 20000
}

deny_reason contains "a credential signature is invalid" if {
	not allow
	not signed_by_did_key(input.authorizationVC.jws, input.authorizationVC.claims.iss)
}

deny_reason contains "a credential is outside its validity window" if {
	not allow
	not within_window(input.authorizationVC.claims.nbf, input.authorizationVC.claims.exp, input.now)
}

deny_reason contains "required: input.authorizationVC.claims.vc.credentialSubject.authorizes_request == input.requestVC.claims.jti" if {
	not allow
	input.authorizationVC.claims.vc.credentialSubject.authorizes_request != input.requestVC.claims.jti
}

deny_reason contains "the authorization is not bound to this request" if {
	not allow
	not hash_binds(input.authorizationVC.claims.vc.credentialSubject.request_hash, input.requestVC.jws)
}

deny_reason contains "a membership credential does not chain to a trusted admin" if {
	not allow
	not member_of(input.approverMembership, input.authorizationVC.claims.iss, input.trustedAdminDids, input.now)
}

deny_reason contains "required: input.approverMembership.claims.vc.credentialSubject.role == \"parent\"" if {
	not allow
	input.approverMembership.claims.vc.credentialSubject.role != "parent"
}

failed_checks contains "t0.c0" if {
	not allow
	not signed_by_did_key(input.requestVC.jws, input.requestVC.claims.iss)
}

failed_checks contains "t0.c1" if {
	not allow
	not within_window(input.requestVC.claims.nbf, input.requestVC.claims.exp, input.now)
}

failed_checks contains "t0.c2" if {
	not allow
	input.requestVC.claims.vc.credentialSubject.requests.type != input.tool
}

failed_checks contains "t0.c3" if {
	not allow
	input.requestVC.claims.vc.credentialSubject.requests.amountCents != input.arguments.amountCents
}

failed_checks contains "t0.c4" if {
	not allow
	input.requestVC.claims.vc.credentialSubject.requests.merchant != input.arguments.merchant
}

failed_checks contains "t0.c5" if {
	not allow
	not member_of(input.requesterMembership, input.requestVC.claims.iss, input.trustedAdminDids, input.now)
}

failed_checks contains "t0.c6" if {
	not allow
	input.requesterMembership.claims.vc.credentialSubject.role != "child"
}

failed_checks contains "t0.c7" if {
	not allow
	input.requestVC.claims.vc.credentialSubject.requests.amountCents > 1000
}

failed_checks contains "t1.c0" if {
	not allow
	not signed_by_did_key(input.requestVC.jws, input.requestVC.claims.iss)
}

failed_checks contains "t1.c1" if {
	not allow
	not within_window(input.requestVC.claims.nbf, input.requestVC.claims.exp, input.now)
}

failed_checks contains "t1.c2" if {
	not allow
	input.requestVC.claims.vc.credentialSubject.requests.type != input.tool
}

failed_checks contains "t1.c3" if {
	not allow
	input.requestVC.claims.vc.credentialSubject.requests.amountCents != input.arguments.amountCents
}

failed_checks contains "t1.c4" if {
	not allow
	input.requestVC.claims.vc.credentialSubject.requests.merchant != input.arguments.merchant
}

failed_checks contains "t1.c5" if {
	not allow
	not member_of(input.requesterMembership, input.requestVC.claims.iss, input.trustedAdminDids, input.now)
}

failed_checks contains "t1.c6" if {
	not allow
	input.requesterMembership.claims.vc.credentialSubject.role != "child"
}

failed_checks contains "t1.c7" if {
	not allow
	1000 >= input.requestVC.claims.vc.credentialSubject.requests.amountCents
}

failed_checks contains "t1.c8" if {
	not allow
	input.requestVC.claims.vc.credentialSubject.requests.amountCents > 20000
}

failed_checks contains "t1.c9" if {
	not allow
	not signed_by_did_key(input.authorizationVC.jws, input.authorizationVC.claims.iss)
}

failed_checks contains "t1.c10" if {
	not allow
	not within_window(input.authorizationVC.claims.nbf, input.authorizationVC.claims.exp, input.now)
}

failed_checks contains "t1.c11" if {
	not allow
	input.authorizationVC.claims.vc.credentialSubject.authorizes_request != input.requestVC.claims.jti
}

failed_checks contains "t1.c12" if {
	not allow
	not hash_binds(input.authorizationVC.claims.vc.credentialSubject.request_hash, input.requestVC.jws)
}

failed_checks contains "t1.c13" if {
	not allow
	not member_of(input.approverMembership, input.authorizationVC.claims.iss, input.trustedAdminDids, input.now)
}

failed_checks contains "t1.c14" if {
	not allow
	input.approverMembership.claims.vc.credentialSubject.role != "parent"
}


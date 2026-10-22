# Generated policy — do not edit by hand.
# METADATA
# schemas:
#   - input: schema
package policybundle.examples.family_spend_webauthn

default allow := false

allow if {
	wa_common_checks
	wa_solo
}

allow if {
	wa_common_checks
	wa_full_chain
}

wa_common_checks if {
	signed_by_did_key(input.requestVC.jws, input.requestVC.claims.iss)
	within_window(input.requestVC.claims.nbf, input.requestVC.claims.exp, input.now)
	input.requestVC.claims.vc.credentialSubject.requests.type == input.tool
	input.requestVC.claims.vc.credentialSubject.requests.amountCents == input.arguments.amountCents
	input.requestVC.claims.vc.credentialSubject.requests.merchant == input.arguments.merchant
	member_of(input.requesterMembership, input.requestVC.claims.iss, input.trustedAdminDids, input.now)
	input.requesterMembership.claims.vc.credentialSubject.role == "child"
}

wa_solo if {
	input.requestVC.claims.vc.credentialSubject.requests.amountCents <= 1000
}

wa_full_chain if {
	1000 < input.requestVC.claims.vc.credentialSubject.requests.amountCents
	input.requestVC.claims.vc.credentialSubject.requests.amountCents <= 20000
	webauthn_verified(input.approval.authenticatorData, input.approval.clientDataJSON, input.approval.signature, input.approverEnrollment.claims.vc.credentialSubject.publicKey, input.webauthnOrigin)
	spend_challenge_binds(input.approval.clientDataJSON, input.tool, input.arguments.amountCents, input.arguments.merchant)
	enrolled_as(input.approverEnrollment, input.approval.credentialId, input.trustedAdminDids, input.now)
	input.approverEnrollment.claims.vc.credentialSubject.role == "parent"
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

enrolled_as(e, cred_id, trusted, now) if {
	enrolled_by_trusted_admin(e, trusted)
	signed_by_key(e.jws, e.adminKey)
	e.claims.sub == cred_id
	within_window(e.claims.nbf, e.claims.exp, now)
}

issued_by_trusted_admin(m, trusted) if {
	some d in trusted
	m.claims.iss == d
}

enrolled_by_trusted_admin(e, trusted) if {
	some d in trusted
	e.claims.iss == d
}

signed_by_did_key(jws, did) if {
	io.jwt.verify_eddsa(jws, key_from_did_key(did))
}

signed_by_key(jws, jwk) if {
	io.jwt.verify_eddsa(jws, jwk)
}

spend_challenge_binds(cd, tool, amount_cents, merchant) if {
	json.unmarshal(base64url.decode(cd)).challenge == base64url.encode_no_pad(crypto.sha256(concat("|", ["legov1", "spend", tool, format_int(amount_cents, 10), merchant])))
}

webauthn_verified(ad, cd, sig, jwk, origin) if {
	verify_webauthn(ad, cd, sig, jwk)
	json.unmarshal(base64url.decode(cd)).origin == origin
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

deny_reason contains "the membership credential's issuer is not a trusted admin" if {
	not allow
	not issued_by_trusted_admin(input.requesterMembership, input.trustedAdminDids)
}

deny_reason contains "a credential's signature could not be verified against its issuer's key" if {
	not allow
	not signed_by_key(input.requesterMembership.jws, input.requesterMembership.adminKey)
}

deny_reason contains "required: input.requesterMembership.claims.sub == input.requestVC.claims.iss" if {
	not allow
	input.requesterMembership.claims.sub != input.requestVC.claims.iss
}

deny_reason contains "a credential is outside its validity window" if {
	not allow
	not within_window(input.requesterMembership.claims.nbf, input.requesterMembership.claims.exp, input.now)
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

deny_reason contains "the passkey assertion is invalid" if {
	not allow
	not webauthn_verified(input.approval.authenticatorData, input.approval.clientDataJSON, input.approval.signature, input.approverEnrollment.claims.vc.credentialSubject.publicKey, input.webauthnOrigin)
}

deny_reason contains "the approval is not bound to this exact call" if {
	not allow
	not spend_challenge_binds(input.approval.clientDataJSON, input.tool, input.arguments.amountCents, input.arguments.merchant)
}

deny_reason contains "the enrollment credential's issuer is not a trusted admin" if {
	not allow
	not enrolled_by_trusted_admin(input.approverEnrollment, input.trustedAdminDids)
}

deny_reason contains "a credential's signature could not be verified against its issuer's key" if {
	not allow
	not signed_by_key(input.approverEnrollment.jws, input.approverEnrollment.adminKey)
}

deny_reason contains "required: input.approverEnrollment.claims.sub == input.approval.credentialId" if {
	not allow
	input.approverEnrollment.claims.sub != input.approval.credentialId
}

deny_reason contains "a credential is outside its validity window" if {
	not allow
	not within_window(input.approverEnrollment.claims.nbf, input.approverEnrollment.claims.exp, input.now)
}

deny_reason contains "required: input.approverEnrollment.claims.vc.credentialSubject.role == \"parent\"" if {
	not allow
	input.approverEnrollment.claims.vc.credentialSubject.role != "parent"
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

failed_checks contains "full_chain.approval.webauthn_verified" if {
	not allow
	not webauthn_verified(input.approval.authenticatorData, input.approval.clientDataJSON, input.approval.signature, input.approverEnrollment.claims.vc.credentialSubject.publicKey, input.webauthnOrigin)
}

failed_checks contains "full_chain.approval.spend_challenge_binds" if {
	not allow
	not spend_challenge_binds(input.approval.clientDataJSON, input.tool, input.arguments.amountCents, input.arguments.merchant)
}

failed_checks contains "full_chain.approver_enrollment.enrolled_by_trusted_admin" if {
	not allow
	not enrolled_by_trusted_admin(input.approverEnrollment, input.trustedAdminDids)
}

failed_checks contains "full_chain.approver_enrollment.signed_by_key" if {
	not allow
	not signed_by_key(input.approverEnrollment.jws, input.approverEnrollment.adminKey)
}

failed_checks contains "full_chain.approver_enrollment.sub_matches" if {
	not allow
	input.approverEnrollment.claims.sub != input.approval.credentialId
}

failed_checks contains "full_chain.approver_enrollment.within_window" if {
	not allow
	not within_window(input.approverEnrollment.claims.nbf, input.approverEnrollment.claims.exp, input.now)
}

failed_checks contains "full_chain.approver_enrollment.role_matches" if {
	not allow
	input.approverEnrollment.claims.vc.credentialSubject.role != "parent"
}


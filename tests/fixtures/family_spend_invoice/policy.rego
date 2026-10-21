# Generated policy — do not edit by hand.
# METADATA
# schemas:
#   - input: schema
package policybundle.examples.family_spend_invoice

default allow := false

allow if {
	invoice_common_checks
	invoice_solo
}

allow if {
	invoice_common_checks
	invoice_dual
}

invoice_common_checks if {
	signed_by_trusted_merchant(input.invoice, input.trustedMerchants)
	invoice_unexpired(input.invoice.canonical, input.now)
	invoice_binds_call
	child_approved
}

invoice_solo if {
	input.arguments.amountCents <= 1000
}

invoice_dual if {
	1000 < input.arguments.amountCents
	input.arguments.amountCents <= 20000
	webauthn_verified(input.parentApproval.authenticatorData, input.parentApproval.clientDataJSON, input.parentApproval.signature, input.parentEnrollment.claims.vc.credentialSubject.publicKey, input.webauthnOrigin)
	invoice_challenge_binds(input.parentApproval.clientDataJSON, input.invoice.canonical)
	enrolled_as(input.parentEnrollment, input.parentApproval.credentialId, input.trustedAdminDids, input.now)
	input.parentEnrollment.claims.vc.credentialSubject.role == "parent"
}

signed_by_trusted_merchant(inv, merchants) if {
	some m in merchants
	invoice_merchant_matches(inv.canonical, m.merchantId)
	verify_ed25519_raw(inv.canonical, inv.signature, m.key)
}

invoice_binds_call if {
	invoice_total_matches(input.invoice.canonical, input.arguments.amountCents)
	invoice_merchant_matches(input.invoice.canonical, input.arguments.merchantId)
}

child_approved if {
	webauthn_verified(input.childApproval.authenticatorData, input.childApproval.clientDataJSON, input.childApproval.signature, input.childEnrollment.claims.vc.credentialSubject.publicKey, input.webauthnOrigin)
	invoice_challenge_binds(input.childApproval.clientDataJSON, input.invoice.canonical)
	enrolled_as(input.childEnrollment, input.childApproval.credentialId, input.trustedAdminDids, input.now)
	input.childEnrollment.claims.vc.credentialSubject.role == "child"
}

enrolled_as(e, cred_id, trusted, now) if {
	enrolled_by_trusted_admin(e, trusted)
	signed_by_key(e.jws, e.adminKey)
	e.claims.sub == cred_id
	within_window(e.claims.nbf, e.claims.exp, now)
}

enrolled_by_trusted_admin(e, trusted) if {
	some d in trusted
	e.claims.iss == d
}

within_window(nbf, exp, now) if {
	nbf <= now
	now < exp
}

invoice_challenge_binds(cd, canonical) if {
	json.unmarshal(base64url.decode(cd)).challenge == base64url.encode_no_pad(crypto.sha256(canonical))
}

invoice_merchant_matches(c, m) if {
	json.unmarshal(c).merchantId == m
}

invoice_total_matches(c, cents) if {
	json.unmarshal(c).totalCents == cents
}

invoice_unexpired(c, now) if {
	now < json.unmarshal(c).exp
}

signed_by_key(jws, jwk) if {
	io.jwt.verify_eddsa(jws, jwk)
}

webauthn_verified(ad, cd, sig, jwk, origin) if {
	verify_webauthn(ad, cd, sig, jwk)
	json.unmarshal(base64url.decode(cd)).origin == origin
}

deny_reason contains "the invoice is not signed by a trusted merchant" if {
	not allow
	not signed_by_trusted_merchant(input.invoice, input.trustedMerchants)
}

deny_reason contains "the invoice has expired" if {
	not allow
	not invoice_unexpired(input.invoice.canonical, input.now)
}

deny_reason contains "the invoice total is not the amount this call would pay" if {
	not allow
	not invoice_total_matches(input.invoice.canonical, input.arguments.amountCents)
}

deny_reason contains "the invoice is not from the merchant this call names" if {
	not allow
	not invoice_merchant_matches(input.invoice.canonical, input.arguments.merchantId)
}

deny_reason contains "the passkey assertion is invalid" if {
	not allow
	not webauthn_verified(input.childApproval.authenticatorData, input.childApproval.clientDataJSON, input.childApproval.signature, input.childEnrollment.claims.vc.credentialSubject.publicKey, input.webauthnOrigin)
}

deny_reason contains "the approval is not bound to this invoice" if {
	not allow
	not invoice_challenge_binds(input.childApproval.clientDataJSON, input.invoice.canonical)
}

deny_reason contains "the enrollment credential's issuer is not a trusted admin" if {
	not allow
	not enrolled_by_trusted_admin(input.childEnrollment, input.trustedAdminDids)
}

deny_reason contains "a credential's signature could not be verified against its issuer's key" if {
	not allow
	not signed_by_key(input.childEnrollment.jws, input.childEnrollment.adminKey)
}

deny_reason contains "required: input.childEnrollment.claims.sub == input.childApproval.credentialId" if {
	not allow
	input.childEnrollment.claims.sub != input.childApproval.credentialId
}

deny_reason contains "a credential is outside its validity window" if {
	not allow
	not within_window(input.childEnrollment.claims.nbf, input.childEnrollment.claims.exp, input.now)
}

deny_reason contains "required: input.childEnrollment.claims.vc.credentialSubject.role == \"child\"" if {
	not allow
	input.childEnrollment.claims.vc.credentialSubject.role != "child"
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

deny_reason contains "the passkey assertion is invalid" if {
	not allow
	not webauthn_verified(input.parentApproval.authenticatorData, input.parentApproval.clientDataJSON, input.parentApproval.signature, input.parentEnrollment.claims.vc.credentialSubject.publicKey, input.webauthnOrigin)
}

deny_reason contains "the approval is not bound to this invoice" if {
	not allow
	not invoice_challenge_binds(input.parentApproval.clientDataJSON, input.invoice.canonical)
}

deny_reason contains "the enrollment credential's issuer is not a trusted admin" if {
	not allow
	not enrolled_by_trusted_admin(input.parentEnrollment, input.trustedAdminDids)
}

deny_reason contains "a credential's signature could not be verified against its issuer's key" if {
	not allow
	not signed_by_key(input.parentEnrollment.jws, input.parentEnrollment.adminKey)
}

deny_reason contains "required: input.parentEnrollment.claims.sub == input.parentApproval.credentialId" if {
	not allow
	input.parentEnrollment.claims.sub != input.parentApproval.credentialId
}

deny_reason contains "a credential is outside its validity window" if {
	not allow
	not within_window(input.parentEnrollment.claims.nbf, input.parentEnrollment.claims.exp, input.now)
}

deny_reason contains "required: input.parentEnrollment.claims.vc.credentialSubject.role == \"parent\"" if {
	not allow
	input.parentEnrollment.claims.vc.credentialSubject.role != "parent"
}

failed_checks contains "solo.invoice.signed_by_trusted_merchant" if {
	not allow
	not signed_by_trusted_merchant(input.invoice, input.trustedMerchants)
}

failed_checks contains "solo.invoice.unexpired" if {
	not allow
	not invoice_unexpired(input.invoice.canonical, input.now)
}

failed_checks contains "solo.invoice.total_matches" if {
	not allow
	not invoice_total_matches(input.invoice.canonical, input.arguments.amountCents)
}

failed_checks contains "solo.invoice.merchant_matches" if {
	not allow
	not invoice_merchant_matches(input.invoice.canonical, input.arguments.merchantId)
}

failed_checks contains "solo.child_approval.webauthn_verified" if {
	not allow
	not webauthn_verified(input.childApproval.authenticatorData, input.childApproval.clientDataJSON, input.childApproval.signature, input.childEnrollment.claims.vc.credentialSubject.publicKey, input.webauthnOrigin)
}

failed_checks contains "solo.child_approval.invoice_challenge_binds" if {
	not allow
	not invoice_challenge_binds(input.childApproval.clientDataJSON, input.invoice.canonical)
}

failed_checks contains "solo.child_enrollment.enrolled_by_trusted_admin" if {
	not allow
	not enrolled_by_trusted_admin(input.childEnrollment, input.trustedAdminDids)
}

failed_checks contains "solo.child_enrollment.signed_by_key" if {
	not allow
	not signed_by_key(input.childEnrollment.jws, input.childEnrollment.adminKey)
}

failed_checks contains "solo.child_enrollment.sub_matches" if {
	not allow
	input.childEnrollment.claims.sub != input.childApproval.credentialId
}

failed_checks contains "solo.child_enrollment.within_window" if {
	not allow
	not within_window(input.childEnrollment.claims.nbf, input.childEnrollment.claims.exp, input.now)
}

failed_checks contains "solo.child_enrollment.role_matches" if {
	not allow
	input.childEnrollment.claims.vc.credentialSubject.role != "child"
}

failed_checks contains "solo.arguments.amount_cents_at_most" if {
	not allow
	input.arguments.amountCents > 1000
}

failed_checks contains "dual.invoice.signed_by_trusted_merchant" if {
	not allow
	not signed_by_trusted_merchant(input.invoice, input.trustedMerchants)
}

failed_checks contains "dual.invoice.unexpired" if {
	not allow
	not invoice_unexpired(input.invoice.canonical, input.now)
}

failed_checks contains "dual.invoice.total_matches" if {
	not allow
	not invoice_total_matches(input.invoice.canonical, input.arguments.amountCents)
}

failed_checks contains "dual.invoice.merchant_matches" if {
	not allow
	not invoice_merchant_matches(input.invoice.canonical, input.arguments.merchantId)
}

failed_checks contains "dual.child_approval.webauthn_verified" if {
	not allow
	not webauthn_verified(input.childApproval.authenticatorData, input.childApproval.clientDataJSON, input.childApproval.signature, input.childEnrollment.claims.vc.credentialSubject.publicKey, input.webauthnOrigin)
}

failed_checks contains "dual.child_approval.invoice_challenge_binds" if {
	not allow
	not invoice_challenge_binds(input.childApproval.clientDataJSON, input.invoice.canonical)
}

failed_checks contains "dual.child_enrollment.enrolled_by_trusted_admin" if {
	not allow
	not enrolled_by_trusted_admin(input.childEnrollment, input.trustedAdminDids)
}

failed_checks contains "dual.child_enrollment.signed_by_key" if {
	not allow
	not signed_by_key(input.childEnrollment.jws, input.childEnrollment.adminKey)
}

failed_checks contains "dual.child_enrollment.sub_matches" if {
	not allow
	input.childEnrollment.claims.sub != input.childApproval.credentialId
}

failed_checks contains "dual.child_enrollment.within_window" if {
	not allow
	not within_window(input.childEnrollment.claims.nbf, input.childEnrollment.claims.exp, input.now)
}

failed_checks contains "dual.child_enrollment.role_matches" if {
	not allow
	input.childEnrollment.claims.vc.credentialSubject.role != "child"
}

failed_checks contains "dual.arguments.amount_cents_above" if {
	not allow
	1000 >= input.arguments.amountCents
}

failed_checks contains "dual.arguments.amount_cents_at_most" if {
	not allow
	input.arguments.amountCents > 20000
}

failed_checks contains "dual.parent_approval.webauthn_verified" if {
	not allow
	not webauthn_verified(input.parentApproval.authenticatorData, input.parentApproval.clientDataJSON, input.parentApproval.signature, input.parentEnrollment.claims.vc.credentialSubject.publicKey, input.webauthnOrigin)
}

failed_checks contains "dual.parent_approval.invoice_challenge_binds" if {
	not allow
	not invoice_challenge_binds(input.parentApproval.clientDataJSON, input.invoice.canonical)
}

failed_checks contains "dual.parent_enrollment.enrolled_by_trusted_admin" if {
	not allow
	not enrolled_by_trusted_admin(input.parentEnrollment, input.trustedAdminDids)
}

failed_checks contains "dual.parent_enrollment.signed_by_key" if {
	not allow
	not signed_by_key(input.parentEnrollment.jws, input.parentEnrollment.adminKey)
}

failed_checks contains "dual.parent_enrollment.sub_matches" if {
	not allow
	input.parentEnrollment.claims.sub != input.parentApproval.credentialId
}

failed_checks contains "dual.parent_enrollment.within_window" if {
	not allow
	not within_window(input.parentEnrollment.claims.nbf, input.parentEnrollment.claims.exp, input.now)
}

failed_checks contains "dual.parent_enrollment.role_matches" if {
	not allow
	input.parentEnrollment.claims.vc.credentialSubject.role != "parent"
}


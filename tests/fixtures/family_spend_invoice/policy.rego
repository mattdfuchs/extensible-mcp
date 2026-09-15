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
	invoice_merchant_is(inv.canonical, m.merchantId)
	verify_ed25519_raw(inv.canonical, inv.signature, m.key)
}

invoice_binds_call if {
	invoice_total_is(input.invoice.canonical, input.arguments.amountCents)
	invoice_merchant_is(input.invoice.canonical, input.arguments.merchantId)
}

child_approved if {
	webauthn_verified(input.childApproval.authenticatorData, input.childApproval.clientDataJSON, input.childApproval.signature, input.childEnrollment.claims.vc.credentialSubject.publicKey, input.webauthnOrigin)
	invoice_challenge_binds(input.childApproval.clientDataJSON, input.invoice.canonical)
	enrolled_as(input.childEnrollment, input.childApproval.credentialId, input.trustedAdminDids, input.now)
	input.childEnrollment.claims.vc.credentialSubject.role == "child"
}

enrolled_as(e, cred_id, trusted, now) if {
	some d in trusted
	e.claims.iss == d
	signed_by_key(e.jws, e.adminKey)
	e.claims.sub == cred_id
	within_window(e.claims.nbf, e.claims.exp, now)
}

within_window(nbf, exp, now) if {
	nbf <= now
	now < exp
}

invoice_challenge_binds(cd, canonical) if {
	json.unmarshal(base64url.decode(cd)).challenge == base64url.encode_no_pad(crypto.sha256(canonical))
}

invoice_merchant_is(c, m) if {
	json.unmarshal(c).merchantId == m
}

invoice_total_is(c, cents) if {
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
	not invoice_total_is(input.invoice.canonical, input.arguments.amountCents)
}

deny_reason contains "the invoice is not from the merchant this call names" if {
	not allow
	not invoice_merchant_is(input.invoice.canonical, input.arguments.merchantId)
}

deny_reason contains "the passkey assertion is invalid" if {
	not allow
	not webauthn_verified(input.childApproval.authenticatorData, input.childApproval.clientDataJSON, input.childApproval.signature, input.childEnrollment.claims.vc.credentialSubject.publicKey, input.webauthnOrigin)
}

deny_reason contains "the approval is not bound to this invoice" if {
	not allow
	not invoice_challenge_binds(input.childApproval.clientDataJSON, input.invoice.canonical)
}

deny_reason contains "the passkey is not enrolled by a trusted admin" if {
	not allow
	not enrolled_as(input.childEnrollment, input.childApproval.credentialId, input.trustedAdminDids, input.now)
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

deny_reason contains "the passkey is not enrolled by a trusted admin" if {
	not allow
	not enrolled_as(input.parentEnrollment, input.parentApproval.credentialId, input.trustedAdminDids, input.now)
}

deny_reason contains "required: input.parentEnrollment.claims.vc.credentialSubject.role == \"parent\"" if {
	not allow
	input.parentEnrollment.claims.vc.credentialSubject.role != "parent"
}

failed_checks contains "t0.c0" if {
	not allow
	not signed_by_trusted_merchant(input.invoice, input.trustedMerchants)
}

failed_checks contains "t0.c1" if {
	not allow
	not invoice_unexpired(input.invoice.canonical, input.now)
}

failed_checks contains "t0.c2" if {
	not allow
	not invoice_total_is(input.invoice.canonical, input.arguments.amountCents)
}

failed_checks contains "t0.c3" if {
	not allow
	not invoice_merchant_is(input.invoice.canonical, input.arguments.merchantId)
}

failed_checks contains "t0.c4" if {
	not allow
	not webauthn_verified(input.childApproval.authenticatorData, input.childApproval.clientDataJSON, input.childApproval.signature, input.childEnrollment.claims.vc.credentialSubject.publicKey, input.webauthnOrigin)
}

failed_checks contains "t0.c5" if {
	not allow
	not invoice_challenge_binds(input.childApproval.clientDataJSON, input.invoice.canonical)
}

failed_checks contains "t0.c6" if {
	not allow
	not enrolled_as(input.childEnrollment, input.childApproval.credentialId, input.trustedAdminDids, input.now)
}

failed_checks contains "t0.c7" if {
	not allow
	input.childEnrollment.claims.vc.credentialSubject.role != "child"
}

failed_checks contains "t0.c8" if {
	not allow
	input.arguments.amountCents > 1000
}

failed_checks contains "t1.c0" if {
	not allow
	not signed_by_trusted_merchant(input.invoice, input.trustedMerchants)
}

failed_checks contains "t1.c1" if {
	not allow
	not invoice_unexpired(input.invoice.canonical, input.now)
}

failed_checks contains "t1.c2" if {
	not allow
	not invoice_total_is(input.invoice.canonical, input.arguments.amountCents)
}

failed_checks contains "t1.c3" if {
	not allow
	not invoice_merchant_is(input.invoice.canonical, input.arguments.merchantId)
}

failed_checks contains "t1.c4" if {
	not allow
	not webauthn_verified(input.childApproval.authenticatorData, input.childApproval.clientDataJSON, input.childApproval.signature, input.childEnrollment.claims.vc.credentialSubject.publicKey, input.webauthnOrigin)
}

failed_checks contains "t1.c5" if {
	not allow
	not invoice_challenge_binds(input.childApproval.clientDataJSON, input.invoice.canonical)
}

failed_checks contains "t1.c6" if {
	not allow
	not enrolled_as(input.childEnrollment, input.childApproval.credentialId, input.trustedAdminDids, input.now)
}

failed_checks contains "t1.c7" if {
	not allow
	input.childEnrollment.claims.vc.credentialSubject.role != "child"
}

failed_checks contains "t1.c8" if {
	not allow
	1000 >= input.arguments.amountCents
}

failed_checks contains "t1.c9" if {
	not allow
	input.arguments.amountCents > 20000
}

failed_checks contains "t1.c10" if {
	not allow
	not webauthn_verified(input.parentApproval.authenticatorData, input.parentApproval.clientDataJSON, input.parentApproval.signature, input.parentEnrollment.claims.vc.credentialSubject.publicKey, input.webauthnOrigin)
}

failed_checks contains "t1.c11" if {
	not allow
	not invoice_challenge_binds(input.parentApproval.clientDataJSON, input.invoice.canonical)
}

failed_checks contains "t1.c12" if {
	not allow
	not enrolled_as(input.parentEnrollment, input.parentApproval.credentialId, input.trustedAdminDids, input.now)
}

failed_checks contains "t1.c13" if {
	not allow
	input.parentEnrollment.claims.vc.credentialSubject.role != "parent"
}


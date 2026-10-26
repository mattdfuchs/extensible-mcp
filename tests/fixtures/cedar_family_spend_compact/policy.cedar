// Derived mechanically by this repository from ../cedar_family_spend/policy.cedar
// (rules supplied by an external policy-authoring toolchain, forbid-only) --
// see PROVENANCE.md. Not supplied, not certified: the same 29 conditions and
// two tiers, re-shaped so that a tier's conjunction is written once and each
// forbid carries only its own condition.
//
// Shape: permit decides, forbid explains (expected_ids.json declares it).
// Decision pass, no `probe` key: forbids inert, the two @tier permits decide,
// an empty set denies. Probe pass, `probe: true`, on a denial only: permits
// inert, the forbids that fire are the failed checks.

@tier("full_chain")
permit (principal, action, resource)
when {
  !(context has probe) &&
  context has requestVCJwsTrustRootJwkKeyWitnesses && context has trustRootJwk &&
  context.requestVCJwsTrustRootJwkKeyWitnesses.contains(context.trustRootJwk) && context has
  requestVC && context.requestVC has claims && context.requestVC.claims has nbf && context has now
  && context.requestVC.claims has exp && context.requestVC.claims.nbf <= context.now &&
  context.now <= context.requestVC.claims.exp && context has requestVC && context.requestVC has
  claims && context.requestVC.claims has action && context has tool &&
  context.requestVC.claims.action == context.tool && context has requestVC && context.requestVC
  has claims && context.requestVC.claims has arguments && context has arguments &&
  context.requestVC.claims.arguments == context.arguments && context has requesterMembership &&
  context.requesterMembership has claims && context.requesterMembership.claims has iss && context
  has trustRootDID && context.requesterMembership.claims.iss == context.trustRootDID && context
  has requesterMembership && context.requesterMembership has claims &&
  context.requesterMembership.claims has nbf && context has now &&
  context.requesterMembership.claims has exp && context.requesterMembership.claims.nbf <=
  context.now && context.now <= context.requesterMembership.claims.exp && context has
  requesterMembershipJwsTrustRootJwkKeyWitnesses && context has trustRootJwk &&
  context.requesterMembershipJwsTrustRootJwkKeyWitnesses.contains(context.trustRootJwk) && context
  has requesterMembership && context.requesterMembership has claims &&
  context.requesterMembership.claims has sub && context has requestVC && context.requestVC has
  claims && context.requestVC.claims has iss && context.requesterMembership.claims.sub ==
  context.requestVC.claims.iss && context has requesterMembership && context.requesterMembership
  has claims && context.requesterMembership.claims has role &&
  context.requesterMembership.claims.role == "kid" && context has arguments && context.arguments
  has amountCents && 1000 < context.arguments.amountCents && context has arguments &&
  context.arguments has amountCents && context.arguments.amountCents <= 20000 && context has
  authorizationVCJwsTrustRootJwkKeyWitnesses && context has trustRootJwk &&
  context.authorizationVCJwsTrustRootJwkKeyWitnesses.contains(context.trustRootJwk) && context has
  authorizationVC && context.authorizationVC has claims && context.authorizationVC.claims has nbf
  && context has now && context.authorizationVC.claims has exp &&
  context.authorizationVC.claims.nbf <= context.now && context.now <=
  context.authorizationVC.claims.exp && context has requestVC && context.requestVC has claims &&
  context.requestVC.claims has jti && context has authorizationVC && context.authorizationVC has
  claims && context.authorizationVC.claims has jti && context.authorizationVC.claims has
  requestHash && context has requestVCJwsDigest && context.requestVC.claims.jti ==
  context.authorizationVC.claims.jti && context.authorizationVC.claims.requestHash ==
  context.requestVCJwsDigest && context has approverMembership && context.approverMembership has
  claims && context.approverMembership.claims has iss && context has trustRootDID &&
  context.approverMembership.claims.iss == context.trustRootDID && context has approverMembership
  && context.approverMembership has claims && context.approverMembership.claims has nbf && context
  has now && context.approverMembership.claims has exp && context.approverMembership.claims.nbf <=
  context.now && context.now <= context.approverMembership.claims.exp && context has
  approverMembershipJwsTrustRootJwkKeyWitnesses && context has trustRootJwk &&
  context.approverMembershipJwsTrustRootJwkKeyWitnesses.contains(context.trustRootJwk) && context
  has approverMembership && context.approverMembership has claims &&
  context.approverMembership.claims has sub && context has authorizationVC &&
  context.authorizationVC has claims && context.authorizationVC.claims has iss &&
  context.approverMembership.claims.sub == context.authorizationVC.claims.iss && context has
  approverMembership && context.approverMembership has claims && context.approverMembership.claims
  has role && context.approverMembership.claims.role == "parent"
};

@tier("solo")
permit (principal, action, resource)
when {
  !(context has probe) &&
  context has requestVCJwsTrustRootJwkKeyWitnesses && context has trustRootJwk &&
  context.requestVCJwsTrustRootJwkKeyWitnesses.contains(context.trustRootJwk) && context has
  requestVC && context.requestVC has claims && context.requestVC.claims has nbf && context has now
  && context.requestVC.claims has exp && context.requestVC.claims.nbf <= context.now &&
  context.now <= context.requestVC.claims.exp && context has requestVC && context.requestVC has
  claims && context.requestVC.claims has action && context has tool &&
  context.requestVC.claims.action == context.tool && context has requestVC && context.requestVC
  has claims && context.requestVC.claims has arguments && context has arguments &&
  context.requestVC.claims.arguments == context.arguments && context has requesterMembership &&
  context.requesterMembership has claims && context.requesterMembership.claims has iss && context
  has trustRootDID && context.requesterMembership.claims.iss == context.trustRootDID && context
  has requesterMembership && context.requesterMembership has claims &&
  context.requesterMembership.claims has nbf && context has now &&
  context.requesterMembership.claims has exp && context.requesterMembership.claims.nbf <=
  context.now && context.now <= context.requesterMembership.claims.exp && context has
  requesterMembershipJwsTrustRootJwkKeyWitnesses && context has trustRootJwk &&
  context.requesterMembershipJwsTrustRootJwkKeyWitnesses.contains(context.trustRootJwk) && context
  has requesterMembership && context.requesterMembership has claims &&
  context.requesterMembership.claims has sub && context has requestVC && context.requestVC has
  claims && context.requestVC.claims has iss && context.requesterMembership.claims.sub ==
  context.requestVC.claims.iss && context has requesterMembership && context.requesterMembership
  has claims && context.requesterMembership.claims has role &&
  context.requesterMembership.claims.role == "kid" && context has arguments && context.arguments
  has amountCents && context.arguments.amountCents <= 1000
};

@id("solo.request_vc.signed_by")
@tier("solo")
forbid (principal, action, resource)
when {
  context has probe &&
  context has requestVCJwsTrustRootJwkKeyWitnesses && context has trustRootJwk &&
  !context.requestVCJwsTrustRootJwkKeyWitnesses.contains(context.trustRootJwk)
};

@id("solo.request_vc.within_window")
@tier("solo")
forbid (principal, action, resource)
when {
  context has probe &&
  context has requestVC && context.requestVC has claims && context.requestVC.claims has nbf &&
  context has now && context.requestVC.claims has exp && !(context.requestVC.claims.nbf <=
  context.now && context.now <= context.requestVC.claims.exp)
};

@id("solo.request_vc.action_matches")
@tier("solo")
forbid (principal, action, resource)
when {
  context has probe &&
  context has requestVC && context.requestVC has claims && context.requestVC.claims has action &&
  context has tool && !(context.requestVC.claims.action == context.tool)
};

@id("solo.request_vc.arguments_matches")
@tier("solo")
forbid (principal, action, resource)
when {
  context has probe &&
  context has requestVC && context.requestVC has claims && context.requestVC.claims has arguments
  && context has arguments && !(context.requestVC.claims.arguments == context.arguments)
};

@id("solo.requester_membership.iss_matches")
@tier("solo")
forbid (principal, action, resource)
when {
  context has probe &&
  context has requesterMembership && context.requesterMembership has claims &&
  context.requesterMembership.claims has iss && context has trustRootDID &&
  !(context.requesterMembership.claims.iss == context.trustRootDID)
};

@id("solo.requester_membership.within_window")
@tier("solo")
forbid (principal, action, resource)
when {
  context has probe &&
  context has requesterMembership && context.requesterMembership has claims &&
  context.requesterMembership.claims has nbf && context has now &&
  context.requesterMembership.claims has exp && !(context.requesterMembership.claims.nbf <=
  context.now && context.now <= context.requesterMembership.claims.exp)
};

@id("solo.requester_membership.signed_by")
@tier("solo")
forbid (principal, action, resource)
when {
  context has probe &&
  context has requesterMembershipJwsTrustRootJwkKeyWitnesses && context has trustRootJwk &&
  !context.requesterMembershipJwsTrustRootJwkKeyWitnesses.contains(context.trustRootJwk)
};

@id("solo.requester_membership.sub_matches")
@tier("solo")
forbid (principal, action, resource)
when {
  context has probe &&
  context has requesterMembership && context.requesterMembership has claims &&
  context.requesterMembership.claims has sub && context has requestVC && context.requestVC has
  claims && context.requestVC.claims has iss && !(context.requesterMembership.claims.sub ==
  context.requestVC.claims.iss)
};

@id("solo.requester_membership.role_matches")
@tier("solo")
forbid (principal, action, resource)
when {
  context has probe &&
  context has requesterMembership && context.requesterMembership has claims &&
  context.requesterMembership.claims has role && !(context.requesterMembership.claims.role ==
  "kid")
};

@id("solo.arguments.amount_cents_at_most")
@tier("solo")
forbid (principal, action, resource)
when {
  context has probe &&
  context has arguments && context.arguments has amountCents && !(context.arguments.amountCents <=
  1000)
};

@id("full_chain.request_vc.signed_by")
@tier("full_chain")
forbid (principal, action, resource)
when {
  context has probe &&
  context has requestVCJwsTrustRootJwkKeyWitnesses && context has trustRootJwk &&
  !context.requestVCJwsTrustRootJwkKeyWitnesses.contains(context.trustRootJwk)
};

@id("full_chain.request_vc.within_window")
@tier("full_chain")
forbid (principal, action, resource)
when {
  context has probe &&
  context has requestVC && context.requestVC has claims && context.requestVC.claims has nbf &&
  context has now && context.requestVC.claims has exp && !(context.requestVC.claims.nbf <=
  context.now && context.now <= context.requestVC.claims.exp)
};

@id("full_chain.request_vc.action_matches")
@tier("full_chain")
forbid (principal, action, resource)
when {
  context has probe &&
  context has requestVC && context.requestVC has claims && context.requestVC.claims has action &&
  context has tool && !(context.requestVC.claims.action == context.tool)
};

@id("full_chain.request_vc.arguments_matches")
@tier("full_chain")
forbid (principal, action, resource)
when {
  context has probe &&
  context has requestVC && context.requestVC has claims && context.requestVC.claims has arguments
  && context has arguments && !(context.requestVC.claims.arguments == context.arguments)
};

@id("full_chain.requester_membership.iss_matches")
@tier("full_chain")
forbid (principal, action, resource)
when {
  context has probe &&
  context has requesterMembership && context.requesterMembership has claims &&
  context.requesterMembership.claims has iss && context has trustRootDID &&
  !(context.requesterMembership.claims.iss == context.trustRootDID)
};

@id("full_chain.requester_membership.within_window")
@tier("full_chain")
forbid (principal, action, resource)
when {
  context has probe &&
  context has requesterMembership && context.requesterMembership has claims &&
  context.requesterMembership.claims has nbf && context has now &&
  context.requesterMembership.claims has exp && !(context.requesterMembership.claims.nbf <=
  context.now && context.now <= context.requesterMembership.claims.exp)
};

@id("full_chain.requester_membership.signed_by")
@tier("full_chain")
forbid (principal, action, resource)
when {
  context has probe &&
  context has requesterMembershipJwsTrustRootJwkKeyWitnesses && context has trustRootJwk &&
  !context.requesterMembershipJwsTrustRootJwkKeyWitnesses.contains(context.trustRootJwk)
};

@id("full_chain.requester_membership.sub_matches")
@tier("full_chain")
forbid (principal, action, resource)
when {
  context has probe &&
  context has requesterMembership && context.requesterMembership has claims &&
  context.requesterMembership.claims has sub && context has requestVC && context.requestVC has
  claims && context.requestVC.claims has iss && !(context.requesterMembership.claims.sub ==
  context.requestVC.claims.iss)
};

@id("full_chain.requester_membership.role_matches")
@tier("full_chain")
forbid (principal, action, resource)
when {
  context has probe &&
  context has requesterMembership && context.requesterMembership has claims &&
  context.requesterMembership.claims has role && !(context.requesterMembership.claims.role ==
  "kid")
};

@id("full_chain.arguments.amount_cents_above")
@tier("full_chain")
forbid (principal, action, resource)
when {
  context has probe &&
  context has arguments && context.arguments has amountCents && !(1000 <
  context.arguments.amountCents)
};

@id("full_chain.arguments.amount_cents_at_most")
@tier("full_chain")
forbid (principal, action, resource)
when {
  context has probe &&
  context has arguments && context.arguments has amountCents && !(context.arguments.amountCents <=
  20000)
};

@id("full_chain.authorization_vc.signed_by")
@tier("full_chain")
forbid (principal, action, resource)
when {
  context has probe &&
  context has authorizationVCJwsTrustRootJwkKeyWitnesses && context has trustRootJwk &&
  !context.authorizationVCJwsTrustRootJwkKeyWitnesses.contains(context.trustRootJwk)
};

@id("full_chain.authorization_vc.within_window")
@tier("full_chain")
forbid (principal, action, resource)
when {
  context has probe &&
  context has authorizationVC && context.authorizationVC has claims &&
  context.authorizationVC.claims has nbf && context has now && context.authorizationVC.claims has
  exp && !(context.authorizationVC.claims.nbf <= context.now && context.now <=
  context.authorizationVC.claims.exp)
};

@id("full_chain.request_vc.bound_to")
@tier("full_chain")
forbid (principal, action, resource)
when {
  context has probe &&
  context has requestVC && context.requestVC has claims && context.requestVC.claims has jti &&
  context has authorizationVC && context.authorizationVC has claims &&
  context.authorizationVC.claims has jti && context.authorizationVC.claims has requestHash &&
  context has requestVCJwsDigest && !(context.requestVC.claims.jti ==
  context.authorizationVC.claims.jti && context.authorizationVC.claims.requestHash ==
  context.requestVCJwsDigest)
};

@id("full_chain.approver_membership.iss_matches")
@tier("full_chain")
forbid (principal, action, resource)
when {
  context has probe &&
  context has approverMembership && context.approverMembership has claims &&
  context.approverMembership.claims has iss && context has trustRootDID &&
  !(context.approverMembership.claims.iss == context.trustRootDID)
};

@id("full_chain.approver_membership.within_window")
@tier("full_chain")
forbid (principal, action, resource)
when {
  context has probe &&
  context has approverMembership && context.approverMembership has claims &&
  context.approverMembership.claims has nbf && context has now &&
  context.approverMembership.claims has exp && !(context.approverMembership.claims.nbf <=
  context.now && context.now <= context.approverMembership.claims.exp)
};

@id("full_chain.approver_membership.signed_by")
@tier("full_chain")
forbid (principal, action, resource)
when {
  context has probe &&
  context has approverMembershipJwsTrustRootJwkKeyWitnesses && context has trustRootJwk &&
  !context.approverMembershipJwsTrustRootJwkKeyWitnesses.contains(context.trustRootJwk)
};

@id("full_chain.approver_membership.sub_matches")
@tier("full_chain")
forbid (principal, action, resource)
when {
  context has probe &&
  context has approverMembership && context.approverMembership has claims &&
  context.approverMembership.claims has sub && context has authorizationVC &&
  context.authorizationVC has claims && context.authorizationVC.claims has iss &&
  !(context.approverMembership.claims.sub == context.authorizationVC.claims.iss)
};

@id("full_chain.approver_membership.role_matches")
@tier("full_chain")
forbid (principal, action, resource)
when {
  context has probe &&
  context has approverMembership && context.approverMembership has claims &&
  context.approverMembership.claims has role && !(context.approverMembership.claims.role ==
  "parent")
};

@assembly("solo")
forbid (principal, action, resource)
when {
  context has probe &&
  !(context has requestVCJwsTrustRootJwkKeyWitnesses && context has trustRootJwk && context has
  requestVC && context.requestVC has claims && context.requestVC.claims has nbf && context has now
  && context.requestVC.claims has exp && context has requestVC && context.requestVC has claims &&
  context.requestVC.claims has action && context has tool && context has requestVC &&
  context.requestVC has claims && context.requestVC.claims has arguments && context has arguments
  && context has requesterMembership && context.requesterMembership has claims &&
  context.requesterMembership.claims has iss && context has trustRootDID && context has
  requesterMembership && context.requesterMembership has claims &&
  context.requesterMembership.claims has nbf && context has now &&
  context.requesterMembership.claims has exp && context has
  requesterMembershipJwsTrustRootJwkKeyWitnesses && context has trustRootJwk && context has
  requesterMembership && context.requesterMembership has claims &&
  context.requesterMembership.claims has sub && context has requestVC && context.requestVC has
  claims && context.requestVC.claims has iss && context has requesterMembership &&
  context.requesterMembership has claims && context.requesterMembership.claims has role && context
  has arguments && context.arguments has amountCents) && !(context has
  requestVCJwsTrustRootJwkKeyWitnesses && context has trustRootJwk &&
  context.requestVCJwsTrustRootJwkKeyWitnesses.contains(context.trustRootJwk) && context has
  requestVC && context.requestVC has claims && context.requestVC.claims has nbf && context has now
  && context.requestVC.claims has exp && context.requestVC.claims.nbf <= context.now &&
  context.now <= context.requestVC.claims.exp && context has requestVC && context.requestVC has
  claims && context.requestVC.claims has action && context has tool &&
  context.requestVC.claims.action == context.tool && context has requestVC && context.requestVC
  has claims && context.requestVC.claims has arguments && context has arguments &&
  context.requestVC.claims.arguments == context.arguments && context has requesterMembership &&
  context.requesterMembership has claims && context.requesterMembership.claims has iss && context
  has trustRootDID && context.requesterMembership.claims.iss == context.trustRootDID && context
  has requesterMembership && context.requesterMembership has claims &&
  context.requesterMembership.claims has nbf && context has now &&
  context.requesterMembership.claims has exp && context.requesterMembership.claims.nbf <=
  context.now && context.now <= context.requesterMembership.claims.exp && context has
  requesterMembershipJwsTrustRootJwkKeyWitnesses && context has trustRootJwk &&
  context.requesterMembershipJwsTrustRootJwkKeyWitnesses.contains(context.trustRootJwk) && context
  has requesterMembership && context.requesterMembership has claims &&
  context.requesterMembership.claims has sub && context has requestVC && context.requestVC has
  claims && context.requestVC.claims has iss && context.requesterMembership.claims.sub ==
  context.requestVC.claims.iss && context has requesterMembership && context.requesterMembership
  has claims && context.requesterMembership.claims has role &&
  context.requesterMembership.claims.role == "kid" && context has arguments && context.arguments
  has amountCents && 1000 < context.arguments.amountCents && context has arguments &&
  context.arguments has amountCents && context.arguments.amountCents <= 20000 && context has
  authorizationVCJwsTrustRootJwkKeyWitnesses && context has trustRootJwk &&
  context.authorizationVCJwsTrustRootJwkKeyWitnesses.contains(context.trustRootJwk) && context has
  authorizationVC && context.authorizationVC has claims && context.authorizationVC.claims has nbf
  && context has now && context.authorizationVC.claims has exp &&
  context.authorizationVC.claims.nbf <= context.now && context.now <=
  context.authorizationVC.claims.exp && context has requestVC && context.requestVC has claims &&
  context.requestVC.claims has jti && context has authorizationVC && context.authorizationVC has
  claims && context.authorizationVC.claims has jti && context.authorizationVC.claims has
  requestHash && context has requestVCJwsDigest && context.requestVC.claims.jti ==
  context.authorizationVC.claims.jti && context.authorizationVC.claims.requestHash ==
  context.requestVCJwsDigest && context has approverMembership && context.approverMembership has
  claims && context.approverMembership.claims has iss && context has trustRootDID &&
  context.approverMembership.claims.iss == context.trustRootDID && context has approverMembership
  && context.approverMembership has claims && context.approverMembership.claims has nbf && context
  has now && context.approverMembership.claims has exp && context.approverMembership.claims.nbf <=
  context.now && context.now <= context.approverMembership.claims.exp && context has
  approverMembershipJwsTrustRootJwkKeyWitnesses && context has trustRootJwk &&
  context.approverMembershipJwsTrustRootJwkKeyWitnesses.contains(context.trustRootJwk) && context
  has approverMembership && context.approverMembership has claims &&
  context.approverMembership.claims has sub && context has authorizationVC &&
  context.authorizationVC has claims && context.authorizationVC.claims has iss &&
  context.approverMembership.claims.sub == context.authorizationVC.claims.iss && context has
  approverMembership && context.approverMembership has claims && context.approverMembership.claims
  has role && context.approverMembership.claims.role == "parent")
};

@assembly("full_chain")
forbid (principal, action, resource)
when {
  context has probe &&
  !(context has requestVCJwsTrustRootJwkKeyWitnesses && context has trustRootJwk && context has
  requestVC && context.requestVC has claims && context.requestVC.claims has nbf && context has now
  && context.requestVC.claims has exp && context has requestVC && context.requestVC has claims &&
  context.requestVC.claims has action && context has tool && context has requestVC &&
  context.requestVC has claims && context.requestVC.claims has arguments && context has arguments
  && context has requesterMembership && context.requesterMembership has claims &&
  context.requesterMembership.claims has iss && context has trustRootDID && context has
  requesterMembership && context.requesterMembership has claims &&
  context.requesterMembership.claims has nbf && context has now &&
  context.requesterMembership.claims has exp && context has
  requesterMembershipJwsTrustRootJwkKeyWitnesses && context has trustRootJwk && context has
  requesterMembership && context.requesterMembership has claims &&
  context.requesterMembership.claims has sub && context has requestVC && context.requestVC has
  claims && context.requestVC.claims has iss && context has requesterMembership &&
  context.requesterMembership has claims && context.requesterMembership.claims has role && context
  has arguments && context.arguments has amountCents && context has arguments && context.arguments
  has amountCents && context has authorizationVCJwsTrustRootJwkKeyWitnesses && context has
  trustRootJwk && context has authorizationVC && context.authorizationVC has claims &&
  context.authorizationVC.claims has nbf && context has now && context.authorizationVC.claims has
  exp && context has requestVC && context.requestVC has claims && context.requestVC.claims has jti
  && context has authorizationVC && context.authorizationVC has claims &&
  context.authorizationVC.claims has jti && context.authorizationVC.claims has requestHash &&
  context has requestVCJwsDigest && context has approverMembership && context.approverMembership
  has claims && context.approverMembership.claims has iss && context has trustRootDID && context
  has approverMembership && context.approverMembership has claims &&
  context.approverMembership.claims has nbf && context has now &&
  context.approverMembership.claims has exp && context has
  approverMembershipJwsTrustRootJwkKeyWitnesses && context has trustRootJwk && context has
  approverMembership && context.approverMembership has claims && context.approverMembership.claims
  has sub && context has authorizationVC && context.authorizationVC has claims &&
  context.authorizationVC.claims has iss && context has approverMembership &&
  context.approverMembership has claims && context.approverMembership.claims has role) &&
  !(context has requestVCJwsTrustRootJwkKeyWitnesses && context has trustRootJwk &&
  context.requestVCJwsTrustRootJwkKeyWitnesses.contains(context.trustRootJwk) && context has
  requestVC && context.requestVC has claims && context.requestVC.claims has nbf && context has now
  && context.requestVC.claims has exp && context.requestVC.claims.nbf <= context.now &&
  context.now <= context.requestVC.claims.exp && context has requestVC && context.requestVC has
  claims && context.requestVC.claims has action && context has tool &&
  context.requestVC.claims.action == context.tool && context has requestVC && context.requestVC
  has claims && context.requestVC.claims has arguments && context has arguments &&
  context.requestVC.claims.arguments == context.arguments && context has requesterMembership &&
  context.requesterMembership has claims && context.requesterMembership.claims has iss && context
  has trustRootDID && context.requesterMembership.claims.iss == context.trustRootDID && context
  has requesterMembership && context.requesterMembership has claims &&
  context.requesterMembership.claims has nbf && context has now &&
  context.requesterMembership.claims has exp && context.requesterMembership.claims.nbf <=
  context.now && context.now <= context.requesterMembership.claims.exp && context has
  requesterMembershipJwsTrustRootJwkKeyWitnesses && context has trustRootJwk &&
  context.requesterMembershipJwsTrustRootJwkKeyWitnesses.contains(context.trustRootJwk) && context
  has requesterMembership && context.requesterMembership has claims &&
  context.requesterMembership.claims has sub && context has requestVC && context.requestVC has
  claims && context.requestVC.claims has iss && context.requesterMembership.claims.sub ==
  context.requestVC.claims.iss && context has requesterMembership && context.requesterMembership
  has claims && context.requesterMembership.claims has role &&
  context.requesterMembership.claims.role == "kid" && context has arguments && context.arguments
  has amountCents && context.arguments.amountCents <= 1000)
};

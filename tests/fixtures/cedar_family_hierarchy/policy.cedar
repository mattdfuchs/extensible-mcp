// Hand-authored for this repository. Not derived from any external toolchain
// -- see PROVENANCE.md. The hierarchy teaching bundle: the first policy in
// the corpus that tests `in`.
//
// Cedar's `in` is a lookup in the subject's closed ancestor set, and the
// proxy forms that set from the fetch plan: `fetchplan.json`'s `entities`
// block names three *membership fields*, each a list of entity references
// the plan assembled from a declared source, and the loader makes them the
// principal's and the resource's parents before `is_authorized`. Three edges,
// three sources, each legible in the plan and in the type name here:
//
//   principal in IdpRole::"parent"   -- the IdP's roles claim (a `caller`
//                                       entry), typed `IdpRole` so a rule can
//                                       never mistake it for a vouched role
//   resource  in Org::"acme"         -- the deployment's word (a `config`
//                                       entry): which organization this
//                                       server belongs to
//   principal in Family::"household" -- a verified membership credential (a
//                                       `derive` fold of verify_eddsa over the
//                                       trust root's key): the edge exists
//                                       only if the signature did
//
// `schema.json` declares exactly those relations in `memberOfTypes`. The
// loader validates this file against it at load and refuses an `in` over any
// relation the schema does not declare, because Cedar would type such a test
// as false and report nothing.
//
// Shape: permit decides, forbid explains (the `@tier` permit declares it;
// there is no expected_ids.json). The proxy evaluates twice, keyed on the
// reserved `probe` key -- see ../cedar_minimal_spend/policy.cedar.

// The tier's decision: every condition, written once. Deny by default.
@tier("solo")
permit (principal, action, resource)
when {
  !(context has probe) &&
  principal in IdpRole::"parent" &&
  resource in Org::"acme" &&
  principal in Family::"household" &&
  context has requesterMembership && context.requesterMembership has claims &&
  context.requesterMembership.claims has sub && context has caller && context.caller has sub &&
  context.requesterMembership.claims.sub == context.caller.sub &&
  context.requesterMembership.claims has nbf && context.requesterMembership.claims has exp && context has now &&
  context.requesterMembership.claims.nbf <= context.now && context.now <= context.requesterMembership.claims.exp &&
  context has arguments && context.arguments has amountCents &&
  context.arguments.amountCents <= 5000
};

// The explanations: one forbid per condition, inert without `probe`.
@id("solo.caller.idp_role_parent")
@sentence("the caller's identity provider does not assert the parent role")
forbid (principal, action, resource)
when { context has probe && !(principal in IdpRole::"parent") };

@id("solo.server.in_org")
@sentence("this server is not in the organization the policy governs")
forbid (principal, action, resource)
when { context has probe && !(resource in Org::"acme") };

@id("solo.caller.family_member")
@sentence("the caller's membership credential is not signed by the household's trust root")
forbid (principal, action, resource)
when { context has probe && !(principal in Family::"household") };

@id("solo.membership.names_caller")
@sentence("the membership credential names someone other than the caller")
forbid (principal, action, resource)
when {
  context has probe &&
  context has requesterMembership && context.requesterMembership has claims &&
  context.requesterMembership.claims has sub && context has caller && context.caller has sub &&
  !(context.requesterMembership.claims.sub == context.caller.sub)
};

@id("solo.membership.within_window")
@sentence("a credential is outside its validity window")
forbid (principal, action, resource)
when {
  context has probe &&
  context has requesterMembership && context.requesterMembership has claims &&
  context.requesterMembership.claims has nbf && context.requesterMembership.claims has exp && context has now &&
  !(context.requesterMembership.claims.nbf <= context.now && context.now <= context.requesterMembership.claims.exp)
};

@id("solo.arguments.amount_cents_at_most")
@sentence("required: input.arguments.amountCents <= 5000")
forbid (principal, action, resource)
when {
  context has probe &&
  context has arguments && context.arguments has amountCents &&
  !(context.arguments.amountCents <= 5000)
};

// The tier's own incompleteness, for the explanation only; no @id.
@assembly("solo")
forbid (principal, action, resource)
when {
  context has probe &&
  !(context has requesterMembership && context.requesterMembership has claims &&
    context.requesterMembership.claims has sub && context.requesterMembership.claims has nbf &&
    context.requesterMembership.claims has exp && context has now &&
    context has caller && context.caller has sub &&
    context has arguments && context.arguments has amountCents)
};

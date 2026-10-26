// Hand-authored for this repository. Not derived from any external toolchain
// -- see PROVENANCE.md. The Cedar twin of ../minimal_spend: the same five
// conditions, decided by Cedar's engine.
//
// Cedar cannot call a host function, so the signature is not checked here.
// The fetch plan's `derive` entry folds `verify_eddsa` over the one trusted
// key and projects the keys that verified into
// `requestVCJwsRequesterJwkKeyWitnesses`; the permit and the first forbid
// below test a relation over that witness set instead of calling anything.
//
// Shape: permit decides, forbid explains (expected_ids.json declares it).
// The proxy evaluates this file twice. In the decision pass the context has
// no `probe` key: every forbid below is inert, the one permit decides, and
// an input that matches no permit is denied -- an empty policy set denies.
// On a denial the proxy evaluates again with `probe: true`: the permit is
// inert and the forbids that fire are the failed checks, each reporting the
// guidance id it carries. The guards are the whole mechanism; `probe` is
// reserved and no fetch plan may name a field by it.

// The tier's decision: every condition, written once. Deny by default.
@tier("solo")
permit (principal, action, resource)
when {
  !(context has probe) &&
  context has requestVCJwsRequesterJwkKeyWitnesses && context has requesterJwk &&
  context.requestVCJwsRequesterJwkKeyWitnesses.contains(context.requesterJwk) &&
  context has requestVC && context.requestVC has claims &&
  context.requestVC.claims has nbf && context.requestVC.claims has exp && context has now &&
  context.requestVC.claims.nbf <= context.now && context.now <= context.requestVC.claims.exp &&
  context.requestVC.claims has action && context has tool &&
  context.requestVC.claims.action == context.tool &&
  context.requestVC.claims has arguments && context has arguments &&
  context.requestVC.claims.arguments == context.arguments &&
  context.arguments has amountCents &&
  context.arguments.amountCents <= 1000
};

// The explanations: one forbid per condition, its own condition and nothing
// else, each carrying the guidance id it reports under and, as @sentence, the
// text a denial renders -- the inline form a hand author uses instead of a
// guidance.json; with one present it wins. Inert without `probe`.
@id("solo.request_vc.signed_by")
@sentence("a credential signature is invalid")
forbid (principal, action, resource)
when {
  context has probe &&
  context has requestVCJwsRequesterJwkKeyWitnesses &&
  context has requesterJwk &&
  !context.requestVCJwsRequesterJwkKeyWitnesses.contains(context.requesterJwk)
};

@id("solo.request_vc.within_window")
@sentence("a credential is outside its validity window")
forbid (principal, action, resource)
when {
  context has probe &&
  context has requestVC && context.requestVC has claims &&
  context.requestVC.claims has nbf && context.requestVC.claims has exp &&
  context has now &&
  !(context.requestVC.claims.nbf <= context.now && context.now <= context.requestVC.claims.exp)
};

@id("solo.request_vc.action_matches")
@sentence("required: input.requestVC.claims.action == input.tool")
forbid (principal, action, resource)
when {
  context has probe &&
  context has requestVC && context.requestVC has claims &&
  context.requestVC.claims has action && context has tool &&
  !(context.requestVC.claims.action == context.tool)
};

@id("solo.request_vc.arguments_matches")
@sentence("required: input.requestVC.claims.arguments == input.arguments")
forbid (principal, action, resource)
when {
  context has probe &&
  context has requestVC && context.requestVC has claims &&
  context.requestVC.claims has arguments && context has arguments &&
  !(context.requestVC.claims.arguments == context.arguments)
};

@id("solo.arguments.amount_cents_at_most")
@sentence("required: input.arguments.amountCents <= 1000")
forbid (principal, action, resource)
when {
  context has probe &&
  context has arguments && context.arguments has amountCents &&
  !(context.arguments.amountCents <= 1000)
};

// The tier's own incompleteness, for the explanation only: an input missing
// a field the conditions read is already denied by the permit's `has`
// guards; this forbid fires in the probe pass so the renderer can say which
// credential was absent, from the fetch plan's guards. It carries no @id
// because it is not a reason the guidance has a sentence for.
@assembly("solo")
forbid (principal, action, resource)
when {
  context has probe &&
  !(context has requestVCJwsRequesterJwkKeyWitnesses && context has requesterJwk &&
    context has requestVC && context.requestVC has claims &&
    context.requestVC.claims has nbf && context.requestVC.claims has exp &&
    context.requestVC.claims has action && context.requestVC.claims has arguments &&
    context has now && context has tool &&
    context has arguments && context.arguments has amountCents)
};

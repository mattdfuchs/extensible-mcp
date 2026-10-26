// Hand-authored for this repository. Not derived from any external toolchain
// -- see PROVENANCE.md. The Cedar twin of ../minimal_spend: the same five
// conditions, decided by Cedar's engine.
//
// Cedar cannot call a host function, so the signature is not checked here.
// The fetch plan's `derive` entry folds `verify_eddsa` over the one trusted
// key and projects the keys that verified into
// `requestVCJwsRequesterJwkKeyWitnesses`; the first forbid below tests a
// relation over that witness set instead of calling anything.
//
// Forbid-only over a base permit. Every forbid is one failable condition,
// negated, and carries the guidance id it reports under. An empty policy set
// would allow everything, so expected_ids.json lists what the loader must
// find before this file may govern a call.

// The base permit. The forbids below carry the whole decision.
permit (principal, action, resource);

@id("solo.request_vc.signed_by")
forbid (principal, action, resource)
when {
  context has requestVCJwsRequesterJwkKeyWitnesses &&
  context has requesterJwk &&
  !context.requestVCJwsRequesterJwkKeyWitnesses.contains(context.requesterJwk)
};

@id("solo.request_vc.within_window")
forbid (principal, action, resource)
when {
  context has requestVC && context.requestVC has claims &&
  context.requestVC.claims has nbf && context.requestVC.claims has exp &&
  context has now &&
  !(context.requestVC.claims.nbf <= context.now && context.now <= context.requestVC.claims.exp)
};

@id("solo.request_vc.action_matches")
forbid (principal, action, resource)
when {
  context has requestVC && context.requestVC has claims &&
  context.requestVC.claims has action && context has tool &&
  !(context.requestVC.claims.action == context.tool)
};

@id("solo.request_vc.arguments_matches")
forbid (principal, action, resource)
when {
  context has requestVC && context.requestVC has claims &&
  context.requestVC.claims has arguments && context has arguments &&
  !(context.requestVC.claims.arguments == context.arguments)
};

@id("solo.arguments.amount_cents_at_most")
forbid (principal, action, resource)
when {
  context has arguments && context.arguments has amountCents &&
  !(context.arguments.amountCents <= 1000)
};

// The tier's own incompleteness: an input missing any field the conditions
// above read would make every `has` guard false and no forbid fire, which in
// a forbid-only set is a permit. This forbid fires instead. It carries no
// @id because it is not a reason the guidance renders; the renderer explains
// a missing credential from the fetch plan's guards.
@assembly("solo")
forbid (principal, action, resource)
when {
  !(context has requestVCJwsRequesterJwkKeyWitnesses && context has requesterJwk &&
    context has requestVC && context.requestVC has claims &&
    context.requestVC.claims has nbf && context.requestVC.claims has exp &&
    context.requestVC.claims has action && context.requestVC.claims has arguments &&
    context has now && context has tool &&
    context has arguments && context.arguments has amountCents)
};

# Fixture provenance — cel_family_spend_bound (the token/evidence seam)

Not derived from any external toolchain. Hand-authored directly for this
repository: `cel_family_spend` plus the one condition that joins the two
identities a call now carries, the session's and the signer's.

**What it adds.** The proxy establishes who a session acts for from the
verified inbound token (a `Principal`: identity provider and account), and
the evidence establishes whose key signed the request (the request
credential's `iss`, a `did:key`, chained to a role by the admin-signed
membership). Nothing in `cel_family_spend` compares them, so a session
authenticated as one member can submit a request another member's wallet
signed. This bundle refuses that:

- the membership's claims may carry `accounts`, a list of `{idp, account}`
  the admin signed — the member's accounts at identity providers. The
  teaching bundle's membership is a flat claims object, so the list sits
  at `claims.accounts`; a production membership carries it inside the
  verifiable credential, at `vc.credentialSubject.accounts`, which is what
  the identity package's issuer emits;
- two `caller`-sourced fields, `callerIdp` and `callerAccount`, read from
  the principal and never from the call — a caller fact the model could
  supply would be the model naming itself. Both are **guarded**
  (`always: false`), so with no principal they are omitted;
- one check per tier, `<tier>.requester_membership.account_bound`, in the
  general form: the session is bound to the requester when the
  membership's `sub` equals `callerAccount` (the case where an issuer's
  subjects are DIDs, a plain equality) or `{callerIdp, callerAccount}` is
  in the membership's `accounts`. With no caller present the check holds
  vacuously: absence of a principal is governed by the deployment's
  `require_principal`, not by the bundle, or the single-tenant shape could
  not run this policy at all.

The condition binds the **requester** only. The approver acts from another
device through the wallet; that authority is evidence, not a session, and
the approver tier is unchanged.

**Relation to `cel_family_spend`.** Same tiers, same 29 checks with the
same ids, plus the two above after each tier's `sub_matches` check; the
manifest gains the two optional root fields and the optional `accounts`
on a membership, the fetch plan the two guarded entries. `guidance.json`
carries the new sentence both ways (the file and the check's own entry),
as the teaching bundles do. The production counterpart is upstream work:
the certified bundles gain the same condition through the toolchain and
come back under a certificate; see the integration doc's handoff section.

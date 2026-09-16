# household-identity

Wallet and DID-hosting infrastructure for the wallet rail of [extensible-mcp](../../README.md)'s Order Pizza demo, in [`examples/agentic-commerce-demo`](../agentic-commerce-demo). The demo's passkey and invoice rails use different evidence and don't involve this package.

## Components

- **`wallet/`** — per-member signing service. Holds the member's `did:key` private key and signs request VCs (originator mode) or authorization VCs (approver mode) after user approval.
- **`did_server/`** — hosts the family admin's `did:web` DID document at `/.well-known/did.json`, and provides a CLI for key generation, member onboarding, and membership-credential issuance.
- **`common/`** — shared key handling, types, and JWS signing primitives used by both services.

Status: feature complete for the demo. 51 tests pass. Each wallet supports both a stdin approval prompt and a browser page served at `/ui` (`wallet run --approve web`) — the latter is what the containerized commerce demo uses, though the wallets there bind loopback and are not published, so their pages are reachable only from inside that container — see the deploy README's note on the container boundary. Phone-app integration is deferred.

## License

Apache License 2.0 — see [LICENSE](../../LICENSE).

# Contributing

Thanks for considering a contribution. This is a small research-adjacent
project (see the Status section of [`README.md`](README.md)) rather than a
maintained product with an SLA, so please open an issue to discuss anything
non-trivial before sending a PR — it saves both of us rework.

For security vulnerabilities, see [`SECURITY.md`](SECURITY.md) instead of
opening a public issue.

## Repository layout

This is a `uv` workspace with three packages:

- `.` (`extensible-mcp`) — the proxy itself: `src/extensible_mcp/`, tested
  by `tests/` at the repo root.
- `examples/agentic-commerce-demo/` (`extensible-mcp-vc`) — the VC/WebAuthn
  commerce demo, with its own `src/`, `tests/`, and `pyproject.toml`.
- `examples/identity/` (`household-identity`) — the wallet and DID-server
  package backing that demo.

Each package's tests run from its own directory (they each have their own
`testpaths` in `pyproject.toml`); there isn't a single top-level `pytest`
invocation that covers all three.

## Setup

```bash
git clone https://github.com/mattdfuchs/extensible-mcp.git
cd extensible-mcp
uv sync --all-packages --all-extras --group dev
```

This resolves all three workspace packages from one lockfile into one
shared virtualenv.

## Running tests

```bash
# The proxy itself
uv run pytest

# The commerce demo
cd examples/agentic-commerce-demo && uv run pytest

# The identity package
cd examples/identity && uv run pytest
```

Run the relevant suite(s) before opening a PR — a change to `src/extensible_mcp/`
should keep both example packages' suites green too, since they depend on
it as a workspace member.

## Code style

- No comments that just restate what the code does — only ones that explain
  a non-obvious *why* (a hidden constraint, a subtle invariant, a workaround
  for a specific bug). Well-named identifiers should carry the "what."
- Don't add abstractions, config knobs, or error handling for cases that
  can't happen. Prefer the straightforward version over the general one
  until a second real use case shows up.
- Match the existing docstring style in the module you're touching — most
  of this codebase explains design intent (why a check exists, what
  invariant it protects) rather than restating parameter types.

## Pull requests

- Keep PRs scoped to one change; unrelated cleanup makes review harder, not
  easier.
- Add or update tests for behavior changes — see `tests/` in the relevant
  package for the existing style (fixtures under `tests/fixtures/`,
  hand-authored bundles documented with a `PROVENANCE.md`).
- Update [`CHANGELOG.md`](CHANGELOG.md) under an `[Unreleased]` heading if
  the change is user-visible.

## License and sign-off

Contributions are under the Apache License 2.0 (see [`LICENSE`](LICENSE)),
the same license as the rest of the project.

Every commit needs a `Signed-off-by` line, which `git` will add for you:

```bash
git commit -s -m "your message"
```

It produces a trailer naming you:

```
Signed-off-by: Jane Developer <jane@example.com>
```

That line is a [Developer Certificate of Origin](https://developercertificate.org/)
sign-off. It is not a copyright assignment and not a CLA — you keep your
copyright, and nothing beyond the Apache-2.0 license is granted. What you are
certifying is that you wrote the patch, or that you have the right to submit
it under that license.

This project is an argument about not taking things on trust, so it would be
odd not to ask where code came from. It also means a later question about the
provenance of any line has an answer recorded at the time, rather than a
reconstruction.

CI checks it on every pull request. If you forget, the fix is one command —
no need to redo the work:

```bash
git rebase --signoff main     # sign off everything on your branch
git push --force-with-lease
```

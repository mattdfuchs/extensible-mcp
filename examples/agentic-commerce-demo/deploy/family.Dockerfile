# The family's side of the demo in one container: kid + parent wallets, the
# WebAuthn approval service, the policy proxy, and the browser console (chat
# + live log) that fronts all of it. Build context is the repo root
# (mcp-alternative):
#   docker compose -f examples/agentic-commerce-demo/deploy/docker-compose.yml build
#
# Stripe is opt-in at BUILD time, not just at runtime: the default build does
# not install the `stripe` SDK at all, so a released/default image cannot
# reach Stripe's API no matter what SETTLEMENT/STRIPE_API_KEY someone sets —
# there is no path to it without rebuilding with ENABLE_STRIPE=true. Setting
# SETTLEMENT=stripe on a default (non-Stripe) build fails clearly at runtime
# ("stripe is not installed. Run: uv sync --extra stripe") instead of a
# confusing crash — see settlement.py's StripeExecutor.
#   docker compose -f examples/agentic-commerce-demo/deploy/docker-compose.yml \
#     build --build-arg ENABLE_STRIPE=true family

FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim

WORKDIR /repo
COPY . .

ARG ENABLE_STRIPE=false

# One workspace, one lockfile: extensible-mcp, extensible-mcp-vc, and
# household-identity all resolve together.
RUN uv sync --no-dev --all-packages \
 && if [ "$ENABLE_STRIPE" = "true" ]; then \
      uv sync --no-dev --package extensible-mcp-vc --extra stripe; \
    fi

# Pre-bake the FastEmbed model so first boot doesn't download ~90 MB.
RUN uv run --package extensible-mcp-vc python -c \
    "from fastembed import TextEmbedding; TextEmbedding('sentence-transformers/all-MiniLM-L6-v2')"

WORKDIR /repo/examples/agentic-commerce-demo
COPY examples/agentic-commerce-demo/deploy/family-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Published: 7300 chat + log console, 7500 passkey approvals. 7400 (proxy)
# and 7401/7402 (wallet pages) stay internal — the console is the only thing
# that talks to the proxy now.
EXPOSE 7300 7500
ENTRYPOINT ["/entrypoint.sh"]

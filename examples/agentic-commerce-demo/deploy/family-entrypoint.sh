#!/usr/bin/env bash
# Family-container launcher: workspace init (first boot), two wallets, the
# WebAuthn approval service, the proxy, then the browser console in the
# foreground. Container stop tears everything down together.
#
# Everything backgrounded here writes to one shared log ($DEMO_LOG_FILE), which
# the console serves live at /logs — so `docker compose logs` isn't the only
# way to see what's happening. Human-facing surfaces: the console
# (chat + log) and the passkey approval page — see the banner this prints
# once everything is up.
set -euo pipefail
cd /repo/examples/agentic-commerce-demo

export DEMO_LOG_FILE="${DEMO_LOG_FILE:-$PWD/workspace/demo.log}"

if [ ! -f workspace/vc-config.json ]; then
  echo "[family] first boot: creating workspace (keys, memberships, DID doc)"
  uv run --package extensible-mcp-vc python examples/setup.py
fi

# Must come after first-boot setup, not before: setup.py refuses to run
# against a non-empty workspace/, and creating the log file first (even an
# empty one) counts as non-empty and made setup refuse to run at all.
mkdir -p "$(dirname "$DEMO_LOG_FILE")"
: > "$DEMO_LOG_FILE"

uv run --package household-identity wallet run \
  --keys-dir workspace/keys --label kid --host 0.0.0.0 --port 7401 \
  --membership-path workspace/memberships/kid.jwt --approve web \
  >> "$DEMO_LOG_FILE" 2>&1 &

uv run --package household-identity wallet run \
  --keys-dir workspace/keys --label parent --host 0.0.0.0 --port 7402 \
  --membership-path workspace/memberships/parent.jwt --approve web \
  >> "$DEMO_LOG_FILE" 2>&1 &

APPROVAL_HOST=0.0.0.0 uv run --package extensible-mcp-vc python examples/approval_service.py \
  >> "$DEMO_LOG_FILE" 2>&1 &

# Give the wallets and approval service a moment to bind before the proxy
# resolves its clients; the proxy retries nothing at startup by design.
sleep 3

# Boot-time trust exchange (a deployment decision, outside any LLM's reach):
# register the parlor's merchant key into the family's trusted-merchant set,
# so its signed invoices are honored — and only its. Runs in the foreground
# deliberately: it doubles as the parlor readiness gate, since the proxy
# connects to its downstreams once at startup and does not retry.
if [ -n "${PIZZA_URL:-}" ]; then
  PARLOR_BASE="${PIZZA_URL%/mcp/}"
  # tee, not >>: this step gates everything after it, so its outcome should
  # be visible on `docker compose logs` even before the console (which
  # serves $DEMO_LOG_FILE) has started. Process substitution, not a pipe —
  # a `cmd | tee file << EOF` heredoc attaches to tee (the last command in
  # the pipeline), not to cmd, so cmd would run with no stdin at all.
  uv run --package extensible-mcp-vc python - "$PARLOR_BASE" \
    > >(tee -a "$DEMO_LOG_FILE") 2>&1 << 'PYEOF'
import sys, time
import httpx

base = sys.argv[1]
for _ in range(30):
    try:
        card = httpx.get(f"{base}/merchant-card", timeout=5.0).json()
        httpx.post(
            "http://127.0.0.1:7500/trust-merchant",
            json={"merchantId": card["merchantId"], "publicKey": card["publicKey"]},
            timeout=5.0,
        ).raise_for_status()
        print(f"[family] trusted merchant {card['merchantId']} ({card['merchant']})")
        break
    except Exception:
        time.sleep(2)
else:
    print("[family] WARNING: could not register the parlor's merchant key")
PYEOF
fi

# The wallet pages (kid/parent, :7401/:7402) aren't published in this
# container — hide the tools whose approval only they can grant, so the
# assistant can't reach for one and stall (see HIDE_WALLET_GATED_TOOLS in
# family_proxy_server.py).
HIDE_WALLET_GATED_TOOLS=true \
  uv run --package extensible-mcp-vc python examples/family_proxy_server.py --host 0.0.0.0 --port 7400 \
  >> "$DEMO_LOG_FILE" 2>&1 &

# Give the proxy a moment to bind before the console connects to it as an
# MCP client.
sleep 2

echo "[family] human surfaces: chat + log http://localhost:7300 · passkey approvals http://localhost:7500 (2 windows: child, parent)"
exec env CONSOLE_HOST=0.0.0.0 CONSOLE_PORT=7300 \
  uv run --package extensible-mcp-vc python examples/console_server.py

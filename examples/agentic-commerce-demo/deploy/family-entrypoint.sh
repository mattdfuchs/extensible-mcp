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

# --host 127.0.0.1, not 0.0.0.0: every consumer of these three services --
# the proxy (wallets) and the console (proxy) -- runs inside this container
# and reaches them over loopback, and none of the three is published to the
# host. Binding them to 0.0.0.0 put the whole family control plane on the
# shared compose network, where the merchant container could reach it: drive
# the proxy as an MCP client, or POST a wallet's /sign/request with its own
# chosen prompt text and callback URL. On loopback they are not reachable
# from another container at all. The approval service stays on 0.0.0.0
# because its passkey pages are published to the host.
uv run --package household-identity wallet run \
  --keys-dir workspace/keys --label kid --host 127.0.0.1 --port 7401 \
  --membership-path workspace/memberships/kid.jwt --approve web \
  >> "$DEMO_LOG_FILE" 2>&1 &

uv run --package household-identity wallet run \
  --keys-dir workspace/keys --label parent --host 127.0.0.1 --port 7402 \
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
  uv run --package extensible-mcp-vc python examples/family_proxy_server.py --host 127.0.0.1 --port 7400 \
  >> "$DEMO_LOG_FILE" 2>&1 &

# Wait for the proxy to actually accept connections. It builds an embedding
# index and connects three stdio downstreams first, which takes tens of
# seconds on a cold container -- a fixed sleep either wasted time or, more
# often, handed the console a port nothing was listening on yet.
uv run python - << 'PYEOF'
import socket, sys, time

deadline = time.monotonic() + 120
while time.monotonic() < deadline:
    with socket.socket() as s:
        s.settimeout(2)
        try:
            s.connect(("127.0.0.1", 7400))
            print("[family] proxy is accepting connections on 127.0.0.1:7400")
            sys.exit(0)
        except OSError:
            time.sleep(1)
print("[family] WARNING: proxy did not come up within 120s", file=sys.stderr)
PYEOF

# The passkey page is behind a sign-in now, and the passwords are random per
# workspace. Echo them to stdout as well as the shared log, so they show up in
# `docker compose logs` and not only at :7300/logs.
if [ -f workspace/approval-users.json ]; then
  uv run python - << 'PYEOF' | tee -a "$DEMO_LOG_FILE"
import json, pathlib
users = json.loads(pathlib.Path("workspace/approval-users.json").read_text())["users"]
creds = "  ".join(f"{n}/{r['password']}" for n, r in sorted(users.items()))
print(f"[family] passkey page sign-in: {creds}")
PYEOF
fi

echo "[family] human surfaces: chat + log http://localhost:7300 · passkey approvals http://localhost:7500 (2 windows: child, parent)"
exec env CONSOLE_HOST=0.0.0.0 CONSOLE_PORT=7300 \
  uv run --package extensible-mcp-vc python examples/console_server.py

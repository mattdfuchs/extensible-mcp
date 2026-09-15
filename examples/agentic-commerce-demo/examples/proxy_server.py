# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Runnable proxy that wires extend_server with a JSON VC config file.

The VC config file is a JSON document matching the VCConfig dataclass
fields. ``preresolved_did_documents`` lets the demo skip real HTTPS
resolution of the admin's did:web by embedding the DID document inline.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from extensible_mcp.config import load_config

from extensible_mcp_vc import VCConfig, extend_server

# Pull in the reference price-tier filter that ships next to this file
sys.path.insert(0, str(Path(__file__).resolve().parent))
from price_tier_filter import PriceTierCallFilter  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(prog="proxy_server")
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--vc-config", required=True, type=Path)
    parser.add_argument(
        "--transport",
        choices=["stdio", "http"],
        default="stdio",
        help="MCP transport (default: stdio for Claude Desktop, http for n8n)",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=7400)
    args = parser.parse_args()

    config = load_config(args.config)
    vc_raw = json.loads(args.vc_config.read_text())
    vc_config = VCConfig(**vc_raw)

    # Household price policy for the pizza demo:
    #   total > $200  → reject outright
    #   total > $10   → require verified vc_authorization (parent's VC)
    #   total ≤ $10   → kid's vc_request alone is enough
    pizza_policy = PriceTierCallFilter(
        tools=["pizza__order_pizza"],
        total_field="total",
        hard_cap=200.0,
        parent_required_above=10.0,
    )

    server = extend_server(config, vc_config, extra_call_filters=[pizza_policy])
    if args.transport == "http":
        server.run(transport="http", host=args.host, port=args.port)
    else:
        server.run()


if __name__ == "__main__":
    main()

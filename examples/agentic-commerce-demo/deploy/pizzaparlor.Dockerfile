# The pizza parlor's side: its MCP tool server as an independent service the
# family proxy reaches over Streamable HTTP — the org boundary is the
# container boundary. This is where the merchant build-out (invoice signer
# behind the parlor's own policy, fulfillment commitments, its own agent)
# will live.

FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim

WORKDIR /repo
COPY . .
RUN uv sync --no-dev --all-packages

WORKDIR /repo/examples/agentic-commerce-demo
ENV PIZZA_PORT=7600 \
    PIZZA_ORDERS_LOG=/data/pizza-orders.log
VOLUME /data
EXPOSE 7600
CMD ["uv", "run", "--package", "extensible-mcp-vc", "python", "examples/pizza_server.py"]

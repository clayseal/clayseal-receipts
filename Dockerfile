# Agent Receipts design-partner image: Rust prover + Python SDK + HTTP verifier
# syntax=docker/dockerfile:1

FROM rust:1-bookworm AS rust-builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build -p agent-receipts-cli --release
RUN ./target/release/agent-receipts setup

FROM python:3.11-slim-bookworm AS runtime
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=rust-builder /build/target/release/agent-receipts /usr/local/bin/agent-receipts
COPY --from=rust-builder /build/keys /app/keys

ENV AGENT_RECEIPTS_CLI=/usr/local/bin/agent-receipts
ENV PYTHONUNBUFFERED=1

COPY pyproject.toml README.md LICENSE ./
COPY agentauth ./agentauth
COPY compliance ./compliance
COPY policies ./policies
COPY config ./config
COPY examples ./examples
COPY scripts ./scripts
COPY docs ./docs

RUN pip install --no-cache-dir ".[server,mcp,verifier]"

RUN cp config/partner.example.yaml config/partner.yaml
RUN addgroup --system agentauth \
    && adduser --system --ingroup agentauth --home /app agentauth \
    && mkdir -p /app/.audit /app/data /app/receipts \
    && chown -R agentauth:agentauth /app

USER agentauth

EXPOSE 8787 8000

# Default: HTTP verifier (override in compose for MCP server)
CMD ["arctl", "serve", "--host", "0.0.0.0", "--port", "8787"]

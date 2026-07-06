# Agent Receipts design-partner image: Rust prover + Python SDK + HTTP verifier
# syntax=docker/dockerfile:1

# Base images pinned by tag + digest for reproducible, supply-chain-checked builds.
# Refresh digests with: docker buildx imagetools inspect <image:tag>
FROM rust:1-bookworm@sha256:a339861ae23e9abb272cea45dfafde21760d2ce6577a70f8a926153677902663 AS rust-builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build -p agent-receipts-cli --release
RUN ./target/release/agent-receipts setup

FROM python:3.11-slim-bookworm@sha256:342ccc964c400ad6644c2035b6afdb246251399d57d973b58a7a353b962981b4 AS runtime
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

# NOTE: no config/partner.yaml is baked in. The example config contains shadow-mode
# placeholders that must never run in production. A producing profile MUST mount/inject
# a real config (e.g. -v ./config/partner.yaml:/app/config/partner.yaml or via
# AGENT_RECEIPTS_* env); PartnerConfig/`arctl preflight` fail closed on placeholders,
# and AGENT_RECEIPTS_ENV=production forces strict validation. The default CMD below runs
# the stateless HTTP verifier, which does not need a partner config.
RUN addgroup --system agentauth \
    && adduser --system --ingroup agentauth --home /app agentauth \
    && mkdir -p /app/.audit /app/data /app/receipts \
    && chown -R agentauth:agentauth /app

USER agentauth

EXPOSE 8787 8000

# Default: HTTP verifier (override in compose for MCP server)
CMD ["arctl", "serve", "--host", "0.0.0.0", "--port", "8787"]

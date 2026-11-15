# Multi-stage production build for Capa 8 (RFC-ILP-2026) MCP Daemons
# Stage 1: Build binaries
FROM rust:1.70-slim-bookworm AS builder

WORKDIR /usr/src/capa8

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency manifests
COPY Cargo.toml Cargo.lock ./

# Cache build dependencies
RUN mkdir src && \
    echo "pub fn main() {}" > src/lib.rs && \
    mkdir -p src/bin && \
    echo "fn main() {}" > src/bin/ilp_mcp_sidecar.rs && \
    echo "fn main() {}" > src/bin/ilp_mcp_gateway.rs && \
    cargo build --release --locked --all-features && \
    rm -rf src

# Copy real source code and policies
COPY src ./src
COPY policies ./policies

# Build release binaries with locked dependencies
RUN cargo build --release --locked --bins --all-features

# Stage 2: Hardened runtime environment
FROM debian:bookworm-slim AS runtime

# Security: Create unprivileged user with fixed UID/GID 10001
RUN groupadd -g 10001 ilp && \
    useradd -u 10001 -g ilp -m -s /usr/sbin/nologin -c "ILP Capa 8 Daemon User" ilp && \
    apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy compiled binaries from builder
COPY --from=builder /usr/src/capa8/target/release/ilp_mcp_sidecar /usr/local/bin/ilp_mcp_sidecar
COPY --from=builder /usr/src/capa8/target/release/ilp_mcp_gateway /usr/local/bin/ilp_mcp_gateway
COPY --from=builder /usr/src/capa8/policies /etc/ilp/policies

# Set directory permissions for unprivileged user
RUN mkdir -p /var/log/ilp /etc/ilp/secrets && \
    chown -R ilp:ilp /var/log/ilp /etc/ilp && \
    chmod 750 /var/log/ilp /etc/ilp

USER 10001:10001

EXPOSE 9001 9002

ENTRYPOINT ["/usr/local/bin/ilp_mcp_sidecar"]
CMD ["--listen", "127.0.0.1:9001", "--gateway", "127.0.0.1:9002", "--policy", "/etc/ilp/policies/default_msac.conf"]

FROM rust:1.93.1-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY rns-crypto rns-crypto
COPY rns-core rns-core
COPY rns-net rns-net
COPY rns-cli rns-cli
COPY rns-ctl rns-ctl
COPY rns-hooks rns-hooks
COPY rns-stats-hook rns-stats-hook
COPY rns-sentinel-hook rns-sentinel-hook
RUN rustup target add wasm32-unknown-unknown
RUN cargo build --release --bin rns-ctl --bin rns-sentineld --features rns-hooks

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends curl iproute2 iptables && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/rns-ctl /usr/local/bin/rns-ctl
COPY --from=builder /build/target/release/rns-sentineld /usr/local/bin/rns-sentineld
RUN mkdir -p /etc/rns /data
EXPOSE 8080
HEALTHCHECK --interval=2s --timeout=2s --retries=15 \
  CMD curl -sf http://localhost:8080/health || exit 1
# Copy config from read-only mount to writable /data, then run from there
CMD ["sh", "-c", "cp /etc/rns/config /data/config && exec rns-ctl http --config /data --disable-auth --host 0.0.0.0 --port 8080"]

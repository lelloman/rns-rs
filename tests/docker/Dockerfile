FROM rust:1.96.0-bookworm AS builder
WORKDIR /build
# Build settings shared with rns-server/Dockerfile.rns-server: both images
# use the same rns-docker-target cache, and cargo only reuses a dependency
# when the profile matches, so these must stay identical in both files.
# On a memory-constrained Docker host, export CARGO_BUILD_JOBS=1 and
# CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 before running the suite; the run
# scripts pass them through as build args.
ARG CARGO_BUILD_JOBS=default
ARG CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16
ENV CARGO_BUILD_JOBS=$CARGO_BUILD_JOBS \
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS=$CARGO_PROFILE_RELEASE_CODEGEN_UNITS \
    RUST_MIN_STACK=67108864
RUN rustup target add wasm32-unknown-unknown
# The workspace build scripts declare rerun-if-changed on ../.git/HEAD and
# ../.git/refs. The build context has no .git, and cargo treats a missing
# rerun-if-changed path as always stale, so every build reran every build
# script and recompiled every workspace crate. Stand in old, unchanging
# paths so a source edit only rebuilds the crates that depend on it.
RUN mkdir -p .git/refs && touch -d @0 .git/HEAD .git/refs
COPY Cargo.toml Cargo.lock ./
COPY build build
COPY rns-crypto rns-crypto
COPY rns-core rns-core
COPY rns-net rns-net
COPY rns-cli rns-cli
COPY rns-ctl rns-ctl
COPY rns-git rns-git
COPY rns-hooks rns-hooks
COPY rns-stats-hook rns-stats-hook
COPY rns-sentinel-hook rns-sentinel-hook
COPY rns-server rns-server
COPY rns-tun rns-tun
COPY rns-tun-android rns-tun-android
COPY tools/rns-bench tools/rns-bench
RUN --mount=type=cache,id=rns-docker-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=rns-docker-target,target=/build/target \
    cargo build --release --bin rns-ctl --bin rns-sentineld --features rns-hooks-wasm \
    && cargo build --release -p rns-tun --bin rntun \
    && mkdir -p /out \
    && cp /build/target/release/rns-ctl /build/target/release/rns-sentineld \
        /build/target/release/rntun /out/

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl iproute2 iptables iputils-ping jq procps socat \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/rns-ctl /usr/local/bin/rns-ctl
COPY --from=builder /out/rns-sentineld /usr/local/bin/rns-sentineld
COPY --from=builder /out/rntun /usr/local/bin/rntun
RUN mkdir -p /etc/rns /data
EXPOSE 8080
HEALTHCHECK --interval=2s --timeout=2s --retries=15 \
  CMD curl -sf http://localhost:8080/health || exit 1
# Copy config from read-only mount to writable /data, then run from there
CMD ["sh", "-c", "cp /etc/rns/config /data/config && exec rns-ctl http --config /data --disable-auth --host 0.0.0.0 --port 8080"]

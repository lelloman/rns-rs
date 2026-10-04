# syntax=docker/dockerfile:1
FROM rust:1.96.0-bookworm@sha256:5e2214abe154fe26e39f64488952e5c991eeed1d6d6da7cc8381ae83927f0cfc
ENV RUSTUP_TOOLCHAIN=1.96.0 CARGO_BUILD_JOBS=2
WORKDIR /source
COPY . .
RUN --mount=type=cache,id=rns-relay-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=rns-relay-target,target=/source/target \
    cargo test --locked -p rns-bench \
    && cargo build --locked --release -p rns-bench \
    && cp target/release/rns-bench /usr/local/bin/rns-relay-bench
ENV RNS_BENCH_SOURCE_RECORD=/source/bench/relay/source-record.json
ENTRYPOINT ["/usr/local/bin/rns-relay-bench", "run", "--relay"]

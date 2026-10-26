# Rust toolchain for static musl agent builds (x86_64 + aarch64) via cargo-zigbuild.
FROM rust:1.90-bookworm

ARG ZIG_VERSION=0.13.0
RUN apt-get update && apt-get install -y --no-install-recommends xz-utils ca-certificates curl \
 && curl -fsSL "https://ziglang.org/download/${ZIG_VERSION}/zig-linux-x86_64-${ZIG_VERSION}.tar.xz" \
    | tar -xJ -C /opt \
 && ln -s /opt/zig-linux-x86_64-${ZIG_VERSION}/zig /usr/local/bin/zig \
 && rm -rf /var/lib/apt/lists/*

RUN rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl \
 && cargo install --locked cargo-zigbuild

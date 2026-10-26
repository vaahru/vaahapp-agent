#!/usr/bin/env bash
# Builds static vaahapp-agent binaries (x86_64 + aarch64, musl) in a container and runs the tests.
# Needs only Docker:  bash build.sh [test]
# Output: dist/vaahapp-agent-{x86_64,aarch64}, matching .sha256 files, VERSION and install.sh.
set -euo pipefail
cd "$(dirname "$0")"
ROOT=$(pwd)
IMG=vaahapp-rust-build:1

if ! docker image inspect "$IMG" >/dev/null 2>&1; then
  docker build -t "$IMG" -f build.Dockerfile .
fi

# Cargo registry and target dir live in named volumes: fast rebuilds, no root-owned files in the repo.
RUN=(docker run --rm -v "$ROOT:/src" -v vaahapp-cargo:/usr/local/cargo/registry -v vaahapp-target:/target
     -e CARGO_TARGET_DIR=/target -w /src "$IMG")

"${RUN[@]}" cargo test --release
if [ "${1:-}" = "test" ]; then exit 0; fi

"${RUN[@]}" cargo zigbuild --release --target x86_64-unknown-linux-musl --target aarch64-unknown-linux-musl

VERSION=$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)
mkdir -p dist
for arch in x86_64 aarch64; do
  docker run --rm -v vaahapp-target:/target -v "$ROOT/dist:/out" "$IMG" \
    sh -c "cp /target/$arch-unknown-linux-musl/release/vaahapp-agent /out/.vaahapp-agent-$arch.tmp && chown $(id -u):$(id -g) /out/.vaahapp-agent-$arch.tmp && mv -f /out/.vaahapp-agent-$arch.tmp /out/vaahapp-agent-$arch"
  # (copy + rename: a running copy of the old binary would make a plain cp fail with "Text file busy")
  (cd dist && sha256sum "vaahapp-agent-$arch" > "vaahapp-agent-$arch.sha256")
done
echo "$VERSION" > dist/VERSION
cp install.sh dist/install.sh
ls -l dist

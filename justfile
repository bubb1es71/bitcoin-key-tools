# Task recipes for bitcoin-key-tools.

_default:
   @just --list

# Target triple for reproducible Linux x86_64 builds.
target := "x86_64-unknown-linux-musl"

# Build reproducible, statically-linked x86_64 Linux release binaries via
# `cross` inside a pinned container (see Cross.toml) with a pinned toolchain
# (see rust-toolchain.toml). Byte-for-byte identical output across builders.
#
# The RUSTFLAGS env var overrides the per-target rustflags in
# .cargo/config.toml, so it must repeat the getrandom_backend cfg to keep the
# musl build on the fail-closed getrandom(2) backend (see .cargo/config.toml).
#
# Requires: Docker (running) or Podman, plus `cross` and the target toolchain.
release-linux:
    SOURCE_DATE_EPOCH=0 \
    CARGO_BUILD_TARGET={{ target }} \
    RUSTFLAGS="--remap-path-prefix=$HOME=/build -C strip=symbols --cfg getrandom_backend=\"linux_getrandom\"" \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=gcc \
    cross build --release

# Print the SHA-256 checksums of the reproducible Linux binaries.
# Uses sha256sum on Linux, shasum on macOS.
checksums:
    #!/usr/bin/env sh
    set -eu
    cd "target/{{ target }}/release"
    bins="seedroller keyderiver"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum $bins
    else
        shasum -a 256 $bins
    fi

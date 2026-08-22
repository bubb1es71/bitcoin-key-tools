# Task recipes for bitcoin-key-tools.

_default:
   @just --list

# Target triple for reproducible Linux x86_64 builds.
target := "x86_64-unknown-linux-musl"

# Key used to clearsign the release checksum manifest (see `sign` recipe).
signing_key := "bubb1es71@proton.me"

# Build reproducible, statically-linked x86_64 Linux release binaries via
# `cross` inside a pinned container (see Cross.toml) with a pinned toolchain
# (see rust-toolchain.toml). Byte-for-byte identical output across builders.
#
# The RUSTFLAGS env var overrides the per-target rustflags in
# .cargo/config.toml, so it must repeat the getrandom_backend cfg to keep the
# musl build on the fail-closed getrandom(2) backend (see .cargo/config.toml).
#
# CROSS_CONTAINER_OPTS pins the build container to host networking: rootless
# Podman's networking helper (pasta) needs /dev/net/tun, which is unavailable
# in some build environments (e.g. unprivileged LXC). Host networking needs no
# tun device and works the same with Docker or Podman on Linux and macOS —
# builds only need outbound connectivity, and network mode does not affect
# the output bytes.
#
# Requires: Docker (running) or Podman, plus `cross` and the target toolchain.
release-linux:
    SOURCE_DATE_EPOCH=0 \
    CARGO_BUILD_TARGET={{ target }} \
    RUSTFLAGS="--remap-path-prefix=$HOME=/build -C strip=symbols --cfg getrandom_backend=\"linux_getrandom\"" \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=gcc \
    CROSS_CONTAINER_OPTS="--network=host" \
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

# Stage release artifacts in dist/: the binaries plus a SHA256SUMS manifest
# (Bitcoin Core convention; verify with `sha256sum -c dist/SHA256SUMS`).
dist: release-linux
    #!/usr/bin/env sh
    set -eu
    mkdir -p dist
    cp "target/{{ target }}/release/seedroller" \
       "target/{{ target }}/release/keyderiver" dist/
    cd dist
    rm -f SHA256SUMS SHA256SUMS.asc
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum seedroller keyderiver > SHA256SUMS
    else
        shasum -a 256 seedroller keyderiver > SHA256SUMS
    fi

# Clearsign dist/SHA256SUMS as dist/SHA256SUMS.asc (Bitcoin Core style: the
# .asc embeds the manifest text plus the signature). gpg will prompt for the
# key's passphrase if it isn't cached in gpg-agent.
sign: dist
    gpg --yes --local-user {{ signing_key }} \
        --output dist/SHA256SUMS.asc --clearsign dist/SHA256SUMS

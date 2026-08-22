[![Test](https://github.com/bubb1es71/bitcoin-key-tools/actions/workflows/test.yml/badge.svg)](https://github.com/bubb1es71/bitcoin-key-tools/actions/workflows/test.yml)
[![Audit](https://github.com/bubb1es71/bitcoin-key-tools/actions/workflows/audit.yml/badge.svg)](https://github.com/bubb1es71/bitcoin-key-tools/actions/workflows/audit.yml)

# bitcoin-key-tools

A Cargo workspace of security-sensitive command-line tools for Bitcoin key
management. Correctness and secrecy of key material are the top priorities.

## The tools

### [seedroller](seedroller/)

Generate a BIP39 mnemonic seed phrase (24 words) from physical dice rolls,
hardened with operating system RNG entropy.

Only the seed words are written to standard output — everything else goes to
standard error — so the phrase can be captured in a shell variable or piped
straight into `keyderiver`:

```sh
seedroller | keyderiver
```

See the [seedroller README](seedroller/README.md) for full usage, entropy
verification details, and security notes.

### [keyderiver](keyderiver/)

Derive BIP380 descriptor key expressions from a BIP39 seed phrase. The seed
words are read via a terminal prompt or from standard input when piped —
never as a command-line argument, so they stay out of shell history and
process listings. The BIP32 master extended private key (xprv, or tprv with
`-t`/`--testnet`) and its fingerprint are derived from the seed words, with
an optional BIP39 passphrase (`-s`/`--secret`).

Outputs both the secret and public account keys as BIP380 key expressions
with the master fingerprint as origin and the BIP389 `/<0;1>/*` multipath
wildcard, at a configurable BIP44 purpose (default 84, P2WPKH) and account
index (default 0).

See the [keyderiver README](keyderiver/README.md) for full usage and security
notes.

## Building

```sh
cargo build                        # debug build of both tools
cargo test                         # run the full test suite
cargo install --path seedroller    # install each tool separately
cargo install --path keyderiver
```

## Reproducible Linux (x86_64) releases

This workspace supports **reproducible builds**: byte-for-byte identical
`seedroller` and `keyderiver` binaries that anyone can rebuild and verify
against a published checksum. Reproducibility is anchored by two pinned files
committed to this repository:

- [`Cross.toml`](Cross.toml) — pins the exact `cross` container image by
  immutable digest, fixing the toolchain, linker, and libc.
- [`rust-toolchain.toml`](rust-toolchain.toml) — pins the exact Rust compiler
  version and target.
- [`.cargo/config.toml`](.cargo/config.toml) — forces the `getrandom` crate's
  fail-closed `linux_getrandom` backend on all Linux targets: OS entropy comes
  only from the `getrandom(2)` syscall, which errors if unavailable, instead
  of the backends that silently fall back to reading `/dev/urandom` (the
  default on musl targets). (The `just release-linux` recipe repeats the cfg
  in its `RUSTFLAGS`, since the environment variable overrides per-target
  rustflags.)

The binaries are statically linked against musl, so they run on any x86_64
Linux with no runtime dependencies.

### Prerequisites

- **A container runtime**: [Docker](https://www.docker.com) (installed *and
  running*) or [Podman](https://podman.io). The build runs inside a pinned
  Linux container, so this works from macOS, Linux, or Windows hosts.
- **[`cross`](https://github.com/cross-rs/cross)**:
  `cargo install cross --locked`
- **[`just`](https://github.com/casey/just)** (optional but recommended):
  `cargo install just --locked`. If you prefer not to use `just`, run the
  equivalent command from the [justfile](justfile) directly.
- **GnuPG** (optional): only needed for `just sign`, or to verify a signed
  release manifest. On macOS: `brew install gnupg`.
- **Rust**: [`rustup`](https://rustup.rs) automatically installs the pinned
  toolchain and target from `rust-toolchain.toml` on first build.

### Build and verify

```sh
just release-linux   # build both reproducible release binaries
just checksums       # print their SHA-256 checksums
just dist            # stage binaries + SHA256SUMS manifest in dist/
just sign            # run `dist` and clearsign the manifest (see below)
```

The binaries are written to:

```
target/x86_64-unknown-linux-musl/release/seedroller
target/x86_64-unknown-linux-musl/release/keyderiver
```

To verify a release, run `just checksums` and compare the output against the
published checksums — they should match exactly.

On a Linux system you can compute the checksums of the binaries directly with
`sha256sum` (part of coreutils, installed by default):

```sh
sha256sum target/x86_64-unknown-linux-musl/release/seedroller \
          target/x86_64-unknown-linux-musl/release/keyderiver
```

### Signed release manifests

`just sign` runs the full release pipeline: the reproducible build, staging in
`dist/` (gitignored), a `SHA256SUMS` manifest, and a clearsigned copy at
`dist/SHA256SUMS.asc` — the Bitcoin Core convention, where the `.asc` embeds
the manifest text plus the signature. Only the holder of the release signing
key can produce the signature; anyone can reproduce the binaries and manifest
and check them against it.

Releases are signed by:

- **Key:** `EB67F70A2AAD0B8B23D980B82D73B1A2DCE9B025`
- **UID:** `bubb1es71 <bubb1es71@proton.me>`

To verify a downloaded release, place `SHA256SUMS` and `SHA256SUMS.asc`
alongside the binaries, then:

```sh
# import the signing key (published on the signer's GitHub profile)
curl -sS https://github.com/bubb1es71.gpg | gpg --import

# expect a "Good signature" from bubb1es71 <bubb1es71@proton.me>, and check
# that the reported primary key fingerprint matches exactly:
#
#   EB67 F70A 2AAD 0B8B 23D9  80B8 2D73 B1A2 DCE9 B025
gpg --verify SHA256SUMS.asc

# then check the binaries against the manifest
# (add --ignore-missing if you downloaded only one of them)
sha256sum --check SHA256SUMS        # macOS: shasum -a 256 --check SHA256SUMS
```

GnuPG's "not a detached signature" warning during `--verify` is normal for a
clearsigned file — it refers to the plain `SHA256SUMS`, which is checked
separately by `sha256sum --check`.

Builders who want to attest to an identical reproducible build with their own
key can change the `signing_key` variable in the [justfile](justfile) and run
`just sign` themselves.

## Security

Both tools forbid `unsafe` code, keep dependencies minimal, and zeroize all
sensitive material from memory after use. For improved security, run them in
an ephemeral environment such as [TAILS](https://tails.net).

**To report a security vulnerability, please see [SECURITY.md](SECURITY.md).**
Do not open a public issue.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.

## Acknowledgements

These tools stand on the shoulders of excellent open-source work. Many thanks
to the maintainers and contributors of the crates this workspace depends on:

- [`bitcoin`](https://github.com/rust-bitcoin/rust-bitcoin) — the Rust
  Bitcoin library and its community of maintainers
- [`bip39`](https://github.com/rust-bitcoin/rust-bip39) — BIP39 mnemonic
  support, maintained alongside rust-bitcoin
- [`clap`](https://github.com/clap-rs/clap) — command-line argument parsing
- [`getrandom`](https://github.com/rust-random/getrandom) — access to the
  operating system RNG
- [`zeroize`](https://github.com/RustCrypto/utils/tree/master/zeroize) —
  secure erasure of sensitive memory, from the RustCrypto project

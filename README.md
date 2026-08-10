[![Test](https://github.com/bubb1es71/bitcoin-key-tools/actions/workflows/test.yml/badge.svg)](https://github.com/bubb1es71/bitcoin-key-tools/actions/workflows/test.yml)
[![Audit](https://github.com/bubb1es71/bitcoin-key-tools/actions/workflows/audit.yml/badge.svg)](https://github.com/bubb1es71/bitcoin-key-tools/actions/workflows/audit.yml)

# bitcoin-key-tools

A Cargo workspace of security-sensitive command-line tools for Bitcoin key
management. Correctness and secrecy of key material are the top priorities.

## The tools

### [seedroller](seedroller/)

Generate a BIP39 mnemonic seed phrase (24 words) from physical dice rolls,
hardened with operating system RNG entropy, and derive the BIP32 master
extended private key (xprv, or tprv with `-t`).

Only the master key is written to standard output — the seed phrase and all
other messages go to standard error — so it can be captured in a shell
variable or piped straight into `keyderiver`:

```sh
seedroller | keyderiver
```

See the [seedroller README](seedroller/README.md) for full usage, entropy
verification details, and security notes.

### [keyderiver](keyderiver/)

Derive BIP380 descriptor key expressions from an existing master extended
private key (xprv/tprv). The master key is read via a hidden terminal prompt
or from standard input when piped — never as a command-line argument, so it
stays out of shell history and process listings.

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
- **Rust**: [`rustup`](https://rustup.rs) automatically installs the pinned
  toolchain and target from `rust-toolchain.toml` on first build.

### Build and verify

```sh
just release-linux   # build both reproducible release binaries
just checksums       # print their SHA-256 checksums
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

To check a downloaded release against a published `SHA256SUMS`-style file
containing the expected hashes, place the file alongside the binaries and run:

```sh
sha256sum --check SHA256SUMS
```

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
- [`rand`](https://github.com/rust-random/rand) — access to the operating
  system RNG
- [`zeroize`](https://github.com/RustCrypto/utils/tree/master/zeroize) —
  secure erasure of sensitive memory, from the RustCrypto project

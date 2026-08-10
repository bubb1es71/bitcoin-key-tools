[![Test](https://github.com/bubb1es71/seedroller/actions/workflows/test.yml/badge.svg)](https://github.com/bubb1es71/seedroller/actions/workflows/test.yml)
[![Audit](https://github.com/bubb1es71/seedroller/actions/workflows/audit.yml/badge.svg)](https://github.com/bubb1es71/seedroller/actions/workflows/audit.yml)


# keyderiver

Derive BIP380 xprv/tprv descriptor keys from a master seed xprv key. The user must provide
the seed xprv (or tprv for a testnet) and may optionally also provide the BIP44 purpose and
account derivation values. If not provided the default purpose is 84 (P2WPKH) and account is
0. 

See the `seedroller` tool to generate a new seed xprv (or tprv).

## Installation

```sh
cargo install --path .
```

This builds the release binary and installs it to `~/.cargo/bin/keyderiver`.

## Usage

### Normal mode (recommended)

```sh
keyderiver <master xprv or tprv key> -p <purpose> -a <account> 
```

### Help

```sh
keyderiver -h
```

### Tests

```sh
cargo test
```

## Security notes

- **Run in an ephemeral environment.** For improved security, only run this on a local temporary system such as [TAILS](https://tails.net) — a live operating system that runs from a USB stick, leaves no trace on shutdown, and keeps your seed phrase off your everyday machine.
- **Write down your derived xprv on paper.** It is displayed on screen and remains in your terminal scrollback — clear it with `clear` when done.
- Where possible sensitive intermediate values (derived xprv) are zeroed from memory after use via [`zeroize`](https://crates.io/crates/zeroize).
- The crate forbids `unsafe` code (`#![forbid(unsafe_code)]`).
- Dependencies are minimal: `bitcoin`, `clap`, `zeroize`.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.

[![Test](https://github.com/bubb1es71/seedroller/actions/workflows/test.yml/badge.svg)](https://github.com/bubb1es71/seedroller/actions/workflows/test.yml)
[![Audit](https://github.com/bubb1es71/seedroller/actions/workflows/audit.yml/badge.svg)](https://github.com/bubb1es71/seedroller/actions/workflows/audit.yml)


# keyderiver

Derive BIP380 descriptor key expressions from a master extended private key. The user must
provide the master xprv (or tprv for a testnet) and may optionally also provide the BIP44
purpose and account derivation values. If not provided the default purpose is 84 (P2WPKH)
and account is 0.

The output includes both the secret account key (xprv/tprv) and the public account key
(xpub/tpub) as BIP380 key expressions with the master fingerprint as origin and the BIP389
`/<0;1>/*` multipath wildcard covering both the receive (0) and change (1) chains.

See the `seedroller` tool to generate a new seed xprv (or tprv).

## Installation

```sh
cargo install --path .
```

This builds the release binary and installs it to `~/.cargo/bin/keyderiver`.

## Usage

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
- **The master key is passed as a command-line argument.** It will be saved in your shell history and is visible in process listings while the tool runs. To keep it out of your shell history, prefix the command with a space (requires `HISTCONTROL=ignorespace` in bash or `HIST_IGNORE_SPACE` in zsh), and delete any history entry that was recorded.
- **Write down your derived xprv on paper.** It is displayed on screen and remains in your terminal scrollback — clear it with `clear` when done.
- Sensitive key material is scrubbed from memory after use: the master key and the derived account private key are erased, and the printed secret key expression string is zeroed via [`zeroize`](https://crates.io/crates/zeroize).
- The crate forbids `unsafe` code (`#![forbid(unsafe_code)]`).
- Dependencies are minimal: `bitcoin`, `clap`, `zeroize`.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.

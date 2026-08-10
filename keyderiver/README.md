# keyderiver

Derive BIP380 descriptor key expressions from a master extended private key. The master
xprv (or tprv for a testnet) is read via a hidden terminal prompt, or from standard input
when piped — never as a command-line argument, so it does not appear in shell history or
process listings. The BIP44 purpose and account derivation values may optionally be
provided; if not provided the default purpose is 84 (P2WPKH) and account is 0.

The output includes both the secret account key (xprv/tprv) and the public account key
(xpub/tpub) as BIP380 key expressions with the master fingerprint as origin and the BIP389
`/<0;1>/*` multipath wildcard covering both the receive (0) and change (1) chains.

See the `seedroller` tool to generate a new seed xprv (or tprv) — it writes only the
master key to standard output, so it can be piped straight into this tool.

## Installation

```sh
cargo install --path .
```

This builds the release binary and installs it to `~/.cargo/bin/keyderiver`.

## Usage

```sh
keyderiver [-p <purpose>] [-a <account>]
```

You are prompted for the master key (xprv or tprv) with terminal echo disabled, so the
key is not displayed as you type or paste it. Alternatively, pipe the key on standard
input — for example directly from a password manager:

```sh
pass show bitcoin/master-xprv | keyderiver
```

Only the first line of standard input is read.

You can also pipe a freshly generated master key directly from `seedroller` (or capture it
in a shell variable first):

```sh
seedroller | keyderiver
```

```sh
MASTER=$(seedroller)
echo "$MASTER" | keyderiver
unset MASTER
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
- **The master key is never taken as a command-line argument.** It is read via a hidden terminal prompt (echo disabled) or from standard input when piped, keeping it out of shell history and process listings. Note that when piping, the command producing the key must not itself record it — good producers are `seedroller`, which writes only the master key to standard output, and password managers such as [`pass`](https://www.passwordstore.org), which decrypt straight to stdout.
- **Write down your master key and derived xprv on paper.** Both are displayed on screen so they can be transcribed — and both remain in your terminal scrollback, so clear it with `clear` when done.
- Sensitive key material is scrubbed from memory after use: the master key and the derived account private key are erased, and the printed secret key expression string is zeroed via [`zeroize`](https://crates.io/crates/zeroize).
- The crate forbids `unsafe` code (`#![forbid(unsafe_code)]`).
- Dependencies are minimal: `bitcoin`, `clap`, `zeroize`.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.

# keyderiver

Derive BIP380 descriptor key expressions from a BIP39 seed phrase. The seed words are
read via a terminal prompt, or from standard input when piped — never as a
command-line argument, so they do not appear in shell history or process listings. The
BIP32 master extended private key (xprv) and its fingerprint are derived from the seed
words, with an optional BIP39 passphrase (`-s`). The BIP44 purpose and account derivation
values may optionally be provided; if not provided the default purpose is 84 (P2WPKH) and
account is 0.

The output includes the master xprv, its fingerprint, and both the secret account key
(xprv) and the public account key (xpub) as BIP380 key expressions with the master
fingerprint as origin and the BIP389 `/<0;1>/*` multipath wildcard covering both the
receive (0) and change (1) chains. Keys carry mainnet version bytes (xprv/xpub); with
`-t` they carry testnet version bytes (tprv/tpub) and use BIP44 coin type `1'`.

See the `seedroller` tool to generate a new seed phrase — it writes only the seed words
to standard output, so it can be piped straight into this tool.

## Installation

```sh
cargo install --path .
```

This builds the release binary and installs it to `~/.cargo/bin/keyderiver`.

## Usage

```sh
keyderiver [-p <purpose>] [-a <account>] [-s] [-t]
```

You are prompted for the seed words; they are displayed as you type or paste them, so
you can visually confirm each word. Alternatively, pipe the words on standard input —
for example directly from a password manager:

```sh
pass show bitcoin/seed-words | keyderiver
```

Only the first line of standard input is read (or the first two lines with `-s` — see
below).

You can also pipe a freshly generated seed phrase directly from `seedroller` (or capture
it in a shell variable first):

```sh
seedroller | keyderiver
```

```sh
SEED=$(seedroller)
echo "$SEED" | keyderiver
unset SEED
```

### With BIP39 passphrase

```sh
keyderiver -s
```

Adds a BIP39 passphrase to the master key derivation. You are prompted for the
passphrase interactively; it is displayed as you type, and never appears on the command
line, keeping it out of shell history and process listings. When
standard input is piped, the passphrase is instead read from the **second** line of
input (the first line holds the seed words):

```sh
printf 'word1 word2 ... word24\npassphrase\n' | keyderiver -s
```

If the pipe has no second line, you are prompted for the passphrase on the terminal
rather than getting an error, so `seedroller | keyderiver -s` works.

The same seed words with different passphrases produce completely different master keys.
The passphrase is zeroized from memory after use.

### Testnet mode

```sh
keyderiver -t
```

Derives the master key with testnet version bytes, producing a **tprv** instead of an
xprv, and derives the account keys as tprv/tpub key expressions with BIP44 coin type
`1'` instead of `0'`. The seed words, key material, and fingerprint are identical to
mainnet mode — only the extended key serialization and the derivation path coin type
differ. Useful for testing wallet setups without touching real funds. Can be combined
with `-s`.

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
- **The seed words and passphrase are never taken as command-line arguments.** They are read via terminal prompts (both visible as you type, so watch for shoulder surfers and clear your terminal scrollback when done) or from standard input when piped, keeping them out of shell history and process listings. Note that when piping, the command producing the input must not itself record it — good producers are `seedroller`, which writes only the seed words to standard output, and password managers such as [`pass`](https://www.passwordstore.org), which decrypt straight to stdout.
- **Write down your master key and derived xprv on paper.** Both are displayed on screen so they can be transcribed — and both remain in your terminal scrollback, so clear it with `clear` when done (a warning to this effect is printed to standard error every run).
- Sensitive key material is scrubbed from memory after use. The seed-word input string, passphrase, BIP39 seed, and printed secret key expression are wrapped in [`Zeroizing`](https://crates.io/crates/zeroize), so they are wiped automatically on drop. The BIP39 mnemonic type already zeroizes on drop. The master and derived account extended private keys have their secret fields (private key and chain code) erased explicitly after use.
- The crate forbids `unsafe` code (`#![forbid(unsafe_code)]`).
- Dependencies are minimal: `bip39`, `bitcoin`, `clap`, `zeroize`.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.

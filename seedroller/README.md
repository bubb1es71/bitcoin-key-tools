# seedroller

Generate a BIP39 mnemonic seed phrase from physical dice rolls, hardened with operating system RNG entropy.

The seedroller tool combines the randomness of real-world dice rolls with your operating system's random number generator (RNG) to produce a standard 24-word BIP39 mnemonic seed phrase and corresponding master extended private key (xprv for mainnet, tprv for testnet with `-t`) for use in bitcoin wallets.

## How it works

1. **Collect dice rolls** — You roll a physical 6-sided die and type each result (1–6). A minimum of 100 rolls is required.
2. **Verify entropy** — The roll distribution is checked to ensure it contains enough measurable entropy (see below).
3. **Mix entropy sources** — Your dice rolls are concatenated with 32 bytes (256 bits) from the operating system RNG (`OsRng`).
4. **Hash** — The combined input is hashed with SHA-256, producing exactly 32 bytes (256 bits) of entropy.
5. **Generate seed phrase** — The 32 bytes are encoded as a standard BIP39 24-word mnemonic with checksum.
6. **Derive master key** — The mnemonic is converted to a 64-byte BIP39 seed (with optional passphrase), from which the BIP32 master extended private key (xprv, or tprv in testnet mode) and fingerprint are derived.
7. **Output the master key** — The master xprv (or tprv) is written to **standard output**; the seed phrase and all other messages go to **standard error** and appear on your terminal as usual. This lets you capture the key in a shell variable or pipe it straight into the `keyderiver` tool to derive BIP380 descriptor account keys (BIP44/BIP84 path).

```text
dice rolls (~258 bits)  ──┐
                          ├── SHA-256 ──> 256 bits ──> BIP39 (24 words) ──> BIP32 xprv/tprv ──> keyderiver (BIP380 account keys)
OS RNG (256 bits)       ──┘
```

Either entropy source alone provides at least 256 bits, so the seed remains secure even if one source is compromised.

## Entropy verification

Before generating the seed, the Shannon entropy of your dice rolls is validated:

| Check | Requirement | Why |
|---|---|---|
| **Shannon entropy** | ≥ 256 bits total | Calculated from the actual roll distribution, not just roll count. 100 uniform rolls give ~258.5 bits. Skewed distributions are rejected even if all 6 values appear. |

When you press **Enter** after 100+ rolls, the check runs. If it fails, the program tells you the current state (e.g. `Insufficient dice entropy: 255.6 bits — minimum 256 bits required.`) and lets you keep rolling until the requirement is met — a typical honest 100-roll session lands just under 256 bits, and ~10 extra rolls reliably pushes it over. The program only exits with an error if you end input early (EOF / Ctrl+D) with insufficient entropy.

Examples:

| Distribution | Total entropy | Result |
|---|---|---|
| All same value | 0 bits | Rejected |
| 2 values, even split | 100 bits | Rejected |
| 6 values, heavy skew \[50,20,10,10,5,5] | ~206 bits | Rejected |
| 6 values, mild unevenness \[18,18,17,17,15,15] | ~258 bits | Accepted |
| 6 values, uniform \[17,17,17,17,16,16] | ~258.5 bits | Accepted |

## Installation

```sh
cargo install --path .
```

This builds the release binary and installs it to `~/.cargo/bin/seedroller`.

## Usage

### Normal mode (recommended)

```sh
seedroller
```

Press keys **1–6** as you roll your die — each keypress registers immediately, no Enter needed. **Backspace** undoes the last roll. After 100 rolls, press **Enter** to finish once the entropy checks pass, or keep adding more rolls for extra entropy.

### Capture or pipe the master key

Only the master extended private key is written to standard output — everything else (prompts, the seed phrase, warnings) goes to standard error and still appears on your terminal. This lets you pipe the key directly into `keyderiver`:

```sh
seedroller | keyderiver
```

or capture it in a shell variable:

```sh
MASTER=$(seedroller)
echo "$MASTER" | keyderiver
unset MASTER
```

In both cases the master key never appears on the command line or in your shell history.

### With BIP39 passphrase

```sh
seedroller -p
```

Adds a BIP39 passphrase to the seed derivation. You are prompted for the passphrase with terminal echo disabled, so it is not displayed as you type and never appears on the command line, keeping it out of shell history and process listings. (When standard input is piped, the passphrase is instead read from the first line of input.) The same dice rolls with different passphrases produce completely different master keys. The passphrase is zeroized from memory after use.

### Testnet mode

```sh
seedroller -t
```

Derives the master key with testnet version bytes, producing a **tprv** instead of an xprv. The seed phrase, key material, and fingerprint are identical to mainnet mode — only the extended key serialization differs. Pipe the resulting tprv to `keyderiver` to derive testnet account keys (`tprv`/`tpub`). Useful for testing wallet setups without touching real funds. Can be combined with `-p`.

### Reproducible mode (testing only)

```sh
seedroller -r
```

Skips the operating system RNG. The seed is derived **only** from your dice rolls, so the same rolls always produce the same seed phrase. A bold warning is displayed when this mode is active. **Do not use this for real funds.**

### Help

```sh
seedroller -h
```

### Tests

```sh
cargo test
```

## Security notes

- **This tool only verifies the entropy of your dice rolls, not their randomness.** Randomness is critical for a strong seed value but can not be verified by this tool. You must ensure the randomness of your dice roles and the data generated by your operating system. See [entropy vs randomness](https://thisvsthat.io/entropy-vs-randomness).
- **Run in an ephemeral environment.** For improved security, only run this on a local temporary system such as [TAILS](https://tails.net) — a live operating system that runs from a USB stick, leaves no trace on shutdown, and keeps your seed phrase off your everyday machine.
- **Write down your seed phrase on paper.** It is displayed on screen (standard error) and remains in your terminal scrollback — clear it with `clear` when done.
- **Only the master key goes to standard output.** When you capture it (`MASTER=$(seedroller)`) or pipe it (`seedroller | keyderiver`), the key never appears on screen — but a captured key lives in your shell's memory: do not `export` the variable (exported variables are visible to all child processes), and `unset` it as soon as you are done. `echo` is a shell builtin, so piping it does not expose the key in process listings.
- All sensitive intermediate values (dice rolls, operating system RNG entropy, hash input, hash output, BIP39 seed bytes, passphrase, mnemonic) are zeroed from memory after use via [`zeroize`](https://crates.io/crates/zeroize).
- The crate forbids `unsafe` code (`#![forbid(unsafe_code)]`).
- Dependencies are minimal: `bip39`, `bitcoin`, `clap`, `rand`, `zeroize`.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.

# seedroller

Generate a BIP39 seed phrase from physical dice rolls, hardened with operating system RNG entropy.

The seedroller tool combines the randomness of real-world dice rolls with your operating system's random number generator (RNG) to produce a standard 24-word BIP39 mnemonic seed phrase and corresponding master xprv key for use in bitcoin wallets.

## How it works

1. **Collect dice rolls** — You roll a physical 6-sided die and type each result (1–6). A minimum of 100 rolls is required.
2. **Verify entropy** — The roll distribution is checked to ensure it contains enough measurable entropy (see below).
3. **Mix entropy sources** — Your dice rolls are length-prefixed and concatenated with 32 bytes (256 bits) from the operating system RNG (`OsRng`).
4. **Hash** — The combined input is hashed with SHA-256, producing exactly 32 bytes (256 bits) of entropy.
5. **Generate seed phrase** — The 32 bytes are encoded as a standard BIP39 24-word mnemonic with checksum.
6. **Derive master key** — The mnemonic is converted to a 64-byte BIP39 seed (with optional passphrase), from which the BIP32 master extended private key (xprv) and fingerprint are derived.

```text
dice rolls (~258 bits)  ──┐
                          ├── SHA-256 ──> 256 bits ──> BIP39 (24 words) ──> BIP32 xprv
OS RNG (256 bits)       ──┘
```

Either entropy source alone provides at least 256 bits, so the seed remains secure even if one source is compromised.

## Entropy verification

Before generating the seed, your dice rolls are validated against two checks:

| Check | Requirement | Why |
|---|---|---|
| **Distinct values** | All 6 faces must appear | With 100 rolls of a fair die, missing a face is essentially impossible (~10⁻⁸ probability). A missing face suggests fake or biased input. |
| **Shannon entropy** | ≥ 256 bits total | Calculated from the actual roll distribution, not just roll count. 100 uniform rolls give ~258.5 bits. Skewed distributions are rejected even if all 6 values appear. |

When you press **Enter** after 100+ rolls, both checks run. If either fails, the program tells you the current state (e.g. `255.6/256 bits of entropy — keep rolling`) and lets you keep rolling until the requirements are met — a typical honest 100-roll session lands just under 256 bits, and ~10 extra rolls reliably pushes it over. The program only exits with an error if you end input early (EOF / Ctrl+D) with insufficient entropy.

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

### With BIP39 passphrase

```sh
seedroller -p "my secret passphrase"
```

Adds a BIP39 passphrase to the seed derivation. The same dice rolls with different passphrases produce completely different master keys. The passphrase is zeroized from memory after use.

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

- **Run in an ephemeral environment.** For improved security, only run this on a local temporary system such as [TAILS](https://tails.net) — a live operating system that runs from a USB stick, leaves no trace on shutdown, and keeps your seed phrase off your everyday machine.
- **Write down your seed phrase on paper.** It is displayed on screen and remains in your terminal scrollback — clear it with `clear` when done.
- All sensitive intermediate values (dice rolls, operating system RNG entropy, hash input, hash output, BIP39 seed bytes, passphrase, mnemonic) are zeroed from memory after use via [`zeroize`](https://crates.io/crates/zeroize).
- The crate forbids `unsafe` code (`#![forbid(unsafe_code)]`).
- Dependencies are minimal: `bip39`, `bitcoin`, `bitcoin_hashes`, `rand`, `zeroize`.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.

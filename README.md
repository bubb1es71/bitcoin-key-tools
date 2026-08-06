# seedroller

Generate a BIP39 seed phrase from physical dice rolls, hardened with operating system RNG entropy.

seedroller combines the randomness of real-world dice rolls with your operating system's random number generator (RNG) to produce a standard 24-word BIP39 mnemonic seed phrase for Bitcoin and other wallets.

## How it works

1. **Collect dice rolls** — You roll a physical 6-sided die and type each result (1–6). A minimum of 100 rolls is required.
2. **Verify entropy** — The roll distribution is checked to ensure it contains enough genuine randomness (see below).
3. **Mix entropy sources** — Your dice rolls are concatenated with 32 bytes (256 bits) from the operating system RNG (`OsRng`).
4. **Hash** — The combined input is hashed with SHA-256, producing exactly 32 bytes (256 bits) of entropy.
5. **Generate seed phrase** — The 32 bytes are encoded as a standard BIP39 24-word mnemonic with checksum.

```
dice rolls (~258 bits)  ──┐
                          ├── SHA-256 ──> 256 bits ──> BIP39 (24 words)
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
| 6 values, heavy skew [50,20,10,10,5,5] | ~206 bits | Rejected |
| 6 values, mild unevenness [18,18,17,17,15,15] | ~258 bits | Accepted |
| 6 values, uniform [17,17,17,17,16,16] | ~258.5 bits | Accepted |

## Usage

### Build

```sh
cargo build --release
```

### Normal mode (recommended)

```sh
./target/release/seedroller
```

Press keys **1–6** as you roll your die — each keypress registers immediately, no Enter needed. **Backspace** undoes the last roll. After 100 rolls, press **Enter** to finish once the entropy checks pass, or keep adding more rolls for extra entropy.

### Reproducible mode (testing only)

```sh
./target/release/seedroller -r
```

Skips the operating system RNG. The seed is derived **only** from your dice rolls, so the same rolls always produce the same seed phrase. A bold warning is displayed when this mode is active. **Do not use this for real funds.**

### Tests

```sh
cargo test
```

## Security notes

- **Run in an ephemeral environment.** For improved security, only run this on a local temporary system such as [TAILS](https://tails.net) — a live operating system that runs from a USB stick, leaves no trace on shutdown, and keeps your seed phrase off your everyday machine.
- **Write down your seed phrase on paper.** It is displayed on screen and remains in your terminal scrollback — clear it with `Cmd+K` (macOS) or `clear` when done.
- All sensitive intermediate values (dice rolls, operating system RNG entropy, hash input, hash output) are zeroed from memory after use via [`zeroize`](https://crates.io/crates/zeroize).
- The crate forbids `unsafe` code (`#![forbid(unsafe_code)]`).
- Dependencies are minimal: `bip39`, `bitcoin_hashes`, `rand`, `zeroize`.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.

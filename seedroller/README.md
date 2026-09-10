# seedroller

Generate a BIP39 mnemonic seed phrase from physical dice rolls, hardened with operating system RNG entropy.

The seedroller tool combines the randomness of real-world dice rolls with your operating system's random number generator (RNG) to produce a standard 24-word BIP39 mnemonic seed phrase for use in bitcoin wallets.

## How it works

1. **Collect dice rolls** — You roll a physical 6-sided die and type each result (1–6). A minimum of 100 rolls is required.
2. **Verify entropy** — The roll distribution is checked to ensure it contains enough measurable entropy (see below).
3. **Mix entropy sources** — Your dice rolls are concatenated with 32 bytes (256 bits) from the operating system RNG (`getrandom`).
4. **Hash** — The combined input is hashed with SHA-256, producing exactly 32 bytes (256 bits) of entropy.
5. **Generate seed phrase** — The 32 bytes are encoded as a standard BIP39 24-word mnemonic with checksum.
6. **Output the seed phrase** — The 24 seed words, space separated, are written to **standard output**; the numbered word list and all other messages go to **standard error** and appear on your terminal as usual. This lets you capture the phrase in a shell variable or pipe it straight into the `keyderiver` tool to derive the master extended private key (xprv) and BIP380 descriptor account keys (BIP44/BIP84 path).

```text
dice rolls (~258 bits)  ──┐
                          ├── SHA-256 ──> 256 bits ──> BIP39 (24 words) ──> keyderiver (master xprv + BIP380 account keys)
OS RNG (256 bits)       ──┘
```

Either entropy source alone provides at least 256 bits, so the seed remains secure even if one source is compromised.

## Entropy verification

Before generating the seed, your dice rolls must pass four checks:

| Check | Requirement | Why |
|---|---|---|
| **Pattern screen** | The session must not be one short pattern (period ≤ 6) repeated | `123456123456…` has a perfectly uniform distribution — and zero randomness. A distribution-only check cannot see it. |
| **Face-frequency bound** | No face may appear in more than 25% of all rolls | A loaded die cannot be made safe by rolling longer: without this bound a die landing on one face 80% of the time would pass the entropy check at ~216 rolls with only ~70 bits of real entropy. With the bound, the worst accepted session still has ~200 bits. |
| **Run screen** | No more than 8 identical rolls in a row | A fair die does this in only ~0.005% of 100-roll sessions; longer runs mean the die is not actually being rolled for every value. |
| **Shannon entropy** | ≥ 256 bits total | Calculated from the actual roll distribution, not just roll count. 100 uniform rolls give ~258.5 bits. Mildly uneven distributions are still rejected. |

When you press **Enter** after 100+ rolls, all checks run. If the Shannon check fails, just keep rolling — a typical honest 100-roll session lands just under 256 bits, and ~10 extra rolls reliably pushes it over. The structure checks are different: a repeated pattern is only diluted once you start actually rolling every value; a long run cannot be undone, so start over; and a skewed distribution that persists means the die is biased — switch dice, because rolling a loaded die for longer does not help. The program only exits with an error if you end input early (EOF / Ctrl+D).

Examples:

| Distribution | Measured entropy | Result |
|---|---|---|
| `123456…` repeated (perfectly uniform counts) | ~258.5 bits | Rejected — pattern screen |
| All same value | 0 bits | Rejected — pattern screen |
| One face 26% of 110 rolls \[29,17,17,17,15,15] | ~279 bits | Rejected — face-frequency bound |
| 2 values, even split | 100 bits | Rejected — face-frequency bound |
| 6 values, heavy skew \[50,20,10,10,5,5] | ~206 bits | Rejected — face-frequency bound |
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

Press keys **1–6** as you roll your die — each keypress registers immediately, no Enter needed. After 100 rolls, press **Enter** to finish once the entropy checks pass, or keep adding more rolls for extra entropy.

### Capture or pipe the seed phrase

Only the seed words are written to standard output — everything else (prompts, the numbered word list, warnings) goes to standard error and still appears on your terminal. This lets you pipe the phrase directly into `keyderiver`:

```sh
seedroller | keyderiver
```

or capture it in a shell variable:

```sh
SEED=$(seedroller)
echo "$SEED" | keyderiver
unset SEED
```

In both cases the seed phrase never appears on the command line or in your shell history.

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
- **Startup sanity check.** Before any key material is handled, the tool verifies the operating system RNG and monotonic clock actually work — every byte position of a 32-byte RNG draw must come back nonzero within 1024 draws, and the clock must advance across a short sleep (modeled on Bitcoin Core's `Random_SanityCheck()`). The tool refuses to run on a system whose RNG appears broken.
- **Write down your seed phrase on paper.** It is displayed on screen as a numbered list (standard error) and remains in your terminal scrollback — clear it with `clear` when done.
- **Only the seed words go to standard output.** When you capture them (`SEED=$(seedroller)`) or pipe them (`seedroller | keyderiver`), the phrase never appears on screen — but a captured phrase lives in your shell's memory: do not `export` the variable (exported variables are visible to all child processes), and `unset` it as soon as you are done. `echo` is a shell builtin, so piping it does not expose the phrase in process listings.
- Sensitive intermediate values are wiped with [`zeroize`](https://crates.io/crates/zeroize). The main owned secrets (`rolls`, `entropy`, and `phrase`) are wrapped in `Zeroizing`, so they are zeroized automatically when they go out of scope. The BIP39 mnemonic type already zeroizes on drop.
- The crate forbids `unsafe` code (`#![forbid(unsafe_code)]`).
- Dependencies are minimal: `bip39`, `bitcoin`, `clap`, `getrandom`, `zeroize`.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.

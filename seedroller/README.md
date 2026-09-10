# seedroller

Generate a BIP39 mnemonic seed phrase from physical dice rolls, hardened with operating system RNG entropy.

The seedroller tool combines the randomness of real-world dice rolls with your operating system's random number generator (RNG) to produce a standard 24-word BIP39 mnemonic seed phrase for use in bitcoin wallets.

## How it works

1. **Collect dice rolls** — You roll a physical 6-sided die and type each result (1–6). A minimum of 100 rolls is required.
2. **Verify entropy** — The rolls are screened for repeated patterns, long runs, and bias, and the distribution is checked for sufficient measurable entropy (see below).
3. **Mix entropy sources** — Your dice rolls are concatenated with 32 bytes (256 bits) from the operating system RNG (`getrandom`).
4. **Hash** — The combined input is hashed with SHA-256, producing exactly 32 bytes (256 bits) of entropy.
5. **Generate seed phrase** — The 32 bytes are encoded as a standard BIP39 24-word mnemonic with checksum.
6. **Output the seed phrase** — The 24 seed words, space separated, are written to **standard output**; the numbered word list and all other messages go to **standard error** and appear on your terminal as usual. This lets you capture the phrase in a shell variable or pipe it straight into the `keyderiver` tool to derive the master extended private key (xprv) and BIP380 descriptor account keys (BIP44/BIP84 path).

```text
dice rolls (~258 bits)  ──┐
                          ├── SHA-256 ──> 256 bits ──> BIP39 (24 words) ──> keyderiver (master xprv + BIP380 account keys)
OS RNG (256 bits)       ──┘
```

The seed stays secure if **either** source is truly random — an attacker must compromise both. Note what is actually verified: the dice checks validate the *distribution and structure* of your rolls (they cannot verify that you actually rolled fairly), and the OS RNG is trusted but can only be checked for catastrophic failure (see Security notes).

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

Skips the operating system RNG. The seed is derived **only** from your dice rolls, so the same rolls always produce the same seed phrase. A bold warning is displayed and you must type a confirmation on the terminal before the mode starts. **Do not use this for real funds.**

Extra risks in this mode:

- Your dice rolls are echoed as you type and remain in terminal scrollback — and with no OS RNG mixed in, the rolls alone determine the seed. Clear the scrollback afterwards (see Security notes) even when just testing.
- Never use example or documented roll sequences: the test-suite vector (`123456` repeated) produces a publicly known seed phrase that anyone can look up in this repository.

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
- **Run in an ephemeral environment — this tool is designed for [TAILS](https://tails.net).** Secrets are wiped from process memory on normal exit, but on a normal OS residual exposure remains: a process killed by a signal (Ctrl+C, closing the terminal) skips the memory wipes, and with no core-dump or swap protection compiled in, a core dump or a swapped-out page could contain key material. TAILS avoids this whole class of risk — it is a live, amnesic operating system that runs from a USB stick, uses no swap, and wipes RAM on shutdown, so nothing, including your seed phrase, persists past the session. Use TAILS (or a similar amnesic live OS) whenever you generate seeds for real funds.
- **Startup sanity check.** Before any key material is handled, the tool verifies the operating system RNG and monotonic clock actually work — every byte position of a 32-byte RNG draw must come back nonzero within 1024 draws, and the clock must advance across a short sleep (modeled on Bitcoin Core's `Random_SanityCheck()`). The tool refuses to run when the RNG appears catastrophically broken. This detects only degenerate failure (such as constant output) — it cannot measure RNG quality, so a low-entropy or secretly deterministic RNG would still pass. You must ultimately trust your operating system's RNG.
- **Write down your seed phrase on paper.** It is displayed on screen (as a numbered list on standard error — plus the bare phrase on standard output when you are not piping) and remains in your terminal scrollback, which `clear` alone does not remove on most terminals. When done, close the window/tab, or run `printf '\033[3J'; clear` (works on GNOME Terminal/VTE, xterm, and most Linux terminals; on macOS Terminal/iTerm2 use Cmd+K). Inside tmux, also run `tmux clear-history`.
- **Only the seed words go to standard output.** When you capture them (`SEED=$(seedroller)`) or pipe them (`seedroller | keyderiver`), the phrase stays off the command line and out of shell history and process listings (`echo` is a shell builtin, so piping it is safe too). Capturing or piping does **not** keep the phrase off your screen: the numbered word list is always printed to standard error, which is your terminal, so the phrase remains in your terminal scrollback in every workflow — clearing it afterwards is always required. A captured phrase also lives in your shell's memory: do not `export` the variable (exported variables are visible to all child processes), and `unset` it as soon as you are done.
- **Never redirect output to a file.** `seedroller > seed.txt` (or `2> words.txt`) writes your unencrypted seed to disk. Capture the phrase in a shell variable or pipe it to `keyderiver` — never to a file.
- Sensitive intermediate values are wiped with [`zeroize`](https://crates.io/crates/zeroize). The main owned secrets (`rolls`, `entropy`, and `phrase`) are wrapped in `Zeroizing`, so they are zeroized automatically when they go out of scope. The BIP39 mnemonic type already zeroizes on drop.
- The crate forbids `unsafe` code (`#![forbid(unsafe_code)]`).
- Dependencies are minimal: `bip39`, `bitcoin`, `clap`, `getrandom`, `zeroize`.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.

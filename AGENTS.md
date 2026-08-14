# AGENTS.md

Guidance for LLM agents working on this repository.

## Project overview

This repository is a Cargo workspace containing two security-sensitive
cryptographic CLI tools for Bitcoin key management:

- **`seedroller`** — generates a BIP39 mnemonic seed phrase (24 words) from
  physical dice rolls, hardened with operating system RNG entropy. Only the
  seed words are written to stdout (everything else goes to stderr), so the
  phrase can be piped straight into `keyderiver`.
- **`keyderiver`** — takes a BIP39 seed phrase (from a terminal prompt or
  stdin), derives the BIP32 master extended private key (xprv, or tprv with
  `-t`/`--testnet`) and its fingerprint, and derives BIP380 descriptor key
  expressions (`[origin/purpose'/coin'/account']<key>/<0;1>/*`) at a
  configurable BIP44 purpose and account index. An optional BIP39 passphrase
  is prompted for with `-s`/`--secret`.

Correctness and secrecy of key material are the top priorities.

## Repository layout

```text
Cargo.toml                — workspace manifest (members: seedroller, keyderiver)
.cargo/config.toml        — forces getrandom's fail-closed linux_getrandom backend
                            on all Linux targets (no /dev/urandom fallback);
                            keep in sync with the RUSTFLAGS in justfile release-linux
seedroller/
  Cargo.toml              — seedroller package manifest
  README.md               — user docs; included as crate-level docs via #![doc = ...]
  src/main.rs             — entire application, including tests (~650 lines)
keyderiver/
  Cargo.toml              — keyderiver package manifest
  README.md               — user docs; included as crate-level docs via #![doc = ...]
  src/main.rs             — entire application, including tests (~460 lines)
.github/workflows/        — CI: cargo test on PRs, nightly cargo audit
```

Each crate deliberately has only one source file. Do not split either into
modules unless the change clearly demands it.

## Build, test, and run

```sh
cargo build            # debug build
cargo test             # run the unit test suite (must pass before committing)
cargo test --locked    # what CI runs
cargo run -- -h        # show usage
cargo install --path . # install to ~/.cargo/bin
```

The test suite lives in `mod tests` at the bottom of `src/main.rs` and
includes BIP39 known-answer vectors — keep those passing. Add tests for any
new logic, following the existing naming style (`snake_case` descriptions of
the behavior being tested).

## Hard rules (do not violate)

1. **`#![forbid(unsafe_code)]`** is set at the crate root. Never write
   `unsafe` code or remove this attribute.
2. **Keep dependencies minimal.** Current deps: `bip39`, `clap`, `bitcoin`,
   `getrandom`, `zeroize` (seedroller); `bip39`, `bitcoin`, `clap`, `zeroize`
   (keyderiver) — see each crate's `Cargo.toml`. Do not add a new dependency
   without a strong justification; prefer the standard library or existing
   crates.
3. **Zeroize all sensitive material.** Any byte buffer, string, or struct
   holding dice rolls, entropy, seed bytes, passphrases, mnemonics, or keys
   must be wiped with `zeroize` after use, matching the existing pattern in
   `main()` and `generate_entropy()`.
4. **Never weaken the entropy checks** (`MIN_DICE_ROLLS`, `MIN_ENTROPY_BITS`,
   `check_entropy_strength`) or the default behavior of
   mixing OS RNG entropy. The `-r` reproducible mode exists only for testing
   and must keep its bold warning. Do not remove the
   `getrandom_backend="linux_getrandom"` cfg (`.cargo/config.toml` and the
   justfile `release-linux` RUSTFLAGS) — it keeps OS entropy fail-closed on
   the getrandom(2) syscall with no `/dev/urandom` fallback.
5. **Doc comments** (`///`) are required on all functions, methods, and
   constants — this is an established convention in the codebase.

## Coding style

- Standard Rust style (`rustfmt` defaults); edition 2024.
- Simple, direct code — this is a small audit-friendly tool, not a framework.
- Exit codes: `0` for help/success, `1` for errors; errors go to stderr.
- Error handling is `Result`-based everywhere (required style): `main`
  returns `Result<(), String>` in both crates — the `Termination` impl
  prints the error to stderr and exits with status 1 on `Err`. Fallible
  helpers return `Result<_, String>` and errors are propagated with `?`:
  plain `?` when the error is already a `String`,
  `.map_err(|e| format!("context: {e}"))?` when converting from another
  error type. Never use `if let Err(e) = ... { return Err(...) }` blocks,
  and never call `unwrap`/`expect`/`panic!` outside of tests.
- Keep error messages single-line: the `Termination` impl prints them via
  `Debug` formatting (`Error: "{msg}"`), which escapes embedded newlines
  and wraps the message in quotes.
- Never call `std::process::exit` — it terminates the process without running
  destructors, so `Zeroizing` values would not be wiped. Returning `Result`
  from `main` drops and wipes secrets on every exit path. If a `?` could
  early-return past a required secret cleanup (such as the `Xpriv` wipes),
  bind the `Result` to a variable first, wipe, then apply `?` — see
  keyderiver's `main`.
- For seedroller, prefer `zeroize::Zeroizing` for the main owned secrets
  (`rolls`, `entropy`, and `phrase`) so they are wiped automatically on drop.
  Leave `bip39::Mnemonic` as-is because it already zeroizes on drop.
- For keyderiver, prefer `zeroize::Zeroizing` for owned secret strings and
  buffers (for example the seed-word input, passphrase, BIP39 seed, and
  derived secret key expression) so they are wiped automatically on drop.
  Leave `bip39::Mnemonic` as-is because it already zeroizes on drop, and keep
  explicit cleanup for `Xpriv` after use: both the master and the derived
  account key get `private_key.non_secure_erase()` plus a `chain_code`
  zeroize via its `AsMut<[u8; 32]>` impl.
- If you change user-facing behavior or flags, update the relevant crate's
  `README.md` (it is the crate documentation, so stale docs break the docs
  contract).

## Commit guidelines (mandatory for agents)

Any agent that makes a git commit in this repository **must** follow these
rules:

1. **Use [Conventional Commits](https://www.conventionalcommits.org/)** style
   for commit messages:

   ```text
   <type>(<optional scope>): <short imperative summary>
   ```

   Common types, matching existing history: `feat`, `fix`, `docs`, `build`,
   `ci`, `refactor`, `test`, `chore`. Examples from this repo:

   - `feat: add -t flag for testnet tprv master key derivation`
   - `fix: zeroize sensitive intermediates and add length prefix to hash input`
   - `ci: fix warnings in test and audit workflows, add badges to README`

2. **Always add a `Co-Authored-by` trailer** identifying the agent, using the
   agent's model name and email address:

   ```text
   Co-Authored-by: <Agent Model Name> <<agent-model-email>>
   ```

   For example:

   ```text
   feat: add checksum validation for roll input

   Co-Authored-by: kimi-k3 <noreply@moonshot.ai>
   ```

3. Only commit when explicitly asked. Before committing, run `cargo test` and
   inspect `git status` / `git diff` so only intended files are staged.

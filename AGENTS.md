# AGENTS.md

Guidance for LLM agents working on this repository.

## Project overview

`seedroller` is a single-binary Rust CLI that generates a BIP39 mnemonic seed
phrase (24 words) from physical dice rolls, hardened with operating system RNG
entropy, and derives the BIP32 master extended private key (xprv/tprv). This is
**security-sensitive cryptographic software** — correctness and secrecy of key
material are the top priorities.

## Repository layout

```text
src/main.rs           — the entire application, including tests (~800 lines)
Cargo.toml            — package manifest; intentionally minimal dependencies
.github/workflows/    — CI: cargo test on PRs, nightly cargo audit
README.md             — user docs; also included as crate-level docs via #![doc = ...]
```

There is deliberately only one source file. Do not split it into modules
unless the change clearly demands it.

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
2. **Keep dependencies minimal.** Current deps: `bip39`, `bitcoin`, `rand`,
   `zeroize` (see `Cargo.toml`). Do not add a new dependency without a strong
   justification; prefer the standard library or existing crates.
3. **Zeroize all sensitive material.** Any byte buffer, string, or struct
   holding dice rolls, entropy, seed bytes, passphrases, mnemonics, or keys
   must be wiped with `zeroize` after use, matching the existing pattern in
   `main()` and `generate_entropy()`.
4. **Never weaken the entropy checks** (`MIN_DICE_ROLLS`, `MIN_ENTROPY_BITS`,
   `MIN_DISTINCT_VALUES`, `check_entropy_strength`) or the default behavior of
   mixing OS RNG entropy. The `-r` reproducible mode exists only for testing
   and must keep its bold warning.
5. **Doc comments** (`///`) are required on all functions, methods, and
   constants — this is an established convention in the codebase.

## Coding style

- Standard Rust style (`rustfmt` defaults); edition 2024.
- Simple, direct code — this is a small audit-friendly tool, not a framework.
- Exit codes: `0` for help/success, `1` for errors; errors go to stderr.
- If you change user-facing behavior or flags, update `README.md` (it is the
  crate documentation, so stale docs break the docs contract).

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

   Co-Authored-by: ExampleModel 9000 <examplemodel9000@agents.example.com>
   ```

3. Only commit when explicitly asked. Before committing, run `cargo test` and
   inspect `git status` / `git diff` so only intended files are staged.

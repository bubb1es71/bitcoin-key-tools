// SPDX-License-Identifier: MIT OR Apache-2.0

#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

use bitcoin::hashes::{Hash, sha256};
use clap::Parser;
use rand::TryRngCore;
use rand::rngs::OsRng;
use std::io::{self, Read, Write};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// Minimum dice rolls before the user may finish. 100 fair rolls yield ~258.5 bits
/// of Shannon entropy, just above the 256-bit threshold.
const MIN_DICE_ROLLS: usize = 100;

/// Bytes read from the OS CSPRNG (via `getrandom` under the hood). 32 bytes = 256 bits.
const SYSTEM_ENTROPY_BYTES: usize = 32;

/// Minimum Shannon entropy required across all dice rolls, in bits.
/// Set to 256 so the dice alone can produce a strong seed even without OS entropy.
const MIN_ENTROPY_BITS: f64 = 256.0;

/// Maximum number of OS RNG draws the startup sanity check makes while trying
/// to observe a nonzero byte in every output position before giving up.
const SANITY_CHECK_MAX_TRIES: usize = 1024;

/// Create a BIP39 seed mnemonic from dice rolls and operating system RNG
/// entropy
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Reproducible mode (dice only, no OS RNG — not for real funds)
    #[arg(short, long, default_value_t = false)]
    reproducible: bool,
}

fn main() -> Result<(), String> {
    let args = Args::parse();

    // Refuse to run on a platform with a broken RNG or clock, before any key
    // material is handled (mirrors Bitcoin Core's Random_SanityCheck()).
    check_rng_sanity()?;

    eprintln!("Press keys 1-6 for each dice roll.");
    eprintln!(
        "After {} rolls, press Enter to finish (or keep adding rolls).",
        MIN_DICE_ROLLS
    );
    eprintln!();

    let rolls = collect_dice_rolls()?;
    eprintln!("\nCollected {} dice rolls.", rolls.len());

    check_entropy_strength(&rolls[..])?;

    let entropy = generate_entropy(&rolls[..], args.reproducible)?;

    // Mnemonic implements ZeroizeOnDrop
    let mnemonic = bip39::Mnemonic::from_entropy(&*entropy).map_err(|e| e.to_string())?;

    eprintln!("\nYour BIP39 seed phrase (24 words):\n");
    eprintln!("WARNING: This seed phrase will remain in your terminal scrollback.");
    eprintln!("Write it down, then clear your terminal (Cmd+K) when done.\n");
    for (i, word) in mnemonic.words().enumerate() {
        eprintln!("  {:>2}. {}", i + 1, word);
    }
    eprintln!();
    let phrase = Zeroizing::new(mnemonic.to_string());
    // send the seed words to standard output so they can be piped to keyderiver
    println!("{}", *phrase);
    Ok(())
}

/// Mix dice rolls with OS RNG entropy (unless reproducible mode) into a 32-byte hash.
/// Zeroizes all intermediates before returning.
fn generate_entropy(
    rolls: &[u8],
    reproducible: bool,
) -> Result<Zeroizing<[u8; SYSTEM_ENTROPY_BYTES]>, String> {
    let system_entropy = if reproducible {
        eprintln!(
            "\x1b[1mWARNING: -r flag set, operating system RNG entropy was NOT added.\x1b[0m"
        );
        eprintln!("\x1b[1mThis seed is derived ONLY from your dice rolls.\x1b[0m");
        Zeroizing::new(Vec::new())
    } else {
        let raw = read_system_entropy()?;
        eprintln!("Read {} bytes from operating system RNG.", raw.len());
        raw
    };

    Ok(combine_and_hash(rolls, &system_entropy))
}

/// Restores terminal settings on drop.
struct TermGuard {
    saved: Option<String>,
}

impl TermGuard {
    /// Save current terminal settings and switch to cbreak mode for
    /// unbuffered keypress input. Original settings are restored on drop.
    fn new() -> Self {
        let saved = Self::run_stty(&["-g"]);
        if saved.is_some() {
            Self::run_stty(&["cbreak"]);
        }
        Self { saved }
    }

    /// Run `stty` with the given arguments on `/dev/tty`, returning trimmed
    /// stdout on success. Returns `None` if the tty cannot be opened or the
    /// command fails.
    fn run_stty(args: &[&str]) -> Option<String> {
        let tty = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .ok()?;
        let output = std::process::Command::new("stty")
            .args(args)
            .stdin(std::process::Stdio::from(tty))
            .output()
            .ok()?;
        let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if s.is_empty() { None } else { Some(s) }
    }
}

impl Drop for TermGuard {
    fn drop(&mut self) {
        if let Some(ref s) = self.saved {
            Self::run_stty(&[s]);
        }
    }
}

/// Interactively collect dice rolls from the user via raw keypress input.
///
/// Reads single bytes from stdin in cbreak mode. Keys 1–6 append a roll,
/// Enter finishes once the minimum roll count is met and entropy checks
/// pass. Returns the collected rolls as a vector of values 1–6, or an
/// error if writing the prompt to stdout fails.
fn collect_dice_rolls() -> Result<Zeroizing<Vec<u8>>, String> {
    let _guard = TermGuard::new();
    let stdin = io::stdin();
    let mut lock = stdin.lock();
    let mut rolls: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
    let mut byte = [0u8; 1];

    loop {
        // Print prompt for the next roll
        let n = rolls.len() + 1;
        if n <= MIN_DICE_ROLLS {
            eprint!("[{}/{}]: ", n, MIN_DICE_ROLLS);
        } else {
            eprint!("[{}/{} enter to end]: ", n, MIN_DICE_ROLLS);
        }
        io::stdout()
            .flush()
            .map_err(|e| format!("failed to flush stdout: {e}"))?;

        // Read one key
        if lock.read_exact(&mut byte).is_err() {
            break;
        }

        match byte[0] {
            b'1'..=b'6' => {
                rolls.push(byte[0] - b'0');
                eprintln!();
            }
            b'\n' | b'\r' => {
                if rolls.len() >= MIN_DICE_ROLLS {
                    match check_entropy_strength(&rolls) {
                        Ok(()) => break,
                        Err(msg) => {
                            eprintln!("{}", msg);
                            continue;
                        }
                    }
                }
            }
            _ => {
                eprintln!(" (use keys 1-6)");
            }
        }
    }

    Ok(rolls)
}

/// Count occurrences of each dice value (1-6).
fn count_values(rolls: &[u8]) -> [usize; 6] {
    let mut counts = [0usize; 6];
    for &r in rolls {
        if (1..=6).contains(&r) {
            counts[(r - 1) as usize] += 1;
        }
    }
    counts
}

/// Shannon entropy of the roll distribution, in bits.
fn shannon_entropy_bits(rolls: &[u8]) -> f64 {
    if rolls.is_empty() {
        return 0.0;
    }
    let counts = count_values(rolls);
    let total = rolls.len() as f64;
    let per_roll: f64 = counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / total;
            -p * p.log2()
        })
        .sum();
    per_roll * total
}

/// Validate that dice rolls contain sufficient entropy.
/// Uses Shannon entropy to measure the actual information content
/// of the roll distribution.
fn check_entropy_strength(rolls: &[u8]) -> Result<(), String> {
    if rolls.is_empty() {
        return Err("No dice rolls provided".to_string());
    }

    for &r in rolls {
        if !(1..=6).contains(&r) {
            return Err(format!("Invalid dice value: {}", r));
        }
    }

    let total_entropy = shannon_entropy_bits(rolls);
    if total_entropy < MIN_ENTROPY_BITS {
        return Err(format!(
            "Insufficient dice entropy: {:.1} bits — minimum {:.0} bits required. \
             Distribution of 1-6: {:?}",
            total_entropy,
            MIN_ENTROPY_BITS,
            count_values(rolls)
        ));
    }

    Ok(())
}

/// Fill a 32-byte buffer from the operating system's cryptographic RNG.
///
/// Uses `OsRng` which delegates to `getrandom` — the platform-native secure
/// RNG (getrandom syscall on Linux, getentropy on macOS, BCryptGenRandom on
/// Windows). Returns an error if the OS RNG is unavailable.
fn read_system_entropy() -> Result<Zeroizing<Vec<u8>>, String> {
    let mut buf = Zeroizing::new([0u8; SYSTEM_ENTROPY_BYTES]);
    OsRng
        .try_fill_bytes(&mut *buf)
        .map_err(|e| format!("failed to read from operating system RNG: {e}"))?;
    Ok(Zeroizing::new(buf.to_vec()))
}

/// Runtime sanity check of the operating system RNG and monotonic clock,
/// modeled on Bitcoin Core's `Random_SanityCheck()`. See:
/// https://github.com/bitcoin/bitcoin/pull/9821
///
/// This does not measure the quality of the randomness; it detects a
/// catastrophically broken platform (e.g. an RNG that returns constant bytes)
/// at startup, before any key material is derived:
///
/// - Every byte position of a 32-byte OS RNG draw must be observed nonzero at
///   least once within [`SANITY_CHECK_MAX_TRIES`] draws. A healthy CSPRNG
///   passes within one or two draws with overwhelming probability.
/// - The monotonic clock must advance across a 1ms sleep.
///
/// Returns an error describing the failure; the caller should refuse to run.
fn check_rng_sanity() -> Result<(), String> {
    let mut nonzero_seen = [false; SYSTEM_ENTROPY_BYTES];
    for _ in 0..SANITY_CHECK_MAX_TRIES {
        let draw = read_system_entropy()?;
        for (i, &b) in draw.iter().enumerate() {
            nonzero_seen[i] |= b != 0;
        }
        if nonzero_seen.iter().all(|&b| b) {
            break;
        }
    }
    if !nonzero_seen.iter().all(|&b| b) {
        return Err(format!(
            "OS RNG sanity check failed: some byte positions were zero in all {} draws. \
             Do not generate keys on this system.",
            SANITY_CHECK_MAX_TRIES
        ));
    }

    let start = Instant::now();
    std::thread::sleep(Duration::from_millis(1));
    if Instant::now() == start {
        return Err("Clock sanity check failed: monotonic clock did not advance.".to_string());
    }

    Ok(())
}

/// Combine dice rolls with OS entropy into a 32-byte SHA-256 hash.
///
/// The input is `rolls || system_entropy`, hashed with SHA-256.
/// The intermediate buffer is zeroized before returning.
fn combine_and_hash(rolls: &[u8], system_entropy: &[u8]) -> Zeroizing<[u8; SYSTEM_ENTROPY_BYTES]> {
    let mut data = Zeroizing::new(Vec::with_capacity(rolls.len() + system_entropy.len()));
    data.extend_from_slice(rolls);
    data.extend_from_slice(system_entropy);

    let hash = sha256::Hash::hash(&data);
    Zeroizing::new(hash.to_byte_array())
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroize;

    // -- combine_and_hash --

    #[test]
    fn hash_output_is_32_bytes() {
        let rolls = vec![1, 2, 3, 4, 5, 6];
        let sys = [0xAB; SYSTEM_ENTROPY_BYTES];
        let result = combine_and_hash(&rolls, &sys);
        assert_eq!(result.len(), SYSTEM_ENTROPY_BYTES);
    }

    #[test]
    fn hash_deterministic_same_inputs() {
        let rolls = vec![1, 2, 3, 4, 5, 6];
        let sys = [0xAB; SYSTEM_ENTROPY_BYTES];
        let a = combine_and_hash(&rolls, &sys);
        let b = combine_and_hash(&rolls, &sys);
        assert_eq!(a, b);
    }

    #[test]
    fn hash_different_rolls_different_output() {
        let sys = [0xAB; SYSTEM_ENTROPY_BYTES];
        let a = combine_and_hash(&[1, 2, 3], &sys);
        let b = combine_and_hash(&[4, 5, 6], &sys);
        assert_ne!(a, b);
    }

    #[test]
    fn hash_different_system_entropy_different_output() {
        let rolls = vec![1, 2, 3];
        let a = combine_and_hash(&rolls, &[0xAA; SYSTEM_ENTROPY_BYTES]);
        let b = combine_and_hash(&rolls, &[0xBB; SYSTEM_ENTROPY_BYTES]);
        assert_ne!(a, b);
    }

    #[test]
    fn hash_empty_rolls_valid() {
        let sys = [0xAB; SYSTEM_ENTROPY_BYTES];
        let result = combine_and_hash(&[], &sys);
        assert_eq!(result.len(), SYSTEM_ENTROPY_BYTES);
    }

    #[test]
    fn hash_empty_system_entropy_valid() {
        // This is the -r (reproducible) mode path
        let rolls = vec![1, 2, 3, 4, 5, 6];
        let result = combine_and_hash(&rolls, &[]);
        assert_eq!(result.len(), SYSTEM_ENTROPY_BYTES);
    }

    #[test]
    fn hash_single_roll_difference_changes_output() {
        let sys = [0xAB; SYSTEM_ENTROPY_BYTES];
        let a = combine_and_hash(&[1, 2, 3], &sys);
        let b = combine_and_hash(&[1, 2, 4], &sys);
        assert_ne!(a, b);
    }

    #[test]
    fn hash_roll_order_matters() {
        let sys = [0xAB; SYSTEM_ENTROPY_BYTES];
        let a = combine_and_hash(&[1, 2], &sys);
        let b = combine_and_hash(&[2, 1], &sys);
        assert_ne!(a, b);
    }

    #[test]
    fn hash_rolls_only_differs_from_rolls_plus_entropy() {
        let rolls = vec![1, 2, 3, 4, 5, 6];
        let sys = [0xAB; SYSTEM_ENTROPY_BYTES];
        let without_sys = combine_and_hash(&rolls, &[]);
        let with_sys = combine_and_hash(&rolls, &sys);
        assert_ne!(without_sys, with_sys);
    }

    // -- read_system_entropy --

    #[test]
    fn system_entropy_returns_32_bytes() {
        let entropy = read_system_entropy().unwrap();
        assert_eq!(entropy.len(), SYSTEM_ENTROPY_BYTES);
    }

    #[test]
    fn system_entropy_not_all_zeros() {
        let entropy = read_system_entropy().unwrap();
        assert!(entropy.iter().any(|&b| b != 0));
    }

    #[test]
    fn system_entropy_different_each_call() {
        let a = read_system_entropy().unwrap();
        let b = read_system_entropy().unwrap();
        assert_ne!(a, b);
    }

    // -- check_rng_sanity --

    #[test]
    fn sanity_check_passes_on_healthy_system() {
        // Mirrors Bitcoin Core's osrandom_tests: on a working platform the
        // startup sanity check must succeed.
        assert!(check_rng_sanity().is_ok());
    }

    // -- BIP39 integration --

    #[test]
    fn entropy_produces_valid_24_word_mnemonic() {
        let rolls = vec![1, 2, 3, 4, 5, 6];
        let sys = [0xAB; SYSTEM_ENTROPY_BYTES];
        let entropy = combine_and_hash(&rolls, &sys);
        let mnemonic = bip39::Mnemonic::from_entropy(&*entropy).unwrap();
        assert_eq!(mnemonic.words().count(), 24);
    }

    #[test]
    fn mnemonic_roundtrip_parse() {
        let rolls = vec![3, 1, 4, 1, 5, 6, 2, 6, 5, 3];
        let sys = [0xCD; SYSTEM_ENTROPY_BYTES];
        let entropy = combine_and_hash(&rolls, &sys);
        let mnemonic = bip39::Mnemonic::from_entropy(&*entropy).unwrap();
        let phrase = mnemonic.to_string();
        let parsed = bip39::Mnemonic::parse(&phrase).unwrap();
        assert_eq!(mnemonic, parsed);
    }

    #[test]
    fn entropy_from_empty_rolls_and_entropy_produces_valid_mnemonic() {
        let entropy = combine_and_hash(&[], &[]);
        let mnemonic = bip39::Mnemonic::from_entropy(&*entropy).unwrap();
        assert_eq!(mnemonic.words().count(), 24);
    }

    // -- Reproducible mode (-r) --

    #[test]
    fn reproducible_same_rolls_same_mnemonic() {
        let rolls = vec![1, 2, 3, 4, 5, 6, 1, 2, 3, 4];
        let a = bip39::Mnemonic::from_entropy(&*combine_and_hash(&rolls, &[])).unwrap();
        let b = bip39::Mnemonic::from_entropy(&*combine_and_hash(&rolls, &[])).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn reproducible_different_rolls_different_mnemonic() {
        let a = bip39::Mnemonic::from_entropy(&*combine_and_hash(&[1, 2, 3], &[])).unwrap();
        let b = bip39::Mnemonic::from_entropy(&*combine_and_hash(&[4, 5, 6], &[])).unwrap();
        assert_ne!(a, b);
    }

    // Test vector created by hashing integer values in `rolls_str` using openssl and
    // entering the resulting entropy as a hex string with https://iancoleman.io/bip39/.
    //
    // echo -n '1234561234561234561234561234561234561234561234561234561234561234561234561234561234561234561234561234' \
    // | python3 -c 'import sys; sys.stdout.buffer.write(bytes(map(int, sys.stdin.read().strip())))' \
    // | openssl dgst -sha256 -binary | od -An -tx1 | tr -d ' \n'
    // 0d91ab5ff9625768d705bb7af3b6d2597d7d8e45572a5dc038a7c86c71739a01
    //
    #[test]
    fn known_answer_100_rolls_no_os_entropy() {
        let rolls_str = "1234561234561234561234561234561234561234561234561234561234561234561234561234561234561234561234561234";
        let rolls: Vec<u8> = rolls_str
            .chars()
            .map(|c| c.to_digit(10).unwrap() as u8)
            .collect();

        // Ensure the test input is valid
        assert!(check_entropy_strength(&rolls).is_ok());

        // Generate entropy in reproducible mode (no OS entropy)
        let entropy = combine_and_hash(&rolls, &[]);

        // Ensure intermediate entropy matches expected hex value:
        // 0d91ab5ff9625768d705bb7af3b6d2597d7d8e45572a5dc038a7c86c71739a01
        let expected = [
            0x0d, 0x91, 0xab, 0x5f, 0xf9, 0x62, 0x57, 0x68, 0xd7, 0x05, 0xbb, 0x7a, 0xf3, 0xb6,
            0xd2, 0x59, 0x7d, 0x7d, 0x8e, 0x45, 0x57, 0x2a, 0x5d, 0xc0, 0x38, 0xa7, 0xc8, 0x6c,
            0x71, 0x73, 0x9a, 0x01,
        ];
        assert_eq!(*entropy, expected);

        let mnemonic = bip39::Mnemonic::from_entropy(&*entropy).unwrap();

        let expected_phrase = "assault minute subject version century refuse foster resist kit oval region real style shrimp best torch fruit achieve clarify move shove right gym decline";
        assert_eq!(mnemonic.to_string(), expected_phrase);
    }

    // -- entropy helpers --

    #[test]
    fn count_values_buckets_correctly() {
        let rolls = vec![1, 1, 1, 2, 2, 3, 4, 5, 6, 6];
        assert_eq!(count_values(&rolls), [3, 2, 1, 1, 1, 2]);
    }

    #[test]
    fn count_values_ignores_invalid() {
        let rolls = vec![0, 1, 7, 6];
        assert_eq!(count_values(&rolls), [1, 0, 0, 0, 0, 1]);
    }

    #[test]
    fn shannon_entropy_empty_is_zero() {
        assert_eq!(shannon_entropy_bits(&[]), 0.0);
    }

    #[test]
    fn shannon_entropy_single_value_is_zero() {
        assert_eq!(shannon_entropy_bits(&[3; 100]), 0.0);
    }

    #[test]
    fn shannon_entropy_uniform_100_rolls() {
        // [17,17,17,17,16,16] -> ~258.4 bits
        let rolls: Vec<u8> = (0..100).map(|i| (i % 6) as u8 + 1).collect();
        let bits = shannon_entropy_bits(&rolls);
        assert!(bits > 258.0 && bits < 258.5, "got {}", bits);
    }

    #[test]
    fn shannon_entropy_max_is_n_log2_6() {
        // Perfectly uniform 600 rolls: exactly 100 * log2(6) * 6... = 600 * log2(6)
        let rolls: Vec<u8> = (0..600).map(|i| (i % 6) as u8 + 1).collect();
        let bits = shannon_entropy_bits(&rolls);
        let expected = 600.0 * 6f64.log2();
        assert!((bits - expected).abs() < 0.001, "got {}", bits);
    }

    #[test]
    fn shannon_entropy_increases_with_rolls() {
        let base: Vec<u8> = (0..100).map(|i| (i % 6) as u8 + 1).collect();
        let more: Vec<u8> = (0..200).map(|i| (i % 6) as u8 + 1).collect();
        assert!(shannon_entropy_bits(&more) > shannon_entropy_bits(&base));
    }

    // -- check_entropy_strength (positive) --

    #[test]
    fn entropy_uniform_100_rolls_passes() {
        // All 6 values, near-even distribution: [17,17,17,17,16,16]
        let rolls: Vec<u8> = (0..100).map(|i| (i % 6) as u8 + 1).collect();
        assert!(check_entropy_strength(&rolls).is_ok());
    }

    #[test]
    fn entropy_uniform_150_rolls_passes() {
        let rolls: Vec<u8> = (0..150).map(|i| (i % 6) as u8 + 1).collect();
        assert!(check_entropy_strength(&rolls).is_ok());
    }

    #[test]
    fn entropy_slightly_uneven_passes() {
        // All 6 values, mild unevenness: [18,18,17,17,15,15] = ~258 bits
        let mut rolls = Vec::new();
        for (val, count) in [(1u8, 18), (2, 18), (3, 17), (4, 17), (5, 15), (6, 15)] {
            rolls.extend(std::iter::repeat_n(val, count));
        }
        assert!(check_entropy_strength(&rolls).is_ok());
    }

    // -- check_entropy_strength (negative) --

    #[test]
    fn entropy_six_values_but_skewed_fails() {
        // All 6 present but heavily skewed: [50,20,10,10,5,5] = ~206 bits
        let mut rolls = Vec::new();
        for (val, count) in [(1u8, 50), (2, 20), (3, 10), (4, 10), (5, 5), (6, 5)] {
            rolls.extend(std::iter::repeat_n(val, count));
        }
        let err = check_entropy_strength(&rolls).unwrap_err();
        assert!(err.contains("Insufficient"));
    }

    #[test]
    fn entropy_six_values_95_percent_one_value_fails() {
        // [95,1,1,1,1,1] — 6 distinct but almost no entropy
        let mut rolls = vec![1u8; 95];
        rolls.extend_from_slice(&[2, 3, 4, 5, 6]);
        let err = check_entropy_strength(&rolls).unwrap_err();
        assert!(err.contains("Insufficient"));
    }

    #[test]
    fn entropy_empty_rolls_fails() {
        let err = check_entropy_strength(&[]).unwrap_err();
        assert!(err.contains("No dice rolls"));
    }

    #[test]
    fn entropy_single_roll_fails() {
        let rolls = vec![4u8];
        assert!(check_entropy_strength(&rolls).is_err());
    }

    #[test]
    fn entropy_invalid_value_fails() {
        let rolls = vec![1, 2, 3, 7, 4, 5];
        let err = check_entropy_strength(&rolls).unwrap_err();
        assert!(err.contains("Invalid"));
    }

    #[test]
    fn entropy_zero_value_fails() {
        let rolls = vec![0, 1, 2, 3, 4, 5];
        let err = check_entropy_strength(&rolls).unwrap_err();
        assert!(err.contains("Invalid"));
    }

    // -- Zeroization --

    #[test]
    fn zeroize_clears_vec() {
        let mut data = vec![1, 2, 3, 4, 5];
        data.zeroize();
        assert!(data.iter().all(|&b| b == 0));
    }

    #[test]
    fn zeroize_clears_array() {
        let mut data = [0xFF; SYSTEM_ENTROPY_BYTES];
        data.zeroize();
        assert!(data.iter().all(|&b| b == 0));
    }
}

// SPDX-License-Identifier: MIT OR Apache-2.0

#![forbid(unsafe_code)]

use std::io::{self, Read, Write};
use zeroize::Zeroize;

const MIN_DICE_ROLLS: usize = 100;
const SYSTEM_ENTROPY_BYTES: usize = 32;
const MIN_ENTROPY_BITS: f64 = 256.0;
const MIN_DISTINCT_VALUES: usize = 6;

fn main() {
    let reproducible = std::env::args().any(|a| a == "-r");

    println!("seedroller - BIP39 seed generation from dice rolls + operating system RNG entropy");
    println!();
    println!("Press keys 1-6 for each dice roll. Backspace to undo.");
    println!(
        "After {} rolls, press Enter to finish (or keep adding rolls).",
        MIN_DICE_ROLLS
    );
    println!();

    let mut rolls = collect_dice_rolls();
    println!("\nCollected {} dice rolls.", rolls.len());

    if let Err(msg) = check_entropy_strength(&rolls) {
        eprintln!("\n\x1b[1mERROR: {}\x1b[0m", msg);
        std::process::exit(1);
    }

    let mut system_entropy = if reproducible {
        println!("\x1b[1mWARNING: -r flag set, operating system RNG entropy was NOT added.\x1b[0m");
        println!("\x1b[1mThis seed is derived ONLY from your dice rolls.\x1b[0m");
        Vec::new()
    } else {
        let entropy = read_system_entropy();
        println!("Read {} bytes from operating system RNG.", entropy.len());
        entropy.to_vec()
    };

    let mut entropy = combine_and_hash(&rolls, &system_entropy);

    let mnemonic = bip39::Mnemonic::from_entropy(&entropy).expect("32-byte entropy is valid");

    // Zeroize all sensitive intermediates
    rolls.zeroize();
    system_entropy.zeroize();
    entropy.zeroize();

    println!("\nYour BIP39 seed phrase (24 words):\n");
    println!("WARNING: This seed phrase will remain in your terminal scrollback.");
    println!("Write it down, then clear your terminal (Cmd+K) when done.\n");
    for (i, word) in mnemonic.words().enumerate() {
        println!("  {:>2}. {}", i + 1, word);
    }
    println!();
    println!("{}", mnemonic);
}

/// Restores terminal settings on drop.
struct TermGuard {
    saved: Option<String>,
}

impl TermGuard {
    fn new() -> Self {
        let saved = Self::stty_save();
        if saved.is_some() {
            Self::stty(&["cbreak"]);
        }
        Self { saved }
    }

    fn open_tty() -> Option<std::fs::File> {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .ok()
    }

    fn stty_save() -> Option<String> {
        let tty = Self::open_tty()?;
        let output = std::process::Command::new("stty")
            .arg("-g")
            .stdin(std::process::Stdio::from(tty))
            .output()
            .ok()?;
        let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if s.is_empty() { None } else { Some(s) }
    }

    fn stty(args: &[&str]) {
        if let Some(tty) = Self::open_tty() {
            std::process::Command::new("stty")
                .args(args)
                .stdin(std::process::Stdio::from(tty))
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .ok();
        }
    }
}

impl Drop for TermGuard {
    fn drop(&mut self) {
        if let Some(ref s) = self.saved {
            Self::stty(&[s]);
        }
    }
}

fn collect_dice_rolls() -> Vec<u8> {
    let _guard = TermGuard::new();
    let stdin = io::stdin();
    let mut lock = stdin.lock();
    let mut rolls: Vec<u8> = Vec::new();
    let mut byte = [0u8; 1];

    loop {
        // Print prompt for the next roll
        let n = rolls.len() + 1;
        if n <= MIN_DICE_ROLLS {
            print!("[{}/{}]: ", n, MIN_DICE_ROLLS);
        } else {
            print!("[{}/{} enter to end]: ", n, MIN_DICE_ROLLS);
        }
        io::stdout().flush().unwrap();

        // Read one key
        if lock.read_exact(&mut byte).is_err() {
            break;
        }

        match byte[0] {
            b'1'..=b'6' => {
                rolls.push(byte[0] - b'0');
                println!();
            }
            0x7f | 0x08 => {
                if rolls.pop().is_some() {
                    println!("(removed, back to {})", rolls.len());
                } else {
                    println!();
                }
            }
            b'\n' | b'\r' => {
                if rolls.len() >= MIN_DICE_ROLLS {
                    let distinct = distinct_values(&rolls);
                    if distinct < MIN_DISTINCT_VALUES {
                        println!(
                            "only {}/{} values seen — keep rolling",
                            distinct, MIN_DISTINCT_VALUES
                        );
                        continue;
                    }
                    let bits = shannon_entropy_bits(&rolls);
                    if bits < MIN_ENTROPY_BITS {
                        println!(
                            "{:.1}/{} bits of entropy — keep rolling",
                            bits, MIN_ENTROPY_BITS as u32
                        );
                        continue;
                    }
                    break;
                }
            }
            _ => {
                println!(" (use keys 1-6)");
            }
        }
    }

    rolls
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

/// Number of distinct dice values (1-6) present in the rolls.
fn distinct_values(rolls: &[u8]) -> usize {
    count_values(rolls).iter().filter(|&&c| c > 0).count()
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

    // Check distinct values
    let distinct = distinct_values(rolls);
    if distinct < MIN_DISTINCT_VALUES {
        return Err(format!(
            "Only {} of 6 dice values appeared — all 6 required.\n\
             With {} rolls every value should come up at least once.\n\
             Roll a real die and record each result honestly.",
            distinct,
            rolls.len()
        ));
    }

    let total_entropy = shannon_entropy_bits(rolls);
    if total_entropy < MIN_ENTROPY_BITS {
        return Err(format!(
            "Insufficient dice entropy: {:.1} bits — minimum {} bits required.\n\
             Distribution of 1-6: {:?}",
            total_entropy,
            MIN_ENTROPY_BITS as u32,
            count_values(rolls)
        ));
    }

    Ok(())
}

fn read_system_entropy() -> [u8; SYSTEM_ENTROPY_BYTES] {
    use rand::TryRngCore;
    use rand::rngs::OsRng;

    let mut buf = [0u8; SYSTEM_ENTROPY_BYTES];
    OsRng
        .try_fill_bytes(&mut buf)
        .expect("failed to read from operating system RNG");
    buf
}

fn combine_and_hash(rolls: &[u8], system_entropy: &[u8]) -> [u8; 32] {
    use bitcoin_hashes::{Hash, sha256};

    let mut data = Vec::with_capacity(rolls.len() + system_entropy.len());
    data.extend_from_slice(rolls);
    data.extend_from_slice(system_entropy);

    let hash = sha256::Hash::hash(&data);
    data.zeroize();

    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_ref());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- combine_and_hash --

    #[test]
    fn hash_output_is_32_bytes() {
        let rolls = vec![1, 2, 3, 4, 5, 6];
        let sys = [0xAB; 256];
        let result = combine_and_hash(&rolls, &sys);
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn hash_deterministic_same_inputs() {
        let rolls = vec![1, 2, 3, 4, 5, 6];
        let sys = [0xAB; 256];
        let a = combine_and_hash(&rolls, &sys);
        let b = combine_and_hash(&rolls, &sys);
        assert_eq!(a, b);
    }

    #[test]
    fn hash_different_rolls_different_output() {
        let sys = [0xAB; 256];
        let a = combine_and_hash(&[1, 2, 3], &sys);
        let b = combine_and_hash(&[4, 5, 6], &sys);
        assert_ne!(a, b);
    }

    #[test]
    fn hash_different_system_entropy_different_output() {
        let rolls = vec![1, 2, 3];
        let a = combine_and_hash(&rolls, &[0xAA; 256]);
        let b = combine_and_hash(&rolls, &[0xBB; 256]);
        assert_ne!(a, b);
    }

    #[test]
    fn hash_empty_rolls_valid() {
        let sys = [0xAB; 256];
        let result = combine_and_hash(&[], &sys);
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn hash_empty_system_entropy_valid() {
        // This is the -r (reproducible) mode path
        let rolls = vec![1, 2, 3, 4, 5, 6];
        let result = combine_and_hash(&rolls, &[]);
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn hash_empty_both_matches_sha256_of_empty() {
        // SHA-256("") is a well-known constant
        let result = combine_and_hash(&[], &[]);
        let expected = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn hash_single_roll_difference_changes_output() {
        let sys = [0xAB; 256];
        let a = combine_and_hash(&[1, 2, 3], &sys);
        let b = combine_and_hash(&[1, 2, 4], &sys);
        assert_ne!(a, b);
    }

    #[test]
    fn hash_roll_order_matters() {
        let sys = [0xAB; 256];
        let a = combine_and_hash(&[1, 2], &sys);
        let b = combine_and_hash(&[2, 1], &sys);
        assert_ne!(a, b);
    }

    #[test]
    fn hash_rolls_only_differs_from_rolls_plus_entropy() {
        let rolls = vec![1, 2, 3, 4, 5, 6];
        let sys = [0xAB; 256];
        let without_sys = combine_and_hash(&rolls, &[]);
        let with_sys = combine_and_hash(&rolls, &sys);
        assert_ne!(without_sys, with_sys);
    }

    // -- read_system_entropy --

    #[test]
    fn system_entropy_returns_32_bytes() {
        let entropy = read_system_entropy();
        assert_eq!(entropy.len(), SYSTEM_ENTROPY_BYTES);
    }

    #[test]
    fn system_entropy_not_all_zeros() {
        let entropy = read_system_entropy();
        assert!(entropy.iter().any(|&b| b != 0));
    }

    #[test]
    fn system_entropy_different_each_call() {
        let a = read_system_entropy();
        let b = read_system_entropy();
        assert_ne!(a, b);
    }

    // -- BIP39 integration --

    #[test]
    fn entropy_produces_valid_24_word_mnemonic() {
        let rolls = vec![1, 2, 3, 4, 5, 6];
        let sys = [0xAB; 256];
        let entropy = combine_and_hash(&rolls, &sys);
        let mnemonic = bip39::Mnemonic::from_entropy(&entropy).unwrap();
        assert_eq!(mnemonic.words().count(), 24);
    }

    #[test]
    fn mnemonic_roundtrip_parse() {
        let rolls = vec![3, 1, 4, 1, 5, 6, 2, 6, 5, 3];
        let sys = [0xCD; 256];
        let entropy = combine_and_hash(&rolls, &sys);
        let mnemonic = bip39::Mnemonic::from_entropy(&entropy).unwrap();
        let phrase = mnemonic.to_string();
        let parsed = bip39::Mnemonic::parse(&phrase).unwrap();
        assert_eq!(mnemonic, parsed);
    }

    #[test]
    fn entropy_from_empty_rolls_and_entropy_produces_valid_mnemonic() {
        let entropy = combine_and_hash(&[], &[]);
        let mnemonic = bip39::Mnemonic::from_entropy(&entropy).unwrap();
        assert_eq!(mnemonic.words().count(), 24);
    }

    // -- Reproducible mode (-r) --

    #[test]
    fn reproducible_same_rolls_same_mnemonic() {
        let rolls = vec![1, 2, 3, 4, 5, 6, 1, 2, 3, 4];
        let a = bip39::Mnemonic::from_entropy(&combine_and_hash(&rolls, &[])).unwrap();
        let b = bip39::Mnemonic::from_entropy(&combine_and_hash(&rolls, &[])).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn reproducible_different_rolls_different_mnemonic() {
        let a = bip39::Mnemonic::from_entropy(&combine_and_hash(&[1, 2, 3], &[])).unwrap();
        let b = bip39::Mnemonic::from_entropy(&combine_and_hash(&[4, 5, 6], &[])).unwrap();
        assert_ne!(a, b);
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
    fn distinct_values_counts() {
        assert_eq!(distinct_values(&[1, 1, 1, 1]), 1);
        assert_eq!(distinct_values(&[1, 2, 3, 4, 5, 6]), 6);
        assert_eq!(distinct_values(&[1, 2, 3, 4, 5]), 5);
        assert_eq!(distinct_values(&[]), 0);
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
    fn entropy_all_same_value_fails() {
        let rolls = vec![3u8; 100];
        let err = check_entropy_strength(&rolls).unwrap_err();
        assert!(err.contains("of 6 dice values"));
    }

    #[test]
    fn entropy_five_distinct_values_fails() {
        // 5 values present but 6 never appears
        let rolls: Vec<u8> = (0..100).map(|i| (i % 5) as u8 + 1).collect();
        let err = check_entropy_strength(&rolls).unwrap_err();
        assert!(err.contains("of 6 dice values"));
    }

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
    fn entropy_two_values_fails() {
        let rolls: Vec<u8> = (0..100).map(|i| (i % 2) as u8 + 1).collect();
        let err = check_entropy_strength(&rolls).unwrap_err();
        assert!(err.contains("of 6 dice values"));
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
        let mut data = [0xFF; 32];
        data.zeroize();
        assert!(data.iter().all(|&b| b == 0));
    }
}

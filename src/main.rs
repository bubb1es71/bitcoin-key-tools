#![forbid(unsafe_code)]

use std::io::{self, Read, Write};
use zeroize::Zeroize;

const MIN_DICE_ROLLS: usize = 100;
const SYSTEM_ENTROPY_BYTES: usize = 256;

fn main() {
    let reproducible = std::env::args().any(|a| a == "-r");

    println!("seedroller - BIP39 seed generation from dice rolls + system entropy");
    println!();
    println!("Press keys 1-6 for each dice roll. Backspace to undo.");
    println!(
        "After {} rolls, press Enter to finish (or keep adding rolls).",
        MIN_DICE_ROLLS
    );
    println!();

    let mut rolls = collect_dice_rolls();
    println!("\nCollected {} dice rolls.", rolls.len());

    let mut system_entropy = if reproducible {
        println!("\x1b[1mWARNING: -r flag set, system entropy was NOT added.\x1b[0m");
        println!("\x1b[1mThis seed is derived ONLY from your dice rolls.\x1b[0m");
        Vec::new()
    } else {
        let entropy = read_system_entropy();
        println!("Read {} bytes from system secure RNG.", entropy.len());
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

fn read_system_entropy() -> [u8; SYSTEM_ENTROPY_BYTES] {
    use rand::TryRngCore;
    use rand::rngs::OsRng;

    let mut buf = [0u8; SYSTEM_ENTROPY_BYTES];
    OsRng
        .try_fill_bytes(&mut buf)
        .expect("failed to read from system RNG");
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

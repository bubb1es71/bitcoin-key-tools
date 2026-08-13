// SPDX-License-Identifier: MIT OR Apache-2.0

#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv, Xpub};
use bitcoin::secp256k1::Secp256k1;
use clap::Parser;
use std::io::{self, IsTerminal, Write};
use zeroize::{Zeroize, Zeroizing};

/// Derive BIP380 descriptor key expressions from a master BIP32 extended key and BIP44
/// derivation path
///
/// The master key (xprv or tprv) is read via a hidden terminal prompt, or from standard
/// input when piped — never as a command-line argument, so it does not appear in shell
/// history or process listings. The derived key expressions use BIP389 multipath wildcard
/// covering both the receive (0) and change (1) chains. The key expressions inherit the
/// master key's network version bytes (xprv/xpub or tprv/tpub).
#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Args {
    /// purpose
    #[arg(short, long, default_value_t = 84, value_parser = parse_hardened_index)]
    purpose: u32,

    /// account
    #[arg(short, long, default_value_t = 0, value_parser = parse_hardened_index)]
    account: u32,
}

/// Parse a base58check-encoded master extended private key (xprv or tprv).
fn parse_master_key(s: &str) -> Result<Xpriv, String> {
    s.parse::<Xpriv>()
        .map_err(|e| format!("invalid extended private key: {e}"))
}

/// Parse a BIP32 hardened child index, rejecting values that do not fit in a
/// hardened child number (must be less than 2^31).
fn parse_hardened_index(s: &str) -> Result<u32, String> {
    match s.parse::<u32>() {
        Ok(idx) if ChildNumber::from_hardened_idx(idx).is_ok() => Ok(idx),
        Ok(idx) => Err(format!(
            "{idx} exceeds the maximum hardened child index (2^31 - 1)"
        )),
        Err(_) => Err(format!("invalid unsigned integer: {s}")),
    }
}

/// Disables terminal echo on creation and restores the original terminal
/// settings on drop.
struct EchoGuard {
    saved: Option<String>,
}

impl EchoGuard {
    /// Save current terminal settings and disable echo, so the master key is
    /// not displayed as it is typed. Original settings are restored on drop.
    fn new() -> Self {
        let saved = Self::run_stty(&["-g"]);
        if saved.is_some() {
            Self::run_stty(&["-echo"]);
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

impl Drop for EchoGuard {
    fn drop(&mut self) {
        if let Some(ref s) = self.saved {
            Self::run_stty(&[s]);
        }
    }
}

/// Read the master extended private key (xprv or tprv) without exposing it:
/// interactively via a hidden terminal prompt (echo disabled), or from the
/// first line of standard input when it is piped. The input string is
/// zeroized on drop, including when an error is returned. Returns an error
/// if reading or parsing fails.
fn read_master_key() -> Result<Xpriv, String> {
    let mut input = Zeroizing::new(String::new());
    if io::stdin().is_terminal() {
        print!("Master key (xprv or tprv): ");
        io::stdout()
            .flush()
            .map_err(|e| format!("failed to flush stdout: {e}"))?;
        let read_result = {
            let _guard = EchoGuard::new();
            io::stdin().read_line(&mut input)
        }; // terminal echo is restored when the guard drops
        println!(); // the user's Enter was not echoed; move to the next line
        read_result.map_err(|e| format!("failed to read master key: {e}"))?;
    } else {
        io::stdin()
            .read_line(&mut input)
            .map_err(|e| format!("failed to read master key from stdin: {e}"))?;
    }
    parse_master_key(input.trim())
}

fn main() -> Result<(), String> {
    let args = Args::parse();
    let mut master = read_master_key()?;

    println!("\nmaster key: {}", master);
    println!("Derived keys for:");
    println!("purpose: {}", args.purpose);
    println!("account: {}", args.account);

    let keys = bip380_account_keys(&master, args.purpose, args.account);
    // The master key is no longer needed; always wipe it before propagating
    // a possible derivation error, so no exit path leaves it in memory.
    master.private_key.non_secure_erase();
    <bitcoin::bip32::ChainCode as AsMut<[u8; 32]>>::as_mut(&mut master.chain_code).zeroize();
    let (seckey, pubkey) = keys?;
    println!("\nSecret account key: {}", *seckey);
    println!("Public account key: {}", pubkey);
    Ok(())
}

/// Derive the BIP44 account-level keys from a master xprv and return BIP380 descriptor
/// key expressions for the account xprv and xpub:
/// `[<master fingerprint>/{purpose}'/{coin_type}'/{account}']<derived key>/<0;1>/*`.
///
/// Following BIP44 coin type is `0'` on mainnet and `1'` for any testnet, the origin
/// fingerprint is that of the master key, and `/<0;1>/*` is the BIP389 multipath
/// wildcard covering both the receive (0) and change (1) chains. The account keys
/// inherit the master's network version bytes (xprv/xpub or tprv/tpub).
///
/// Returns an error if an index does not fit in a hardened child number or if
/// BIP32 derivation fails (a ~2^-127 probability event).
fn bip380_account_keys(
    master: &Xpriv,
    purpose: u32,
    account: u32,
) -> Result<(Zeroizing<String>, String), String> {
    let secp = Secp256k1::new();
    let coin_type = if master.network.is_mainnet() { 0 } else { 1 };
    let path = DerivationPath::from(vec![
        ChildNumber::from_hardened_idx(purpose)
            .map_err(|e| format!("invalid purpose index {purpose}: {e}"))?,
        ChildNumber::from_hardened_idx(coin_type)
            .map_err(|e| format!("invalid coin type index {coin_type}: {e}"))?,
        ChildNumber::from_hardened_idx(account)
            .map_err(|e| format!("invalid account index {account}: {e}"))?,
    ]);
    let mut account_xprv = master
        .derive_priv(&secp, &path)
        .map_err(|e| format!("BIP32 derivation failed: {e}"))?;
    let account_xpub = Xpub::from_priv(&secp, &account_xprv);
    let origin = format!(
        "[{}/{}'/{}'/{}']",
        master.fingerprint(&secp),
        purpose,
        coin_type,
        account
    );
    let xprv_expr = Zeroizing::new(format!("{}{}/<0;1>/*", origin, account_xprv));
    // Safe to wipe: the account key has already been serialized into the expression.
    account_xprv.private_key.non_secure_erase();
    <bitcoin::bip32::ChainCode as AsMut<[u8; 32]>>::as_mut(&mut account_xprv.chain_code).zeroize();
    let xpub_expr = format!("{}{}/<0;1>/*", origin, account_xpub);
    Ok((xprv_expr, xpub_expr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::NetworkKind;

    // -- BIP380 account keys --

    #[test]
    fn bip84_mainnet_test() {
        // Official BIP-84 test vector (mnemonic "abandon ... about", account 0).
        // The spec serializes the account keys as zprv/zpub (SLIP-132 version
        // bytes); the values below carry the identical key material with
        // standard xprv/xpub version bytes. See:
        // https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki
        let mnemonic = bip39::Mnemonic::parse(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap();
        let seed = mnemonic.to_seed("");
        let master = Xpriv::new_master(NetworkKind::Main, &seed).unwrap();
        let (xprv_expr, xpub_expr) = bip380_account_keys(&master, 84, 0).unwrap();
        assert_eq!(
            &*xprv_expr,
            "[73c5da0a/84'/0'/0']xprv9ybY78BftS5UGANki6oSifuQEjkpyAC8ZmBvBNTshQnCBcxnefjHS7buPMkkqhcRzmoGZ5bokx7GuyDAiktd5HemohAU4wV1ZPMDRmLpBMm/<0;1>/*"
        );
        assert_eq!(
            xpub_expr,
            "[73c5da0a/84'/0'/0']xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V/<0;1>/*"
        );
    }

    #[test]
    fn bip84_testnet_test() {
        // BIP-84 has no testnet vectors; reuse the BIP-84 vector mnemonic with
        // a testnet master to check the serialization and coin type: derived
        // account keys must carry tprv/tpub version bytes and coin type 1'.
        let mnemonic = bip39::Mnemonic::parse(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap();
        let seed = mnemonic.to_seed("");
        let master = Xpriv::new_master(NetworkKind::Test, &seed).unwrap();
        let (xprv_expr, xpub_expr) = bip380_account_keys(&master, 84, 0).unwrap();
        assert!(xprv_expr.contains("/84'/1'/0']tprv"));
        assert!(xpub_expr.contains("/84'/1'/0']tpub"));
    }

    #[test]
    fn bip84_fingerprint_matches_master() {
        // The origin fingerprint must be the master key's fingerprint.
        let mnemonic = bip39::Mnemonic::parse(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap();
        let seed = mnemonic.to_seed("");
        let master = Xpriv::new_master(NetworkKind::Main, &seed).unwrap();
        let (xprv_expr, xpub_expr) = bip380_account_keys(&master, 84, 0).unwrap();
        let secp = Secp256k1::new();
        let expected_origin = format!("[{}/84'/0'/0']", master.fingerprint(&secp));
        assert!(xprv_expr.starts_with(&expected_origin));
        assert!(xpub_expr.starts_with(&expected_origin));
    }

    // -- Hardened index parsing --

    #[test]
    fn hardened_index_accepts_values_below_2_to_the_31() {
        assert_eq!(parse_hardened_index("0"), Ok(0));
        assert_eq!(parse_hardened_index("84"), Ok(84));
        assert_eq!(parse_hardened_index("2147483647"), Ok(2_147_483_647));
    }

    #[test]
    fn hardened_index_rejects_out_of_range_and_malformed_input() {
        assert!(parse_hardened_index("2147483648").is_err());
        assert!(parse_hardened_index("4294967295").is_err());
        assert!(parse_hardened_index("-1").is_err());
        assert!(parse_hardened_index("abc").is_err());
    }

    // -- Master key parsing --

    #[test]
    fn parse_master_key_accepts_mainnet_xprv() {
        // BIP39 "legal winner" test vector master key.
        let key = parse_master_key(
            "xprv9s21ZrQH143K3Lv9MZLj16np5GzLe7tDKQfVusBni7toqJGcnKRtHSxUwbKUyUWiwpK55g1DUSsw76TF1T93VT4gz4wt5RM23pkaQLnvBh7",
        )
        .unwrap();
        assert!(key.network.is_mainnet());
    }

    #[test]
    fn parse_master_key_rejects_xpub_and_malformed_input() {
        // An extended public key is not usable as a master private key.
        assert!(
            parse_master_key(
                "xpub6CWXS3XJKMTChnkP87ETxuT4hrZsfPCFFiELYffd9fMWBnkWUw44uL4dywAn8mksW7MkCNjXzeia1ZYdDRz5Jx3cmqg6AqJaZHqLdBZ81zV"
            )
            .is_err()
        );
        assert!(parse_master_key("notakey").is_err());
        assert!(parse_master_key("").is_err());
    }
}

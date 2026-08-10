// SPDX-License-Identifier: MIT OR Apache-2.0

#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv, Xpub};
use bitcoin::secp256k1::Secp256k1;
use clap::Parser;
use zeroize::Zeroize;

/// Derive BIP380 descriptor key expressions from a master BIP32 extended key and BIP44
/// derivation path
///
/// The derived key expressions use BIP389 multipath wildcard covering both the receive (0)
/// and change (1) chains. The key expressions inherit the master key's network version
/// bytes (xprv/xpub or tprv/tpub).
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// master key (xprv or tprv)
    #[arg(value_parser = parse_master_key)]
    master: Xpriv,

    /// purpose
    #[arg(short, long, default_value_t = 84)]
    purpose: u32,

    /// account
    #[arg(short, long, default_value_t = 0)]
    account: u32,
}

/// Parse a base58check-encoded master extended private key (xprv or tprv).
fn parse_master_key(s: &str) -> Result<Xpriv, String> {
    s.parse::<Xpriv>()
        .map_err(|e| format!("invalid extended private key: {e}"))
}

fn main() {
    let args = Args::parse();

    println!("Derived keys for:");
    println!("master key: {}", args.master);
    println!("purpose: {}", args.purpose);
    println!("account: {}", args.account);

    let (mut seckey, pubkey) = bip380_account_keys(args.master, args.purpose, args.account);
    println!("\nSecret account key: {}", seckey);
    println!("Public account key: {}", pubkey);
    seckey.zeroize();
}

/// Derive the BIP44 account-level keys from a master xprv and return BIP380 descriptor
/// key expressions for the account xprv and xpub:
/// `[<master fingerprint>/{purpose}'/{coin_type}'/{account}']<derived key>/<0;1>/*`.
///
/// Following BIP44 coin type is `0'` on mainnet and `1'` for any testnet, the origin
/// fingerprint is that of the master key, and `/<0;1>/*` is the BIP389 multipath
/// wildcard covering both the receive (0) and change (1) chains. The account keys
/// inherit the master's network version bytes (xprv/xpub or tprv/tpub).
fn bip380_account_keys(master: Xpriv, purpose: u32, account: u32) -> (String, String) {
    let secp = Secp256k1::new();
    let coin_type = if master.network.is_mainnet() { 0 } else { 1 };
    let path = DerivationPath::from(vec![
        ChildNumber::from_hardened_idx(purpose).expect("must fit in a hardened child index"),
        ChildNumber::from_hardened_idx(coin_type).expect("must fit in a hardened child index"),
        ChildNumber::from_hardened_idx(account).expect("must fit in a hardened child index"),
    ]);
    let mut account_xprv = master
        .derive_priv(&secp, &path)
        .expect("BIP32 derivation failure has ~2^-127 probability");
    let account_xpub = Xpub::from_priv(&secp, &account_xprv);
    let origin = format!(
        "[{}/{}'/{}'/{}']",
        master.fingerprint(&secp),
        purpose,
        coin_type,
        account
    );
    let xprv_expr = format!("{}{}/<0;1>/*", origin, account_xprv);
    account_xprv.private_key.non_secure_erase();
    let xpub_expr = format!("{}{}/<0;1>/*", origin, account_xpub);
    (xprv_expr, xpub_expr)
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
        let (xprv_expr, xpub_expr) = bip380_account_keys(master, 84, 0);
        assert_eq!(
            xprv_expr,
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
        let (xprv_expr, xpub_expr) = bip380_account_keys(master, 84, 0);
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
        let (xprv_expr, xpub_expr) = bip380_account_keys(master, 84, 0);
        let secp = Secp256k1::new();
        let expected_origin = format!("[{}/84'/0'/0']", master.fingerprint(&secp));
        assert!(xprv_expr.starts_with(&expected_origin));
        assert!(xpub_expr.starts_with(&expected_origin));
    }
}

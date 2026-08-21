// SPDX-License-Identifier: MIT OR Apache-2.0

#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

use bitcoin::NetworkKind;
use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv, Xpub};
use bitcoin::secp256k1::Secp256k1;
use clap::Parser;
use std::io::{self, IsTerminal, Write};
use zeroize::{Zeroize, Zeroizing};

/// Derive BIP380 descriptor key expressions from a BIP39 seed phrase and BIP44
/// derivation path
///
/// The seed words are read via a terminal prompt, or from standard input
/// when piped — never as a command-line argument, so they do not appear in shell
/// history or process listings. The BIP32 master extended private key (xprv) is
/// derived from the seed words with an optional BIP39 passphrase. The derived key
/// expressions use BIP389 multipath wildcard covering both the receive (0) and
/// change (1) chains. Keys carry mainnet version bytes (xprv/xpub), or testnet
/// version bytes (tprv/tpub) with BIP44 coin type 1' when `-t` is given.
#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Args {
    /// purpose
    #[arg(short, long, default_value_t = 84, value_parser = parse_hardened_index)]
    purpose: u32,

    /// account
    #[arg(short, long, default_value_t = 0, value_parser = parse_hardened_index)]
    account: u32,

    /// Prompt for a BIP39 passphrase to combine with the seed words when
    /// creating the master key (prompted interactively, never on the
    /// command line)
    #[arg(short = 's', long, default_value_t = false)]
    secret: bool,

    /// Testnet mode (derive a testnet tprv master key and tprv/tpub key
    /// expressions with BIP44 coin type 1')
    #[arg(short, long, default_value_t = false)]
    testnet: bool,
}

/// Parse a BIP39 mnemonic seed phrase, validating the words and checksum.
fn parse_seed_words(s: &str) -> Result<bip39::Mnemonic, String> {
    bip39::Mnemonic::parse(s).map_err(|e| format!("invalid seed phrase: {e}"))
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

/// Read the BIP39 seed words: interactively via a terminal prompt, or from
/// the first line of standard input when it is piped. What the user types is
/// displayed as they type (echo is not disabled). The input string is
/// zeroized on drop, including when an error is returned. Returns an error if
/// reading or parsing fails.
fn read_seed_words() -> Result<bip39::Mnemonic, String> {
    let mut input = Zeroizing::new(String::new());
    if io::stdin().is_terminal() {
        print!("Seed words: ");
        io::stdout()
            .flush()
            .map_err(|e| format!("failed to flush stdout: {e}"))?;
    }
    io::stdin()
        .read_line(&mut input)
        .map_err(|e| format!("failed to read seed words: {e}"))?;
    parse_seed_words(input.trim())
}

/// Read the BIP39 passphrase: interactively via a terminal prompt, or from
/// the second line of standard input when it is piped (the first line holds
/// the seed words). If the pipe does not provide a second line, fall back to
/// a prompt on the controlling terminal. What the user types is displayed as
/// they type (echo is not disabled). Only the trailing line ending is
/// stripped — other whitespace can be part of the passphrase. The buffer is
/// zeroized on drop, including when an error is returned. Returns an error if
/// reading fails or the input is empty.
fn read_passphrase() -> Result<Zeroizing<String>, String> {
    let mut passphrase = Zeroizing::new(String::new());
    if io::stdin().is_terminal() {
        prompt_passphrase(&mut io::stdin().lock(), &mut passphrase)?;
    } else {
        io::stdin()
            .read_line(&mut passphrase)
            .map_err(|e| format!("failed to read passphrase: {e}"))?;
        trim_line_ending(&mut passphrase);
        if passphrase.is_empty() {
            // The pipe supplied no passphrase line; ask the user directly on
            // the controlling terminal instead of failing.
            let tty = std::fs::OpenOptions::new()
                .read(true)
                .open("/dev/tty")
                .map_err(|e| {
                    format!("no passphrase on standard input and cannot prompt for one: {e}")
                })?;
            prompt_passphrase(&mut io::BufReader::new(tty), &mut passphrase)?;
        }
    }
    if passphrase.is_empty() {
        return Err("empty passphrase; omit the -s flag to derive without one".to_string());
    }
    Ok(passphrase)
}

/// Prompt for the BIP39 passphrase and read one line from `reader` into
/// `passphrase`, stripping the trailing line ending. What the user types is
/// displayed on the terminal (echo is not disabled).
fn prompt_passphrase(
    reader: &mut impl io::BufRead,
    passphrase: &mut Zeroizing<String>,
) -> Result<(), String> {
    print!("BIP39 passphrase: ");
    io::stdout()
        .flush()
        .map_err(|e| format!("failed to flush stdout: {e}"))?;
    reader
        .read_line(passphrase)
        .map_err(|e| format!("failed to read passphrase: {e}"))?;
    trim_line_ending(passphrase);
    Ok(())
}

/// Strip a trailing line ending (`\r\n` or `\n`) from the string in place.
/// Other whitespace is left untouched — it can be part of the passphrase.
fn trim_line_ending(s: &mut String) {
    while matches!(s.chars().last(), Some('\r' | '\n')) {
        s.pop();
    }
}

/// Derive the BIP32 master extended private key from a BIP39 mnemonic and
/// passphrase, using mainnet (xprv) or testnet (tprv) version bytes. The
/// intermediate BIP39 seed is zeroized on drop.
fn master_key_from_seed(
    mnemonic: &bip39::Mnemonic,
    passphrase: &str,
    network: NetworkKind,
) -> Result<Xpriv, String> {
    let seed = Zeroizing::new(mnemonic.to_seed(passphrase));
    Xpriv::new_master(network, &seed[..]).map_err(|e| e.to_string())
}

fn main() -> Result<(), String> {
    let args = Args::parse();
    // Mnemonic implements ZeroizeOnDrop
    let mnemonic = read_seed_words()?;
    let passphrase = if args.secret {
        read_passphrase()?
    } else {
        Zeroizing::new(String::new())
    };
    let network = if args.testnet {
        NetworkKind::Test
    } else {
        NetworkKind::Main
    };
    let mut master = master_key_from_seed(&mnemonic, &passphrase, network)?;

    eprintln!(
        "\nWARNING: The master key and secret account key will remain in your terminal scrollback."
    );
    eprintln!("Write them down, then clear your terminal (Cmd+K) when done.\n");
    println!("\nmaster key: {}", master);
    println!("fingerprint: {}", master.fingerprint(&Secp256k1::new()));
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

    // -- Seed word parsing --

    #[test]
    fn parse_seed_words_accepts_valid_12_and_24_word_phrases() {
        assert!(
            parse_seed_words(
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            )
            .is_ok()
        );
        assert!(
            parse_seed_words(
                "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will"
            )
            .is_ok()
        );
    }

    #[test]
    fn parse_seed_words_rejects_bad_checksum_unknown_word_and_empty_input() {
        // Twelve times "abandon" fails the checksum check (valid phrase ends in "about").
        assert!(
            parse_seed_words(
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
            )
            .is_err()
        );
        assert!(
            parse_seed_words(
                "notaword abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            )
            .is_err()
        );
        assert!(parse_seed_words("").is_err());
    }

    // -- Passphrase input --

    #[test]
    fn prompt_passphrase_reads_line_and_strips_line_ending() {
        let mut reader = io::BufReader::new(&b"hunter2\r\n"[..]);
        let mut passphrase = Zeroizing::new(String::new());
        prompt_passphrase(&mut reader, &mut passphrase).unwrap();
        assert_eq!(&*passphrase, "hunter2");
    }

    #[test]
    fn prompt_passphrase_preserves_other_whitespace() {
        let mut reader = io::BufReader::new(&b"  two words  \n"[..]);
        let mut passphrase = Zeroizing::new(String::new());
        prompt_passphrase(&mut reader, &mut passphrase).unwrap();
        assert_eq!(&*passphrase, "  two words  ");
    }

    #[test]
    fn trim_line_ending_strips_lf_and_crlf_only() {
        for (input, expected) in [
            ("abc\n", "abc"),
            ("abc\r\n", "abc"),
            ("abc", "abc"),
            ("abc ", "abc "),
            ("", ""),
        ] {
            let mut s = String::from(input);
            trim_line_ending(&mut s);
            assert_eq!(s, expected);
        }
    }

    // -- Master key derivation --

    #[test]
    fn master_key_known_answer_bip39_legal_winner() {
        // BIP39 test vector from the official BIP-0039 specification:
        // https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#test-vectors
        //
        // Mnemonic:  "legal winner thank year wave sausage worth useful legal winner
        //             thank year wave sausage worth useful legal will"
        // Passphrase: "TREZOR"
        // Entropy:    7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f
        let mnemonic = parse_seed_words(
            "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
        )
        .unwrap();
        let master = master_key_from_seed(&mnemonic, "TREZOR", NetworkKind::Main).unwrap();
        assert_eq!(
            master.to_string(),
            "xprv9s21ZrQH143K3Lv9MZLj16np5GzLe7tDKQfVusBni7toqJGcnKRtHSxUwbKUyUWiwpK55g1DUSsw76TF1T93VT4gz4wt5RM23pkaQLnvBh7"
        );
    }

    #[test]
    fn master_key_known_answer_bip39_legal_winner_testnet() {
        // Same BIP39 test vector as master_key_known_answer_bip39_legal_winner,
        // serialized with testnet version bytes.
        let mnemonic = parse_seed_words(
            "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
        )
        .unwrap();
        let master = master_key_from_seed(&mnemonic, "TREZOR", NetworkKind::Test).unwrap();
        assert_eq!(
            master.to_string(),
            "tprv8ZgxMBicQKsPeA9g28CEAkQoPQQYsdvDexacnHcFC6PHcu1hmgmdoCKvrmV8yqu3KFqr5mcydoTjZwzz8fUzJWLHWiABjn54xvVzr3oUVN7"
        );
    }

    #[test]
    fn master_key_testnet_shares_key_material_with_mainnet() {
        // Testnet and mainnet master keys share the same key material and
        // chain code; only the serialized version bytes differ.
        let mnemonic = parse_seed_words(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap();
        let mainnet = master_key_from_seed(&mnemonic, "", NetworkKind::Main).unwrap();
        let testnet = master_key_from_seed(&mnemonic, "", NetworkKind::Test).unwrap();
        assert_eq!(mainnet.private_key, testnet.private_key);
        assert_eq!(mainnet.chain_code, testnet.chain_code);
        assert_ne!(mainnet.to_string(), testnet.to_string());
        assert!(testnet.to_string().starts_with("tprv"));
    }

    #[test]
    fn master_key_fingerprint_matches_bip84_vector() {
        // BIP-84 test vector: mnemonic "abandon ... about" has master
        // fingerprint 73c5da0a. See:
        // https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki
        let mnemonic = parse_seed_words(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap();
        let master = master_key_from_seed(&mnemonic, "", NetworkKind::Main).unwrap();
        assert_eq!(
            master.fingerprint(&Secp256k1::new()).to_string(),
            "73c5da0a"
        );
    }

    #[test]
    fn master_key_different_passphrases_different_keys() {
        let mnemonic = parse_seed_words(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap();
        let a = master_key_from_seed(&mnemonic, "", NetworkKind::Main).unwrap();
        let b = master_key_from_seed(&mnemonic, "secret", NetworkKind::Main).unwrap();
        assert_ne!(a, b);
    }
}

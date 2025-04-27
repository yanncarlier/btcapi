use sha2::{Digest, Sha256};
use ripemd160::Ripemd160;
use base58::ToBase58;
use secp256k1::{Secp256k1, SecretKey, PublicKey};
use std::env;
use std::process;

/// Generates a Bitcoin brain wallet from a passphrase, returning the WIF private key and address.
///
/// # Arguments
/// * `passphrase` - A string slice containing the passphrase.
///
/// # Returns
/// A tuple containing:
/// - WIF private key as a `String`
/// - Bitcoin address as a `String`
///
/// # Panics
/// Panics if the private key is invalid (extremely unlikely with a 32-byte SHA-256 output).
fn brain_wallet(passphrase: &str) -> (String, String) {
    // Step 1: Generate private key from passphrase using SHA-256
    let mut hasher = Sha256::new();
    hasher.update(passphrase.as_bytes());
    let private_key_bytes = hasher.finalize();
    let private_key = SecretKey::from_slice(&private_key_bytes).expect("Invalid private key");

    // Step 2: Create WIF private key
    // Prepend 0x80 (mainnet private key version byte for uncompressed keys)
    let mut extended_private_key = vec![0x80];
    extended_private_key.extend_from_slice(&private_key_bytes);
    // Compute checksum: double SHA-256 and take first 4 bytes
    let mut hasher = Sha256::new();
    hasher.update(&extended_private_key);
    let hash1 = hasher.finalize();
    let mut hasher = Sha256::new();
    hasher.update(&hash1);
    let hash2 = hasher.finalize();
    let checksum = &hash2[0..4];
    // Append checksum to extended private key
    extended_private_key.extend_from_slice(checksum);
    // Encode to Base58 to get WIF
    let wif = extended_private_key.to_base58();

    // Step 3: Generate public key (uncompressed)
    let secp = Secp256k1::new();
    let public_key = PublicKey::from_secret_key(&secp, &private_key);
    let public_key_uncompressed = public_key.serialize_uncompressed(); // 65 bytes, starts with 0x04

    // Step 4: Create Bitcoin address
    // SHA-256 of public key
    let mut hasher = Sha256::new();
    hasher.update(&public_key_uncompressed);
    let hash1 = hasher.finalize();
    // RIPEMD-160 of the SHA-256 hash
    let mut hasher = Ripemd160::new();
    hasher.update(&hash1);
    let hash2 = hasher.finalize(); // 20 bytes
    // Prepend 0x00 (mainnet address version byte)
    let mut address_bytes = vec![0x00];
    address_bytes.extend_from_slice(&hash2);
    // Compute checksum: double SHA-256 and take first 4 bytes
    let mut hasher = Sha256::new();
    hasher.update(&address_bytes);
    let hash3 = hasher.finalize();
    let mut hasher = Sha256::new();
    hasher.update(&hash3);
    let hash4 = hasher.finalize();
    let checksum = &hash4[0..4];
    // Append checksum
    address_bytes.extend_from_slice(checksum);
    // Encode to Base58 to get address
    let address = address_bytes.to_base58();

    (wif, address)
}

fn main() {
    // Collect command-line arguments
    let args: Vec<String> = env::args().collect();

    // Check if at least one passphrase word is provided
    if args.len() < 2 {
        eprintln!("Usage: {} <passphrase words...>", args[0]);
        process::exit(1);
    }

    // Join all arguments after the program name with spaces to form the passphrase
    let passphrase = args[1..].join(" ");

    // Generate WIF private key and Bitcoin address
    let (wif, bitcoin_address) = brain_wallet(&passphrase);

    // Print the results
    println!("WIF Private Key: {}", wif);
    println!("Bitcoin Address: {}", bitcoin_address);
}
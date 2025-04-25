use bip39::{Mnemonic, Language};
use bip32::{ExtendedPrivateKey, ChildNumber};
use bitcoin::{Network, PrivateKey, PublicKey, Address};
use hex;
use k256::ecdsa::SigningKey;
use bitcoin::secp256k1::SecretKey;

fn main() {
    // Define the mnemonic phrase and passphrase
    let mnemonic_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let passphrase = ""; // Optional passphrase

    // Validate and create Mnemonic
    let mnemonic = match Mnemonic::parse_in(Language::English, mnemonic_phrase) {
        Ok(m) => m,
        Err(e) => {
            println!("Error: Invalid mnemonic phrase provided: {}", e);
            return;
        }
    };

    // Print mnemonic and passphrase for verification
    println!("Mnemonic Phrase: {}", mnemonic_phrase);
    println!("Passphrase: {}", if passphrase.is_empty() { "<empty>" } else { passphrase });

    // Generate seed from mnemonic and passphrase
    let seed = mnemonic.to_seed(passphrase);
    println!("Seed (hex): {}", hex::encode(&seed));

    // Create master extended private key
    let network = Network::Bitcoin;
    let xprv = match ExtendedPrivateKey::<SigningKey>::new(&seed) {
        Ok(key) => key,
        Err(e) => {
            println!("An unexpected error occurred: {}", e);
            return;
        }
    };

    // Define the derivation path: m/0'/0/0
    let path = vec![
        ChildNumber::new(0, true).unwrap(),  // m/0' (hardened)
        ChildNumber::new(0, false).unwrap(), // m/0'/0
        ChildNumber::new(0, false).unwrap(), // m/0'/0/0
    ];

    // Derive the child extended private key
    let mut current_key = xprv;
    for &child in &path {
        current_key = current_key.derive_child(child).expect("Failed to derive child key");
    }
    let child_xprv = current_key;

    // Extract private key (SigningKey)
    let signing_key = child_xprv.private_key();
    let private_key_hex = hex::encode(signing_key.to_bytes());

    // Derive public key (compressed form)
    let verifying_key = signing_key.verifying_key();
    let encoded_point = verifying_key.to_encoded_point(true);  // Compressed public key
    let pub_key_bytes = encoded_point.as_bytes();             // Borrow the bytes
    let public_key = PublicKey::from_slice(pub_key_bytes).expect("Invalid public key");
    let public_key_hex = hex::encode(pub_key_bytes);

    // Generate WIF from private key
    let private_key_bytes = signing_key.to_bytes();
    let secret_key = SecretKey::from_slice(&private_key_bytes).expect("Invalid private key");
    let privkey = PrivateKey::new(secret_key, network);
    let wif = privkey.to_wif();

    // Generate P2PKH address from public key
    let address = Address::p2pkh(&public_key, network).to_string();

    // Print the results in a structured format
    println!("{{");
    println!("  derivation_path: m/0'/0/0");
    println!("  address: {}", address);
    println!("  public_key: {}", public_key_hex);
    println!("  private_key: {}", private_key_hex);
    println!("  wif: {}", wif);
    println!("}}");
}
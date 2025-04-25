use bip39::{Mnemonic, Language};
use bip32::{ExtendedPrivateKey, ChildNumber};
use bitcoin::{Network, PrivateKey, PublicKey, Address};
use hex;
use k256::ecdsa::SigningKey;
use bitcoin::secp256k1::SecretKey;

fn main() {
    // Collect command-line arguments
    let args: Vec<String> = std::env::args().collect();
    
    // Validate argument count
    if args.len() < 2 || args.len() > 3 {
        println!("Usage: {} <mnemonic_phrase> [passphrase]", args[0]);
        return;
    }
    
    // Parse mnemonic phrase and passphrase
    let mnemonic_phrase = args[1].trim();
    let passphrase = if args.len() == 3 { args[2].as_str() } else { "" };

    // Display inputs for verification
    println!("Mnemonic Phrase: {}", mnemonic_phrase);
    println!("Passphrase: {}", if passphrase.is_empty() { "<empty>" } else { passphrase });

    // Parse mnemonic
    let mnemonic = match Mnemonic::parse_in(Language::English, mnemonic_phrase) {
        Ok(m) => m,
        Err(e) => {
            println!("Error: Invalid mnemonic phrase provided: {}", e);
            return;
        }
    };

    // Generate seed
    let seed = mnemonic.to_seed(passphrase);
    println!("Seed (hex): {}", hex::encode(&seed));

    // Derive master extended private key
    let network = Network::Bitcoin;
    let xprv = match ExtendedPrivateKey::<SigningKey>::new(&seed) {
        Ok(key) => key,
        Err(e) => {
            println!("An unexpected error occurred: {}", e);
            return;
        }
    };

    // Define parent derivation path: m/0'/0
    let parent_path = vec![
        ChildNumber::new(0, true).unwrap(),  // m/0' (hardened)
        ChildNumber::new(0, false).unwrap(), // m/0'/0
    ];

    // Derive parent key
    let mut current_key = xprv;
    for &child in &parent_path {
        current_key = current_key.derive_child(child).expect("Failed to derive child key");
    }
    let parent_xprv = current_key;

    // Generate 100 addresses
    for index in 0..100 {
        // Define child number for current index
        let child_number = ChildNumber::new(index, false).unwrap(); // m/0'/0/index
        let child_xprv = parent_xprv.derive_child(child_number).expect("Failed to derive child key");

        // Extract private key
        let signing_key = child_xprv.private_key();
        let private_key_hex = hex::encode(signing_key.to_bytes());

        // Derive public key (compressed)
        let verifying_key = signing_key.verifying_key();
        let encoded_point = verifying_key.to_encoded_point(true);
        let pub_key_bytes = encoded_point.as_bytes();
        let public_key = PublicKey::from_slice(pub_key_bytes).expect("Invalid public key");
        let public_key_hex = hex::encode(pub_key_bytes);

        // Generate WIF
        let secret_key = SecretKey::from_slice(&signing_key.to_bytes()).expect("Invalid private key");
        let privkey = PrivateKey::new(secret_key, network);
        let wif = privkey.to_wif();

        // Generate P2PKH address
        let address = Address::p2pkh(&public_key, network).to_string();

        // Print structured output
        println!("{{");
        println!("  derivation_path: m/0'/0/{}", index);
        println!("  address: {}", address);
        println!("  public_key: {}", public_key_hex);
        println!("  private_key: {}", private_key_hex);
        println!("  wif: {}", wif);
        println!("}}");
    }
}
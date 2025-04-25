use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Sha256, Digest};
use bitvec::prelude::*;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

// Function to read the wordlist from a file
fn read_wordlist<P: AsRef<Path>>(path: P) -> io::Result<Vec<String>> {
    let file = File::open(path)?;
    let reader = io::BufReader::new(file);
    let wordlist: Vec<String> = reader.lines().collect::<io::Result<Vec<String>>>()?;
    if wordlist.len() != 2048 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Wordlist must contain exactly 2048 words",
        ));
    }
    Ok(wordlist)
}

fn main() -> io::Result<()> {
    // Read the wordlist from bip-0039/english.txt
    let wordlist_path = "bip-0039/english.txt";
    let wordlist = read_wordlist(wordlist_path)?;

    // Parse command-line arguments for number of words
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        println!("Usage: {} <number_of_words>", args[0]);
        return Ok(());
    }

    let words: usize = match args[1].parse() {
        Ok(n) => n,
        Err(_) => {
            println!("Invalid number of words");
            return Ok(());
        }
    };

    // Validate number of words (must be 12, 15, 18, 21, or 24 per BIP39)
    if ![12, 15, 18, 21, 24].contains(&words) {
        println!("Number of words must be 12, 15, 18, 21, or 24");
        return Ok(());
    }

    // Calculate entropy size in bits (ENT = 32 * (words / 3))
    let ent_bits = (words / 3) * 32;
    let ent_bytes = ent_bits / 8;

    // Generate random entropy
    let mut entropy = vec![0u8; ent_bytes];
    OsRng.fill_bytes(&mut entropy);

    // Compute SHA-256 hash of entropy
    let hash = Sha256::digest(&entropy);

    // Calculate checksum size (CS = ENT / 32 bits)
    let cs_bits = ent_bits / 32;

    // Convert to bits with correct BitVec type parameters
    let entropy_bits = BitVec::<u8, Msb0>::from_slice(&entropy);
    let hash_bits = BitVec::<u8, Msb0>::from_slice(&hash);
    let checksum_bits = &hash_bits[..cs_bits];

    // Combine entropy and checksum
    let mut total_bits = entropy_bits;
    total_bits.extend_from_bitslice(checksum_bits);

    // Generate mnemonic by splitting into 11-bit chunks
    let mut mnemonic = Vec::new();
    for i in 0..words {
        let chunk = &total_bits[i * 11..i * 11 + 11];
        let index = (chunk.load_be::<u16>() >> 5) as usize;
        mnemonic.push(&wordlist[index]);
    }

    // Convert Vec<&String> to Vec<&str> and join with spaces
    let mnemonic_phrase: String = mnemonic.iter().map(|s| s.as_str()).collect::<Vec<&str>>().join(" ");
    println!("{}", mnemonic_phrase);

    Ok(())
}
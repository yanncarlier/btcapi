use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Sha256, Digest};
use bitvec::prelude::*;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;
use std::collections::HashMap;

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

    // Validate number of words (must be 12, 15, 18, 21, or 24 per BIP-39)
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
        let index = chunk.load_be::<u16>() as usize;
        mnemonic.push(&wordlist[index]);
    }

    // Convert Vec<&String> to Vec<&str> and join with spaces
    let mnemonic_phrase: String = mnemonic.iter().map(|s| s.as_str()).collect::<Vec<&str>>().join(" ");
    println!("{}", mnemonic_phrase);

    // Verify the mnemonic
    let word_to_index: HashMap<&str, usize> = wordlist.iter().enumerate().map(|(i, word)| (word.as_str(), i)).collect();
    let mnemonic_words: Vec<&str> = mnemonic_phrase.split_whitespace().collect();
    let mut recovered_bits = BitVec::<u8, Msb0>::new();
    for &word in &mnemonic_words {
        let index = *word_to_index.get(word).expect("Word not found in wordlist");
        let index_u16 = index as u16;
        for bit_pos in (0..11).rev() { // Push bits 10 to 0
            let bit = (index_u16 >> bit_pos) & 1;
            recovered_bits.push(bit != 0);
        }
    }
    let ent_bits = words * 11 - cs_bits; // Recalculate ent_bits if needed
    let entropy_recovered = &recovered_bits[0..ent_bits];
    let checksum_recovered = &recovered_bits[ent_bits..ent_bits + cs_bits];

    // Convert entropy_recovered to bytes manually
    let mut entropy_bytes = vec![0u8; (ent_bits + 7) / 8];
    for (i, bit) in entropy_recovered.iter().enumerate() {
        if *bit {
            let byte_index = i / 8;
            let bit_index = 7 - (i % 8);
            entropy_bytes[byte_index] |= 1 << bit_index;
        }
    }
    let entropy_bytes = &entropy_bytes[0..ent_bytes];

    // Compute hash and verify checksum
    let hash_recovered = Sha256::digest(entropy_bytes);
    let hash_bits_recovered = BitVec::<u8, Msb0>::from_slice(&hash_recovered);
    let checksum_computed = &hash_bits_recovered[0..cs_bits];

    if checksum_computed == checksum_recovered {
        // println!("Checksum is valid");
    } else {
        println!("Checksum is invalid");
    }

    Ok(())
}
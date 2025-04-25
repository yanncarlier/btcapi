use std::env;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::Path;
use std::collections::HashMap;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Sha256, Digest};
use bitvec::prelude::*;

// Function to read the wordlist from a file
fn read_wordlist<P: AsRef<Path>>(path: P) -> io::Result<Vec<String>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
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
    // Collect command-line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        println!("Usage: {} <wordlist_path> <number_of_words>", args[0]);
        return Ok(());
    }

    // Read the wordlist from the specified file path
    let wordlist = read_wordlist(&args[1])?;

    // Parse the number of words
    let words: usize = match args[2].parse() {
        Ok(n) => n,
        Err(_) => {
            println!("Invalid number of words: {}", args[2]);
            return Ok(());
        }
    };

    // Validate the number of words
    if ![12, 15, 18, 21, 24].contains(&words) {
        println!("Number of words must be 12, 15, 18, 21, or 24");
        return Ok(());
    }

    // Calculate entropy size in bits and bytes
    let ent_bits = (words / 3) * 32;
    let ent_bytes = ent_bits / 8;

    // Generate random entropy
    let mut entropy = vec![0u8; ent_bytes];
    OsRng.fill_bytes(&mut entropy);

    // Compute SHA-256 hash of the entropy
    let hash = Sha256::digest(&entropy);

    // Calculate checksum size in bits
    let cs_bits = ent_bits / 32;

    // Convert entropy and hash to bit vectors
    let entropy_bits = BitVec::<u8, Msb0>::from_slice(&entropy);
    let hash_bits = BitVec::<u8, Msb0>::from_slice(&hash);
    let checksum_bits = &hash_bits[0..cs_bits];

    // Combine entropy and checksum bits
    let mut total_bits = entropy_bits;
    total_bits.extend_from_bitslice(checksum_bits);

    // Generate the mnemonic by splitting into 11-bit chunks
    let mut mnemonic = Vec::new();
    for i in 0..words {
        let start = i * 11;
        let end = start + 11;
        let chunk = &total_bits[start..end];
        let index = chunk.load_be::<u16>() as usize;
        mnemonic.push(&wordlist[index]);
    }

    // Join the mnemonic words into a phrase and print it
    let mnemonic_phrase: String = mnemonic.iter().map(|s| s.as_str()).collect::<Vec<&str>>().join(" ");
    println!("{}", mnemonic_phrase);

    // Verification: Create a word-to-index mapping
    let word_to_index: HashMap<&str, usize> = wordlist
        .iter()
        .enumerate()
        .map(|(i, word)| (word.as_str(), i))
        .collect();

    // Split the mnemonic phrase back into words
    let mnemonic_words: Vec<&str> = mnemonic_phrase.split_whitespace().collect();

    // Recover the bits from the mnemonic words
    let mut recovered_bits = BitVec::<u8, Msb0>::new();
    for &word in &mnemonic_words {
        let index = *word_to_index.get(word).expect("Word not found in wordlist");
        let index_u16 = index as u16;
        for bit_pos in (0..11).rev() {
            let bit = (index_u16 >> bit_pos) & 1;
            recovered_bits.push(bit != 0);
        }
    }

    // Split recovered bits into entropy and checksum
    let recovered_ent_bits = words * 11 - cs_bits;
    let entropy_recovered = &recovered_bits[0..recovered_ent_bits];
    let checksum_recovered = &recovered_bits[recovered_ent_bits..recovered_ent_bits + cs_bits];

    // Convert recovered entropy bits back to bytes
    let mut entropy_bytes = vec![0u8; ent_bytes];
    for (i, bit) in entropy_recovered.iter().enumerate() {
        if *bit {
            let byte_index = i / 8;
            let bit_index = 7 - (i % 8);
            entropy_bytes[byte_index] |= 1 << bit_index;
        }
    }

    // Recompute the hash and checksum from recovered entropy
    let hash_recovered = Sha256::digest(&entropy_bytes);
    let hash_bits_recovered = BitVec::<u8, Msb0>::from_slice(&hash_recovered);
    let checksum_computed = &hash_bits_recovered[0..cs_bits];

    // Verify the checksum
    if checksum_computed != checksum_recovered {
        println!("Checksum is invalid");
    }

    Ok(())
}
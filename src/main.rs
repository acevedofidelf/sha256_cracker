use sha2::{Digest, Sha256}; // Cambiar importaciones
use std::{
    env,
    error::Error,
    fs::File,
    io::{BufRead, BufReader},
};
const SHA256_HEX_STRING_LENGTH: usize = 64; // Longitud del hash SHA-256

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        println!("Usage:");
        println!("sha256_cracker: <wordlist.txt> <sha256_hash>");
        return Ok(());
    }
    let hash_to_crack = args[2].trim();
    if hash_to_crack.len() != SHA256_HEX_STRING_LENGTH {
        return Err("sha256 hash is not valid".into());
    }
    let wordlist_file = File::open(&args[1])?;
    let reader = BufReader::new(&wordlist_file);
    for line in reader.lines() {
        let line = line?;
        let common_password = line.trim();
        let mut hasher = Sha256::new();
        hasher.update(common_password.as_bytes());
        let result = hasher.finalize();
        let hash_hex = hex::encode(result);
        if hash_to_crack == hash_hex {
            println!("Password found: {}", &common_password);
            return Ok(());
        }
    }
    println!("Password not found in wordlist :(");
    Ok(())
}
//! Test key generation utility
//!
//! Generates BLS12-381 validator keypairs and saves them as EIP-2335 JSON keystores.

use anyhow::{Context, Result};
use nklave_core::BlsKeypair;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    let mut count = 1usize;
    let mut output_dir = PathBuf::from("./keys");
    let mut password = "testpassword".to_string();

    // Simple argument parsing
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--count" | "-c" => {
                i += 1;
                count = args.get(i).map(|s| s.parse().unwrap_or(1)).unwrap_or(1);
            }
            "--output" | "-o" => {
                i += 1;
                if let Some(path) = args.get(i) {
                    output_dir = PathBuf::from(path);
                }
            }
            "--password" | "-p" => {
                i += 1;
                if let Some(pwd) = args.get(i) {
                    password = pwd.clone();
                }
            }
            "--help" | "-h" => {
                print_help();
                return Ok(());
            }
            _ => {}
        }
        i += 1;
    }

    // Create output directory
    std::fs::create_dir_all(&output_dir)
        .with_context(|| format!("Failed to create output directory: {}", output_dir.display()))?;

    println!("Generating {} test validator key(s)...", count);

    for i in 0..count {
        let keypair = BlsKeypair::generate();
        let pubkey_bytes = keypair.public_key_bytes();
        let pubkey_hex = hex::encode(pubkey_bytes);

        // Create keystore JSON (simplified version)
        let keystore = create_keystore(&keypair, &password)?;

        // Save to file
        let filename = format!("keystore-{}.json", &pubkey_hex[..16]);
        let filepath = output_dir.join(&filename);

        std::fs::write(&filepath, keystore)
            .with_context(|| format!("Failed to write keystore: {}", filepath.display()))?;

        println!(
            "  [{}/{}] Created: {} (pubkey: 0x{}...{})",
            i + 1,
            count,
            filename,
            &pubkey_hex[..8],
            &pubkey_hex[pubkey_hex.len() - 8..]
        );
    }

    println!("\nKeys saved to: {}", output_dir.display());
    println!("\nTo use these keys with nklave:");
    println!("  export NKLAVE_KEYSTORE_PASSWORD={}", password);
    println!("  cargo run --release");

    Ok(())
}

fn print_help() {
    println!("generate-test-keys - Generate test validator keys for nklave");
    println!();
    println!("USAGE:");
    println!("    generate-test-keys [OPTIONS]");
    println!();
    println!("OPTIONS:");
    println!("    -c, --count <NUM>       Number of keys to generate (default: 1)");
    println!("    -o, --output <DIR>      Output directory (default: ./keys)");
    println!("    -p, --password <PWD>    Keystore password (default: testpassword)");
    println!("    -h, --help              Print this help message");
}

/// Create an EIP-2335 keystore JSON for the given keypair
fn create_keystore(keypair: &BlsKeypair, password: &str) -> Result<String> {
    use aes::cipher::{KeyIvInit, StreamCipher};

    type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;

    // Generate random salt and IV
    let mut salt = [0u8; 32];
    let mut iv = [0u8; 16];
    fill_random(&mut salt);
    fill_random(&mut iv);

    // Derive key using scrypt (simplified parameters for testing)
    let scrypt_params = scrypt::Params::new(14, 8, 1, 32).unwrap(); // n=16384
    let mut decryption_key = [0u8; 32];
    scrypt::scrypt(password.as_bytes(), &salt, &scrypt_params, &mut decryption_key).unwrap();

    // Encrypt the secret key
    let secret_bytes = keypair.secret.to_bytes();
    let aes_key: [u8; 16] = decryption_key[0..16].try_into().unwrap();
    let mut cipher = Aes128Ctr::new(&aes_key.into(), &iv.into());
    let mut ciphertext = secret_bytes.to_vec();
    cipher.apply_keystream(&mut ciphertext);

    // Compute checksum
    let mut hasher = Sha256::new();
    hasher.update(&decryption_key[16..32]);
    hasher.update(&ciphertext);
    let checksum: [u8; 32] = hasher.finalize().into();

    // Build keystore JSON
    let pubkey_hex = format!("0x{}", hex::encode(keypair.public_key_bytes()));

    let keystore = serde_json::json!({
        "crypto": {
            "kdf": {
                "function": "scrypt",
                "params": {
                    "dklen": 32,
                    "n": 16384,
                    "p": 1,
                    "r": 8,
                    "salt": hex::encode(salt)
                },
                "message": ""
            },
            "checksum": {
                "function": "sha256",
                "params": {},
                "message": hex::encode(checksum)
            },
            "cipher": {
                "function": "aes-128-ctr",
                "params": {
                    "iv": hex::encode(iv)
                },
                "message": hex::encode(ciphertext)
            }
        },
        "description": "Test validator key",
        "pubkey": pubkey_hex,
        "path": "m/12381/3600/0/0/0",
        "uuid": uuid::Uuid::new_v4().to_string(),
        "version": 4
    });

    Ok(serde_json::to_string_pretty(&keystore)?)
}

fn fill_random(dest: &mut [u8]) {
    use std::io::Read;

    #[cfg(unix)]
    {
        let mut file = std::fs::File::open("/dev/urandom").expect("Failed to open /dev/urandom");
        file.read_exact(dest).expect("Failed to read random bytes");
    }

    #[cfg(windows)]
    {
        for byte in dest.iter_mut() {
            *byte = (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos() as u8)
                .wrapping_add(*byte);
        }
    }
}

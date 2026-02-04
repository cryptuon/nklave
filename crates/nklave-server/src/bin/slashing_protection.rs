//! EIP-3076 Slashing Protection CLI
//!
//! Import and export slashing protection data in EIP-3076 interchange format.

use anyhow::{Context, Result};
use nklave_storage::{Checkpoint, Eip3076Interchange};
use std::collections::HashMap;
use std::path::PathBuf;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        print_help();
        return Ok(());
    }

    match args[1].as_str() {
        "import" => cmd_import(&args[2..])?,
        "export" => cmd_export(&args[2..])?,
        "--help" | "-h" | "help" => print_help(),
        _ => {
            eprintln!("Unknown command: {}", args[1]);
            print_help();
            std::process::exit(1);
        }
    }

    Ok(())
}

fn print_help() {
    println!("slashing-protection - EIP-3076 Slashing Protection CLI");
    println!();
    println!("USAGE:");
    println!("    slashing-protection <COMMAND> [OPTIONS]");
    println!();
    println!("COMMANDS:");
    println!("    import    Import slashing protection data from EIP-3076 JSON");
    println!("    export    Export slashing protection data to EIP-3076 JSON");
    println!("    help      Print this help message");
    println!();
    println!("IMPORT OPTIONS:");
    println!("    -i, --input <FILE>      Input EIP-3076 JSON file");
    println!("    -d, --data-dir <DIR>    Data directory containing checkpoint (default: ./data)");
    println!();
    println!("EXPORT OPTIONS:");
    println!("    -o, --output <FILE>     Output EIP-3076 JSON file");
    println!("    -d, --data-dir <DIR>    Data directory containing checkpoint (default: ./data)");
    println!();
    println!("EXAMPLES:");
    println!("    slashing-protection import -i lighthouse_export.json -d ./data");
    println!("    slashing-protection export -o backup.json -d ./data");
}

fn cmd_import(args: &[String]) -> Result<()> {
    let mut input_path: Option<PathBuf> = None;
    let mut data_dir = PathBuf::from("./data");

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-i" | "--input" => {
                i += 1;
                if let Some(path) = args.get(i) {
                    input_path = Some(PathBuf::from(path));
                }
            }
            "-d" | "--data-dir" => {
                i += 1;
                if let Some(path) = args.get(i) {
                    data_dir = PathBuf::from(path);
                }
            }
            _ => {}
        }
        i += 1;
    }

    let input_path = input_path.context("Missing required -i/--input argument")?;

    println!("Importing EIP-3076 data from: {}", input_path.display());
    println!("Data directory: {}", data_dir.display());

    // Load the EIP-3076 interchange file
    let interchange = Eip3076Interchange::import(&input_path)
        .with_context(|| format!("Failed to load EIP-3076 file: {}", input_path.display()))?;

    let genesis_root = interchange.genesis_validators_root()
        .context("Failed to parse genesis validators root")?;

    println!(
        "Genesis validators root: 0x{}",
        hex::encode(genesis_root)
    );
    println!(
        "Number of validators in file: {}",
        interchange.data.len()
    );

    // Load existing checkpoint or start fresh
    let checkpoint_path = data_dir.join("checkpoint.json");
    let mut validators = if checkpoint_path.exists() {
        let checkpoint = Checkpoint::load(&checkpoint_path)
            .with_context(|| "Failed to load existing checkpoint")?;
        println!(
            "Loaded existing checkpoint with {} validators",
            checkpoint.validators.len()
        );
        checkpoint.validators
    } else {
        println!("No existing checkpoint found, starting fresh");
        HashMap::new()
    };

    // Apply the interchange data
    interchange
        .apply_to_validators(&mut validators)
        .context("Failed to apply EIP-3076 data")?;

    // Save the updated checkpoint
    std::fs::create_dir_all(&data_dir)
        .with_context(|| format!("Failed to create data directory: {}", data_dir.display()))?;

    let checkpoint = Checkpoint {
        sequence: 0, // Will be updated on next signing operation
        state_hash: [0u8; 32],
        genesis_validators_root: Some(genesis_root),
        validators,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };

    checkpoint
        .save(&checkpoint_path)
        .with_context(|| "Failed to save checkpoint")?;

    println!("Successfully imported slashing protection data");
    println!("Checkpoint saved to: {}", checkpoint_path.display());

    Ok(())
}

fn cmd_export(args: &[String]) -> Result<()> {
    let mut output_path: Option<PathBuf> = None;
    let mut data_dir = PathBuf::from("./data");

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-o" | "--output" => {
                i += 1;
                if let Some(path) = args.get(i) {
                    output_path = Some(PathBuf::from(path));
                }
            }
            "-d" | "--data-dir" => {
                i += 1;
                if let Some(path) = args.get(i) {
                    data_dir = PathBuf::from(path);
                }
            }
            _ => {}
        }
        i += 1;
    }

    let output_path = output_path.context("Missing required -o/--output argument")?;

    println!("Exporting EIP-3076 data to: {}", output_path.display());
    println!("Data directory: {}", data_dir.display());

    // Load checkpoint
    let checkpoint_path = data_dir.join("checkpoint.json");
    if !checkpoint_path.exists() {
        anyhow::bail!("No checkpoint found at: {}", checkpoint_path.display());
    }

    let checkpoint = Checkpoint::load(&checkpoint_path)
        .with_context(|| "Failed to load checkpoint")?;

    let genesis_root = checkpoint
        .genesis_validators_root
        .context("Checkpoint does not have a genesis validators root")?;

    println!(
        "Genesis validators root: 0x{}",
        hex::encode(genesis_root)
    );
    println!(
        "Number of validators: {}",
        checkpoint.validators.len()
    );

    // Create the interchange format
    let validator_refs: Vec<_> = checkpoint.validators.values().collect();
    let interchange = Eip3076Interchange::from_validators(genesis_root, &validator_refs);

    // Export to file
    interchange
        .export(&output_path)
        .with_context(|| format!("Failed to export to: {}", output_path.display()))?;

    println!("Successfully exported slashing protection data");
    println!("Output saved to: {}", output_path.display());

    // Print summary
    let total_blocks: usize = interchange
        .data
        .iter()
        .map(|v| v.signed_blocks.len())
        .sum();
    let total_attestations: usize = interchange
        .data
        .iter()
        .map(|v| v.signed_attestations.len())
        .sum();

    println!();
    println!("Summary:");
    println!("  Validators: {}", interchange.data.len());
    println!("  Signed blocks: {}", total_blocks);
    println!("  Signed attestations: {}", total_attestations);

    Ok(())
}

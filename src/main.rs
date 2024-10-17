use std::path::PathBuf;

use anyhow::Result;
use serde_json::Value;

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("! No JSON file was provided for the chalenge definition");
    }
    let path: PathBuf = args[1].clone().into();
    eprintln!("* Path of the challenge definition: {:?}", path);
    eprintln!("* Reading the challenge definition into memory");

    let json_value: Value = serde_json::from_str(&std::fs::read_to_string(&path)?)
        .expect("challenge definition contains invalid JSON");
    eprintln!("? Dump of challenge: {json_value:#}");

    kauma_analyzer::challenge::run_challenge(&json_value)?;

    Ok(())
}

use std::path::PathBuf;

use anyhow::{anyhow, Result};
use serde_json::Value;

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("! No JSON file was provided for the chalenge definition");
        return Err(anyhow!("no JSON file provided"));
    }
    let path: PathBuf = args[1].clone().into();
    eprintln!("* Path of the challenge definition: {:?}", path);
    eprintln!("* Reading the challenge definition into memory");

    let raw_text = std::fs::read_to_string(&path)
        .inspect_err(|e| eprintln!("! Could not read the challenge definition file: {e}"))?;
    let json_value: Value = serde_json::from_str(&raw_text).inspect_err(|e| {
        eprintln!("! Could not parse the text of the challenge definition file as JSON: {e}")
    })?;
    eprintln!("? challenge definition: {json_value:#}");

    kauma_analyzer::challenge::run_challenge(&json_value)?;

    Ok(())
}

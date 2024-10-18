use std::path::PathBuf;

use anyhow::{anyhow, Result};
use kauma_analyzer::challenge::{ManyTestcases, Testcase};
use serde_json::Value;
use uuid::Uuid;

fn main() -> Result<()> {
    #[cfg(debug_assertions)]
    {
        eprintln!(
            "? Example Testcase\n{:#}",
            serde_json::to_string(&Testcase::default())
                .expect("could not serialize testcase struct")
        );

        let mut exhm = ManyTestcases::new();
        exhm.insert(Uuid::default(), Testcase::default());
        eprintln!(
            "? Example ManyTestcases\n{:#}",
            serde_json::to_string(&exhm).expect("could not serialize testcase struct")
        )
    }

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

    // print our response to stdout
    println!(
        "{}",
        kauma_analyzer::challenge::run_challenges(&json_value)?
    );

    Ok(())
}

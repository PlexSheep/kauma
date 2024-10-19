//! Helps parse a few common datatypes from the JSON challenge definitions and write them back out

use anyhow::{anyhow, Result};
use base64::prelude::*;

/// Convert the base64 string of the JSON challenge definition to a [Vec<u8>].
///
/// All binary data is encoded in base64 strings.
pub fn get_bytes(args: &serde_json::Value, key: &str) -> Result<Vec<u8>> {
    let bytes: Vec<u8> = if args[key].is_string() {
        let v: String = serde_json::from_value(args[key].clone())
            .inspect_err(|e| eprintln!("! something went wrong when serializing {key}: {e}"))?;
        BASE64_STANDARD.decode(v)?
    } else {
        return Err(anyhow!("{key} is not a string"));
    };
    Ok(bytes)
}

/// Convert from [Vec<u8>] to a [serde_json::Value] with a [base64] string encoding that data.
#[inline]
pub fn put_bytes(data: &Vec<u8>) -> Result<serde_json::Value> {
    Ok(BASE64_STANDARD.encode(data).into())
}

//! Helps parse a few common datatypes from the JSON challenge definitions and write them back out

use std::fmt::Write;

use anyhow::{anyhow, Result};
use base64::prelude::*;

///  Hex encoded [String] to [byte](u8) slice
pub fn decode_hex(s: &str) -> Result<Vec<u8>, std::num::ParseIntError> {
    let mut s: String = s.to_string();
    if s.starts_with("0x") {
        s = s.strip_prefix("0x").unwrap().into();
    }
    if s.len() % 2 == 1 {
        s = format!("0{s}");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

/// [Byte](u8) slice to hex encoded [String]
pub fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

/// Convert the base64 string of the JSON challenge definition to a [`Vec<u8>`].
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

/// Convert from [`Vec<u8>`] to a [serde_json::Value] with a [base64] string encoding that data.
#[inline]
pub fn put_bytes(data: &Vec<u8>) -> Result<serde_json::Value> {
    Ok(BASE64_STANDARD.encode(data).into())
}

#[cfg(test)]
mod test {
    use crate::common::interface::{decode_hex, encode_hex};

    #[test]
    fn test_decode_hex() {
        assert_eq!(decode_hex("0x1337").unwrap(), &[0x13, 0x37]);
        assert_eq!(decode_hex("1337").unwrap(), &[0x13, 0x37]);
        assert_eq!(decode_hex("0337").unwrap(), &[0x03, 0x37]);
        assert_eq!(decode_hex("337").unwrap(), &[0x03, 0x37]);
        assert_eq!(decode_hex("0x0337").unwrap(), &[0x03, 0x37]);
        assert_eq!(decode_hex("0x337").unwrap(), &[0x03, 0x37]);
        assert_eq!(
            decode_hex(
                "0x4141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141"
            )
            .unwrap(),
            &[
                0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            ]
        );
    }

    #[test]
    fn test_encode_hex() {
        assert_eq!("1337", encode_hex(&[0x13, 0x37]));
        assert_eq!("0337", encode_hex(&[0x03, 0x37]));
        assert_eq!(
                "4141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141",
            encode_hex(
            &[
                0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            ])
        );
    }
}

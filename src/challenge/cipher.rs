use anyhow::{anyhow, Result};
use openssl::symm::{Cipher, Crypter, Mode as OpenSslMode};
use serde::{Deserialize, Serialize};

use crate::common::interface::{get_bytes, put_bytes};
use crate::common::vec_to_arr;

use super::{Action, Testcase};

pub const SEA_128_MAGIC_NUMBER: u128 = 0xc0ffeec0ffeec0ffeec0ffeec0ffee11;
pub const SEA_128_MAGIC_NUMBER_ARR: [u8; 16] = [
    0xc0, 0xff, 0xee, 0xc0, 0xff, 0xee, 0xc0, 0xff, 0xee, 0xc0, 0xff, 0xee, 0xc0, 0xff, 0xee, 0x11,
];

#[derive(Debug, Deserialize, Serialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Encrypt,
    Decrypt,
}

impl From<OpenSslMode> for Mode {
    fn from(value: OpenSslMode) -> Self {
        match value {
            OpenSslMode::Decrypt => Mode::Decrypt,
            OpenSslMode::Encrypt => Mode::Encrypt,
        }
    }
}

impl From<Mode> for OpenSslMode {
    fn from(value: Mode) -> Self {
        match value {
            Mode::Decrypt => Self::Decrypt,
            Mode::Encrypt => Self::Encrypt,
        }
    }
}

pub fn sea_128_encrypt(key: &[u8; 16], data: &[u8; 16]) -> Result<Vec<u8>> {
    eprintln!("? key:\t\t{key:02x?}");

    let mut crypter = Crypter::new(Cipher::aes_128_ecb(), OpenSslMode::Encrypt, key, None)?;
    crypter.pad(false);

    eprintln!("? data:\t\t{data:02x?}");

    // NOTE: openssl panics if the buffer is not at least 32 bytes
    let mut enc: Vec<u8> = [0; 32].to_vec();
    let mut pos: usize;
    pos = crypter
        .update(data, &mut enc)
        .inspect_err(|e| eprintln!("! error while encrypting with sea_128: {e:#?}"))?;
    pos += crypter
        .finalize(&mut enc)
        .inspect_err(|e| eprintln!("! error while encrypting with sea_128: {e:#?}"))?;
    enc.truncate(pos);

    eprintln!("? enc:\t\t{enc:02x?}");

    eprintln!("? sea_magic:\t{SEA_128_MAGIC_NUMBER_ARR:02x?}");
    // xor with the SEA_128_MAGIC_NUMBER
    for chunk in enc.chunks_exact_mut(16) {
        assert_eq!(chunk.len(), 16);
        for (n, magic_number) in chunk.iter_mut().zip(SEA_128_MAGIC_NUMBER_ARR) {
            *n ^= magic_number;
        }
    }

    eprintln!("? xor:\t\t{enc:02x?}");
    Ok(enc.to_vec())
}

pub fn sea_128_decrypt(key: &[u8; 16], enc: &[u8; 16]) -> Result<Vec<u8>> {
    eprintln!("? key:\t\t{key:02x?}");

    let mut crypter = Crypter::new(Cipher::aes_128_ecb(), OpenSslMode::Decrypt, key, None)?;
    crypter.pad(false);

    eprintln!("? enc:\t\t{enc:02x?}");

    eprintln!("? sea_magic:\t{SEA_128_MAGIC_NUMBER_ARR:02x?}");
    let mut dxor = enc.to_vec();
    // xor with the SEA_128_MAGIC_NUMBER
    for chunk in dxor.chunks_exact_mut(16) {
        assert_eq!(chunk.len(), 16);
        for (n, magic_number) in chunk.iter_mut().zip(SEA_128_MAGIC_NUMBER_ARR) {
            *n ^= magic_number;
        }
    }

    eprintln!("? dxor:\t\t{dxor:02x?}");

    // NOTE: openssl panics if the buffer is not at least 32 bytes
    let mut denc: Vec<u8> = [0; 32].to_vec();
    let mut pos: usize;
    pos = crypter
        .update(&dxor, &mut denc)
        .inspect_err(|e| eprintln!("! error while decrypting with sea_128: {e:#?}"))?;
    pos += crypter
        .finalize(&mut denc[pos..])
        .inspect_err(|e| eprintln!("! error while decrypting with sea_128: {e:#?}"))?;
    denc.truncate(pos);

    eprintln!("? denc:\t\t{denc:02x?}");

    Ok(denc.to_vec())
}

pub fn run_testcase(testcase: &Testcase) -> Result<serde_json::Value> {
    Ok(match testcase.action {
        Action::Sea128 => {
            let mode = get_mode(&testcase.arguments)?;
            let key = get_bytes(&testcase.arguments, "key")?;
            let input = get_bytes(&testcase.arguments, "input")?;

            let key: [u8; 16] = vec_to_arr(&key)?;
            let input: [u8; 16] = vec_to_arr(&input)?;

            let output = match mode {
                Mode::Encrypt => sea_128_encrypt(&key, &input)?,
                Mode::Decrypt => sea_128_decrypt(&key, &input)?,
            };
            put_bytes(&output)?
        }
        _ => unreachable!(),
    })
}

fn get_mode(args: &serde_json::Value) -> Result<Mode> {
    let semantic: Mode = if args["mode"].is_string() {
        serde_json::from_value(args["mode"].clone())
            .inspect_err(|e| eprintln!("! something went wrong when serializing the mode: {e}"))?
    } else {
        return Err(anyhow!("mode is not a string"));
    };
    Ok(semantic)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_sea_128_encrypt_decrypt() {
        const PLAIN: [u8; 16] = *b"foobarqux amogus";
        const KEY: [u8; 16] = *b"1238742fsaflk249";

        let enc = sea_128_encrypt(&KEY, &PLAIN).expect("encrypt fail");
        let enc = vec_to_arr(&enc).expect("could not convert from vec to arr");
        let denc = sea_128_decrypt(&KEY, &enc).expect("decrypt fail");

        assert_eq!(denc, PLAIN);
    }

    #[test]
    fn test_openssl_aes_128_ecb_encrypt_decrypt() {
        const PLAIN: [u8; 16] = *b"foobarqux amogus";
        const KEY: [u8; 16] = *b"1238742fsaflk249";

        let mut crypter_e =
            Crypter::new(Cipher::aes_128_ecb(), OpenSslMode::Encrypt, &KEY, None).unwrap();
        let mut crypter_d =
            Crypter::new(Cipher::aes_128_ecb(), OpenSslMode::Decrypt, &KEY, None).unwrap();
        crypter_d.pad(false);
        crypter_e.pad(false);

        let mut buf = [0; 32].to_vec();
        let mut position: usize;
        position = crypter_e.update(&PLAIN, &mut buf).expect("encrypt failed");
        position += crypter_e
            .finalize(&mut buf[position..])
            .expect("encrypt final failed");
        buf.truncate(position);

        let cipher = buf;
        let mut buf = [0; 32].to_vec();
        eprintln!("ciphertext: {cipher:02x?}");

        position = crypter_d.update(&cipher, &mut buf).expect("decrypt failed");
        position += crypter_d
            .finalize(&mut buf[position..])
            .expect("decrypt final failed");
        buf.truncate(position);

        assert_eq!(PLAIN.to_vec(), buf);
    }
}

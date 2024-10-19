use anyhow::{anyhow, Result};
use openssl::symm::{decrypt, encrypt, Cipher, Crypter, Mode as OpenSslMode};
use serde::{Deserialize, Serialize};

use crate::common::interface::{get_bytes, put_bytes};
use crate::common::{bytes_to_u128, vec_to_arr};

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
    let mut crypter = Crypter::new(Cipher::aes_128_ecb(), OpenSslMode::Encrypt, key, None)?;
    crypter.pad(false);

    eprintln!("? data:\t\t{data:02x?}");

    // NOTE: openssl panics if the buffer is not at least 32 bytes
    let mut enc: Vec<u8> = [0; 32].to_vec();
    crypter
        .update(data, &mut enc)
        .inspect_err(|e| eprintln!("! error while encrypting with sea_128: {e:#?}"))?;
    crypter
        .finalize(&mut enc)
        .inspect_err(|e| eprintln!("! error while encrypting with sea_128: {e:#?}"))?;

    // NOTE: openssl returns more than the length of the data in some cases, perhaps because of
    // padding. This does not seem to be needed for the testcases, so I limit the length of the
    // ciphertext to that of the data.

    enc.truncate(data.len());

    eprintln!("? pxor:\t\t{enc:02x?}");

    // xor with the SEA_128_MAGIC_NUMBER
    for chunk in enc.chunks_exact_mut(16) {
        assert_eq!(chunk.len(), 16);
        for (n, magic_number) in chunk.iter_mut().zip(SEA_128_MAGIC_NUMBER_ARR) {
            *n ^= magic_number;
        }
    }

    eprintln!("? enc:\t\t{enc:02x?}");
    Ok(enc.to_vec())
}

pub fn sea_128_decrypt(key: &[u8; 16], enc: &[u8; 16]) -> Result<Vec<u8>> {
    let mut crypter = Crypter::new(Cipher::aes_128_ecb(), OpenSslMode::Decrypt, key, None)?;
    crypter.pad(false);

    eprintln!("? denc:\t\t{enc:02x?}");

    // xor with the SEA_128_MAGIC_NUMBER
    for chunk in enc.to_vec().chunks_exact_mut(16) {
        assert_eq!(chunk.len(), 16);
        for (n, magic_number) in chunk.iter_mut().zip(SEA_128_MAGIC_NUMBER_ARR) {
            *n ^= magic_number;
        }
    }

    eprintln!("? dxor:\t\t{enc:02x?}");

    // NOTE: openssl panics if the buffer is not at least 32 bytes
    let mut denc: Vec<u8> = [0; 32].to_vec();
    crypter
        .update(enc, &mut denc)
        .inspect_err(|e| eprintln!("! error while decrypting with sea_128: {e:#?}"))?;
    crypter
        .finalize(&mut denc)
        .inspect_err(|e| eprintln!("! error while decrypting with sea_128: {e:#?}"))?;

    // NOTE: openssl returns more than the length of the data in some cases, perhaps because of
    // padding. This does not seem to be needed for the testcases, so I limit the length of the
    // ciphertext to that of the data.

    denc.truncate(enc.len());
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
        crypter_e.update(&PLAIN, &mut buf).expect("encrypt failed");
        crypter_e.finalize(&mut buf).expect("encrypt final failed");
        eprintln!("ciphertext: {buf:02x?}");
        crypter_d.update(&PLAIN, &mut buf).expect("decrypt failed");
        crypter_d.finalize(&mut buf).expect("decrypt final failed");

        assert_eq!(PLAIN.to_vec(), buf);
    }
}

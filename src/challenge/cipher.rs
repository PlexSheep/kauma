use anyhow::{anyhow, Result};
use openssl::symm::{Cipher, Crypter, Mode as OpenSslMode};
use serde::{Deserialize, Serialize};

use crate::common::interface::{get_bytes_base64, put_bytes};
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
    pos = crypter.update(data, &mut enc).map_err(|e| {
        eprintln!("! error while encrypting with sea_128: {e:#?}");
        e
    })?;
    pos += crypter.finalize(&mut enc).map_err(|e| {
        eprintln!("! error while encrypting with sea_128: {e:#?}");
        e
    })?;
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
    pos = crypter.update(&dxor, &mut denc).map_err(|e| {
        eprintln!("! error while decrypting with sea_128: {e:#?}");
        e
    })?;
    pos += crypter.finalize(&mut denc[pos..]).map_err(|e| {
        eprintln!("! error while decrypting with sea_128: {e:#?}");
        e
    })?;
    denc.truncate(pos);

    eprintln!("? denc:\t\t{denc:02x?}");

    Ok(denc.to_vec())
}

pub fn run_testcase(testcase: &Testcase) -> Result<serde_json::Value> {
    Ok(match testcase.action {
        Action::Sea128 => {
            let mode = get_mode(&testcase.arguments)?;
            let key = get_bytes_base64(&testcase.arguments, "key")?;
            let input = get_bytes_base64(&testcase.arguments, "input")?;

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
        serde_json::from_value(args["mode"].clone()).map_err(|e| {
            eprintln!("! something went wrong when serializing the mode: {e}");
            e
        })?
    } else {
        return Err(anyhow!("mode is not a string"));
    };
    Ok(semantic)
}

#[cfg(test)]
mod test {
    use super::*;

    fn assert_hex(data: &[u8], correct: &[u8]) {
        assert_eq!(data, correct, "\n{data:02X?}\nshould be\n{correct:02X?}");
    }

    #[test]
    fn test_sea_128_encrypt_decrypt() {
        const PLAIN: [u8; 16] = *b"foobarqux amogus";
        const KEY: [u8; 16] = *b"1238742fsaflk249";

        let enc = sea_128_encrypt(&KEY, &PLAIN).expect("encrypt fail");
        let enc = vec_to_arr(&enc).expect("could not convert from vec to arr");
        let denc = sea_128_decrypt(&KEY, &enc).expect("decrypt fail");

        assert_hex(&denc, &PLAIN);
    }

    #[test]
    fn test_sea_128_encrypt() {
        const PLAIN: [u8; 16] = [
            0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88, 0x88, 0x33,
            0x44, 0x55,
        ];
        const KEY: [u8; 16] = [
            0x8a, 0xcb, 0x43, 0x01, 0x27, 0xa2, 0x9d, 0xca, 0x28, 0x95, 0xea, 0xca, 0x11, 0x8a,
            0xe8, 0x7e,
        ];
        const ENC: [u8; 16] = [
            0xf, 0x91, 0x43, 0xa3, 0x78, 0x95, 0x6, 0x80, 0x4d, 0xf6, 0x5, 0x62, 0xf7, 0xf3, 0x12,
            0x29,
        ];

        assert_hex(
            &sea_128_encrypt(&KEY, &PLAIN).expect("could not encrypt"),
            &ENC,
        );
    }

    #[test]
    fn test_sea_128_decrypt() {
        const PLAIN: [u8; 16] = [
            0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88, 0x88, 0x33,
            0x44, 0x55,
        ];
        const KEY: [u8; 16] = [
            0x8a, 0xcb, 0x43, 0x01, 0x27, 0xa2, 0x9d, 0xca, 0x28, 0x95, 0xea, 0xca, 0x11, 0x8a,
            0xe8, 0x7e,
        ];
        const ENC: [u8; 16] = [
            0xf, 0x91, 0x43, 0xa3, 0x78, 0x95, 0x6, 0x80, 0x4d, 0xf6, 0x5, 0x62, 0xf7, 0xf3, 0x12,
            0x29,
        ];

        assert_hex(
            &sea_128_decrypt(&KEY, &ENC).expect("could not decrypt"),
            &PLAIN,
        );
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

        assert_hex(&PLAIN, &buf);
    }
}

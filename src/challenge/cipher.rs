use anyhow::{anyhow, Result};
use openssl::symm::{Cipher, Crypter, Mode as OpenSslMode};
use serde::{Deserialize, Serialize};

use crate::common::interface::{get_bytes_base64, put_bytes};
use crate::common::{bytes_to_u128, len_to_const_arr, veprintln};
use crate::settings::Settings;

use super::ffield::{F_2_128, F_2_128_ALPHA};
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

#[derive(Debug, Deserialize, Serialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum PrimitiveAlgorithm {
    Aes128,
    Sea128,
}

pub struct GcmEncrypted {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub auth_tag: [u8; 16],
    pub authentic: bool,
}

pub struct GcmDecrypted {
    pub nonce: [u8; 12],
    pub associated_data: Vec<u8>,
    pub plaintext: Vec<u8>,
}

impl PrimitiveAlgorithm {
    pub fn encrypt(self, key: &[u8; 16], data: &[u8], verbose: bool) -> Result<Vec<u8>> {
        match self {
            Self::Sea128 => Ok(sea_128_encrypt(key, data, verbose)?),
            Self::Aes128 => Ok(aes_128_encrypt(key, data, verbose)?),
        }
    }

    pub fn decrypt(self, key: &[u8; 16], ciphertext: &[u8], verbose: bool) -> Result<Vec<u8>> {
        match self {
            Self::Sea128 => Ok(sea_128_decrypt(key, ciphertext, verbose)?),
            Self::Aes128 => Ok(aes_128_decrypt(key, ciphertext, verbose)?),
        }
    }
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

pub fn aes_128_encrypt(key: &[u8; 16], data: &[u8], _verbose: bool) -> Result<Vec<u8>> {
    if data.len() % 16 != 0 {
        return Err(anyhow!(
            "data length is not a multiple of 16: {}",
            data.len()
        ));
    }

    let mut crypter = Crypter::new(Cipher::aes_128_ecb(), OpenSslMode::Encrypt, key, None)?;
    crypter.pad(false);

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

    Ok(enc)
}

pub fn aes_128_decrypt(key: &[u8; 16], enc: &[u8], verbose: bool) -> Result<Vec<u8>> {
    let mut crypter = Crypter::new(Cipher::aes_128_ecb(), OpenSslMode::Decrypt, key, None)?;
    crypter.pad(false);

    // NOTE: openssl panics if the buffer is not at least 32 bytes
    let mut denc: Vec<u8> = [0; 32].to_vec();
    let mut pos: usize;
    pos = crypter.update(enc, &mut denc).map_err(|e| {
        eprintln!("! error while decrypting with sea_128: {e:#?}");
        e
    })?;
    pos += crypter.finalize(&mut denc[pos..]).map_err(|e| {
        eprintln!("! error while decrypting with sea_128: {e:#?}");
        e
    })?;
    denc.truncate(pos);

    if verbose {
        eprintln!("? denc:\t\t{denc:02x?}");
    }

    Ok(denc)
}

pub fn sea_128_encrypt(key: &[u8; 16], data: &[u8], verbose: bool) -> Result<Vec<u8>> {
    if data.len() % 16 != 0 {
        return Err(anyhow!(
            "data length is not a multiple of 16: {}",
            data.len()
        ));
    }
    if verbose {
        veprintln("key", format_args!("{key:02x?}"))
    }

    let mut crypter = Crypter::new(Cipher::aes_128_ecb(), OpenSslMode::Encrypt, key, None)?;
    crypter.pad(false);

    if verbose {
        veprintln("data", format_args!("{data:02x?}"))
    }

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

    if verbose {
        veprintln("enc", format_args!("{enc:02x?}"));
        veprintln(
            "sea_magic",
            format_args!("{:02x?}", SEA_128_MAGIC_NUMBER_ARR),
        );
    }
    // xor with the SEA_128_MAGIC_NUMBER
    for chunk in enc.chunks_exact_mut(16) {
        assert_eq!(chunk.len(), 16);
        for (n, magic_number) in chunk.iter_mut().zip(SEA_128_MAGIC_NUMBER_ARR) {
            *n ^= magic_number;
        }
    }

    if verbose {
        veprintln("xor", format_args!("{enc:02x?}"));
    }
    Ok(enc)
}

pub fn sea_128_decrypt(key: &[u8; 16], enc: &[u8], verbose: bool) -> Result<Vec<u8>> {
    if verbose {
        eprintln!("? key:\t\t{key:02x?}");
    }

    let mut crypter = Crypter::new(Cipher::aes_128_ecb(), OpenSslMode::Decrypt, key, None)?;
    crypter.pad(false);

    if verbose {
        eprintln!("? enc:\t\t{enc:02x?}");
        eprintln!("? sea_magic:\t{SEA_128_MAGIC_NUMBER_ARR:02x?}");
    }
    let mut dxor = enc.to_vec();
    // xor with the SEA_128_MAGIC_NUMBER
    for chunk in dxor.chunks_exact_mut(16) {
        assert_eq!(chunk.len(), 16);
        for (n, magic_number) in chunk.iter_mut().zip(SEA_128_MAGIC_NUMBER_ARR) {
            *n ^= magic_number;
        }
    }

    if verbose {
        eprintln!("? dxor:\t\t{dxor:02x?}");
    }

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

    if verbose {
        eprintln!("? denc:\t\t{denc:02x?}");
    }

    Ok(denc)
}

/// Helper function to get the first part for AES-XEX
///
/// NOTE: The second key of XEX mode needs to be given to this!
fn sea_128_xex_enc0(key: &[u8; 16], tweak: &[u8; 16], verbose: bool) -> Result<[u8; 16]> {
    let enc0 = sea_128_encrypt(key, tweak, false)?;
    if verbose {
        veprintln("enc0", format_args!("{enc0:02x?}"));
    }
    len_to_const_arr(&enc0)
}

pub fn sea_128_decrypt_xex(
    keys: &([u8; 16], [u8; 16]),
    tweak: &[u8; 16],
    input: &[u8],
    verbose: bool,
) -> Result<Vec<u8>> {
    let tweakblock = sea_128_xex_enc0(&keys.1, tweak, verbose)?;
    if input.len() % 16 != 0 {
        return Err(anyhow!(
            "XEX plaintext input of bad length: {}",
            input.len()
        ));
    }
    let inputs: Vec<&[u8]> = input.chunks_exact(16).collect();

    let mut plain_text: Vec<[u8; 16]> = Vec::new();
    let mut xorval = tweakblock;
    let mut buf = [0u8; 16];
    plain_text.reserve(input.len());

    if verbose {
        veprintln("ciphertext_c", format_args!("{inputs:02x?}"));
        veprintln("tweak", format_args!("{tweak:02x?}"));
        veprintln("key0", format_args!("{:02x?}", keys.0));
        veprintln("key1", format_args!("{:02x?}", keys.1));
    }
    for input in inputs {
        if verbose {
            veprintln("xorval", format_args!("{xorval:02x?}"));
        }
        for (byte_idx, (inbyte, xorbyte)) in input.iter().zip(xorval).enumerate() {
            buf[byte_idx] = inbyte ^ xorbyte;
        }
        if verbose {
            veprintln("post xor0", format_args!("{buf:02x?}"));
        }
        let tmp = sea_128_decrypt(&keys.0, &buf, false)?;
        if verbose {
            veprintln("post denc", format_args!("{tmp:02x?}"));
        }
        for (byte_idx, (cybyte, xorbyte)) in tmp.iter().zip(xorval).enumerate() {
            buf[byte_idx] = cybyte ^ xorbyte;
        }
        if verbose {
            veprintln("post xor1", format_args!("{buf:02x?}"));
        }
        plain_text.push(buf);

        xorval = F_2_128
            .mul(bytes_to_u128(&xorval)?, F_2_128_ALPHA)
            .to_be_bytes();
    }
    if verbose {
        veprintln("plaintext", format_args!("{plain_text:02x?}"));
    }
    Ok(plain_text.concat())
}

pub fn sea_128_encrypt_xex(
    keys: &([u8; 16], [u8; 16]),
    tweak: &[u8; 16],
    input: &[u8],
    verbose: bool,
) -> Result<Vec<u8>> {
    let tweakblock = sea_128_xex_enc0(&keys.1, tweak, verbose)?;
    if input.len() % 16 != 0 {
        return Err(anyhow!(
            "XEX plaintext input of bad length: {}",
            input.len()
        ));
    }
    let inputs: Vec<&[u8]> = input.chunks_exact(16).collect();

    let mut cipher_text: Vec<[u8; 16]> = Vec::new();
    let mut xorval = tweakblock;
    let mut buf = [0u8; 16];
    cipher_text.reserve(input.len());

    if verbose {
        veprintln("plaintext_c", format_args!("{inputs:02x?}"));
        veprintln("tweak", format_args!("{tweak:02x?}"));
        veprintln("key0", format_args!("{:02x?}", keys.0));
        veprintln("key1", format_args!("{:02x?}", keys.1));
    }
    for input in inputs {
        if verbose {
            veprintln("xorval", format_args!("{xorval:02x?}"));
        }
        for (byte_idx, (inbyte, xorbyte)) in input.iter().zip(xorval).enumerate() {
            buf[byte_idx] = inbyte ^ xorbyte;
        }
        if verbose {
            veprintln("post xor0", format_args!("{buf:02x?}"));
        }
        let tmp = sea_128_encrypt(&keys.0, &buf, false)?;
        if verbose {
            veprintln("post enc", format_args!("{tmp:02x?}"));
        }
        for (byte_idx, (cybyte, xorbyte)) in tmp.iter().zip(xorval).enumerate() {
            buf[byte_idx] = cybyte ^ xorbyte;
        }
        if verbose {
            veprintln("post xor1", format_args!("{buf:02x?}"));
        }
        cipher_text.push(buf);

        xorval = F_2_128
            .mul(bytes_to_u128(&xorval)?, F_2_128_ALPHA)
            .to_be_bytes();
    }
    if verbose {
        veprintln("ciphertext", format_args!("{cipher_text:02x?}"));
    }
    Ok(cipher_text.concat())
}

pub fn run_testcase(testcase: &Testcase, settings: Settings) -> Result<serde_json::Value> {
    Ok(match testcase.action {
        Action::Sea128 => {
            let mode = get_mode(&testcase.arguments)?;
            let key = get_bytes_base64(&testcase.arguments, "key")?;
            let input = get_bytes_base64(&testcase.arguments, "input")?;

            let key: [u8; 16] = len_to_const_arr(&key)?;
            let input: [u8; 16] = len_to_const_arr(&input)?;

            let output = match mode {
                Mode::Encrypt => sea_128_encrypt(&key, &input, settings.verbose)?,
                Mode::Decrypt => sea_128_decrypt(&key, &input, settings.verbose)?,
            };
            put_bytes(&output)?
        }
        Action::Xex => {
            let mode = get_mode(&testcase.arguments)?;
            let key = get_bytes_base64(&testcase.arguments, "key")?;
            let tweak = get_bytes_base64(&testcase.arguments, "tweak")?;
            let input = get_bytes_base64(&testcase.arguments, "input")?;

            let key: [u8; 32] = len_to_const_arr(&key)?;
            let keys: ([u8; 16], [u8; 16]) = {
                let (a, b) = key.split_at(16);
                (len_to_const_arr(a)?, len_to_const_arr(b)?)
            };
            let tweak: [u8; 16] = len_to_const_arr(&tweak)?;

            let output = match mode {
                Mode::Encrypt => sea_128_encrypt_xex(&keys, &tweak, &input, settings.verbose)?,
                Mode::Decrypt => sea_128_decrypt_xex(&keys, &tweak, &input, settings.verbose)?,
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
    use base64::prelude::*;

    fn assert_hex(data: &[u8], correct: &[u8]) {
        assert_eq!(data, correct, "\n{data:02X?}\nshould be\n{correct:02X?}");
    }

    #[test]
    fn test_sea_128_encrypt_decrypt() {
        const PLAIN: [u8; 16] = *b"foobarqux amogus";
        const KEY: [u8; 16] = *b"1238742fsaflk249";

        let enc = sea_128_encrypt(&KEY, &PLAIN, true).expect("encrypt fail");
        let denc = sea_128_decrypt(&KEY, &enc, true).expect("decrypt fail");

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
            &sea_128_encrypt(&KEY, &PLAIN, true).expect("could not encrypt"),
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
            &sea_128_decrypt(&KEY, &ENC, true).expect("could not decrypt"),
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

    #[test]
    fn test_sea_128_xex_back_and_forth() {
        const PLAIN: &[u8; 16 * 3] = b"geheimer geheim text ist total super geheim.....";
        const KEYS: ([u8; 16], [u8; 16]) = (*b"1238742fsaflk249", *b"abti74kfsaflh2b9");
        const TWEAK: &[u8; 16] = b"9812485081250825";

        eprintln!("encrypting...");
        let ciphertext = sea_128_encrypt_xex(&KEYS, TWEAK, PLAIN, true).expect("could not encrypt");
        eprintln!("decrypting...");
        veprintln("ciphertext", format_args!("{ciphertext:02x?}"));
        let plaintext =
            sea_128_decrypt_xex(&KEYS, TWEAK, &ciphertext, true).expect("could not decrypt");
        assert_hex(&plaintext, PLAIN);
    }

    #[test]
    fn test_sea_128_xex_tweakblock() {
        let keys: ([u8; 16], [u8; 16]) = {
            let v: Vec<_> = BASE64_STANDARD
                .decode("B1ygNO/CyRYIUYhTSgoUysX5Y/wWLi4UiWaVeloUWs0=")
                .unwrap()
                .chunks_exact(16)
                .map(|c| c.to_owned())
                .collect();
            (
                len_to_const_arr(&v[0]).unwrap(),
                len_to_const_arr(&v[1]).unwrap(),
            )
        };
        let tweak: [u8; 16] =
            len_to_const_arr(&BASE64_STANDARD.decode("6VXORr+YYHrd2nVe0OlA+Q==").unwrap()).unwrap();
        const SOLUTION: &[u8] = &[
            0xAF, 0x8D, 0x74, 0xBC, 0x32, 0x9E, 0x0D, 0xE0, 0xC9, 0x4E, 0x2C, 0xA4, 0xAF, 0xD1,
            0x5D, 0xD4,
        ];
        veprintln("keys", format_args!("{keys:02x?}"));
        veprintln("tweak", format_args!("{tweak:02x?}"));
        let a = sea_128_xex_enc0(&keys.1, &tweak, true).expect("could not compute the tweakblock");
        assert_hex(&a, SOLUTION);
    }

    #[test]
    fn test_sea_128_xex_encrypt() {
        let plain: &[u8] = &BASE64_STANDARD
            .decode("/aOg4jMocLkBLkDLgkHYtFKc2L9jjyd2WXSSyxXQikpMY9ZRnsJE76e9dW9olZIW")
            .unwrap();
        let keys: ([u8; 16], [u8; 16]) = {
            let v: Vec<_> = BASE64_STANDARD
                .decode("B1ygNO/CyRYIUYhTSgoUysX5Y/wWLi4UiWaVeloUWs0=")
                .unwrap()
                .chunks_exact(16)
                .map(|c| c.to_owned())
                .collect();
            (
                len_to_const_arr(&v[0]).unwrap(),
                len_to_const_arr(&v[1]).unwrap(),
            )
        };
        let tweak: [u8; 16] =
            len_to_const_arr(&BASE64_STANDARD.decode("6VXORr+YYHrd2nVe0OlA+Q==").unwrap()).unwrap();
        let ciphertext_correct: &[u8] = &BASE64_STANDARD
            .decode("mHAVhRCKPAPx0BcufG5BZ4+/CbneMV/gRvqK5rtLe0OJgpDU5iT7z2P0R7gEeRDO")
            .unwrap();

        let ciphertext =
            sea_128_encrypt_xex(&keys, &tweak, plain, true).expect("could not encrypt");
        assert_hex(&ciphertext, ciphertext_correct);
    }

    #[test]
    fn test_sea_128_xex_decrypt() {
        let plain_correct: &[u8] = &BASE64_STANDARD
            .decode("/aOg4jMocLkBLkDLgkHYtFKc2L9jjyd2WXSSyxXQikpMY9ZRnsJE76e9dW9olZIW")
            .unwrap();
        let ciphertext: &[u8] = &BASE64_STANDARD
            .decode("mHAVhRCKPAPx0BcufG5BZ4+/CbneMV/gRvqK5rtLe0OJgpDU5iT7z2P0R7gEeRDO")
            .unwrap();
        let keys: ([u8; 16], [u8; 16]) = {
            let v: Vec<_> = BASE64_STANDARD
                .decode("B1ygNO/CyRYIUYhTSgoUysX5Y/wWLi4UiWaVeloUWs0=")
                .unwrap()
                .chunks_exact(16)
                .map(|c| c.to_owned())
                .collect();
            (
                len_to_const_arr(&v[0]).unwrap(),
                len_to_const_arr(&v[1]).unwrap(),
            )
        };
        let tweak: [u8; 16] =
            len_to_const_arr(&BASE64_STANDARD.decode("6VXORr+YYHrd2nVe0OlA+Q==").unwrap()).unwrap();

        let plain =
            sea_128_decrypt_xex(&keys, &tweak, ciphertext, true).expect("could not decrypt");
        assert_hex(&plain, plain_correct);
    }
}

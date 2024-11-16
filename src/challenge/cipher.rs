use anyhow::{anyhow, Result};
use openssl::symm::{Cipher, Crypter, Mode as OpenSslMode};
use serde::{Deserialize, Serialize};

use crate::common::interface::{get_bytes_base64, put_bytes};
use crate::common::{bytes_to_u128, len_to_const_arr, veprintln};
use crate::settings::Settings;

use super::ffield::{self, F_2_128, F_2_128_ALPHA};
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

#[derive(Debug, Clone)]
pub struct GcmEncrypted {
    pub nonce: [u8; 12],
    pub associated_data: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub auth_tag: [u8; 16],
    pub l: u128,
    pub h: [u8; 16],
}

#[derive(Debug, Clone)]
pub struct GcmDecrypted {
    pub nonce: [u8; 12],
    pub associated_data: Vec<u8>,
    pub plaintext: Vec<u8>,
    pub authentic: bool,
}

impl GcmEncrypted {
    pub fn build(
        nonce: &[u8; 12],
        associated_data: &[u8],
        ciphertext: &[u8],
        auth_tag: &[u8; 16],
    ) -> Result<Self> {
        let associated_data = associated_data.to_vec();
        let ciphertext = ciphertext.to_vec();

        Ok(Self {
            nonce: *nonce,
            associated_data,
            ciphertext,
            auth_tag: *auth_tag,
            l: 0,
            h: [0; 16],
        })
    }
}

impl GcmDecrypted {
    pub fn build(nonce: &[u8; 12], associated_data: &[u8], plaintext: &[u8]) -> Result<Self> {
        let associated_data = associated_data.to_vec();
        let plaintext = plaintext.to_vec();

        Ok(Self {
            nonce: *nonce,
            associated_data,
            plaintext,
            authentic: false,
        })
    }
}

impl PrimitiveAlgorithm {
    pub fn encrypt(self, key: &[u8; 16], data: &[u8; 16], verbose: bool) -> Result<[u8; 16]> {
        match self {
            Self::Sea128 => Ok(sea_128_encrypt(key, data, verbose)?),
            Self::Aes128 => Ok(aes_128_encrypt(key, data, verbose)?),
        }
    }

    pub fn decrypt(self, key: &[u8; 16], ciphertext: &[u8; 16], verbose: bool) -> Result<[u8; 16]> {
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

pub fn aes_128_encrypt(key: &[u8; 16], data: &[u8; 16], _verbose: bool) -> Result<[u8; 16]> {
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

    len_to_const_arr(&enc)
}

pub fn aes_128_decrypt(key: &[u8; 16], enc: &[u8; 16], verbose: bool) -> Result<[u8; 16]> {
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

    len_to_const_arr(&denc)
}

pub fn sea_128_encrypt(key: &[u8; 16], data: &[u8; 16], verbose: bool) -> Result<[u8; 16]> {
    if verbose {
        veprintln("key", format_args!("{key:02x?}"))
    }

    let mut crypter = Crypter::new(Cipher::aes_128_ecb(), OpenSslMode::Encrypt, key, None)?;
    crypter.pad(false);

    if verbose {
        veprintln("data", format_args!("{data:02x?}"))
    }

    // NOTE: openssl panics if the buffer is not at least 32 bytes
    let mut enc: Vec<u8> = vec![0; data.len() + 16];
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
    len_to_const_arr(&enc)
}

pub fn sea_128_decrypt(key: &[u8; 16], data: &[u8; 16], verbose: bool) -> Result<[u8; 16]> {
    if verbose {
        eprintln!("? key:\t\t{key:02x?}");
    }

    let mut crypter = Crypter::new(Cipher::aes_128_ecb(), OpenSslMode::Decrypt, key, None)?;
    crypter.pad(false);

    if verbose {
        eprintln!("? enc:\t\t{data:02x?}");
        eprintln!("? sea_magic:\t{SEA_128_MAGIC_NUMBER_ARR:02x?}");
    }
    let mut dxor = data.to_vec();
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
    let mut denc: Vec<u8> = vec![0; data.len() + 16];
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

    len_to_const_arr(&denc)
}

/// Helper function to get the first part for AES-XEX
///
/// NOTE: The second key of XEX mode needs to be given to this!
fn sea_128_xex_enc0(key: &[u8; 16], tweak: &[u8; 16], verbose: bool) -> Result<[u8; 16]> {
    let enc0 = sea_128_encrypt(key, tweak, false)?;
    if verbose {
        veprintln("enc0", format_args!("{enc0:02x?}"));
    }
    Ok(enc0)
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

fn ghash(
    auth_key: &[u8; 16],
    associated_data: &[u8],
    ciphertext: &[u8],
    verbose: bool,
) -> ([u8; 16], u128) {
    let mut buf: u128 = 0;
    let mut ad = Vec::from(associated_data);
    let mut ct = Vec::from(ciphertext);
    if verbose {
        veprintln("H", format_args!("{auth_key:02x?}"));
        veprintln("C", format_args!("{ct:02x?}"));
        veprintln("A", format_args!("{ad:02x?}"));
    }
    while ad.len() % 16 != 0 {
        ad.push(0);
    }
    while ct.len() % 16 != 0 {
        ct.push(0);
    }
    assert!(ct.len() % 16 == 0);
    assert!(ad.len() % 16 == 0);
    let ak: u128 = u128::from_be_bytes(*auth_key);
    let ak_sem = ffield::change_semantic(ak, ffield::Semantic::Gcm, ffield::Semantic::Xex);
    let l: u128 = ((associated_data.len() as u128 * 8) << 64) | (ciphertext.len() as u128 * 8);

    if verbose {
        veprintln("H", format_args!("{ak:032x}"));
        veprintln("C", format_args!("{ct:02x?}"));
        veprintln("A", format_args!("{ad:02x?}"));
    }

    let mut all = ad;
    assert!(all.len() % 16 == 0);
    all.extend(ct);
    assert!(all.len() % 16 == 0);
    let chunks = all.chunks_exact(16);
    assert!(chunks.remainder().is_empty());
    let mut all: Vec<u128> = chunks
        .map(|c| u128::from_be_bytes(len_to_const_arr(c).unwrap()))
        .collect();
    all.push(l);

    if verbose {
        veprintln("L", format_args!("{l:032x}"));
        veprintln("all", format_args!("{all:032x?}"));
    }

    for item in all {
        // just xor
        buf ^= item;
        // multiply in field, but we need to change semantic from gcm for xex for internal reasons,
        // and back
        buf = ffield::change_semantic(
            F_2_128.mul(
                ffield::change_semantic(buf, ffield::Semantic::Gcm, ffield::Semantic::Xex),
                ak_sem,
            ),
            ffield::Semantic::Xex,
            ffield::Semantic::Gcm,
        );
        veprintln("buf", format_args!("{buf:032x}"));
    }

    (buf.to_be_bytes(), l)
}

/// Makes the auth tag with [ghash]. First return is the tag second is L.
fn gcm_make_tag(
    auth_key: &[u8; 16],
    associated_data: &[u8],
    ciphertext: &[u8],
    xor_with_ghash: [u8; 16],
    verbose: bool,
) -> ([u8; 16], u128) {
    let mut auth_tag = [0; 16];
    let ghash_out = ghash(auth_key, associated_data, ciphertext, verbose);
    veprintln("ghash tag", format_args!("{:02x?}", ghash_out.0));
    for ((xb, gb), ab) in xor_with_ghash
        .iter()
        .zip(ghash_out.0)
        .zip(auth_tag.iter_mut())
    {
        *ab = xb ^ gb;
    }
    (auth_tag, ghash_out.1)
}

pub fn gcm_encrypt(
    algorithm: PrimitiveAlgorithm,
    key: &[u8; 16],
    input: &GcmDecrypted,
    verbose: bool,
) -> Result<GcmEncrypted> {
    let mut ciphertext: Vec<u8> = Vec::with_capacity(input.plaintext.len());
    let mut counter: u32 = 1;

    let mut nonce_up = [0; 16];
    nonce_up[..12].copy_from_slice(&input.nonce);
    let nonce_up: u128 = u128::from_be_bytes(nonce_up);

    let mut y = nonce_up | counter as u128;

    let xor_with_ghash = algorithm.encrypt(key, &y.to_be_bytes(), false)?;
    let auth_key = algorithm.encrypt(key, &[0; 16], false)?;

    for chunk in input.plaintext.chunks(16) {
        counter += 1;
        y = nonce_up | counter as u128;

        let k = algorithm.encrypt(key, &y.to_be_bytes(), false)?;
        for (kb, pb) in k.iter().zip(chunk) {
            ciphertext.push(kb ^ pb);
        }
    }

    let (at, l) = gcm_make_tag(
        &auth_key,
        &input.associated_data,
        &ciphertext,
        xor_with_ghash,
        verbose,
    );

    let out = GcmEncrypted {
        nonce: input.nonce,
        associated_data: input.associated_data.clone(),
        ciphertext,
        auth_tag: at,
        l,
        h: auth_key,
    };
    Ok(out)
}

pub fn gcm_decrypt(
    algorithm: PrimitiveAlgorithm,
    key: &[u8; 16],
    input: &GcmEncrypted,
    verbose: bool,
) -> Result<GcmDecrypted> {
    let mut plaintext: Vec<u8> = Vec::with_capacity(input.ciphertext.len());
    let mut nonce_up = [0; 16];
    let mut counter: u32 = 1;

    nonce_up[..12].copy_from_slice(&input.nonce);
    let nonce_up: u128 = u128::from_be_bytes(nonce_up);

    let mut y = nonce_up | counter as u128;
    let xor_with_ghash = algorithm.encrypt(key, &y.to_be_bytes(), false)?;
    let auth_key = algorithm.encrypt(key, &[0; 16], false)?;

    for chunk in input.ciphertext.chunks(16) {
        counter += 1;
        y = nonce_up | counter as u128;

        let k = algorithm.encrypt(key, &y.to_be_bytes(), false)?;
        for (kb, pb) in k.iter().zip(chunk) {
            plaintext.push(kb ^ pb);
        }
    }

    let (at, _l) = gcm_make_tag(
        &auth_key,
        &input.associated_data,
        &input.ciphertext,
        xor_with_ghash,
        verbose,
    );

    let out = GcmDecrypted {
        nonce: input.nonce,
        associated_data: input.associated_data.clone(),
        plaintext,
        authentic: at == input.auth_tag,
    };
    veprintln("auth_tag given", format_args!("{:02x?}", input.auth_tag));
    veprintln("auth_tag made", format_args!("{:02x?}", at));
    Ok(out)
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
        Action::GcmEncrypt => {
            let algorithm: PrimitiveAlgorithm = get_algorithm(&testcase.arguments)?;
            let nonce: [u8; 12] =
                len_to_const_arr(&get_bytes_base64(&testcase.arguments, "nonce")?)?;
            let key: [u8; 16] = len_to_const_arr(&get_bytes_base64(&testcase.arguments, "key")?)?;
            let pt = get_bytes_base64(&testcase.arguments, "plaintext")?;
            let ad = get_bytes_base64(&testcase.arguments, "ad")?;

            let inp = GcmDecrypted::build(&nonce, &ad, &pt)?;

            let dec = gcm_encrypt(algorithm, &key, &inp, settings.verbose)?;
            serde_json::json!(
                {
                    "ciphertext": put_bytes(&dec.ciphertext)?,
                    "tag": put_bytes(&dec.auth_tag)?,
                    "L": put_bytes(&dec.l.to_be_bytes())?,
                    "H": put_bytes(&dec.h)?
                }
            )
        }
        Action::GcmDecrypt => {
            let algorithm: PrimitiveAlgorithm = get_algorithm(&testcase.arguments)?;
            let nonce: [u8; 12] =
                len_to_const_arr(&get_bytes_base64(&testcase.arguments, "nonce")?)?;
            let key: [u8; 16] = len_to_const_arr(&get_bytes_base64(&testcase.arguments, "key")?)?;
            let ct = get_bytes_base64(&testcase.arguments, "ciphertext")?;
            let ad = get_bytes_base64(&testcase.arguments, "ad")?;
            let tag: [u8; 16] = len_to_const_arr(&get_bytes_base64(&testcase.arguments, "tag")?)?;

            let inp = GcmEncrypted::build(&nonce, &ad, &ct, &tag)?;

            let ec = gcm_decrypt(algorithm, &key, &inp, settings.verbose)?;
            serde_json::json!(
                {
                    "plaintext": put_bytes(&ec.plaintext)?,
                    "authentic": ec.authentic
                }
            )
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

fn get_algorithm(args: &serde_json::Value) -> Result<PrimitiveAlgorithm> {
    let alg: PrimitiveAlgorithm = if args["algorithm"].is_string() {
        serde_json::from_value(args["algorithm"].clone()).map_err(|e| {
            eprintln!("! something went wrong when serializing the mode: {e}");
            e
        })?
    } else {
        return Err(anyhow!("algorithm is not a string"));
    };
    Ok(alg)
}

#[cfg(test)]
mod test {
    use crate::common::assert_hex;

    use super::*;
    use base64::prelude::*;

    #[allow(unused)] // I use it every once in a while to help debug tests
    fn dump_b64(base: &str) -> Vec<u8> {
        let a = BASE64_STANDARD.decode(base).expect("this is bad base64");
        eprintln!("{a:#02x?}");
        a
    }

    #[test]
    fn test_sea_128_encrypt_decrypt() {
        const PLAIN: [u8; 16] = *b"foobarqux amogus";
        const KEY: [u8; 16] = *b"1238742fsaflk249";

        let enc = sea_128_encrypt(&KEY, &PLAIN, true).expect("encrypt fail");
        let enc = len_to_const_arr(&enc).expect("could not convert from vec to arr");
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

    #[test]
    fn test_aes_encrypt_then_decrypt() {
        const PLAIN: [u8; 16] = *b"foobarqux amogus";
        const KEY: [u8; 16] = *b"1238742fsaflk249";

        let enc = aes_128_encrypt(&KEY, &PLAIN, true).expect("could not encrypt");
        let denc = aes_128_decrypt(&KEY, &enc, true).expect("could not decrypt");

        assert_hex(&denc, &PLAIN)
    }

    #[test]
    fn test_gcm_aes_encrypt() {
        const NONCE: [u8; 12] = [
            0xe2, 0x1, 0x7e, 0x6, 0xd4, 0x77, 0x92, 0xef, 0xcf, 0x51, 0x7, 0x22,
        ];
        const KEY: [u8; 16] = [
            0x5e, 0x3a, 0xbf, 0x1a, 0x4a, 0x53, 0x49, 0x6a, 0x1e, 0xdd, 0x91, 0xf4, 0x17, 0xeb,
            0x63, 0xad,
        ];
        const PLAIN: [u8; 16] = [
            0x44, 0x61, 0x73, 0x20, 0x69, 0x73, 0x74, 0x20, 0x65, 0x69, 0x6e, 0x20, 0x54, 0x65,
            0x73, 0x74,
        ];
        const AD: [u8; 8] = [0x41, 0x44, 0x2d, 0x44, 0x61, 0x74, 0x65, 0x6e];
        const CIPHER: [u8; 16] = [
            0x11, 0x3d, 0xd1, 0x9a, 0xf1, 0xff, 0x1d, 0xbb, 0xb1, 0x6d, 0xae, 0xb7, 0x12, 0xe3,
            0xd1, 0xaf,
        ];
        const AUTH: [u8; 16] = [
            0x32, 0x9d, 0x0, 0x3c, 0x96, 0xff, 0x64, 0x85, 0x11, 0x47, 0x4, 0x25, 0x32, 0x3, 0x4d,
            0xff,
        ];
        let input: GcmDecrypted = GcmDecrypted::build(&NONCE, &AD, &PLAIN).unwrap();

        let enc =
            gcm_encrypt(PrimitiveAlgorithm::Aes128, &KEY, &input, true).expect("could not encrypt");

        assert_hex(&enc.ciphertext, &CIPHER);
        assert_hex(&enc.auth_tag, &AUTH);
    }

    #[test]
    fn test_gcm_aes_decrypt() {
        const NONCE: [u8; 12] = [
            0xe2, 0x1, 0x7e, 0x6, 0xd4, 0x77, 0x92, 0xef, 0xcf, 0x51, 0x7, 0x22,
        ];
        const KEY: [u8; 16] = [
            0x5e, 0x3a, 0xbf, 0x1a, 0x4a, 0x53, 0x49, 0x6a, 0x1e, 0xdd, 0x91, 0xf4, 0x17, 0xeb,
            0x63, 0xad,
        ];
        const PLAIN: [u8; 16] = [
            0x44, 0x61, 0x73, 0x20, 0x69, 0x73, 0x74, 0x20, 0x65, 0x69, 0x6e, 0x20, 0x54, 0x65,
            0x73, 0x74,
        ];
        const AD: [u8; 8] = [0x41, 0x44, 0x2d, 0x44, 0x61, 0x74, 0x65, 0x6e];
        const CIPHER: [u8; 16] = [
            0x11, 0x3d, 0xd1, 0x9a, 0xf1, 0xff, 0x1d, 0xbb, 0xb1, 0x6d, 0xae, 0xb7, 0x12, 0xe3,
            0xd1, 0xaf,
        ];
        const AUTH: [u8; 16] = [
            0x32, 0x9d, 0x0, 0x3c, 0x96, 0xff, 0x64, 0x85, 0x11, 0x47, 0x4, 0x25, 0x32, 0x3, 0x4d,
            0xff,
        ];
        let input: GcmEncrypted = GcmEncrypted::build(&NONCE, &AD, &CIPHER, &AUTH).unwrap();

        let denc =
            gcm_decrypt(PrimitiveAlgorithm::Aes128, &KEY, &input, true).expect("could not encrypt");

        assert_hex(&denc.plaintext, &PLAIN);
        assert!(denc.authentic);
    }

    #[test]
    fn test_gcm_aes_decrypt_no_full_block() {
        const NONCE: [u8; 12] = [
            0xe2, 0x1, 0x7e, 0x6, 0xd4, 0x77, 0x92, 0xef, 0xcf, 0x51, 0x7, 0x22,
        ];
        const KEY: [u8; 16] = [
            0x5e, 0x3a, 0xbf, 0x1a, 0x4a, 0x53, 0x49, 0x6a, 0x1e, 0xdd, 0x91, 0xf4, 0x17, 0xeb,
            0x63, 0xad,
        ];
        const PLAIN: [u8; 8] = [0x44, 0x61, 0x73, 0x20, 0x69, 0x73, 0x74, 0x20];
        const AD: [u8; 8] = [0x41, 0x44, 0x2d, 0x44, 0x61, 0x74, 0x65, 0x6e];
        const CIPHER: [u8; 8] = [0x11, 0x3d, 0xd1, 0x9a, 0xf1, 0xff, 0x1d, 0xbb];
        const AUTH: [u8; 16] = [
            0xa2, 0xd7, 0x89, 0x8f, 0x70, 0x19, 0x7c, 0x82, 0xc2, 0x33, 0x81, 0x4f, 0x7b, 0x27,
            0xf1, 0x6a,
        ];
        let input: GcmEncrypted = GcmEncrypted::build(&NONCE, &AD, &CIPHER, &AUTH).unwrap();

        let denc =
            gcm_decrypt(PrimitiveAlgorithm::Aes128, &KEY, &input, true).expect("could not encrypt");

        assert_hex(&denc.plaintext, &PLAIN);
        assert!(denc.authentic);
    }

    #[test]
    fn test_ghash() {
        const H: [u8; 16] = 0x06eeb2c1bb142a5a66657310cae1809eu128.to_be_bytes();
        const C: [u8; 16] = 0x113dd19af1ff1dbbb16daeb712e3d1afu128.to_be_bytes();
        const A: [u8; 8] = 0x41442d446174656eu64.to_be_bytes();
        let hash = ghash(&H, &A, &C, true);
        assert_hex(
            &hash.0,
            &0xDB4F289C6F3FFBB2CCB75B70389BD5E4u128.to_be_bytes(),
        );
    }
}

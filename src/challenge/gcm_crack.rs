use anyhow::Result;
use base64::prelude::*;
use num::traits::ToBytes;
use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize, Serializer};

use crate::common::{self, bytes_to_u128, len_to_const_arr};

use super::cipher::ghash;
use super::ffield::element::FieldElement;
use super::superpoly::SuperPoly;

pub trait GcmData {
    fn associated_data(&self) -> &[u8];
    fn ciphertext(&self) -> &[u8];
}

#[derive(Debug)]
pub struct GcmMessage {
    pub associated_data: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub tag: [u8; 16],
}

#[derive(Debug)]
pub struct GcmForgery {
    pub ciphertext: Vec<u8>,
    pub associated_data: Vec<u8>,
}

#[derive(Debug)]
pub struct GcmSolution {
    tag: [u8; 16],
    h: [u8; 16],
    mask: [u8; 16],
}

impl GcmData for GcmMessage {
    fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
    fn associated_data(&self) -> &[u8] {
        &self.associated_data
    }
}

impl GcmData for GcmForgery {
    fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
    fn associated_data(&self) -> &[u8] {
        &self.associated_data
    }
}

impl GcmMessage {
    pub fn length(&self) -> u128 {
        ((self.associated_data.len() as u128 * 8) << 64) | (self.ciphertext.len() as u128 * 8)
    }

    pub fn get_magic_p(&self) -> SuperPoly {
        // WARN: DO NOT TOUCH
        /////////////////////////////////////////////////////////////////////
        ///// UNDER NO CIRCUMSTANCES TOUCH THIS IF IT WORKS
        ///// ADD YOUR MARK IF YOU DESPAIRED: II
        /////////////////////////////////////////////////////////////////////
        let length: u128 = self.length();

        let mut ad = self.associated_data.clone();
        let mut ct = self.ciphertext.clone();

        if ad.len() % 16 != 0 || ad.is_empty() {
            ad.append(vec![0u8; 16 - (ad.len() % 16)].as_mut());
        }
        if ct.len() % 16 != 0 || ct.is_empty() {
            ct.append(vec![0u8; 16 - (ct.len() % 16)].as_mut());
        }
        let ad_chunks: Vec<FieldElement> = ad
            .chunks(16)
            .map(|chunk| {
                FieldElement::from_gcm_convert_to_xex(bytes_to_u128(
                    &len_to_const_arr::<16>(chunk).expect("is not len 16"),
                ))
            })
            .collect();
        let ct_chunks: Vec<FieldElement> = ct
            .chunks(16)
            .map(|chunk| {
                FieldElement::from_gcm_convert_to_xex(bytes_to_u128(
                    &len_to_const_arr::<16>(chunk).expect("is not len 16"),
                ))
            })
            .rev()
            .collect();

        let mut raw: Vec<FieldElement> = Vec::with_capacity(
            (self.associated_data.len() / 16) + (self.ciphertext.len() / 16) + 1 + 1,
        );
        raw.push(FieldElement::from_gcm_convert_to_xex(bytes_to_u128(
            &self.tag,
        )));
        raw.push(FieldElement::from_gcm_convert_to_xex(length));
        raw.extend(ct_chunks);
        raw.extend(ad_chunks);

        let a = SuperPoly::from(raw.as_slice());
        a
    }
}

impl<'de> Deserialize<'de> for GcmMessage {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        #[derive(Deserialize)]
        struct RawMessage {
            ciphertext: String,
            associated_data: String,
            tag: String,
        }

        let raw = RawMessage::deserialize(deserializer)?;

        Ok(GcmMessage {
            ciphertext: BASE64_STANDARD
                .decode(&raw.ciphertext)
                .map_err(D::Error::custom)?,
            associated_data: BASE64_STANDARD
                .decode(&raw.associated_data)
                .map_err(D::Error::custom)?,
            tag: BASE64_STANDARD
                .decode(&raw.tag)
                .map_err(D::Error::custom)?
                .try_into()
                .map_err(|_| D::Error::custom("Invalid tag length"))?,
        })
    }
}

impl<'de> Deserialize<'de> for GcmForgery {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        #[derive(Deserialize)]
        struct RawForgery {
            ciphertext: String,
            associated_data: String,
        }

        let raw = RawForgery::deserialize(deserializer)?;

        Ok(GcmForgery {
            ciphertext: BASE64_STANDARD
                .decode(&raw.ciphertext)
                .map_err(D::Error::custom)?,
            associated_data: BASE64_STANDARD
                .decode(&raw.associated_data)
                .map_err(D::Error::custom)?,
        })
    }
}

impl Serialize for GcmSolution {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let tag = BASE64_STANDARD.encode(self.tag);
        let h = BASE64_STANDARD.encode(self.h);
        let mask = BASE64_STANDARD.encode(self.mask);

        let mut s = serializer.serialize_map(Some(3))?;
        s.serialize_entry("tag", &tag)?;
        s.serialize_entry("h", &h)?;
        s.serialize_entry("mask", &mask)?;
        s.end()
    }
}

pub fn crack(
    m1: &GcmMessage,
    m2: &GcmMessage,
    m3: &GcmMessage,
    forgery: &GcmForgery,
) -> Result<GcmSolution> {
    let p1 = m1.get_magic_p();
    let p2 = m2.get_magic_p();
    let pdiff = p1 ^ p2;

    let pdiff_sff = pdiff.make_monic().factor_sff();
    let mut pdiff_ddf: Vec<_> = Vec::with_capacity(pdiff_sff.len() * 3);
    for factor in pdiff_sff.iter().map(|f| &f.factor) {
        pdiff_ddf.extend(factor.factor_ddf());
    }
    let mut pdiff_edf: Vec<_> = Vec::with_capacity(1);
    for factor in pdiff_ddf
        .iter()
        .filter(|v| v.degree == 1)
        .map(|v| &v.factor)
    {
        pdiff_edf.extend(factor.factor_edf(1));
    }
    pdiff_edf = pdiff_edf
        .iter()
        .filter(|v| v.deg() == 1)
        .map(|v| v.to_owned())
        .collect();
    if pdiff_edf.is_empty() {
        panic!("edf returned no candidates with deg 1");
    }

    let mut m3_tag: [u8; 16];
    let mut h_candidate: FieldElement = FieldElement::ZERO;
    let mut hashes: [FieldElement; 3] = [FieldElement::ZERO; 3];
    let mut eky0: [u8; 16] = [0; 16];

    // will run at least once because we panic early if pdiff_edf is empty
    for candidate in pdiff_edf {
        h_candidate = candidate.coefficients[0];
        hashes[0] = hash_msg(h_candidate, m1);

        eky0 = xor_bytes(&m1.tag, hashes[0].to_be_bytes());
        hashes[1] = hash_msg(h_candidate, m3);

        m3_tag = xor_bytes(&eky0, hashes[1].to_be_bytes());

        if m3_tag == m3.tag {
            break;
        }
    }

    hashes[2] = hash_msg(h_candidate, forgery);
    let tag = xor_bytes(&eky0, hashes[2].to_be_bytes());

    h_candidate = h_candidate.change_semantic(h_candidate.sem(), super::ffield::Semantic::Gcm);

    Ok(GcmSolution {
        tag,
        h: h_candidate.to_be_bytes(),
        mask: eky0,
    })
}

fn xor_bytes(a: &[u8; 16], b: [u8; 16]) -> [u8; 16] {
    len_to_const_arr(&a.iter().zip(b).map(|(a, b)| a ^ b).collect::<Vec<_>>())
        .expect("was somehow wrong length")
}

fn hash_msg(key: FieldElement, msg: &impl GcmData) -> FieldElement {
    FieldElement::const_from_raw_gcm(bytes_to_u128(
        &ghash(
            &key.change_semantic(key.sem(), crate::challenge::ffield::Semantic::Gcm)
                .to_be_bytes(),
            msg.associated_data(),
            msg.ciphertext(),
            false,
        )
        .0,
    ))
}

pub fn run_testcase(
    testcase: &super::Testcase,
    _settings: crate::settings::Settings,
) -> Result<serde_json::Value> {
    match testcase.action {
        super::Action::GcmCrack => {
            let m1: GcmMessage = serde_json::from_value(testcase.arguments["m1"].clone())?;
            let m2: GcmMessage = serde_json::from_value(testcase.arguments["m2"].clone())?;
            let m3: GcmMessage = serde_json::from_value(testcase.arguments["m3"].clone())?;
            let _nonce: [u8; 12] = len_to_const_arr(&common::interface::get_bytes_base64(
                &testcase.arguments,
                "nonce",
            )?)?;
            let forgery: GcmForgery =
                serde_json::from_value(testcase.arguments["forgery"].clone())?;

            let a = crack(&m1, &m2, &m3, &forgery)?;
            Ok(serde_json::to_value(&a)?)
        }
        _ => unreachable!(),
    }
}

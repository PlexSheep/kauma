use anyhow::{anyhow, Result};
use base64::prelude::*;
use num::traits::ToBytes as _;
use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize, Serializer};

use crate::common::{self, bytes_to_u128, len_to_const_arr};

use super::cipher::ghash;
use super::ffield::element::FieldElement;
use super::superpoly::SuperPoly;

#[derive(Debug)]
pub struct GcmMessage {
    pub ciphertext: Vec<u8>,
    pub associated_data: Vec<u8>,
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

impl GcmMessage {
    pub fn get_ghash(&self) -> Result<FieldElement> {
        let (hash, _) = ghash(&[0; 16], &self.associated_data, &self.ciphertext, false);
        Ok(FieldElement::from(bytes_to_u128(&hash)))
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
        let tag = common::interface::encode_hex(&self.tag);
        let h = common::interface::encode_hex(&self.h);
        let mask = common::interface::encode_hex(&self.mask);

        let mut s = serializer.serialize_map(Some(3))?;
        s.serialize_entry("tag", &tag)?;
        s.serialize_entry("h", &h)?;
        s.serialize_entry("mask", &mask)?;
        s.end()
    }
}

pub fn crack(
    _nonce: &[u8; 12],
    m1: &GcmMessage,
    m2: &GcmMessage,
    m3: &GcmMessage,
    forgery: &GcmForgery,
) -> Result<GcmSolution> {
    // Calculate GHASH polynomials
    let p1 = m1.get_ghash()?;
    let p2 = m2.get_ghash()?;
    let p3 = m3.get_ghash()?;

    // Get auth tags
    let t1 = FieldElement::from(bytes_to_u128(&m1.tag));
    let t2 = FieldElement::from(bytes_to_u128(&m2.tag));
    let t3 = FieldElement::from(bytes_to_u128(&m3.tag));

    // Create polynomial for first equation
    let mut coeffs = Vec::new();
    coeffs.push(t1 ^ t2); // constant term
    coeffs.push(p1 ^ p2); // coefficient of X
    let poly1 = SuperPoly::from(coeffs.as_slice());

    // Create polynomial for second equation
    coeffs.clear();
    coeffs.push(t2 ^ t3);
    coeffs.push(p2 ^ p3);
    let poly2 = SuperPoly::from(coeffs.as_slice());

    // Form a combined polynomial that H must satisfy
    // Multiply equations to get:
    // ((p1 ⊕ p2)·H ⊕ (t1 ⊕ t2))·((p2 ⊕ p3)·H ⊕ (t2 ⊕ t3)) = 0
    let combined_poly = &poly1 * &poly2;

    // Factor the polynomial to find H
    let factors = combined_poly.factor_sff();

    // Find linear factors which give us candidates for H
    for factor in factors {
        let factor_poly = factor.factor;
        if factor_poly.deg() == 1 {
            // Extract H value from linear factor
            let h = factor_poly.coefficients[0] / factor_poly.coefficients[1];

            // Calculate EK(Y0) using first message
            let ek_y0 = t1 ^ (p1 * h);

            // Verify it works for all messages
            if (t2 ^ (p2 * h) == ek_y0) && (t3 ^ (p3 * h) == ek_y0) {
                // Found valid H - now calculate forgery tag
                let (forge_hash, _) = ghash(
                    &h.to_be_bytes(),
                    &forgery.associated_data,
                    &forgery.ciphertext,
                    false,
                );
                let forge_poly = FieldElement::from(bytes_to_u128(&forge_hash));
                let forge_tag = ek_y0 ^ (forge_poly * h);

                return Ok(GcmSolution {
                    tag: forge_tag.to_be_bytes(),
                    h: h.to_be_bytes(),
                    mask: ek_y0.to_be_bytes(),
                });
            }
        }
    }

    // If we reach here, we failed to find a valid H
    Err(anyhow!("Could not find valid H value"))
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
            let nonce: [u8; 12] = len_to_const_arr(&common::interface::get_bytes_base64(
                &testcase.arguments,
                "nonce",
            )?)?;
            let forgery: GcmForgery =
                serde_json::from_value(testcase.arguments["forgery"].clone())?;

            let a = crack(&nonce, &m1, &m2, &m3, &forgery)?;
            Ok(serde_json::to_value(&a)?)
        }
        _ => unreachable!(),
    }
}

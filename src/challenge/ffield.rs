//! multiply / add polynomials in a gallois field

use std::default::Default;
use std::fmt::Display;

use anyhow::{anyhow, Result};
use base64::prelude::*;
use serde::{Deserialize, Serialize};

use crate::common::{bit_at_i_inverted_order, byte_to_bits};

use super::{Action, Testcase};

/// A type alias for the polinomials.
///
/// Polynomials (if the factors are all either 0 or 1) can be represented as numbers where each bit
/// is the factor for the alpha at that specific position.
///
/// This alias is useful to make sure I don't accidentally use a regular number as a polynomial and
/// vice versa.
pub type Polynomial = u128;

/// α^128 + α^7 + α^2 + α + 1
///
/// This relation defines the finite field used in AES.
// NOTE: this might be just wrong, and I don't know how to get it into a u128. The α^128 would be the
// 129th bit, no? I could just abstract it away and store α^7 + α^2 + α + 1 while having the α^128
// implied...
pub const DEFINING_RELATION_F_2_128: Polynomial = 0x87000000_00000000_00000000_00000080;
pub const DEFINING_RELATION_F_2_3: Polynomial = 0xb;
pub const DEFINING_RELATION_F_2_4: Polynomial = 0x13;
pub const DEFINING_RELATION_F_2_8: Polynomial = 0x11b;
/// A finite field over 2^128 with the defining relation [DEFINING_RELATION_F_2_128] as used in
/// AES.
pub const F_2_128: FField = FField::new(2, DEFINING_RELATION_F_2_128);
/// This is a special polynomial used for multiplication in F_2_128
pub const SPECIAL_ELEMENT_R: Polynomial = 0xE1000000_00000000_00000000_00000080;

#[derive(Debug, Deserialize, Serialize, Clone, Copy, Default)]
#[serde(rename_all = "snake_case")]
pub enum Semantic {
    /// whatever is used in AES-XEX
    #[default]
    Xex,
}

/// Which finite field to use, e.g. F_(2^(128))
///
/// For the purposes of kauma-analyzer, we will focus on binary finite fields, so those with a base
/// of 2^n.
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
pub struct FField {
    /// Forms the base as 2^n
    n: u64,
    /// The defining relation, represented as a number, where the least significant bit
    /// signifies b * α^0, the second least significant bit signifies b * α^1 and so on, where b is
    /// the value of that bit.
    ///
    /// Note that the byte order is from least to highest, unintuitively.
    defining_relation: Polynomial,
}

impl FField {
    /// Create a new finite field with a base that is a power of two.
    pub const fn new(n: u64, defining_relation: Polynomial) -> Self {
        Self {
            n,
            defining_relation,
        }
    }
    /// Convert the machine representation of a polynomial to the human representation
    /// ```
    /// use kauma_analyzer::challenge::ffield::F_2_128;
    /// assert_eq!(F_2_128.display_poly(1 << 121), "α");
    /// assert_eq!(F_2_128.display_poly(0b1001 << 55), "α^79 + α^66");
    /// ```
    pub fn display_poly(&self, poly: Polynomial) -> String {
        let mut buf = String::new();
        let enabled = self.poly_to_coefficients(poly, Semantic::default());
        if enabled.is_empty() {
            buf = "0".to_string();
            return buf;
        }
        for (i, exp) in enabled.iter().enumerate() {
            if i == enabled.len() - 1 {
                if *exp == 0 {
                    buf += "1";
                } else if *exp == 1 {
                    buf += "α";
                } else {
                    buf += &format!("α^{exp}");
                }
                break;
            }
            buf += &format!("α^{exp} + ")
        }
        buf
    }

    /// Reduces the given [Polynomial] with the [defining relation](Self::defining_relation)
    pub fn reduce(&self, poly: Polynomial) -> Polynomial {
        poly ^ self.defining_relation
    }
    /// Get the sum of two [polynomials](Polynomial)
    ///
    /// Adds poly a and b together.
    ///
    /// This is not regular addition of two numbers!
    ///
    /// Addition on the finite field with a base of 2^n is the same as xor, therefore no reduction
    /// is needed.
    pub fn add(&self, poly_a: Polynomial, poly_b: Polynomial) -> Polynomial {
        poly_a ^ poly_b
    }
    /// Get the product of two [polynomials](Polynomial)
    ///
    /// Multiplies poly a by poly b together, automatically reducing it with the defining relation.
    ///
    /// This is not regular multiplication of two numbers!
    ///
    /// Multiplication in a finite field is rather complicated, so I use an algorithm from
    /// a research paper.
    ///
    /// # Citation
    /// - The Galois/Counter Mode of Operation (GCM) by McGrew and Viega, Sect. 2.5, Algorithm 1
    ///     <https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf>
    pub fn mul(&self, poly_a: Polynomial, poly_b: Polynomial) -> Polynomial {
        if *self != F_2_128 {
            panic!("I don't know how to multiply if it's not in F_2_128 (well, or in real regular numbers)!")
        }
        let mut z: Polynomial = 0;
        let mut v: Polynomial = poly_a;
        for i in 0..128 {
            if bit_at_i_inverted_order(poly_b, i) {
                z ^= v;
            }
            if bit_at_i_inverted_order(v, 127) {
                v = (v >> 1) ^ SPECIAL_ELEMENT_R;
            } else {
                v >>= 1;
            }
        }
        z
    }

    pub fn coefficients_to_poly(
        &self,
        coefficients: Vec<usize>,
        _semantic: Semantic,
    ) -> Polynomial {
        let mut poly: Polynomial = 0;
        for coefficient in coefficients {
            poly |= 1u128 << coefficient as u128;
        }
        // PERF: by using swap bytes we can safe a bit of performance, as we dont need to do
        // (127-coefficient) each time
        poly.swap_bytes()
    }

    pub fn poly_to_coefficients(&self, poly: Polynomial, _semantic: Semantic) -> Vec<usize> {
        let mut enabled = Vec::new();
        for (byte_idx, byte) in poly.to_le_bytes().iter().rev().enumerate() {
            for (bit_idx, bit) in byte_to_bits(*byte).iter().rev().enumerate() {
                if *bit {
                    enabled.push(bit_idx + (byte_idx * 8));
                }
            }
        }

        enabled.sort();
        enabled.reverse();
        enabled
    }
}

impl Default for FField {
    fn default() -> Self {
        Self::new(128, DEFINING_RELATION_F_2_128)
    }
}

impl Display for FField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "F_2^({}); {}",
            self.n,
            self.display_poly(self.defining_relation)
        )
    }
}

pub fn run_testcase(testcase: &Testcase) -> Result<serde_json::Value> {
    Ok(match testcase.action {
        Action::Poly2Block => {
            let coefficients: Vec<usize>;

            let semantic: Semantic = if testcase.arguments["semantic"].is_string() {
                serde_json::from_value(testcase.arguments["semantic"].clone()).inspect_err(|e| {
                    eprintln!("! something went wrong when serializing the semantinc: {e}")
                })?
            } else {
                return Err(anyhow!("semantic is not a string"));
            };

            if let Some(downcast) = testcase.arguments["coefficients"].as_array() {
                coefficients = downcast
                    .iter()
                    .map(|v| serde_json::from_value(v.clone()).expect("thing is not an int"))
                    .collect();
            } else {
                return Err(anyhow!("coefficients is not a list"));
            }
            dbg!(&coefficients);
            let sol = F_2_128.coefficients_to_poly(coefficients, semantic);
            eprintln!("* block {:016X}", sol);
            // NOTE: I'm not sure why we need to reverse the byte order again here. The test case
            // does not require this.
            serde_json::to_value(BASE64_STANDARD.encode(sol.to_be_bytes()))
                .inspect_err(|e| eprintln!("! could not convert block to json: {e}"))?
        }
        Action::Block2Poly => {
            let semantic: Semantic = if testcase.arguments["semantic"].is_string() {
                serde_json::from_value(testcase.arguments["semantic"].clone()).inspect_err(|e| {
                    eprintln!("! something went wrong when serializing the semantinc: {e}")
                })?
            } else {
                return Err(anyhow!("semantic is not a string"));
            };

            let block: Polynomial = if testcase.arguments["block"].is_string() {
                let v: String = serde_json::from_value(testcase.arguments["block"].clone())
                    .inspect_err(|e| {
                        eprintln!("! something went wrong when serializing the semantinc: {e}")
                    })?;
                let bytes = BASE64_STANDARD.decode(v)?;
                crate::common::bytes_to_u128(&bytes)?
            } else {
                return Err(anyhow!("block is not a string"));
            };
            serde_json::to_value(F_2_128.poly_to_coefficients(block, semantic))?
        }
        _ => unreachable!(),
    })
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_add_alpha() {
        const SOLUTION: Polynomial = 0x14000000_00000000_00000000_00000000; // α^4 + α^2
        let sol = F_2_128.add(
            0x16000000_00000000_00000000_00000000, // α^4 + α^2 + α
            0x02000000_00000000_00000000_00000000, // α
        );
        assert_eq!(
            sol,
            SOLUTION,
            "\n0x{:016X} => {}\nshould be\n0x{SOLUTION:016X} => {}",
            sol,
            F_2_128.display_poly(sol),
            F_2_128.display_poly(SOLUTION),
        );
    }

    #[test]
    fn test_dipsplay_poly() {
        let a: Polynomial = 0x14000000_00000000_00000000_00000000; // α^4 + α^2
        let b: Polynomial = 0x16000000_00000000_00000000_00000000; // α^4 + α^2 + α
        let c: Polynomial = 0x02000000_00000000_00000000_00000000; // α
        assert_eq!(F_2_128.display_poly(1 << 120), "1");
        assert_eq!(F_2_128.display_poly(1 << 121), "α");
        assert_eq!(F_2_128.display_poly(a), "α^4 + α^2");
        assert_eq!(F_2_128.display_poly(b), "α^4 + α^2 + α");
        assert_eq!(F_2_128.display_poly(c), "α");
    }
}

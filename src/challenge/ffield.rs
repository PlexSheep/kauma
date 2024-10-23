//! multiply / add polynomials in a gallois field

use core::panic;
use std::default::Default;
use std::fmt::Display;

use anyhow::{anyhow, Result};
use base64::prelude::*;
use serde::{Deserialize, Serialize};

use crate::common::interface::get_bytes_maybe_hex;
use crate::common::{byte_to_bits, bytes_to_u128};
use crate::settings::Settings;

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
pub const DEFINING_RELATION_F_2_128: Polynomial = 0x87000000_00000000_00000000_00000000;
pub const DEFINING_RELATION_F_2_3: Polynomial = 0xb;
pub const DEFINING_RELATION_F_2_4: Polynomial = 0x13;
pub const DEFINING_RELATION_F_2_8: Polynomial = 0x11b;
/// A finite field over 2^128 with the defining relation [DEFINING_RELATION_F_2_128] as used in
/// AES.
pub const F_2_128: FField = FField::new(2, DEFINING_RELATION_F_2_128);
/// This is a special polynomial used for multiplication in F_2_128
pub const SPECIAL_ELEMENT_R: Polynomial = 0b11100001 << 120;

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
    pub n: u64,
    /// The defining relation, represented as a number, where the least significant bit
    /// signifies b * α^0, the second least significant bit signifies b * α^1 and so on, where b is
    /// the value of that bit.
    ///
    /// Note that the byte order is from least to highest, unintuitively.
    pub defining_relation: Polynomial,
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
    pub const fn reduce(&self, poly: Polynomial) -> Polynomial {
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
    pub const fn add(&self, poly_a: Polynomial, poly_b: Polynomial) -> Polynomial {
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
    // keep it close to the original algorithm in the cited paper
    #[allow(clippy::style)]
    #[allow(clippy::complexity)]
    pub fn mul_alpha(&self, poly_x: Polynomial, poly_y: Polynomial, verbose: bool) -> Polynomial {
        if verbose {
            eprintln!("? x:\t{poly_x:0128b}");
            eprintln!("? y:\t{poly_y:0128b}");
        }
        if self.display_poly(poly_y) != "α" {
            panic!("Only multiplying wiht α is supported as of now!");
        }

        let carry: bool;

        let mut x: Polynomial = poly_x.to_be();

        if x >> 127 == 1 {
            carry = true;
        } else {
            carry = false;
        }
        x <<= 1;

        if verbose {
            eprintln!("? relation:\t{:032x}", self.defining_relation);
            eprintln!("? prereduc:\t{x:032x}");
            eprintln!("? x displa:\t{}", self.display_poly(x.to_be()));
            eprintln!("? r displa:\t{}", self.display_poly(self.defining_relation));
        }

        if verbose {
            eprintln!("? carry:\t{carry}");
        }
        if !carry {
        } else {
            x ^= self.defining_relation.to_be();
        }

        if verbose {
            eprintln!("? done:\t\t{x:032x}");
        }
        x.to_be()
    }

    pub fn coefficients_to_poly(
        &self,
        coefficients: Vec<usize>,
        _semantic: Semantic,
    ) -> Polynomial {
        let mut poly: Polynomial = 0;
        for coefficient in coefficients {
            // NOTE: Why does this work? Shouldn't the horrible repr kill everything that uses
            // simple bitshifts and indexing?
            poly |= 1u128 << coefficient as u128;
        }
        // PERF: by using swap bytes we can safe a bit of performance, as we dont need to do
        // (127-coefficient) each time
        poly.swap_bytes()
    }

    pub fn poly_to_coefficients(&self, poly: Polynomial, _semantic: Semantic) -> Vec<usize> {
        let mut enabled = Vec::new();
        for (byte_idx, byte) in poly.to_be_bytes().iter().enumerate() {
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

pub fn run_testcase(testcase: &Testcase, settings: Settings) -> Result<serde_json::Value> {
    Ok(match testcase.action {
        Action::Poly2Block => {
            let coefficients: Vec<usize>;

            let semantic: Semantic = get_semantic(&testcase.arguments)?;

            if let Some(downcast) = testcase.arguments["coefficients"].as_array() {
                coefficients = downcast
                    .iter()
                    .map(|v| serde_json::from_value(v.clone()).expect("thing is not an int"))
                    .collect();
            } else {
                return Err(anyhow!("coefficients is not a list"));
            }
            let sol = F_2_128.coefficients_to_poly(coefficients, semantic);
            eprintln!("* block {:032X}", sol);
            serde_json::to_value(BASE64_STANDARD.encode(sol.to_be_bytes())).map_err(|e| {
                eprintln!("! could not convert block to json: {e}");
                e
            })?
        }
        Action::Block2Poly => {
            let semantic: Semantic = get_semantic(&testcase.arguments)?;
            let block: Polynomial = get_poly(&testcase.arguments, "block")?;
            serde_json::to_value(F_2_128.poly_to_coefficients(block, semantic))?
        }
        Action::GfMul => {
            let _semantic: Semantic = get_semantic(&testcase.arguments)?;
            let a: Polynomial = get_poly(&testcase.arguments, "a")?;
            let b: Polynomial = get_poly(&testcase.arguments, "b")?;
            if settings.verbose {
                eprintln!("? a:\t{a:032X} => {}", F_2_128.display_poly(a));
            }
            if settings.verbose {
                eprintln!("? b:\t{b:032X} => {}", F_2_128.display_poly(b));
            }

            let sol = F_2_128.mul_alpha(a, b, settings.verbose);
            if settings.verbose {
                eprintln!("? a*b:\t{sol:032X} => {}", F_2_128.display_poly(sol));
            }
            serde_json::to_value(BASE64_STANDARD.encode(sol.to_be_bytes())).map_err(|e| {
                eprintln!("! could not convert block to json: {e}");
                e
            })?
        }
        Action::SD_DisplayPolyBlock => {
            let _semantic: Semantic = get_semantic(&testcase.arguments)?;
            let block: Polynomial = get_poly(&testcase.arguments, "block")?;
            serde_json::to_value(F_2_128.display_poly(block))?
        }
        _ => unreachable!(),
    })
}

fn get_semantic(args: &serde_json::Value) -> Result<Semantic> {
    let semantic: Semantic = if args["semantic"].is_string() {
        serde_json::from_value(args["semantic"].clone()).map_err(|e| {
            eprintln!("! something went wrong when serializing the semantinc: {e}");
            e
        })?
    } else {
        return Err(anyhow!("semantic is not a string"));
    };
    Ok(semantic)
}

fn get_poly(args: &serde_json::Value, key: &str) -> Result<Polynomial> {
    let bytes = get_bytes_maybe_hex(args, key)?;
    let v = crate::common::bytes_to_u128(&bytes)?;
    Ok(v)
}

#[cfg(test)]
mod test {
    use std::collections::HashSet;

    use super::*;

    fn assert_eq_polys(poly_a: Polynomial, poly_b: Polynomial) {
        assert_eq!(
            poly_a,
            poly_b,
            "\n0x{poly_a:032X} => {}\nshould be\n0x{poly_b:032X} => {}\nbin of false solution:\n{:0128b}",
            F_2_128.display_poly(poly_a),
            F_2_128.display_poly(poly_b),
            poly_a
        );
    }

    #[test]
    fn test_add() {
        const SOLUTION: Polynomial = 0x14000000_00000000_00000000_00000000; // α^4 + α^2
        let sol = F_2_128.add(
            0x16000000_00000000_00000000_00000000, // α^4 + α^2 + α
            0x02000000_00000000_00000000_00000000, // α
        );
        assert_eq_polys(sol, SOLUTION);
    }

    #[test]
    fn test_poly_from_coefficients() {
        const SOLUTION: Polynomial = 0x01120000000000000000000000000080;
        let sol = F_2_128.coefficients_to_poly(vec![0, 9, 12, 127], Semantic::Xex);
        assert_eq_polys(sol, SOLUTION);
    }

    #[test]
    fn test_coefficients_from_poly() {
        // we don't care about order, so just put things in a set
        assert_eq!(
            F_2_128
                .poly_to_coefficients(0x01120000000000000000000000000080, Semantic::Xex)
                .into_iter()
                .collect::<HashSet<_>>(),
            HashSet::from([0, 9, 12, 127])
        )
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
        assert_eq!(F_2_128.display_poly(1 << 7), "α^127");
    }

    #[test]
    fn test_mul_0() {
        const SOLUTION: Polynomial = 0x2c000000000000000000000000000000; // α^5 + α^3 + α^2
        let sol = F_2_128.mul_alpha(
            0x16000000_00000000_00000000_00000000, // α^4 + α^2 + α
            0x02000000_00000000_00000000_00000000, // α
            true,
        );
        assert_eq_polys(sol, SOLUTION);
    }

    #[test]
    fn test_mul_1() {
        const SOLUTION: Polynomial = 0x04000000000000000000000000000000; // α^2
        let sol = F_2_128.mul_alpha(
            0x02000000_00000000_00000000_00000000, // α
            0x02000000_00000000_00000000_00000000, // α
            true,
        );
        assert_eq_polys(sol, SOLUTION);
    }

    #[test]
    fn test_mul_2() {
        const SOLUTION: Polynomial = 0x85240000000000000000000000000000; // α^13 + α^10 + α^7 + α^2 + 1
        let sol = F_2_128.mul_alpha(
            0x01120000_00000000_00000000_00000080, // α^127 + α^12 + α^9 + 1
            0x02000000_00000000_00000000_00000000, // α
            true,
        );
        assert_eq_polys(sol, SOLUTION);
    }
}

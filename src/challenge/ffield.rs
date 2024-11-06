//! multiply / add polynomials in a gallois field

use std::default::Default;
use std::fmt::Display;

use anyhow::{anyhow, Result};
use base64::prelude::*;
use bint_easy::u256::U256;
use serde::{Deserialize, Serialize};

use crate::common::interface::get_bytes_maybe_hex;
use crate::common::{bit_at_i, byte_to_bits, veprintln};
use crate::settings::{Settings, DEFAULT_SETTINGS};

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
pub const DEFINING_RELATION_F_2_128: U256 = U256(1, DEFINING_RELATION_F_2_128_SHORT);
pub const DEFINING_RELATION_F_2_128_SHORT: Polynomial = 0x87000000_00000000_00000000_00000000;
pub const DEFINING_RELATION_F_2_3: Polynomial = 0xb;
pub const DEFINING_RELATION_F_2_4: Polynomial = 0x13;
pub const DEFINING_RELATION_F_2_8: Polynomial = 0x11b;
/// A finite field over 2^128 with the defining relation [DEFINING_RELATION_F_2_128] as used in
/// AES.
pub const F_2_128: FField = FField::new(2, DEFINING_RELATION_F_2_128, DEFAULT_SETTINGS);
/// Special element that also finds use in XEX mode
pub const F_2_128_ALPHA: Polynomial = 0x02000000_00000000_00000000_00000000; // α

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FField {
    /// Forms the base as 2^n
    pub n: u64,
    /// The defining relation, represented as a number, where the least significant bit
    /// signifies b * α^0, the second least significant bit signifies b * α^1 and so on, where b is
    /// the value of that bit.
    ///
    /// Note that the byte order is from least to highest, unintuitively.
    pub defining_relation: U256,
    /// Defines how the program executes, mostly concerned with debug printing.
    ///
    /// The important variables are part of [FField], not [Settings].
    pub settings: Settings,
}

impl FField {
    /// Create a new finite field with a base that is a power of two.
    pub const fn new(n: u64, defining_relation: U256, settings: Settings) -> Self {
        Self {
            n,
            defining_relation,
            settings,
        }
    }

    pub fn set_settings(&mut self, settings: &Settings) {
        self.settings = *settings
    }

    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    pub fn settings_mut(&mut self) -> &mut Settings {
        &mut self.settings
    }

    pub fn verbose(&self) -> bool {
        self.settings.verbose
    }

    /// Convert the machine representation of a polynomial to the human representation, using [XEX Semantic](Semantic::Xex).
    /// ```
    /// use kauma_analyzer::challenge::ffield::F_2_128;
    /// assert_eq!(F_2_128.display_poly(1 << 121), "α");
    /// assert_eq!(F_2_128.display_poly(0b1001 << 55), "α^79 + α^66");
    /// ```
    pub fn display_poly(&self, poly: Polynomial) -> String {
        let mut buf = String::new();
        let enabled: Vec<_> = self
            .poly_to_coefficients(poly, Semantic::default())
            .into_iter()
            .rev()
            .collect();
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
    /// Note: This function uses the [XEX Semantic](Semantic::Xex) for [polynomials](Polynomial).
    pub fn mul(&self, x: Polynomial, y: Polynomial) -> Polynomial {
        if self.verbose() {
            eprintln!("? inputs");
            veprintln("x", format_args!("{}", self.dbg_poly(x)));
            veprintln("y", format_args!("{}", self.dbg_poly(y)));
            veprintln(
                "relation~",
                format_args!("{}", self.dbg_poly(self.defining_relation.lower())),
            );
            veprintln("relation", format_args!("{:032x}", self.defining_relation));
        }

        // Reverse the byte order, so that we can work with regular bitshifts.
        // Otherwise, the bit order and the byte order are different, resulting in garbage.
        let mut x = U256::from(x.to_be());
        let mut y = U256::from(y.to_be());
        let mut z = U256::from(0);

        self.dbg_mul("preparation", x, y, z);

        // if lsb
        if bit_at_i(y.lower(), 0) {
            z ^= x;
        }
        self.dbg_mul("first", x, y, z);

        y >>= 1;

        while y != 0 {
            x <<= 1;

            // if msb
            if x.upper() > 0 {
                // the defining relation needs to be converted to the same ordering as the x,y and
                // z values
                x = (x.lower() ^ self.defining_relation.lower().to_be()).into();
            }

            // if lsb
            if bit_at_i(y.lower(), 0) {
                z ^= x;
            }
            y >>= 1;
            self.dbg_mul("step", x, y, z);
        }

        self.dbg_mul("final", x, y, z);

        if self.verbose() {
            eprintln!("? outputs");
            veprintln("x", format_args!("{}", self.dbg_poly(x.lower())));
            veprintln("y", format_args!("{}", self.dbg_poly(y.lower())));
            veprintln("z", format_args!("{}", self.dbg_poly(z.lower())));
        }

        z
            // swap the byte order of the result back, so that we are in XEX semantic again.
            .swap_bytes()
            .swap_parts()
            // convert U256 into u128, dropping the higher part of the 'big' int
            .try_into()
            .expect("z is still too big, was not reduced correctly in multiplication")
    }

    /// helper function for debug prints in [Self::mul].
    fn dbg_mul(&self, title: &str, x: U256, y: U256, z: U256) {
        if self.verbose() {
            eprintln!("? {title}");
            veprintln("x", format_args!("{x:032x}"));
            veprintln("y", format_args!("{y:032x}"));
            veprintln("z", format_args!("{z:032x}"));
        }
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
        enabled
    }

    /// helps print a [Polynomial] for debug purposes
    #[inline]
    pub(crate) fn dbg_poly(&self, p: Polynomial) -> String {
        format!("{p:032X} => {}", self.display_poly(p))
    }
}

impl Default for FField {
    fn default() -> Self {
        Self::new(128, DEFINING_RELATION_F_2_128, Settings::default())
    }
}

impl Display for FField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "F_2^({}); ~{}",
            self.n,
            self.display_poly(self.defining_relation.0)
        )
    }
}

pub fn run_testcase(testcase: &Testcase, settings: Settings) -> Result<serde_json::Value> {
    let mut field = F_2_128;
    field.set_settings(&settings);

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
            let sol = field.coefficients_to_poly(coefficients, semantic);
            eprintln!("* block {:032X}", sol);
            serde_json::to_value(BASE64_STANDARD.encode(sol.to_be_bytes())).map_err(|e| {
                eprintln!("! could not convert block to json: {e}");
                e
            })?
        }
        Action::Block2Poly => {
            let semantic: Semantic = get_semantic(&testcase.arguments)?;
            let block: Polynomial = get_poly(&testcase.arguments, "block")?;
            serde_json::to_value(field.poly_to_coefficients(block, semantic))?
        }
        Action::GfMul => {
            let _semantic: Semantic = get_semantic(&testcase.arguments)?;
            let a: Polynomial = get_poly(&testcase.arguments, "a")?;
            let b: Polynomial = get_poly(&testcase.arguments, "b")?;
            eprintln!("{a:032x}");

            let sol = field.mul(a, b);
            serde_json::to_value(BASE64_STANDARD.encode(sol.to_be_bytes())).map_err(|e| {
                eprintln!("! could not convert block to json: {e}");
                e
            })?
        }
        Action::SD_DisplayPolyBlock => {
            let _semantic: Semantic = get_semantic(&testcase.arguments)?;
            let block: Polynomial = get_poly(&testcase.arguments, "block")?;
            serde_json::to_value(field.display_poly(block))?
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

    fn field() -> FField {
        let mut f = F_2_128;
        f.set_settings(&Settings {
            verbose: true,
            threads: None,
        });
        f
    }

    fn assert_eq_polys(poly_a: Polynomial, poly_b: Polynomial) {
        assert_eq!(
            poly_a,
            poly_b,
            "\n0x{poly_a:032X} => {}\nshould be\n0x{poly_b:032X} => {}\nbin of false solution:\n{:0128b}",
            field().display_poly(poly_a),
            field().display_poly(poly_b),
            poly_a
        );
    }

    #[test]
    fn test_add() {
        const SOLUTION: Polynomial = 0x14000000_00000000_00000000_00000000; // α^4 + α^2
        let sol = field().add(
            0x16000000_00000000_00000000_00000000, // α^4 + α^2 + α
            0x02000000_00000000_00000000_00000000, // α
        );
        assert_eq_polys(sol, SOLUTION);
    }

    #[test]
    fn test_poly_from_coefficients() {
        const SOLUTION: Polynomial = 0x01120000000000000000000000000080;
        let sol = field().coefficients_to_poly(vec![0, 9, 12, 127], Semantic::Xex);
        assert_eq_polys(sol, SOLUTION);
    }

    #[test]
    fn test_coefficients_from_poly() {
        // we don't care about order, so just put things in a set
        assert_eq!(
            field()
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
        assert_eq!(field().display_poly(1 << 120), "1");
        assert_eq!(field().display_poly(1 << 121), "α");
        assert_eq!(field().display_poly(a), "α^4 + α^2");
        assert_eq!(field().display_poly(b), "α^4 + α^2 + α");
        assert_eq!(field().display_poly(c), "α");
        assert_eq!(field().display_poly(1 << 7), "α^127");
    }

    #[test]
    fn test_mul_0() {
        const SOLUTION: Polynomial = 0x2c000000000000000000000000000000; // α^5 + α^3 + α^2
        let sol = field().mul(
            0x16000000_00000000_00000000_00000000, // α^4 + α^2 + α
            0x02000000_00000000_00000000_00000000, // α
        );
        assert_eq_polys(sol, SOLUTION);
    }

    #[test]
    fn test_mul_1() {
        const SOLUTION: Polynomial = 0x04000000000000000000000000000000; // α^2
        let sol = field().mul(
            0x02000000_00000000_00000000_00000000, // α
            0x02000000_00000000_00000000_00000000, // α
        );
        assert_eq_polys(sol, SOLUTION);
    }

    #[test]
    fn test_mul_2() {
        const SOLUTION: Polynomial = 0x85240000000000000000000000000000; // α^13 + α^10 + α^7 + α^2 + 1
        let sol = field().mul(
            0x01120000_00000000_00000000_00000080, // α^127 + α^12 + α^9 + 1
            0x02000000_00000000_00000000_00000000, // α
        );
        assert_eq_polys(sol, SOLUTION);
    }

    #[test]
    fn test_mul_3() {
        const SOLUTION: Polynomial = 0x85240000000000000000000000000000; // α^13 + α^10 + α^7 + α^2 + 1
        let sol = field().mul(
            0x02000000_00000000_00000000_00000000, // α
            0x01120000_00000000_00000000_00000080, // α^127 + α^12 + α^9 + 1
        );
        assert_eq_polys(sol, SOLUTION);
    }

    #[test]
    fn test_mul_4() {
        const SOLUTION: Polynomial = 0x40A81400000000000000000000000000;
        let sol = field().mul(
            0x03010000000000000000000000000080,
            0x80100000000000000000000000000000,
        );
        assert_eq_polys(sol, SOLUTION);
    }

    #[test]
    fn test_mul_5() {
        const SOLUTION: Polynomial = 0x50801400000000000000000000000000;
        let sol = field().mul(
            0x03010000000000000000000000000080,
            0xA0100000000000000000000000000000,
        );
        assert_eq_polys(sol, SOLUTION);
    }

    #[test]
    fn test_mul_6() {
        const SOLUTION: Polynomial = 0x85240000000000000000000000000000;
        let sol = field().mul(
            0x01120000000000000000000000000080,
            0x02000000000000000000000000000000,
        );
        assert_eq_polys(sol, SOLUTION);
    }

    #[test]
    fn test_mul_7() {
        const SOLUTION: Polynomial = 0x04000000_00000000_00000000_00000000;
        let sol = field().mul(
            0x02000000_00000000_00000000_00000000, // α
            0x02000000_00000000_00000000_00000000, // α
        );
        assert_eq_polys(sol, SOLUTION);
    }
}

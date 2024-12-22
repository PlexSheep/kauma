//! multiply / add polynomials in a gallois field

use std::default::Default;

use anyhow::{anyhow, Result};
use base64::prelude::*;
use bint_easy::u256::U256;
use num::traits::ToBytes;
use serde::{Deserialize, Serialize};

use crate::common::interface::get_bytes_maybe_hex;
use crate::common::{bit_at_i, veprintln};
use crate::settings::{Settings, DEFAULT_SETTINGS};

use self::element::{FieldElement, DEFINING_RELATION_F_2_128};

use super::{Action, Testcase};

pub mod element;

/// A finite field over 2^128 with the defining relation [DEFINING_RELATION_F_2_128] as used in
/// AES.
pub const F_2_128: FField = FField::new(2, DEFAULT_SETTINGS);

#[derive(Debug, Deserialize, Serialize, Clone, Copy, Default)]
#[serde(rename_all = "snake_case")]
pub enum Semantic {
    /// whatever is used in AES-XEX
    #[default]
    Xex,
    Gcm,
}

/// Which finite field to use, e.g. F_(2^(128))
///
/// For the purposes of kauma-analyzer, we will focus on binary finite fields, so those with a base
/// of 2^n.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FField {
    /// Forms the base as 2^n
    pub n: u64,
    /// Defines how the program executes, mostly concerned with debug printing.
    ///
    /// The important variables are part of [FField], not [Settings].
    pub settings: Settings,
}

impl FField {
    /// Create a new finite field with a base that is a power of two.
    pub const fn new(n: u64, settings: Settings) -> Self {
        Self { n, settings }
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

    /// Get the sum of two [polynomials](Polynomial)
    ///
    /// Adds poly a and b together.
    ///
    /// This is not regular addition of two numbers!
    ///
    /// Addition on the finite field with a base of 2^n is the same as xor, therefore no reduction
    /// is needed.
    pub fn add(&self, poly_a: FieldElement, poly_b: FieldElement) -> FieldElement {
        poly_a + poly_b
    }
    /// Get the product of two [polynomials](Polynomial)
    ///
    /// Multiplies poly a by poly b together, automatically reducing it with the defining relation.
    ///
    /// This is not regular multiplication of two numbers!
    ///
    /// Note: This function uses the [XEX Semantic](Semantic::Xex) for [polynomials](Polynomial).
    pub fn mul(&self, x: FieldElement, y: FieldElement) -> FieldElement {
        if self.verbose() {
            eprintln!("? inputs");
            veprintln("x", format_args!("{}", x.dbg()));
            veprintln("y", format_args!("{}", y.dbg()));
            veprintln(
                "relation~",
                format_args!("{}", FieldElement::RELATION.dbg()),
            );
            veprintln(
                "relation",
                format_args!("{:032x}", DEFINING_RELATION_F_2_128),
            );
        }

        // Reverse the byte order, so that we can work with regular bitshifts.
        // Otherwise, the bit order and the byte order are different, resulting in garbage.
        let mut x = U256::from(x.raw().to_be());
        let mut y = U256::from(y.raw().to_be());
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
                x = (x.lower() ^ DEFINING_RELATION_F_2_128.lower().to_be()).into();
            }

            // if lsb
            if bit_at_i(y.lower(), 0) {
                z ^= x;
            }
            y >>= 1;
        }

        self.dbg_mul("final", x, y, z);

        let a: u128 = z
            // swap the byte order of the result back, so that we are in XEX semantic again.
            .swap_bytes()
            .swap_parts()
            // convert U256 into u128, dropping the higher part of the 'big' int
            .try_into()
            .expect("z is still too big, was not reduced correctly in multiplication");
        a.into()
    }

    /// helper function for debug prints in [Self::mul].
    #[inline]
    fn dbg_mul(&self, title: &str, x: U256, y: U256, z: U256) {
        if self.verbose() {
            eprintln!("? {title}");
            veprintln("x", format_args!("{x:032x}"));
            veprintln("y", format_args!("{y:032x}"));
            veprintln("z", format_args!("{z:032x}"));
        }
    }

    /// divide [Polynomial] `a` by [Polynomial] `b`
    ///
    /// Internally, this is just multiplication with the inverse element of `b`
    ///
    /// # Panics
    ///
    /// Panics if `b` is 0
    pub fn div(&self, a: FieldElement, b: FieldElement) -> FieldElement {
        if b == FieldElement::ZERO {
            panic!("cannot divide by zero: {b}");
        }
        self.mul(a, self.inv(b))
    }

    /// get the inverse of a [Polynomial] `p`
    pub fn inv(&self, mut p: FieldElement) -> FieldElement {
        const BASE: u128 = 0xfffffffffffffffffffffffffffffffe;
        let mut counter: u128 = BASE;
        let mut acc: FieldElement = FieldElement::from(1u128.to_be());

        while counter > 0 {
            if counter & 1 == 1 {
                acc = self.mul(p, acc);
            }
            counter >>= 1;
            p = self.mul(p, p)
        }

        acc
    }
}

impl Default for FField {
    fn default() -> Self {
        Self::new(128, Settings::default())
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
            let sol = FieldElement::from_coefficients(coefficients)
                .change_semantic(Semantic::Xex, semantic);
            serde_json::to_value(BASE64_STANDARD.encode(sol.to_be_bytes())).map_err(|e| {
                eprintln!("! could not convert block to json: {e}");
                e
            })?
        }
        Action::Block2Poly => {
            let semantic: Semantic = get_semantic(&testcase.arguments)?;
            let block: FieldElement = get_poly(&testcase.arguments, "block", semantic)?;
            serde_json::to_value(block.to_coefficients())?
        }
        Action::GfMul => {
            let semantic: Semantic = get_semantic(&testcase.arguments)?;
            let a: FieldElement = get_poly(&testcase.arguments, "a", semantic)?;
            let b: FieldElement = get_poly(&testcase.arguments, "b", semantic)?;

            let sol = field.mul(a, b).change_semantic(Semantic::Xex, semantic);
            serde_json::to_value(BASE64_STANDARD.encode(sol.to_be_bytes())).map_err(|e| {
                eprintln!("! could not convert block to json: {e}");
                e
            })?
        }
        Action::GfDiv => {
            let semantic: Semantic = Semantic::Gcm;
            let a: FieldElement = get_poly(&testcase.arguments, "a", semantic)?;
            let b: FieldElement = get_poly(&testcase.arguments, "b", semantic)?;

            let sol = field.div(a, b);
            let sol = sol.change_semantic(Semantic::Xex, semantic);
            serde_json::to_value(BASE64_STANDARD.encode(sol.to_be_bytes())).map_err(|e| {
                eprintln!("! could not convert block to json: {e}");
                e
            })?
        }
        Action::SD_DisplayPolyBlock => {
            let semantic: Semantic = get_semantic(&testcase.arguments)?;
            let block: FieldElement = get_poly(&testcase.arguments, "block", semantic)?;
            serde_json::to_value(block.display_algebra())?
        }
        _ => unreachable!(),
    })
}

pub(crate) fn get_semantic(args: &serde_json::Value) -> Result<Semantic> {
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

pub(crate) fn get_poly_from_bytes(bytes: &[u8], semantic: Semantic) -> Result<FieldElement> {
    let v: FieldElement = crate::common::bytes_to_u128_unknown_size(bytes)?.into();
    Ok(v.change_semantic(semantic, Semantic::Xex))
}

pub(crate) fn get_poly(
    args: &serde_json::Value,
    key: &str,
    semantic: Semantic,
) -> Result<FieldElement> {
    let bytes = get_bytes_maybe_hex(args, key)?;
    let v = get_poly_from_bytes(&bytes, semantic)?;
    Ok(v)
}

#[cfg(test)]
mod test {
    use std::collections::HashSet;

    use serde_json::json;

    use crate::common::assert_int;

    use super::*;

    fn field() -> FField {
        let mut f = F_2_128;
        f.set_settings(&Settings {
            verbose: true,
            threads: None,
        });
        f
    }

    fn assert_eq_polys(poly_a: FieldElement, poly_b: FieldElement) {
        assert_eq!(
            poly_a,
            poly_b,
            "\n0x{poly_a:032X} => {}\nshould be\n0x{poly_b:032X} => {}\nbin of false solution:\n{:0128b}",
            poly_a.display_algebra(),
            poly_b.display_algebra(),
            poly_a
        );
    }

    #[test]
    fn test_ffield_add() {
        const SOLUTION: FieldElement =
            FieldElement::const_from_raw(0x14000000_00000000_00000000_00000000); // α^4 + α^2
        let sol = field().add(
            FieldElement::const_from_raw(0x16000000_00000000_00000000_00000000), // α^4 + α^2 + α
            FieldElement::const_from_raw(0x02000000_00000000_00000000_00000000), // α
        );
        assert_eq_polys(sol, SOLUTION);
    }

    #[test]
    fn test_ffield_poly_from_coefficients() {
        const SOLUTION: FieldElement =
            FieldElement::const_from_raw(0x01120000000000000000000000000080);
        let sol = FieldElement::from_coefficients(vec![0, 9, 12, 127]);
        assert_eq_polys(sol, SOLUTION);
    }

    #[test]
    fn test_ffield_coefficients_from_poly() {
        // we don't care about order, so just put things in a set
        assert_eq!(
            FieldElement::const_from_raw(0x01120000000000000000000000000080)
                .to_coefficients()
                .into_iter()
                .collect::<HashSet<_>>(),
            HashSet::from([0, 9, 12, 127])
        )
    }

    #[test]
    fn test_ffield_mul_0() {
        const SOLUTION: FieldElement =
            FieldElement::const_from_raw(0x2c000000000000000000000000000000); // α^5 + α^3 + α^2
        let sol = field().mul(
            FieldElement::const_from_raw(0x16000000_00000000_00000000_00000000), // α^4 + α^2 + α
            FieldElement::const_from_raw(0x02000000_00000000_00000000_00000000), // α
        );
        assert_eq_polys(sol, SOLUTION);
    }

    #[test]
    fn test_ffield_mul_1() {
        const SOLUTION: FieldElement =
            FieldElement::const_from_raw(0x04000000000000000000000000000000); // α^2
        let sol = field().mul(
            FieldElement::const_from_raw(0x02000000_00000000_00000000_00000000), // α
            FieldElement::const_from_raw(0x02000000_00000000_00000000_00000000), // α
        );
        assert_eq_polys(sol, SOLUTION);
    }

    #[test]
    fn test_ffield_mul_2() {
        const SOLUTION: FieldElement =
            FieldElement::const_from_raw(0x85240000000000000000000000000000); // α^13 + α^10 + α^7 + α^2 + 1
        let sol = field().mul(
            FieldElement::const_from_raw(0x01120000_00000000_00000000_00000080), // α^127 + α^12 + α^9 + 1
            FieldElement::const_from_raw(0x02000000_00000000_00000000_00000000), // α
        );
        assert_eq_polys(sol, SOLUTION);
    }

    #[test]
    fn test_ffield_mul_3() {
        const SOLUTION: FieldElement =
            FieldElement::const_from_raw(0x85240000000000000000000000000000); // α^13 + α^10 + α^7 + α^2 + 1
        let sol = field().mul(
            FieldElement::const_from_raw(0x02000000_00000000_00000000_00000000), // α
            FieldElement::const_from_raw(0x01120000_00000000_00000000_00000080), // α^127 + α^12 + α^9 + 1
        );
        assert_eq_polys(sol, SOLUTION);
    }

    #[test]
    fn test_ffield_mul_4() {
        const SOLUTION: FieldElement =
            FieldElement::const_from_raw(0x40A81400000000000000000000000000);
        let sol = field().mul(
            FieldElement::const_from_raw(0x03010000000000000000000000000080),
            FieldElement::const_from_raw(0x80100000000000000000000000000000),
        );
        assert_eq_polys(sol, SOLUTION);
    }

    #[test]
    fn test_ffield_mul_5() {
        const SOLUTION: FieldElement =
            FieldElement::const_from_raw(0x50801400000000000000000000000000);
        let sol = field().mul(
            FieldElement::const_from_raw(0x03010000000000000000000000000080),
            FieldElement::const_from_raw(0xA0100000000000000000000000000000),
        );
        assert_eq_polys(sol, SOLUTION);
    }

    #[test]
    fn test_ffield_mul_6() {
        const SOLUTION: FieldElement =
            FieldElement::const_from_raw(0x85240000000000000000000000000000);
        let sol = field().mul(
            FieldElement::const_from_raw(0x01120000000000000000000000000080),
            FieldElement::const_from_raw(0x02000000000000000000000000000000),
        );
        assert_eq_polys(sol, SOLUTION);
    }

    #[test]
    fn test_ffield_mul_7() {
        const SOLUTION: FieldElement =
            FieldElement::const_from_raw(0x04000000_00000000_00000000_00000000);
        let sol = field().mul(
            FieldElement::const_from_raw(0x02000000_00000000_00000000_00000000), // α
            FieldElement::const_from_raw(0x02000000_00000000_00000000_00000000), // α
        );
        assert_eq_polys(sol, SOLUTION);
    }

    #[test]
    fn test_ffield_poly_from_gcm() {
        let xex = BASE64_STANDARD.decode("ARIAAAAAAAAAAAAAAAAAgA==").unwrap();
        let gcm = BASE64_STANDARD.decode("gEgAAAAAAAAAAAAAAAAAAQ==").unwrap();

        eprintln!("XEX DUMP: {xex:02x?}");
        eprintln!("GCM DUMP: {gcm:02x?}");

        assert_eq_polys(
            get_poly_from_bytes(&xex, Semantic::Xex).unwrap(),
            get_poly_from_bytes(&gcm, Semantic::Gcm).unwrap(),
        )
    }

    #[test]
    fn test_ffield_change_sem_lossles() {
        let p: FieldElement = FieldElement::const_from_raw(0xb1480000000000000000000000000000);
        let mut t = p;
        for _ in 0..5000 {
            t = t.change_semantic(Semantic::Xex, Semantic::Gcm);
            t = t.change_semantic(Semantic::Gcm, Semantic::Xex);
            assert_int(p, t);
        }
    }

    #[test]
    fn test_ffield_div_0() {
        const SOLUTION: FieldElement =
            FieldElement::const_from_raw(0x02000000_00000000_00000000_00000000); // α
        let sol = field().div(
            FieldElement::const_from_raw(0x04000000000000000000000000000000), // α^2
            FieldElement::const_from_raw(0x02000000_00000000_00000000_00000000), // α
        );
        assert_eq_polys(sol, SOLUTION);
    }

    #[test]
    fn test_ffield_div_1() {
        const SOLUTION: FieldElement =
            FieldElement::const_from_raw(0x01000000_00000000_00000000_00000000); // 1
        const A: FieldElement = FieldElement::const_from_raw(0x02000000_00000000_00000000_00000000); // α
        let sol = field().div(A, A);
        assert_eq_polys(sol, SOLUTION);
    }

    #[test]
    fn test_ffield_div_2() {
        let args = json!(
            {
                "a": "JAAAAAAAAAAAAAAAAAAAAA==",
                "b": "wAAAAAAAAAAAAAAAAAAAAA==",
                "s": "OAAAAAAAAAAAAAAAAAAAAA=="
            }
        );

        let a = get_poly(&args, "a", Semantic::Gcm).unwrap();
        let b = get_poly(&args, "b", Semantic::Gcm).unwrap();
        let s = get_poly(&args, "s", Semantic::Gcm).unwrap();

        let sol = field().div(a, b);
        assert_eq_polys(sol, s);
    }
}

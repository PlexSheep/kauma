//! # superpoly
//!
//! The `superpoly` module provides an implementation of "super polynomials" - polynomials with coefficients that are also polynomials in a finite field.
//! This type has uses in cryptography and other advanced mathematical applications.

use std::ops::{Add, AddAssign, BitXor, BitXorAssign, Mul, MulAssign};

use anyhow::Result;
use base64::prelude::*;
use num::pow::Pow;
use serde::{Serialize, Serializer};

use crate::common::bytes_to_u128_unknown_size;
use crate::common::interface::{get_any, maybe_hex};
use crate::settings::Settings;

use super::ffield::{change_semantic, F_2_128};
use super::{ffield, Action, Testcase};
use ffield::Polynomial;

#[derive(Debug, Clone, PartialOrd, Eq, Ord)]
pub struct SuperPoly {
    coefficients: Vec<Polynomial>,
}

/// A struct representing a "super polynomial" - a polynomial with coefficients that are also polynomials in a finite field.
impl SuperPoly {
    /// Returns a "zero" [`SuperPoly`] with all coefficients set to 0.
    #[inline]
    pub fn zero() -> Self {
        Self::empty()
    }
    /// Returns an "empty" [`SuperPoly`] with all coefficients set to 0.
    #[inline]
    fn empty() -> Self {
        SuperPoly::from(Vec::<u128>::new().as_slice())
    }
    /// Returns a "one" [`SuperPoly`] with all coefficients set to 0, but the LSC, which is 1.
    #[inline]
    pub fn one() -> Self {
        // In XEX semantic, we need to byte-swap 1 to get it in the right position
        SuperPoly::from([1u128.to_be()])
    }
    /// Check if this [`SuperPoly`] is actually [zero](Self::zero).
    ///
    /// This is not as trivial as it sounds, because the inner [Vec] holding the coefficients might
    /// have multiple coefficients with the value 0 saved, but that does not actually make
    /// a difference mathmatically.
    #[inline]
    pub fn is_zero(&self) -> bool {
        // A SuperPoly is zero <=> all it's coefficients are zero
        self.coefficients.iter().all(|p| *p == 0)
    }
    /// remove leading zeros
    pub fn normalize(&mut self) {
        while self.coefficients.last() == Some(&0) {
            self.coefficients.pop();
        }
    }

    #[inline]
    pub fn deg(&self) -> usize {
        self.coefficients.len()
    }

    pub fn divmod(&self, rhs: &Self) -> (Self, Self) {
        // Check for division by zero
        if rhs.is_zero() {
            panic!("division by zero");
        }

        // If degree of dividend < degree of divisor, quotient is 0 and remainder is dividend
        if self.deg() < rhs.deg() {
            return (SuperPoly::zero(), self.clone());
        }

        // Initialize remainder as dividend and will be modified during division
        let mut remainder = self.clone();

        // Get the leading coefficient of divisor
        let divisor_lc = *rhs.coefficients.last().unwrap();

        // Initialize quotient vector with enough capacity
        let mut quotient_coeffs = vec![0; remainder.deg() - rhs.deg() + 1];

        // While remainder has degree >= divisor degree
        while remainder.deg() >= rhs.deg() {
            // Calculate degree difference
            let deg_diff = remainder.deg() - rhs.deg();

            // Calculate the leading coefficient for this term of quotient
            // by dividing leading coefficients in F_2^128
            let term_coeff = F_2_128.div(*remainder.coefficients.last().unwrap(), divisor_lc);

            // Save coefficient in quotient
            quotient_coeffs[deg_diff] = term_coeff;

            // Subtract (rhs * term) from remainder
            // We do this term by term to avoid creating a temporary polynomial
            for (i, &coeff) in rhs.coefficients.iter().enumerate() {
                let pos = deg_diff + i;
                remainder.coefficients[pos] ^= F_2_128.mul(coeff, term_coeff);
            }

            // Remove trailing zeros from remainder
            remainder.normalize();
        }

        // Create quotient polynomial and normalize it
        let mut quotient = SuperPoly::from(quotient_coeffs.as_slice());
        quotient.normalize();

        (quotient, remainder)
    }
}

impl Serialize for SuperPoly {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let coefficients: Vec<String> = self
            .coefficients
            .iter()
            .map(|coeff| change_semantic(*coeff, ffield::Semantic::Xex, ffield::Semantic::Gcm))
            .map(|coeff| BASE64_STANDARD.encode(coeff.to_be_bytes()))
            .collect();

        coefficients.serialize(serializer)
    }
}

/** Calculation stuff ********************************************************/

impl PartialEq for SuperPoly {
    fn eq(&self, other: &Self) -> bool {
        if self.coefficients.len() == other.coefficients.len() {
            self.coefficients == other.coefficients
        } else {
            // could only be equal if both are zero, but the vec is larger in one
            self.is_zero() && other.is_zero()
        }
    }
}

impl Add for SuperPoly {
    type Output = SuperPoly;
    fn add(self, rhs: Self) -> Self::Output {
        &self + &rhs
    }
}

impl BitXor for SuperPoly {
    type Output = SuperPoly;
    fn bitxor(self, rhs: Self) -> Self::Output {
        &self ^ &rhs
    }
}

impl Add for &SuperPoly {
    type Output = SuperPoly;
    #[allow(clippy::suspicious_arithmetic_impl)] // it's mathmatically the same, I study this shit
    fn add(self, rhs: Self) -> Self::Output {
        self ^ rhs
    }
}

impl AddAssign for SuperPoly {
    #[allow(clippy::suspicious_op_assign_impl)] // it's mathmatically the same, I study this shit
    fn add_assign(&mut self, rhs: Self) {
        *self ^= rhs;
    }
}

impl BitXor for &SuperPoly {
    type Output = SuperPoly;
    fn bitxor(self, rhs: Self) -> Self::Output {
        let max_idx: usize = self.coefficients.len().max(rhs.coefficients.len());
        let mut new_coefficients: Vec<Polynomial> = Vec::with_capacity(max_idx);

        for i in 0..max_idx {
            new_coefficients.push(
                self.coefficients.get(i).unwrap_or(&0) ^ rhs.coefficients.get(i).unwrap_or(&0),
            );
        }

        let mut p = SuperPoly::from(new_coefficients.as_slice());
        p.normalize();
        p
    }
}

impl BitXorAssign for SuperPoly {
    fn bitxor_assign(&mut self, rhs: Self) {
        let max_idx: usize = self.coefficients.len().max(rhs.coefficients.len());
        for i in 0..max_idx {
            self.coefficients[i] ^= rhs.coefficients.get(i).unwrap_or(&0);
        }
        self.normalize();
    }
}

impl Mul for SuperPoly {
    type Output = SuperPoly;
    fn mul(self, rhs: Self) -> Self::Output {
        &self * &rhs
    }
}

impl Mul for &SuperPoly {
    type Output = SuperPoly;
    fn mul(self, rhs: Self) -> Self::Output {
        if *self == SuperPoly::one() && *rhs == SuperPoly::one() {
            return SuperPoly::one();
        }
        if self.is_zero() || rhs.is_zero() {
            return SuperPoly::zero();
        }
        let mut result: Vec<Polynomial> =
            vec![0; self.coefficients.len() + rhs.coefficients.len() - 1];

        for i in 0..self.coefficients.len() {
            for j in 0..rhs.coefficients.len() {
                result[i + j] ^= F_2_128.mul(self.coefficients[i], rhs.coefficients[j]);
            }
        }

        let mut a = SuperPoly::from(result.as_slice());
        a.normalize();
        a
    }
}

impl MulAssign for SuperPoly {
    fn mul_assign(&mut self, rhs: Self) {
        *self *= &rhs;
    }
}

impl MulAssign<&SuperPoly> for SuperPoly {
    fn mul_assign(&mut self, rhs: &SuperPoly) {
        *self = &(*self) * rhs;
    }
}

impl Pow<u32> for SuperPoly {
    type Output = SuperPoly;
    fn pow(self, rhs: u32) -> Self::Output {
        (&self).pow(rhs)
    }
}

impl Pow<u32> for &SuperPoly {
    type Output = SuperPoly;
    fn pow(self, mut power: u32) -> Self::Output {
        if *self == SuperPoly::zero() {
            return SuperPoly::zero();
        }
        if *self == SuperPoly::one() {
            return SuperPoly::one();
        }
        if power == 0 {
            return SuperPoly::one();
        }
        if power == 1 {
            return self.clone();
        }

        let base: SuperPoly = self.clone();
        let mut accu: SuperPoly = base.clone();

        while power > 1 {
            accu *= &base;
            power -= 1;
        }

        accu.normalize();
        accu
    }
}

/** From *********************************************************************/

impl From<&[Polynomial]> for SuperPoly {
    fn from(value: &[Polynomial]) -> Self {
        SuperPoly {
            coefficients: value.to_vec(),
        }
    }
}

impl From<&[&Polynomial]> for SuperPoly {
    fn from(value: &[&Polynomial]) -> Self {
        SuperPoly {
            coefficients: value.iter().map(|v| **v).collect(),
        }
    }
}

impl<const N: usize> From<&[Polynomial; N]> for SuperPoly {
    fn from(value: &[Polynomial; N]) -> Self {
        SuperPoly {
            coefficients: value.to_vec(),
        }
    }
}

impl<const N: usize> From<&[&Polynomial; N]> for SuperPoly {
    fn from(value: &[&Polynomial; N]) -> Self {
        SuperPoly {
            coefficients: value.map(|v| *v).to_vec(),
        }
    }
}

impl<const N: usize> From<[Polynomial; N]> for SuperPoly {
    fn from(value: [Polynomial; N]) -> Self {
        SuperPoly {
            coefficients: value.to_vec(),
        }
    }
}

impl<const N: usize> From<&[&[u8; 16]; N]> for SuperPoly {
    fn from(value: &[&[u8; 16]; N]) -> Self {
        SuperPoly {
            coefficients: value
                .iter()
                .map(|v| {
                    bytes_to_u128_unknown_size(*v)
                        .expect("bytes are correct length but u128 can still not be made")
                })
                .collect(),
        }
    }
}

impl<const N: usize> From<&[[u8; 16]; N]> for SuperPoly {
    fn from(value: &[[u8; 16]; N]) -> Self {
        SuperPoly {
            coefficients: value
                .iter()
                .map(|v| {
                    bytes_to_u128_unknown_size(v)
                        .expect("bytes are correct length but u128 can still not be made")
                })
                .collect(),
        }
    }
}

impl<const N: usize> From<[[u8; 16]; N]> for SuperPoly {
    fn from(value: [[u8; 16]; N]) -> Self {
        SuperPoly {
            coefficients: value
                .iter()
                .map(|v| {
                    bytes_to_u128_unknown_size(v)
                        .expect("bytes are correct length but u128 can still not be made")
                })
                .collect(),
        }
    }
}

impl From<&[[u8; 16]]> for SuperPoly {
    fn from(value: &[[u8; 16]]) -> Self {
        SuperPoly {
            coefficients: value
                .iter()
                .map(|v| {
                    bytes_to_u128_unknown_size(v)
                        .expect("bytes are correct length but u128 can still not be made")
                })
                .collect(),
        }
    }
}

impl From<&[&[u8; 16]]> for SuperPoly {
    fn from(value: &[&[u8; 16]]) -> Self {
        SuperPoly {
            coefficients: value
                .iter()
                .map(|v| {
                    bytes_to_u128_unknown_size(*v)
                        .expect("bytes are correct length but u128 can still not be made")
                })
                .collect(),
        }
    }
}

/** Interface *****************************************************************/

#[allow(unreachable_code)]
pub fn run_testcase(testcase: &Testcase, _settings: Settings) -> Result<serde_json::Value> {
    Ok(match testcase.action {
        Action::GfpolyAdd => {
            let a: SuperPoly = get_spoly(&testcase.arguments, "A")?;
            let b: SuperPoly = get_spoly(&testcase.arguments, "B")?;

            let s = a + b;
            serde_json::to_value(&s)?
        }
        Action::GfpolyMul => {
            let a: SuperPoly = get_spoly(&testcase.arguments, "A")?;
            let b: SuperPoly = get_spoly(&testcase.arguments, "B")?;

            let s = a * b;
            serde_json::to_value(&s)?
        }
        Action::GfpolyDivMod => {
            let a: SuperPoly = get_spoly(&testcase.arguments, "A")?;
            let b: SuperPoly = get_spoly(&testcase.arguments, "B")?;

            let (q, r) = a.divmod(&b);
            serde_json::json!(
                {
                    "Q": q,
                    "R": r
                }
            )
        }
        Action::GfpolyPow => {
            let a: SuperPoly = get_spoly(&testcase.arguments, "A")?;
            let k: u32 = get_any(&testcase.arguments, "k")?;

            let s = a.pow(k);
            serde_json::to_value(&s)?
        }
        _ => unreachable!(),
    })
}

/// Retrieves a [`SuperPoly`] from the provided arguments.
fn get_spoly(args: &serde_json::Value, key: &str) -> Result<SuperPoly> {
    let raw_parts: Vec<String> = serde_json::from_value(args[key].clone()).map_err(|e| {
        eprintln!("Error while serializing '{key}': {e}");
        e
    })?;

    let mut coefficients: Vec<_> = Vec::with_capacity(raw_parts.len());
    for raw_part in raw_parts {
        coefficients.push(change_semantic(
            bytes_to_u128_unknown_size(&maybe_hex(&raw_part)?)?,
            ffield::Semantic::Gcm,
            ffield::Semantic::Xex,
        ));
    }

    Ok(SuperPoly::from(coefficients.as_slice()))
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use super::*;

    fn assert_poly(a: &SuperPoly, b: &SuperPoly) {
        assert_eq!(a, b, "\na\t: {a:#x?}\nb\t: {b:#x?}");
    }

    #[test]
    fn test_spoly_construct_superpoly() {
        const C: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let _p: SuperPoly = SuperPoly::from(&[&C, &C]);
        let _p: SuperPoly = SuperPoly::from(&[C, C]);
        let _p: SuperPoly = SuperPoly::from([C, C]);
        let _p: SuperPoly = SuperPoly::from([0, 0]);
        let _p: SuperPoly = SuperPoly::from([0, u128::MAX]);
        let _p: SuperPoly = SuperPoly::from(&[0, 0]);
        let _p: SuperPoly = SuperPoly::from(&[&0, &0]);

        let a: u128 = 19;
        let _p: SuperPoly = SuperPoly::from([
            a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a,
            a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a,
            a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a,
            a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a,
            a, a, a, a, a, a, a, a, a, a, a, a, a,
        ]);
    }

    #[test]
    fn test_spoly_add_and_add_assign_produce_same_result() {
        let a = SuperPoly::from([0b1, 0b10, 0b11]);
        let b = SuperPoly::from([0b100, 0b101]);

        // Test Add
        let c1 = &a + &b;

        // Test AddAssign
        let mut c2 = a.clone();
        c2 += b;

        assert_eq!(c1, c2);
    }

    #[test]
    fn test_spoly_add_empty_polynomials() {
        let a = SuperPoly::zero();
        let b = SuperPoly::zero();
        let c = a + b;
        assert_eq!(c, SuperPoly::zero());
    }

    #[test]
    fn test_spoly_add_identical_polynomials() {
        let a = SuperPoly::from([1, 2, 3]);
        let b = SuperPoly::from([1, 2, 3]);
        let c = a + b;
        assert_eq!(c, SuperPoly::zero());

        let a = SuperPoly::one();
        let b = SuperPoly::one();
        let c = a + b;
        assert_eq!(c, SuperPoly::zero());
    }

    #[test]
    fn test_spoly_add_is_just_xor() {
        let a = SuperPoly::from([0b001]);
        let b = SuperPoly::from([0b101]);
        let c = a + b;
        assert_eq!(c, SuperPoly::from([0b100]));
    }

    #[test]
    fn test_spoly_add_is_just_xor_but_with_more_coefficients() {
        let a = SuperPoly::from([0b001, 0b001]);
        let b = SuperPoly::from([0b101, 0b101]);
        let c = a + b;
        assert_eq!(c, SuperPoly::from([0b100, 0b100]));
    }

    #[test]
    fn test_spoly_add_different_sized_polynomials() {
        let a = SuperPoly::from([0b001, 0b001]);
        let b = SuperPoly::from([0b101 /* 0 */]);
        let c = a + b;
        assert_eq!(c, SuperPoly::from([0b100, 0b001]));
    }

    #[test]
    fn test_spoly_add_different_sized_polynomials_but_cooler() {
        let a = SuperPoly::from([0b001, 0b010, 0b11]);
        let b = SuperPoly::from([0b100, 0b101 /* 0 */]);
        let c = a + b;
        assert_eq!(c, SuperPoly::from([0b101, 0b111, 0b11]));
    }

    #[test]
    fn test_spoly_add_with_zero_polynomial() {
        let a = SuperPoly::from([1, 2, 3]);
        let b = SuperPoly::zero();
        let c = a + b;
        assert_eq!(c, SuperPoly::from([1, 2, 3]));
    }

    #[test]
    fn test_spoly_eq_zero_is_zero() {
        let a = SuperPoly::from([0, 0, 0]);
        let b = SuperPoly::from([0, 0, 0, 0, 0, 0, 0, 0]);
        let c = SuperPoly::zero();
        assert!(a == b && b == c);
    }

    #[should_panic(expected = "assertion failed: a == b")]
    #[test]
    fn test_spoly_eq_zero_is_one() {
        let a = SuperPoly::zero();
        let b = SuperPoly::one();
        assert!(a == b);
    }

    #[test]
    fn test_spoly_mul_zero() {
        let a = SuperPoly::one();
        let b = SuperPoly::from([1337, 19, 29, 1131, 0, 0, 0, 0, 0, 121]);
        let z = SuperPoly::zero();
        assert!(&a * &z == SuperPoly::zero());
        assert!(&b * &z == SuperPoly::zero());
    }

    #[test]
    fn test_spoly_mul_identity() {
        let a = SuperPoly::one() * SuperPoly::one();
        assert_eq!(a, SuperPoly::one(), "\n{a:#x?}\n{:#x?}", SuperPoly::one());
    }

    #[test]
    fn test_spoly_mul_something() {
        let fake_args = json!(
        {
            "A": [
                "JAAAAAAAAAAAAAAAAAAAAA==",
                "wAAAAAAAAAAAAAAAAAAAAA==",
                "ACAAAAAAAAAAAAAAAAAAAA=="
            ],
            "B": [
                "0AAAAAAAAAAAAAAAAAAAAA==",
                "IQAAAAAAAAAAAAAAAAAAAA=="
            ],
            "P": [
                "MoAAAAAAAAAAAAAAAAAAAA==",
                "sUgAAAAAAAAAAAAAAAAAAA==",
                "MbQAAAAAAAAAAAAAAAAAAA==",
                "AAhAAAAAAAAAAAAAAAAAAA=="
            ]
        }
        );
        let a = get_spoly(&fake_args, "A").expect("could not parse args");
        let b = get_spoly(&fake_args, "B").expect("could not parse args");
        let p = get_spoly(&fake_args, "P").expect("could not parse args");
        let c = &a * &b;

        assert_eq!(c, p, "\nA: {c:#x?}\nS: {p:#x?}");
    }

    #[test]
    fn test_spoly_pow_something() {
        let fake_args = json!(
        {
            "A": [
                "JAAAAAAAAAAAAAAAAAAAAA==",
                "wAAAAAAAAAAAAAAAAAAAAA==",
                "ACAAAAAAAAAAAAAAAAAAAA=="
            ],
            "k": 3,
            "Z": [
                "AkkAAAAAAAAAAAAAAAAAAA==",
                "DDAAAAAAAAAAAAAAAAAAAA==",
                "LQIIAAAAAAAAAAAAAAAAAA==",
                "8AAAAAAAAAAAAAAAAAAAAA==",
                "ACgCQAAAAAAAAAAAAAAAAA==",
                "AAAMAAAAAAAAAAAAAAAAAA==",
                "AAAAAgAAAAAAAAAAAAAAAA=="
            ]
        });
        let a = get_spoly(&fake_args, "A").expect("could not parse args");
        let z = get_spoly(&fake_args, "Z").expect("could not parse args");
        let k: u32 = get_any(&fake_args, "k").expect("could not parse args");

        let c = a.pow(k);

        assert_eq!(c, z, "\nA: {c:#x?}\nS: {z:#x?}");
    }

    #[test]
    fn test_spoly_pow_is_mul() {
        let fake_args = json!(
        {
            "A": [
                "JAAAAAAAAAAAAAAAAAAAAA==",
                "wAAAAAAAAAAAAAAAAAAAAA==",
                "ACAAAAAAAAAAAAAAAAAAAA=="
            ],
        });
        let a = get_spoly(&fake_args, "A").expect("could not parse args");
        let a2 = &a * &a;
        let a2p = a.pow(2);
        assert_eq!(a2p, a2, "\na2p\t: {a2p:#x?}\na2\t: {a2:#x?}");
    }

    #[test]
    fn test_spoly_pow_edge() {
        assert_eq!(SuperPoly::one().pow(0), SuperPoly::one());
        assert_eq!(SuperPoly::one().pow(1), SuperPoly::one());
        assert_eq!(SuperPoly::one().pow(2), SuperPoly::one());
        assert_eq!(SuperPoly::one().pow(200), SuperPoly::one());
        assert_eq!(SuperPoly::zero().pow(1), SuperPoly::zero());
        assert_eq!(SuperPoly::zero().pow(20), SuperPoly::zero());
    }

    #[test]
    fn test_spoly_divmod_identity() {
        let fake_args = json!({
            "A": [
                "JAAAAAAAAAAAAAAAAAAAAA==",
                "wAAAAAAAAAAAAAAAAAAAAA==",
                "ACAAAAAAAAAAAAAAAAAAAA=="
            ],
        });
        let a = get_spoly(&fake_args, "A").expect("could not parse args");
        let (q, r) = a.divmod(&a);
        assert_poly(&q, &SuperPoly::one()); // When dividing by itself, quotient should be 1
        assert_poly(&r, &SuperPoly::zero()); // and remainder should be 0
    }

    #[test]
    fn test_spoly_divmod_something() {
        let fake_args = json!(
        {
        "A": [
                "JAAAAAAAAAAAAAAAAAAAAA==",
                "wAAAAAAAAAAAAAAAAAAAAA==",
                "ACAAAAAAAAAAAAAAAAAAAA=="
        ],
        "B": [
                "0AAAAAAAAAAAAAAAAAAAAA==",
                "IQAAAAAAAAAAAAAAAAAAAA=="
        ],
        "Q": [
                "nAIAgCAIAgCAIAgCAIAgCg==",
                "m85znOc5znOc5znOc5znOQ=="
        ],
        "R": [
                "lQNA0DQNA0DQNA0DQNA0Dg=="
        ]
        });
        let a = get_spoly(&fake_args, "A").expect("could not parse args");
        let b = get_spoly(&fake_args, "B").expect("could not parse args");
        let q = get_spoly(&fake_args, "Q").expect("could not parse args");
        let r = get_spoly(&fake_args, "R").expect("could not parse args");
        let (myq, myr) = a.divmod(&b);
        assert_poly(&myq, &q);
        assert_poly(&myr, &r);
    }

    #[test]
    fn test_spoly_add_normalize_required() {
        // Test case where both polynomials have trailing zeros
        let a = SuperPoly::from([1, 0, 0]); // x^2 + 0x + 0
        let b = SuperPoly::from([2, 0, 0]); // 2x^2 + 0x + 0
        let c = &a + &b;
        assert_eq!(c.coefficients.len(), 1); // Should normalize to [3]
        assert_eq!(c.coefficients[0], 3);
    }

    #[test]
    fn test_spoly_add_different_lengths() {
        // Test polynomials of different lengths where normalization is needed
        let a = SuperPoly::from([1, 2, 0, 0]); // x^3 + 2x^2
        let b = SuperPoly::from([3, 4]); // 3x + 4
        let c = &a + &b;
        assert_eq!(c.coefficients.len(), 2); // Should normalize properly
    }

    #[test]
    fn test_spoly_add_result_shorter() {
        // Test where addition results in cancellation making result shorter
        let a = SuperPoly::from([1, 1]); // x + 1
        let b = SuperPoly::from([0, 1]); // 1
        let c = &a + &b;
        assert_eq!(c.coefficients.len(), 1); // Should be just [1]
        assert_eq!(c.coefficients[0], 1);
    }

    #[test]
    fn test_spoly_add_zero_length() {
        // Test addition with zero-length polynomial
        let a = SuperPoly::empty();
        let b = SuperPoly::from([1, 2, 3]);
        let c = &a + &b;
        assert_eq!(c.coefficients, b.coefficients);
    }

    #[test]
    fn test_spoly_add_all_terms_cancel() {
        // Test where all terms cancel out
        let a = SuperPoly::from([1, 2, 3]);
        let b = SuperPoly::from([1, 2, 3]);
        let c = &a + &b;
        assert!(c.is_zero());
        assert_eq!(c.coefficients.len(), 0); // Should normalize to empty
    }

    #[test]
    fn test_spoly_add_leading_zeros() {
        // Test with leading zeros that should be removed
        let a = SuperPoly::from([1, 2, 0, 0, 0]);
        let b = SuperPoly::from([3, 4, 0, 0]);
        let c = &a + &b;
        assert!(c.coefficients.len() <= 2); // Should not keep trailing zeros
    }

    #[test]
    fn test_spoly_add_alternating_zeros() {
        // Test with alternating zero and non-zero coefficients
        let a = SuperPoly::from([1, 0, 2, 0, 3, 0]);
        let b = SuperPoly::from([0, 1, 0, 2, 0, 3]);
        let c = &a + &b;
        // All coefficients should be non-zero in result
        assert!(c.coefficients.iter().all(|&x| x != 0));
    }
}

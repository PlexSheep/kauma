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
        SuperPoly::from([0])
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
        if self.is_zero() {
            panic!("division by zero");
        }
        if self.deg() < rhs.deg() {
            return (SuperPoly::zero(), self.to_owned());
        }

        let mut remainder = self.clone();
        let mut divisor = rhs.clone();
        let mut q = vec![0; remainder.deg() - divisor.deg() + 1];

        let mut guard: u16 = 0;
        while divisor.deg() < remainder.deg() {
            if guard == u16::MAX {
                panic!("divmod took too many loops")
            }
            let deg_delta = remainder.deg() - divisor.deg();
            let coeff_delta =
                remainder.coefficients.last().unwrap() / divisor.coefficients.last().unwrap();
            q[deg_delta] = coeff_delta;
            let mut pos;
            for (i, coeff) in divisor.coefficients.iter().enumerate() {
                pos = deg_delta + i;
                let a = remainder.coefficients[pos];
                remainder.coefficients[pos] = a + (coeff * coeff_delta);
                remainder.normalize();
            }

            guard += 1;
        }

        (Self::from(q.as_slice()), remainder)
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
        let fake_args = json!(
        {
            "A": [
                "JAAAAAAAAAAAAAAAAAAAAA==",
                "wAAAAAAAAAAAAAAAAAAAAA==",
                "ACAAAAAAAAAAAAAAAAAAAA=="
            ],
            "S?": [
                "JAAAAAAAAAAAAAAAAAAAAA==",
                "wAAAAAAAAAAAAAAAAAAAAA==",
                "ACAAAAAAAAAAAAAAAAAAAA=="
            ],
        });
        let a = get_spoly(&fake_args, "A").expect("could not parse args");
        let s = get_spoly(&fake_args, "S?").expect("could not parse args");
        let (q, r) = a.divmod(&a);
        assert_poly(&q, &s);
        assert_poly(&r, &SuperPoly::zero());
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
}

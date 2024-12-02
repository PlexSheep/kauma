//! # superpoly
//!
//! The `superpoly` module provides an implementation of "super polynomials" - polynomials with coefficients that are also polynomials in a finite field.
//! This type has uses in cryptography and other advanced mathematical applications.

use std::ops::{Add, AddAssign, BitXor, BitXorAssign};

use anyhow::Result;
use base64::prelude::*;
use num::traits::ToBytes;
use serde::{Serialize, Serializer};

use crate::common::interface::maybe_hex;
use crate::common::{bytes_to_u128, len_to_const_arr};
use crate::settings::Settings;

use super::{ffield, Action, Testcase};
use ffield::Polynomial;

#[derive(Debug, Clone, PartialOrd, Eq, Ord)]
pub struct SuperPoly {
    coefficients: Vec<Polynomial>,
}

/// A struct representing a "super polynomial" - a polynomial with coefficients that are also polynomials in a finite field.
impl SuperPoly {
    /// Returns a "zero" [`SuperPoly`] with all coefficients set to 0.
    pub fn zero() -> Self {
        SuperPoly::from([0])
    }
    /// Returns a "one" [`SuperPoly`] with all coefficients set to 0, but the LSC, which is 1.
    pub fn one() -> Self {
        SuperPoly::from([1])
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
}

impl Serialize for SuperPoly {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let coefficients: Vec<String> = self
            .coefficients
            .iter()
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
        SuperPoly::from(new_coefficients.as_slice())
    }
}

impl BitXorAssign for SuperPoly {
    fn bitxor_assign(&mut self, rhs: Self) {
        let max_idx: usize = self.coefficients.len().max(rhs.coefficients.len());
        for i in 0..max_idx {
            self.coefficients[i] ^= rhs.coefficients.get(i).unwrap_or(&0);
        }
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
                    bytes_to_u128(*v)
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
                    bytes_to_u128(v)
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
                    bytes_to_u128(v)
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
                    bytes_to_u128(v)
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
                    bytes_to_u128(*v)
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
        _ => unreachable!(),
    })
}

/// Retrieves a [`SuperPoly`] from the provided arguments.
fn get_spoly(args: &serde_json::Value, key: &str) -> Result<SuperPoly> {
    let raw_parts: Vec<String> = serde_json::from_value(args[key].clone()).map_err(|e| {
        eprintln!("Error while serializing '{key}': {e}");
        e
    })?;

    let mut coefficients: Vec<[u8; 16]> = Vec::with_capacity(raw_parts.len());
    for raw_part in raw_parts {
        coefficients.push(len_to_const_arr(&maybe_hex(&raw_part)?)?);
    }

    Ok(SuperPoly::from(coefficients.as_slice()))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_construct_superpoly() {
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
    fn test_add_and_add_assign_produce_same_result() {
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
    fn test_add_empty_polynomials() {
        let a = SuperPoly::zero();
        let b = SuperPoly::zero();
        let c = a + b;
        assert_eq!(c, SuperPoly::zero());
    }

    #[test]
    fn test_add_identical_polynomials() {
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
    fn test_add_is_just_xor() {
        let a = SuperPoly::from([0b001]);
        let b = SuperPoly::from([0b101]);
        let c = a + b;
        assert_eq!(c, SuperPoly::from([0b100]));
    }

    #[test]
    fn test_add_is_just_xor_but_with_more_coefficients() {
        let a = SuperPoly::from([0b001, 0b001]);
        let b = SuperPoly::from([0b101, 0b101]);
        let c = a + b;
        assert_eq!(c, SuperPoly::from([0b100, 0b100]));
    }

    #[test]
    fn test_add_different_sized_polynomials() {
        let a = SuperPoly::from([0b001, 0b001]);
        let b = SuperPoly::from([0b101 /* 0 */]);
        let c = a + b;
        assert_eq!(c, SuperPoly::from([0b100, 0b001]));
    }

    #[test]
    fn test_add_different_sized_polynomials_but_cooler() {
        let a = SuperPoly::from([0b001, 0b010, 0b11]);
        let b = SuperPoly::from([0b100, 0b101 /* 0 */]);
        let c = a + b;
        assert_eq!(c, SuperPoly::from([0b101, 0b111, 0b11]));
    }

    #[test]
    fn test_add_with_zero_polynomial() {
        let a = SuperPoly::from([1, 2, 3]);
        let b = SuperPoly::zero();
        let c = a + b;
        assert_eq!(c, SuperPoly::from([1, 2, 3]));
    }

    #[test]
    fn test_eq_zero_is_zero() {
        let a = SuperPoly::from([0, 0, 0]);
        let b = SuperPoly::from([0, 0, 0, 0, 0, 0, 0, 0]);
        let c = SuperPoly::zero();
        assert!(a == b && b == c);
    }

    #[should_panic(expected = "assertion failed: a == b")]
    #[test]
    fn test_eq_zero_is_one() {
        let a = SuperPoly::zero();
        let b = SuperPoly::one();
        assert!(a == b);
    }
}

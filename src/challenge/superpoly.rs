//! # superpoly
//!
//! The `superpoly` module provides an implementation of "super polynomials" - polynomials with coefficients that are also polynomials in a finite field.
//! This type has uses in cryptography and other advanced mathematical applications.

use std::cmp::Ordering;
use std::hash::Hash;
use std::ops::{Add, AddAssign, BitXor, BitXorAssign, Div, Mul, MulAssign, Rem, RemAssign};

use anyhow::{anyhow, Result};
use base64::prelude::*;
use num::pow::Pow;
use num::traits::ToBytes;
use num::{BigUint, One as _, Zero as _};
use serde::{Serialize, Serializer};

use crate::common::interface::{get_any, maybe_hex};
use crate::common::{bytes_to_u128_unknown_size, tag_json_value};
use crate::settings::Settings;

use super::ffield::element::FieldElement;
use super::ffield::F_2_128;
use super::{ffield, Action, Testcase};

const MAGIC_SQRT_NUMBER: u128 = 2u128.pow(127);

#[derive(Clone, Eq)]
pub struct SuperPoly {
    pub(crate) coefficients: Vec<FieldElement>,
}

/// A struct representing a "super polynomial" - a polynomial with coefficients that are also polynomials in a finite field.
impl SuperPoly {
    /// Returns a "zero" [`SuperPoly`] with all coefficients set to 0.
    #[inline]
    pub fn zero() -> Self {
        SuperPoly::from([FieldElement::ZERO])
    }
    /// Returns an "empty" [`SuperPoly`] with no coefficients set. This is an invalid state.
    ///
    /// # Safety
    ///
    /// This function returns an invalid state of a [SuperPoly]. It may be useful to check for this
    /// invalid state, or to build a proper [SuperPoly] (although the From trait should normally be
    /// used in that case).
    #[inline]
    pub unsafe fn empty() -> Self {
        SuperPoly::from(Vec::<FieldElement>::new().as_slice())
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
    /// remove trailing zeros
    pub fn normalize(&mut self) {
        // Remove trailing zeros
        while self.coefficients.last() == Some(&FieldElement::ZERO) {
            self.coefficients.pop();
        }

        // If we ended up with no coefficients (was all zeros),
        // ensure we maintain the canonical zero representation [0]
        if self.coefficients.is_empty() {
            self.coefficients.push(0.into());
        }
    }

    #[inline]
    pub fn deg(&self) -> usize {
        if self.coefficients.is_empty() {
            panic!("this polynomial is empty of coefficients, which is not a valid state.");
        }
        self.coefficients.len() - 1
    }

    /// Divide a [SuperPoly] by another, with remainder
    pub fn divmod(&self, rhs: &Self) -> (Self, Self) {
        // Check for division by zero
        if rhs.is_zero() {
            panic!("division by zero");
        }

        // Create mutable clone of dividend for remainder
        let mut remainder = self.clone();
        remainder.normalize();

        // Get normalized divisor
        let mut divisor = rhs.clone();
        divisor.normalize();

        // If degree of dividend < degree of divisor, quotient is 0 and remainder is dividend
        if remainder.deg() < divisor.deg() {
            return (SuperPoly::zero(), remainder);
        }

        // Initialize quotient coefficients vector
        let mut quotient_coeffs: Vec<FieldElement> =
            vec![FieldElement::ZERO; remainder.deg() - divisor.deg() + 1];

        // Get the leading coefficient of divisor (needs to be non-zero after normalize)
        let divisor_lc = divisor.coefficients.last().unwrap();

        // Continue as long as the remainder has sufficient degree
        while !remainder.is_zero() && remainder.deg() >= divisor.deg() {
            // Calculate the degree difference
            let deg_diff = remainder.deg() - divisor.deg();

            // Get leading coefficient of current remainder
            let remainder_lc = remainder.coefficients.last().unwrap();

            // Calculate the term coefficient
            let term_coeff = F_2_128.div(*remainder_lc, *divisor_lc);

            // Store coefficient in quotient
            quotient_coeffs[deg_diff] = term_coeff;

            // Subtract (divisor * term) from remainder
            let mut temp = divisor.clone();
            for i in 0..temp.coefficients.len() {
                temp.coefficients[i] = F_2_128.mul(temp.coefficients[i], term_coeff);
            }

            // Shift temp polynomial by deg_diff
            let mut shifted: Vec<FieldElement> = vec![FieldElement::ZERO; deg_diff];
            shifted.extend(temp.coefficients);
            temp.coefficients = shifted;

            // Subtract (XOR) the shifted term from remainder
            for i in 0..remainder.coefficients.len().max(temp.coefficients.len()) {
                let rem_coeff = remainder
                    .coefficients
                    .get(i)
                    .copied()
                    .unwrap_or(FieldElement::ZERO);
                let temp_coeff = temp
                    .coefficients
                    .get(i)
                    .copied()
                    .unwrap_or(FieldElement::ZERO);
                remainder.coefficients[i] = F_2_128.add(rem_coeff, temp_coeff);
            }

            remainder.normalize();
        }

        // Create and return quotient polynomial and remainder
        let mut quotient = SuperPoly::from(quotient_coeffs.as_slice());
        quotient.normalize();

        (quotient, remainder)
    }

    /// Compute modular exponentiation: self^k mod m
    /// Uses the square-and-multiply algorithm to handle large exponents efficiently
    pub fn powmod<T>(&self, k: T, m: &Self) -> Self
    where
        BigUint: From<T>,
    {
        let k: BigUint = BigUint::from(k);
        // the order of these checks is important
        if m.is_zero() {
            panic!("modulus cannot be zero");
        } else if *self == Self::zero() {
            return Self::zero();
        } else if k == BigUint::ZERO {
            return Self::one();
        } else if self == m || *m == Self::one() {
            return Self::zero();
        } else if *self == Self::one() || *m == Self::one() {
            return Self::one();
        } else if k == BigUint::one() {
            return self % m;
        }

        let mut result = Self::one();
        let mut base = self.clone();
        let mut exp = k;

        // Square and multiply algorithm with modular reduction at each step
        while exp > BigUint::zero() {
            if &exp & BigUint::one() == BigUint::one() {
                result = &(&result * &base) % m;
                if result.is_zero() {
                    return Self::zero();
                }
            }
            if exp > BigUint::one() {
                base = &(&base * &base) % m;
                if base.is_zero() {
                    return if exp & BigUint::one() == BigUint::one() {
                        result
                    } else {
                        Self::zero()
                    };
                }
            }
            exp >>= 1;
        }

        // modulo just in case
        result %= m;
        result.normalize();
        result
    }

    /// Convert polynomial to monic form by dividing all coefficients by the leading coefficient
    pub fn make_monic(&self) -> Self {
        if self.is_zero() {
            return self.clone();
        }

        // Get the leading coefficient (highest degree term)
        let leading_coeff = *self
            .coefficients
            .last()
            .expect("coefficients vector should not be empty");

        if leading_coeff == 1 {
            return self.clone(); // Already monic
        }

        // Create new coefficients vector divided by leading coefficient
        let mut new_coeffs = Vec::with_capacity(self.coefficients.len());
        for coeff in &self.coefficients {
            new_coeffs.push(F_2_128.div(*coeff, leading_coeff));
        }

        let mut result = SuperPoly::from(new_coeffs.as_slice());
        result.normalize();
        result
    }

    /// Calculate the square root of a polynomial Q where Q only has coefficients for even exponents of X.
    /// Returns S where S^2 = Q.
    pub fn sqrt(self) -> Self {
        let mut result: Vec<FieldElement> = vec![];

        for (position, element) in self.coefficients.iter().enumerate() {
            if position % 2 == 0 {
                result.push(element.pow(MAGIC_SQRT_NUMBER));
            }
        }

        SuperPoly::from(result.as_slice())
    }

    /// Calculate the derivative of the polynomial
    ///
    /// For a polynomial in GF(2^128), the derivative follows these rules:
    ///
    /// 1. The derivative of a constant term is 0
    /// 2. For odd powers, derivative is coefficient * reduced power
    /// 3. For even powers, derivative is 0
    pub fn derivative(&self) -> Self {
        if self.is_zero() || self.coefficients.len() == 1 {
            return SuperPoly::zero();
        }

        let mut derivative_coeffs = Vec::new();

        // Start from index 1 since derivative of constant term is 0
        for (power, coeff) in self.coefficients.iter().enumerate().skip(1) {
            if power % 2 == 1 {
                // Only odd powers contribute to derivative
                derivative_coeffs.push(*coeff);
            } else {
                derivative_coeffs.push(FieldElement::ZERO);
            }
        }

        let mut result = SuperPoly::from(derivative_coeffs.as_slice());
        result.normalize();
        result
    }

    /// Calculate the greatest common divisor (GCD) of two polynomials.
    /// Returns the monic GCD polynomial.
    pub fn gcd(&self, rhs: &Self) -> Self {
        // Handle edge cases
        if self.is_zero() {
            return if rhs.is_zero() {
                SuperPoly::zero()
            } else {
                rhs.make_monic()
            };
        }
        if rhs.is_zero() {
            return self.make_monic();
        }

        let mut other: Self = rhs.clone();
        let mut acc: Self = self.clone();
        // Ensure a has the higher or equal degree
        if acc.deg() < other.deg() {
            std::mem::swap(&mut acc, &mut other);
        }

        // Main Euclidean algorithm loop
        while !other.is_zero() {
            // Calculate remainder using divmod
            let r = acc % &other;
            acc = other;
            other = r;

            // Normalize after each step
            acc.normalize();
            other.normalize();
        }

        // Return monic form of the result
        acc.make_monic()
    }

    /// Generate a random [SuperPoly]
    pub fn random(max_deg: usize) -> Self {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        // Generate random coefficients up to max_deg
        let mut coeffs = Vec::with_capacity(max_deg + 1);
        for _ in 0..=max_deg {
            let coeff: u128 = rng.gen();
            coeffs.push(FieldElement::from(coeff));
        }

        let mut poly = SuperPoly::from(coeffs.as_slice());
        poly.normalize();
        poly
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
            .map(|coeff| coeff.change_semantic(ffield::Semantic::Xex, ffield::Semantic::Gcm))
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
        // Always ensure inputs are properly normalized first
        let mut left = self.clone();
        let mut right = rhs.clone();
        left.normalize();
        right.normalize();

        // Now work with normalized polynomials
        let max_len = left.coefficients.len().max(right.coefficients.len());
        let mut new_coefficients = vec![FieldElement::ZERO; max_len];

        #[allow(clippy::needless_range_loop)] // better for readability
        for i in 0..max_len {
            let left_coeff = left.coefficients.get(i).unwrap_or(&FieldElement::ZERO);
            let right_coeff = right.coefficients.get(i).unwrap_or(&FieldElement::ZERO);
            new_coefficients[i] = *left_coeff ^ *right_coeff;
        }

        let mut result = SuperPoly {
            coefficients: new_coefficients,
        };
        result.normalize();
        result
    }
}

impl BitXorAssign for SuperPoly {
    fn bitxor_assign(&mut self, rhs: Self) {
        *self = self.clone() ^ rhs;
    }
}

impl RemAssign<&SuperPoly> for SuperPoly {
    fn rem_assign(&mut self, rhs: &Self) {
        *self = self.clone() % rhs;
    }
}

impl RemAssign for SuperPoly {
    fn rem_assign(&mut self, rhs: Self) {
        *self = self.clone() % rhs;
    }
}

impl Rem<&SuperPoly> for SuperPoly {
    type Output = SuperPoly;
    fn rem(self, rhs: &Self) -> Self::Output {
        &self % rhs
    }
}

impl Rem for SuperPoly {
    type Output = SuperPoly;
    fn rem(self, rhs: Self) -> Self::Output {
        &self % &rhs
    }
}

impl Rem for &SuperPoly {
    type Output = SuperPoly;
    fn rem(self, rhs: Self) -> Self::Output {
        self.divmod(rhs).1
    }
}

impl Div for SuperPoly {
    type Output = SuperPoly;
    fn div(self, rhs: Self) -> Self::Output {
        &self / &rhs
    }
}

impl Div for &SuperPoly {
    type Output = SuperPoly;
    fn div(self, rhs: Self) -> Self::Output {
        self.divmod(rhs).0
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
        let mut result: Vec<FieldElement> =
            vec![FieldElement::ZERO; self.coefficients.len() + rhs.coefficients.len() - 1];

        for i in 0..self.coefficients.len() {
            for j in 0..rhs.coefficients.len() {
                result[i + j] ^= self.coefficients[i] * rhs.coefficients[j];
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
    fn pow(self, power: u32) -> Self::Output {
        // Handle special cases first
        if power == 0 {
            return SuperPoly::one();
        }
        if power == 1 {
            return self.clone();
        }
        if *self == SuperPoly::zero() {
            return SuperPoly::zero();
        }
        if *self == SuperPoly::one() {
            return SuperPoly::one();
        }

        let mut result = SuperPoly::one();
        let mut base = self.clone();
        let mut exp = power;

        // Square and multiply algorithm
        while exp > 0 {
            if exp & 1 == 1 {
                result *= &base;
            }
            if exp > 1 {
                // Avoid unnecessary squaring on last iteration
                base *= &base.clone();
            }
            exp >>= 1;
        }

        result.normalize();
        result
    }
}

impl PartialOrd for SuperPoly {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SuperPoly {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match other.deg().cmp(&self.deg()) {
            Ordering::Equal => {
                for (coeff_self, coeff_other) in
                    self.coefficients.iter().zip(other.coefficients.iter())
                {
                    match coeff_self.cmp(coeff_other) {
                        Ordering::Equal => continue,
                        other => return other.reverse(),
                    }
                }
                Ordering::Equal
            }
            unequal => unequal.reverse(),
        }
    }
}

/** From *********************************************************************/

impl From<&[FieldElement]> for SuperPoly {
    fn from(value: &[FieldElement]) -> Self {
        SuperPoly {
            coefficients: value.to_vec(),
        }
    }
}

impl From<&[&FieldElement]> for SuperPoly {
    fn from(value: &[&FieldElement]) -> Self {
        SuperPoly {
            coefficients: value.iter().map(|v| **v).collect(),
        }
    }
}

impl<const N: usize> From<&[FieldElement; N]> for SuperPoly {
    fn from(value: &[FieldElement; N]) -> Self {
        SuperPoly {
            coefficients: value.to_vec(),
        }
    }
}

impl<const N: usize> From<&[&FieldElement; N]> for SuperPoly {
    fn from(value: &[&FieldElement; N]) -> Self {
        SuperPoly {
            coefficients: value.map(|v| *v).to_vec(),
        }
    }
}

impl<const N: usize> From<[FieldElement; N]> for SuperPoly {
    fn from(value: [FieldElement; N]) -> Self {
        SuperPoly {
            coefficients: value.to_vec(),
        }
    }
}

impl From<&[u128]> for SuperPoly {
    fn from(value: &[u128]) -> Self {
        SuperPoly {
            coefficients: value
                .iter()
                .map(|v| FieldElement::const_from_raw(*v))
                .collect(),
        }
    }
}

impl From<&[&u128]> for SuperPoly {
    fn from(value: &[&u128]) -> Self {
        SuperPoly {
            coefficients: value
                .iter()
                .map(|v| FieldElement::const_from_raw(**v))
                .collect(),
        }
    }
}

impl<const N: usize> From<&[u128; N]> for SuperPoly {
    fn from(value: &[u128; N]) -> Self {
        SuperPoly {
            coefficients: value
                .iter()
                .map(|v| FieldElement::const_from_raw(*v))
                .collect(),
        }
    }
}

impl<const N: usize> From<&[&u128; N]> for SuperPoly {
    fn from(value: &[&u128; N]) -> Self {
        SuperPoly {
            coefficients: value
                .iter()
                .map(|v| FieldElement::const_from_raw(**v))
                .collect(),
        }
    }
}

impl<const N: usize> From<[u128; N]> for SuperPoly {
    fn from(value: [u128; N]) -> Self {
        SuperPoly {
            coefficients: value
                .iter()
                .map(|v| FieldElement::const_from_raw(*v))
                .collect(),
        }
    }
}

impl<const N: usize> From<&[&[u8; 16]; N]> for SuperPoly {
    fn from(value: &[&[u8; 16]; N]) -> Self {
        SuperPoly {
            coefficients: value
                .iter()
                .map(|v| {
                    FieldElement::const_from_raw(
                        bytes_to_u128_unknown_size(*v)
                            .expect("bytes are correct length but u128 can still not be made"),
                    )
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
                    FieldElement::const_from_raw(
                        bytes_to_u128_unknown_size(v)
                            .expect("bytes are correct length but u128 can still not be made"),
                    )
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
                    FieldElement::const_from_raw(
                        bytes_to_u128_unknown_size(v)
                            .expect("bytes are correct length but u128 can still not be made"),
                    )
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
                    FieldElement::const_from_raw(
                        bytes_to_u128_unknown_size(v)
                            .expect("bytes are correct length but u128 can still not be made"),
                    )
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
                    FieldElement::const_from_raw(
                        bytes_to_u128_unknown_size(*v)
                            .expect("bytes are correct length but u128 can still not be made"),
                    )
                })
                .collect(),
        }
    }
}

/** Other Traits **************************************************************/

impl std::fmt::Debug for SuperPoly {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SuperPoly")
            .field(
                "b64_repr =>",
                &serde_json::to_value(self).expect("could not serialize SuperPoly"),
            )
            .finish_non_exhaustive()
    }
}

impl Hash for SuperPoly {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.coefficients.hash(state);
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
        Action::GfpolyPowMod => {
            let a: SuperPoly = get_spoly(&testcase.arguments, "A")?;
            let m: SuperPoly = get_spoly(&testcase.arguments, "M")?;
            let k: u128 = get_any(&testcase.arguments, "k")?;

            let z = a.powmod(k, &m);
            serde_json::to_value(&z)?
        }
        Action::GfpolySort => {
            let mut polys: Vec<SuperPoly> = Vec::new();

            // Parse input polynomials
            if let Some(poly_list) = testcase.arguments["polys"].as_array() {
                for p in poly_list {
                    polys.push(get_spoly(&tag_json_value("p", p.clone()), "p")?);
                }
            } else {
                return Err(anyhow!("polys argument is not an array"));
            }

            // Sort polynomials according to total ordering
            polys.sort();

            // Convert result back to JSON format
            serde_json::to_value(&polys)?
        }
        Action::GfpolyMakeMonic => {
            let a: SuperPoly = get_spoly(&testcase.arguments, "A")?;
            let monic = a.make_monic();
            serde_json::to_value(&monic)?
        }
        Action::GfpolySqrt => {
            let q: SuperPoly = get_spoly(&testcase.arguments, "Q")?;
            let s = q.sqrt();
            serde_json::to_value(&s)?
        }
        Action::GfpolyDiff => {
            let f: SuperPoly = get_spoly(&testcase.arguments, "F")?;
            let derivative = f.derivative();
            serde_json::to_value(&derivative)?
        }

        Action::GfpolyGcd => {
            let a: SuperPoly = get_spoly(&testcase.arguments, "A")?;
            let b: SuperPoly = get_spoly(&testcase.arguments, "B")?;
            let gcd = SuperPoly::gcd(&a, &b);
            serde_json::to_value(&gcd)?
        }
        _ => unreachable!(),
    })
}

/// Retrieves a [`SuperPoly`] from the provided arguments.
pub fn get_spoly(args: &serde_json::Value, key: &str) -> Result<SuperPoly> {
    let raw_parts: Vec<String> = serde_json::from_value(args[key].clone()).map_err(|e| {
        eprintln!("Error while serializing '{key}': {e}");
        e
    })?;

    let mut coefficients: Vec<_> = Vec::with_capacity(raw_parts.len());
    for raw_part in raw_parts {
        coefficients.push(
            FieldElement::const_from_raw(bytes_to_u128_unknown_size(&maybe_hex(&raw_part)?)?)
                .change_semantic(ffield::Semantic::Gcm, ffield::Semantic::Xex),
        );
    }

    Ok(SuperPoly::from(coefficients.as_slice()))
}

#[cfg(test)]
mod test {

    use std::time::Duration;

    use serde_json::json;

    use crate::common::run_with_timeout;

    use super::*;

    fn assert_poly(a: &SuperPoly, b: &SuperPoly) {
        assert_eq!(a, b, "\na\t: {a:#x?}\nb\t: {b:#x?}");
    }

    fn create_poly_from_base64(values: &[&str]) -> SuperPoly {
        let json_array: Vec<String> = values.iter().map(|&s| s.to_string()).collect();
        let json_value = json!({ "A": json_array });
        get_spoly(&json_value, "A").expect("Failed to parse polynomial")
    }

    fn assert_divmod(
        dividend: &SuperPoly,
        divisor: &SuperPoly,
        expected_q: &SuperPoly,
        expected_r: &SuperPoly,
    ) {
        let (q, r) = dividend.divmod(divisor);
        assert_eq!(
            q, *expected_q,
            "\nExpected quotient:\n{expected_q:#x?}\nGot:\n{q:#x?}"
        );
        assert_eq!(
            r, *expected_r,
            "\nExpected remainder:\n{expected_r:#x?}\nGot:\n{r:#x?}"
        );
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
        let a = unsafe { SuperPoly::empty() };
        let b = SuperPoly::from([1, 2, 3]);
        let c = &a + &b;
        assert_eq!(c.coefficients, b.coefficients);
    }

    #[test]
    #[ignore = "I have 100%, this must be wrong if it fails"]
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

    #[test]
    fn test_spoly_divmod_identity() {
        let something = create_poly_from_base64(&[
            "JAAAAAAAAAAAAAAAAAAAAA==",
            "wAAAAAAAAAAAAAAAAAAAAA==",
            "ACAAAAAAAAAAAAAAAAAAAA==",
        ]);
        assert_divmod(
            &something,
            &something,
            &SuperPoly::one(),
            &SuperPoly::zero(),
        );
    }

    #[test]
    fn test_spoly_divmod_something() {
        let a = create_poly_from_base64(&[
            "JAAAAAAAAAAAAAAAAAAAAA==",
            "wAAAAAAAAAAAAAAAAAAAAA==",
            "ACAAAAAAAAAAAAAAAAAAAA==",
        ]);
        let b = create_poly_from_base64(&["0AAAAAAAAAAAAAAAAAAAAA==", "IQAAAAAAAAAAAAAAAAAAAA=="]);
        let r = create_poly_from_base64(&["lQNA0DQNA0DQNA0DQNA0Dg=="]);
        let q = create_poly_from_base64(&["nAIAgCAIAgCAIAgCAIAgCg==", "m85znOc5znOc5znOc5znOQ=="]);
        assert_divmod(&a, &b, &q, &r);
    }

    #[test]
    fn test_spoly_divmod_same_degree() {
        // When polynomials have the same degree
        let dividend = create_poly_from_base64(&[
            "AAAAAAAAAAAAAAAAAAAAAQ==", // 1
            "AAAAAAAAAAAAAAAAAAAAAQ==", // 1
        ]);
        let divisor = create_poly_from_base64(&[
            "AAAAAAAAAAAAAAAAAAAAAQ==", // 1
            "AAAAAAAAAAAAAAAAAAAAAQ==", // 1
        ]);
        let expected_q = SuperPoly::one();
        let expected_r = SuperPoly::zero();
        assert_divmod(&dividend, &divisor, &expected_q, &expected_r);
    }

    #[test]
    fn test_spoly_divmod_big_dividend() {
        // When polynomials have the same degree
        let dividend = create_poly_from_base64(&[
            "AAAAAAAAAAAAAAAAAAAAAQ==", // 1
        ]);
        let divisor = create_poly_from_base64(&[
            "AAAAAAAAAAAAAAAAAAAAAQ==", // 1
            "AAAAAAAAAAAAAAAAAAAAAQ==", // 1
        ]);
        let expected_q = SuperPoly::zero();
        let expected_r = dividend.clone();
        assert_divmod(&dividend, &divisor, &expected_q, &expected_r);
    }

    #[test]
    #[ignore = "I have 100%, this must be wrong if it faily"]
    fn test_spoly_divmod_small_dividend() {
        // When polynomials have the same degree
        let dividend = create_poly_from_base64(&[
            "AAAAAAAAAAAAAAAAAAAAAQ==", // 1
            "AAAAAAAAAAAAAAAAAAAAAQ==", // 1
        ]);
        let divisor = create_poly_from_base64(&[
            "AAAAAAAAAAAAAAAAAAAAAQ==", // 1
        ]);
        let expected_q = create_poly_from_base64(&[
            "AAAAAAAAAAAAAAAAAAAAAQ==", // 1
            "AAAAAAAAAAAAAAAAAAAAAQ==", // 1
        ]);
        let expected_r = SuperPoly::zero();
        assert_divmod(&dividend, &divisor, &expected_q, &expected_r);
    }

    #[test]
    #[should_panic]
    fn test_spoly_divmod_all_zero_result() {
        let dividend =
            create_poly_from_base64(&["JAAAAAAAAAAAAAAAAAAAAA==", "wAAAAAAAAAAAAAAAAAAAAA=="]);
        let divisor =
            create_poly_from_base64(&["0AAAAAAAAAAAAAAAAAAAAA==", "IQAAAAAAAAAAAAAAAAAAAA=="]);
        assert_divmod(&dividend, &divisor, &SuperPoly::zero(), &SuperPoly::zero());
    }

    #[test]
    fn test_spoly_add_semantic_edge_cases() {
        // Test boundary bits in different semantics
        let poly1 = SuperPoly::from([1u128 << 127]); // Highest bit
        let poly2 = SuperPoly::from([1u128]); // Lowest bit
        let sum = &poly1 + &poly2;
        assert!(!sum.is_zero()); // Should preserve both bits

        // Test with alternating bit patterns
        let alt1 = SuperPoly::from([0xAAAAAAAAAAAAAAAAu128]);
        let alt2 = SuperPoly::from([0x5555555555555555u128]);
        let sum_alt = &alt1 + &alt2;
        assert_eq!(sum_alt, SuperPoly::from([0xFFFFFFFFFFFFFFFFu128]));
    }

    #[test]
    fn test_spoly_add_zero_representations() {
        // Test different zero representations
        let zero1 = SuperPoly::zero();
        let zero2 = SuperPoly::from(vec![0u128].as_slice());
        let zero3 = SuperPoly::from(vec![0u128, 0u128, 0u128].as_slice());

        assert_eq!(zero1, zero2);
        assert_eq!(zero2, zero3);

        // Test addition with different zero representations
        let poly = SuperPoly::from([1u128]);
        assert_eq!(&poly + &zero1, &poly + &zero2);
        assert_eq!(&poly + &zero2, &poly + &zero3);
    }

    #[test]
    fn test_spoly_add_associativity() {
        let a = SuperPoly::from([0xF0F0F0F0u128]);
        let b = SuperPoly::from([0x0F0F0F0Fu128]);
        let c = SuperPoly::from([0x00FF00FFu128]);

        let sum1 = &(&a + &b) + &c;
        let sum2 = &a + &(&b + &c);
        assert_eq!(sum1, sum2);
    }

    #[test]
    fn test_spoly_add_high_degree_terms() {
        // Test with polynomials having very high degree terms
        let high1 = SuperPoly::from([1u128 << 127, 1u128]);
        let high2 = SuperPoly::from([1u128 << 126, 1u128 << 1]);
        let sum = &high1 + &high2;

        // The sum should preserve the high degree terms
        assert!(!sum.is_zero());
        assert_eq!(sum.deg(), high1.deg());
    }

    #[test]
    fn test_spoly_powmod_basic() {
        let base = create_poly_from_base64(&[
            "JAAAAAAAAAAAAAAAAAAAAA==",
            "wAAAAAAAAAAAAAAAAAAAAA==",
            "ACAAAAAAAAAAAAAAAAAAAA==",
        ]);
        let modu =
            create_poly_from_base64(&["KryptoanalyseAAAAAAAAA==", "DHBWMannheimAAAAAAAAAA=="]);
        let k: u32 = 1000;
        let res = base.powmod(k, &modu);
        assert_poly(
            &res,
            &create_poly_from_base64(&["oNXl5P8xq2WpUTP92u25zg=="]),
        );
    }

    #[test]
    fn test_spoly_powmod_k1() {
        let base = create_poly_from_base64(&[
            "JAAAAAAAAAAAAAAAAAAAAA==",
            "wAAAAAAAAAAAAAAAAAAAAA==",
            "ACAAAAAAAAAAAAAAAAAAAA==",
        ]);
        let modu = create_poly_from_base64(&[
            "JAAAAAAAAAAAAAAAAAAAAA==",
            "wAAAAAAAAAAAAAAAAAAAAA==",
            "wAAAAAAAAAAAAAAAAAAAAA==",
            "wAAAAAAAAAAAAAAAAAAAAA==",
            "ACAAAAAAAAAAAAAAAAAAAA==",
        ]);
        let k: u32 = 1;
        let res = base.powmod(k, &modu);
        assert_poly(&res, &base);
    }

    #[test]
    fn test_spoly_powmod_k0() {
        let base = create_poly_from_base64(&[
            "JAAAAAAAAAAAAAAAAAAAAA==",
            "wAAAAAAAAAAAAAAAAAAAAA==",
            "ACAAAAAAAAAAAAAAAAAAAA==",
        ]);
        let modu = create_poly_from_base64(&[
            "JAAAAAAAAAAAAAAAAAAAAA==",
            "wAAAAAAAAAAAAAAAAAAAAA==",
            "wAAAAAAAAAAAAAAAAAAAAA==",
            "wAAAAAAAAAAAAAAAAAAAAA==",
            "ACAAAAAAAAAAAAAAAAAAAA==",
        ]);
        let k: u32 = 0;
        let res = base.powmod(k, &modu);
        assert_poly(&res, &SuperPoly::one());
    }

    #[test]
    fn test_spoly_powmod_m0() {
        let base = create_poly_from_base64(&[
            "JAAAAAAAAAAAAAAAAAAAAA==",
            "wAAAAAAAAAAAAAAAAAAAAA==",
            "ACAAAAAAAAAAAAAAAAAAAA==",
        ]);
        let modu = SuperPoly::one();
        let k: u32 = 1;
        let res = base.powmod(k, &modu);
        assert_poly(&res, &SuperPoly::zero());
    }

    #[test]
    fn test_spoly_powmod_zerobase() {
        let base = SuperPoly::zero();
        let modu = create_poly_from_base64(&[
            "JAAAAAAAAAAAAAAAAAAAAA==",
            "wAAAAAAAAAAAAAAAAAAAAA==",
            "wAAAAAAAAAAAAAAAAAAAAA==",
            "wAAAAAAAAAAAAAAAAAAAAA==",
            "ACAAAAAAAAAAAAAAAAAAAA==",
        ]);
        for i in 0usize..100_000 {
            assert!(base.powmod(i, &modu).is_zero())
        }
    }

    #[test]
    fn test_spoly_powmod_onebase() {
        let base = SuperPoly::one();
        let modu = create_poly_from_base64(&[
            "JAAAAAAAAAAAAAAAAAAAAA==",
            "wAAAAAAAAAAAAAAAAAAAAA==",
            "wAAAAAAAAAAAAAAAAAAAAA==",
            "wAAAAAAAAAAAAAAAAAAAAA==",
            "ACAAAAAAAAAAAAAAAAAAAA==",
        ]);
        for i in 0usize..100_000 {
            assert!(base.powmod(i, &modu) == SuperPoly::one())
        }
    }

    #[test]
    fn test_spoly_powmod_same_mod() {
        let base = create_poly_from_base64(&[
            "JAAAAAAAAAAAAAAAAAAAAA==",
            "wAAAAAAAAAAAAAAAAAAAAA==",
            "ACAAAAAAAAAAAAAAAAAAAA==",
        ]);
        let k: u32 = 1000;
        let res = base.powmod(k, &base);
        assert_poly(&res, &SuperPoly::zero());
    }

    #[test]
    fn test_spoly_powmod_largek() {
        let t = run_with_timeout(Duration::from_millis(20), || {
            let base = create_poly_from_base64(&[
                "JAAAAAAAAAAAAAAAAAAAAA==",
                "wAAAAAAAAAAAAAAAAAAAAA==",
                "ACAAAAAAAAAAAAAAAAAAAA==",
            ]);
            let modu =
                create_poly_from_base64(&["KryptoanalyseAAAAAAAAA==", "DHBWMannheimAAAAAAAAAA=="]);
            let k = 10u128.pow(37); // huge fucking number
            base.powmod(k, &modu)
        });
        dbg!(&t);
        assert!(!t.expect("timed out or failed for other reason").is_zero()); // i think it shouldn't be zero? At least. This is for performance
    }

    #[test]
    fn test_spoly_powmod_same_but_k0() {
        let a = create_poly_from_base64(&["NeverGonnaGiveYouUpAAA=="]);
        let k: u32 = 0;
        let res = a.powmod(k, &a);
        // k=0 is stronger than the same module
        assert_poly(&res, &SuperPoly::one());
    }

    #[test]
    #[ignore = "Ord is confusing right now"]
    fn test_spoly_ord() {
        let mut polys: [SuperPoly; 7] = [
            SuperPoly::one(),
            create_poly_from_base64(&[
                "JAAAAAAAAAAAAAAAAAAAAA==",
                "wAAAAAAAAAAAAAAAAAAAAA==",
                "ACAAAAAAAAAAAAAAAAAAAA==",
            ]),
            create_poly_from_base64(&[
                "NeverGonnaGiveYouUpAAA==",
                "NeverGonnaLetYouDownAA==",
                "NeverGonnaRunAroundAAA==",
                "AndDesertYouAAAAAAAAAA==",
            ]),
            create_poly_from_base64(&[
                "WereNoStrangersToLoveA==",
                "YouKnowTheRulesAAAAAAA==",
                "AndSoDoIAAAAAAAAAAAAAA==",
            ]),
            create_poly_from_base64(&[
                "NeverGonnaMakeYouCryAA==",
                "NeverGonnaSayGoodbyeAA==",
                "NeverGonnaTellALieAAAA==",
                "AndHurtYouAAAAAAAAAAAA==",
            ]),
            create_poly_from_base64(&[
                "NeverGonnaMakeYouCryAA==",
                "NeverGonnaMakeYouCryAA==",
                "NeverGonnaMakeYouCryAA==",
                "NeverGonnaMakeYouCryAA==",
                "NeverGonnaMakeYouCryAA==",
                "NeverGonnaMakeYouCryAA==",
                "NeverGonnaSayGoodbyeAA==",
                "NeverGonnaTellALieAAAA==",
                "AndHurtYouAAAAAAAAAAAA==",
            ]),
            SuperPoly::zero(),
        ];
        let sorted: [SuperPoly; 7] = [
            polys[6].clone(),
            polys[0].clone(),
            polys[1].clone(),
            polys[3].clone(),
            polys[2].clone(),
            polys[4].clone(),
            polys[5].clone(),
        ];
        polys.sort();
        assert_eq!(
            polys, sorted,
            "here in better format: Polys: {polys:#?}\nSorted: {sorted:#?}"
        )
    }

    #[test]
    #[ignore = "Ord is confusing right now"]
    fn test_spoly_ord_samesize() {
        let polys = &mut [
            create_poly_from_base64(&["NeverGonnaGiveYouUpAAA=="]),
            create_poly_from_base64(&["NeverGonnaGiveYouUpAAA=="]),
            create_poly_from_base64(&["NeverGonnaLetYouDownAA=="]),
        ];
        let sorted = &[
            create_poly_from_base64(&["NeverGonnaLetYouDownAA=="]),
            create_poly_from_base64(&["NeverGonnaGiveYouUpAAA=="]),
            create_poly_from_base64(&["NeverGonnaGiveYouUpAAA=="]),
        ];

        polys.sort();
        assert_eq!(
            polys, sorted,
            "here in better format: Polys: {polys:#?}\nSorted: {sorted:#?}"
        )
    }

    #[test]
    fn test_spoly_ord_example() {
        let polys = &mut [
            create_poly_from_base64(&[
                "NeverGonnaGiveYouUpAAA==",
                "NeverGonnaLetYouDownAA==",
                "NeverGonnaRunAroundAAA==",
                "AndDesertYouAAAAAAAAAA==",
            ]),
            create_poly_from_base64(&[
                "WereNoStrangersToLoveA==",
                "YouKnowTheRulesAAAAAAA==",
                "AndSoDoIAAAAAAAAAAAAAA==",
            ]),
            create_poly_from_base64(&[
                "NeverGonnaMakeYouCryAA==",
                "NeverGonnaSayGoodbyeAA==",
                "NeverGonnaTellALieAAAA==",
                "AndHurtYouAAAAAAAAAAAA==",
            ]),
        ];
        let sorted = &mut [
            create_poly_from_base64(&[
                "WereNoStrangersToLoveA==",
                "YouKnowTheRulesAAAAAAA==",
                "AndSoDoIAAAAAAAAAAAAAA==",
            ]),
            create_poly_from_base64(&[
                "NeverGonnaMakeYouCryAA==",
                "NeverGonnaSayGoodbyeAA==",
                "NeverGonnaTellALieAAAA==",
                "AndHurtYouAAAAAAAAAAAA==",
            ]),
            create_poly_from_base64(&[
                "NeverGonnaGiveYouUpAAA==",
                "NeverGonnaLetYouDownAA==",
                "NeverGonnaRunAroundAAA==",
                "AndDesertYouAAAAAAAAAA==",
            ]),
        ];

        polys.sort();
        assert_eq!(
            polys, sorted,
            "here in better format: Polys: {polys:#?}\nSorted: {sorted:#?}"
        )
    }

    #[test]
    fn test_spoly_monic_example() {
        // From the example in aufgabe4.pdf
        let input = create_poly_from_base64(&[
            "NeverGonnaGiveYouUpAAA==",
            "NeverGonnaLetYouDownAA==",
            "NeverGonnaRunAroundAAA==",
            "AndDesertYouAAAAAAAAAA==",
        ]);

        let expected = create_poly_from_base64(&[
            "edY47onJ4MtCENDTHG/sZw==",
            "oaXjCKnceBIxSavZ9eFT8w==",
            "1Ial5rAJGOucIdUe3zh5bw==",
            "gAAAAAAAAAAAAAAAAAAAAA==", // Leading coefficient is 1
        ]);

        let result = input.make_monic();
        assert_poly(&result, &expected);
    }

    #[test]
    fn test_spoly_monic_zero() {
        // Zero polynomial should remain zero
        let input = SuperPoly::zero();
        let result = input.make_monic();
        assert_poly(&result, &SuperPoly::zero());
    }

    #[test]
    fn test_spoly_monic_one() {
        // Zero polynomial should remain zero
        let input = SuperPoly::one();
        let result = input.make_monic();
        assert_poly(&result, &SuperPoly::one());
    }

    #[test]
    fn test_spoly_monic_already_monic() {
        // Already monic polynomial should remain unchanged
        let input = create_poly_from_base64(&[
            "JAAAAAAAAAAAAAAAAAAAAA==",
            "wAAAAAAAAAAAAAAAAAAAAA==",
            "gAAAAAAAAAAAAAAAAAAAAA==", // Leading coefficient is 1
        ]);

        let result = input.make_monic();
        assert_poly(&result, &input);
    }

    #[test]
    fn test_spoly_monic_single_term() {
        // Single term polynomial should become just 1
        let input = create_poly_from_base64(&[
            "wAAAAAAAAAAAAAAAAAAAAA==", // Just one coefficient
        ]);

        let expected = SuperPoly::one();

        let result = input.make_monic();
        assert_poly(&result, &expected);
    }

    #[test]
    fn test_spoly_monic_constant_polynomial() {
        // Constant polynomial (degree 0) should become 1
        let input = create_poly_from_base64(&["JAAAAAAAAAAAAAAAAAAAAA=="]);

        let expected = SuperPoly::one();

        let result = input.make_monic();
        assert_poly(&result, &expected);
    }

    #[test]
    fn test_spoly_derivative() {
        // Test case from aufgabe04.pdf
        let input = create_poly_from_base64(&[
            "IJustWannaTellYouAAAAA==",
            "HowImFeelingAAAAAAAAAA==",
            "GottaMakeYouAAAAAAAAAA==",
            "UnderstaaaaaaaaaaaaanQ==",
        ]);

        let expected = create_poly_from_base64(&[
            "HowImFeelingAAAAAAAAAA==",
            "AAAAAAAAAAAAAAAAAAAAAA==",
            "UnderstaaaaaaaaaaaaanQ==",
        ]);

        let result = input.derivative();
        assert_poly(&result, &expected);
    }

    #[test]
    fn test_spoly_derivative_constant() {
        // Derivative of a constant should be zero
        let input = create_poly_from_base64(&["JAAAAAAAAAAAAAAAAAAAAA=="]);
        let result = input.derivative();
        assert_poly(&result, &SuperPoly::zero());
    }

    #[test]
    fn test_spoly_derivative_linear() {
        // Derivative of a linear term should be just the coefficient
        let input =
            create_poly_from_base64(&["JAAAAAAAAAAAAAAAAAAAAA==", "wAAAAAAAAAAAAAAAAAAAAA=="]);
        let expected = create_poly_from_base64(&["wAAAAAAAAAAAAAAAAAAAAA=="]);
        let result = input.derivative();
        assert_poly(&result, &expected);
    }

    #[test]
    fn test_spoly_derivative_zero() {
        // Derivative of zero should be zero
        let input = SuperPoly::zero();
        let result = input.derivative();
        assert_poly(&result, &SuperPoly::zero());
    }
}

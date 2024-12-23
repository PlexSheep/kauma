use anyhow::Result;
use num::{BigUint, FromPrimitive, One};
use serde::Serialize;

use crate::common::interface::get_any;
use crate::settings::Settings;

use super::superpoly::{get_spoly, SuperPoly};
use super::{Action, Testcase};

/// For the [GfpolyFactorSff](Action::GfpolyFactorSff) action
#[derive(Serialize)]
pub struct FactorExp {
    pub factor: SuperPoly,
    pub exponent: u32,
}

impl SuperPoly {
    /// Compute the square-free factorization of the polynomial
    /// Returns a vector of (factor, exponent) pairs
    pub fn factor_sff(mut self) -> Vec<FactorExp> {
        // Make input polynomial monic first
        self = self.make_monic();

        // Step 2: Calculate GCD of f and its derivative
        let derivative = self.derivative();
        let mut c = Self::gcd(self.clone(), derivative);

        // Step 3: Get the square-free part
        let mut f = &self / &c;

        // Step 4: Initialize result vector
        let mut factors: Vec<FactorExp> = Vec::new();

        // Step 5: Initialize multiplicity counter
        let mut e = 1;

        // Step 6-14: Main factorization loop
        while !f.is_zero() && f != Self::one() {
            // Step 7: Calculate new GCD
            let y = Self::gcd(f.clone(), c.clone());

            // Step 8-10: If we found a factor, add it
            if f != y {
                factors.push(FactorExp {
                    factor: (&f / &y).make_monic(),
                    exponent: e,
                });
            }

            // Step 11-12: Update for next iteration
            f = y.clone();
            c = &c / &y;

            // Step 13: Increment multiplicity
            e += 1;
        }

        // Step 15-20: Handle the case where c != 1
        if !c.is_zero() && c != Self::one() {
            // Recursively factor the square part
            let sqrt_factors = c.sqrt().factor_sff();

            // Double the exponents and add to results
            for facexp in sqrt_factors {
                factors.push(FactorExp {
                    factor: facexp.factor,
                    exponent: 2 * facexp.exponent,
                });
            }
        }

        // Sort the factors according to the total ordering rules
        factors.sort_by(|a, b| a.factor.cmp(&b.factor));

        factors
    }

    /// Implements the Cantor-Zassenhaus algorithm for equal-degree factorization
    pub fn factor_edf(&self, d: usize) -> Vec<Self> {
        // Make input monic first
        let monic = self.make_monic();

        // Early exit for special cases
        if monic.is_zero() || monic == Self::one() {
            return vec![monic];
        }

        // Calculate q = 2^128 (field characteristic)
        let q: u128 = 1u128 << 127;

        // Calculate n = deg(f)/d which is the number of factors
        let n = monic.deg() / d;
        if n == 1 {
            // f is already irreducible
            return vec![monic];
        }

        // Initialize result vector with just f
        let mut factors = vec![monic.clone()];

        // Main factorization loop
        while factors.len() < n {
            // Generate a random polynomial of degree < deg(f)
            let randpol = Self::random(monic.deg() - 1);

            // Calculate g = h^((q^d-1)/3) - 1 mod f
            let exp = (q.pow(d as u32) - 1) / 3;
            let mut g = randpol.powmod(exp, &monic);
            g ^= Self::one(); // Subtract 1

            // Try to split factors using gcd
            let mut updated_factors = Vec::new();
            for u in factors {
                if u.deg() > d {
                    let j = Self::gcd(u.clone(), g.clone());
                    if !j.is_zero() && j != u {
                        // Found a non-trivial factor, add both
                        updated_factors.push(j.make_monic());
                        updated_factors.push((&u / &j).make_monic());
                    } else {
                        // No split found, keep original
                        updated_factors.push(u);
                    }
                } else {
                    // Factor already at target degree
                    updated_factors.push(u);
                }
            }

            factors = updated_factors;
        }

        // Sort factors according to total ordering
        factors.sort();
        factors
    }
}

pub fn run_testcase(testcase: &Testcase, _settings: Settings) -> Result<serde_json::Value> {
    Ok(match testcase.action {
        Action::GfpolyFactorSff => {
            let f: SuperPoly = get_spoly(&testcase.arguments, "F")?;
            let factors: Vec<FactorExp> = f.factor_sff();

            serde_json::to_value(&factors)?
        }
        Action::GfpolyFactorEdf => {
            let f: SuperPoly = get_spoly(&testcase.arguments, "F")?;
            let d: usize = get_any(&testcase.arguments, "d")?;

            let factors = f.factor_edf(d);
            serde_json::to_value(&factors)?
        }
        _ => unreachable!(),
    })
}

use anyhow::Result;
use num::{BigUint, FromPrimitive, One};
use serde::Serialize;

use crate::common::interface::get_any;
use crate::settings::Settings;

use super::ffield::element::FieldElement;
use super::superpoly::{get_spoly, SuperPoly};
use super::{Action, Testcase};

/// For the [GfpolyFactorSff](Action::GfpolyFactorSff) action
#[derive(Serialize)]
pub struct FactorExp {
    pub factor: SuperPoly,
    pub exponent: u32,
}

/// For the [GfpolyFactorDdf](Action::GfpolyFactorDdf) action
#[derive(Serialize)]
pub struct FactorDeg {
    pub factor: SuperPoly,
    pub degree: usize,
}

impl SuperPoly {
    /// Compute the square-free factorization of the polynomial
    /// Returns a vector of (factor, exponent) pairs
    pub fn factor_sff(mut self) -> Vec<FactorExp> {
        // Make input polynomial monic first
        self = self.make_monic();

        // Step 2: Calculate GCD of f and its derivative
        let mut c = self.gcd(&self.derivative());

        // Step 3: Get the square-free part
        let mut f = &self / &c;

        // Step 4: Initialize result vector
        let mut factors: Vec<FactorExp> = Vec::new();

        // Step 5: Initialize multiplicity counter
        let mut e = 1;

        // Step 6-14: Main factorization loop
        while !f.is_zero() && f != Self::one() {
            // Step 7: Calculate new GCD
            let y = f.gcd(&c);

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

    /// Implements the distinct-degree factorization (DDF) algorithm for polynomials
    /// Takes a monic, square-free polynomial and factors it into polynomials that are products of irreducible polynomials of the same degree
    pub fn factor_ddf(&self) -> Vec<FactorDeg> {
        let mut f_star = self.make_monic();
        let mut factors = Vec::new();
        let mut d = 1;
        let q = BigUint::pow(&BigUint::from_u64(2).unwrap(), 128);

        while f_star.deg() >= 2 * d {
            // Calculate h = X^(q^d) - X mod f*
            let mut x_poly = SuperPoly::zero();
            x_poly.coefficients = vec![FieldElement::ZERO, FieldElement::ONE.to_be()];

            // Calculate X^(q^d) mod f*
            let h = x_poly.powmod(q.pow(d as u32), &f_star) + x_poly;
            let g = h.gcd(&f_star);

            // If we found a factor
            if !g.is_zero() && g != SuperPoly::one() {
                // Add the factor and its degree to results
                factors.push(FactorDeg {
                    factor: g.clone(),
                    degree: d,
                });

                // Update f* for next iteration
                f_star = &f_star / &g;
            }

            d += 1;
        }

        // Handle remaining factor if any
        if !f_star.is_zero() && f_star != SuperPoly::one() {
            factors.push(FactorDeg {
                degree: f_star.deg(),
                factor: f_star,
            });
        } else if factors.is_empty() {
            // Special case: input was irreducible
            factors.push(FactorDeg {
                factor: self.clone(),
                degree: 1,
            });
        }

        factors.sort_by(|a, b| a.factor.cmp(&b.factor));
        factors
    }

    /// Implements the Cantor-Zassenhaus algorithm for equal-degree factorization
    pub fn factor_edf(&self, d: usize) -> Vec<Self> {
        // variable names like in the formal definition of the algorithm
        // math people make weird one-letter names
        let f = self.make_monic();

        let q = BigUint::pow(&BigUint::from_u8(2).unwrap(), 128);
        let n = f.deg() / (d);
        let mut z: Vec<SuperPoly> = vec![f.clone()];

        while (z.len()) < n {
            let h = SuperPoly::random(f.deg());

            let exponent = (q.pow(d as u32) - BigUint::one()) / BigUint::from_u8(3).unwrap();

            let g = h.powmod(exponent, &f) + SuperPoly::one();

            for i in 0..z.len() {
                if z[i].deg() > d {
                    let j = z[i].gcd(&g);
                    if j != SuperPoly::one() && j != z[i] {
                        let intemediate = &z[i] / &j;
                        z.remove(i);
                        z.push(intemediate);
                        z.push(j.clone());
                    }
                }
            }
        }

        z
    }
}

pub fn run_testcase(testcase: &Testcase, _settings: Settings) -> Result<serde_json::Value> {
    Ok(match testcase.action {
        Action::GfpolyFactorSff => {
            let f: SuperPoly = get_spoly(&testcase.arguments, "F")?;
            let factors: Vec<FactorExp> = f.factor_sff();

            serde_json::to_value(&factors)?
        }
        Action::GfpolyFactorDdf => {
            let f: SuperPoly = get_spoly(&testcase.arguments, "F")?;
            let factors: Vec<FactorDeg> = f.factor_ddf();

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

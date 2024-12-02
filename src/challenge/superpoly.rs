use std::ops::{Add, AddAssign};

use anyhow::Result;

use crate::common::interface::{get_bytes_maybe_hex, maybe_hex};
use crate::common::{bytes_to_u128, len_to_const_arr};
use crate::settings::Settings;

use super::{ffield, Action, Testcase};
use ffield::Polynomial;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SuperPoly {
    coefficients: Vec<Polynomial>,
}

impl SuperPoly {
    pub fn zero() -> Self {
        SuperPoly::from([0])
    }
    pub fn one() -> Self {
        SuperPoly::from([1])
    }

    // implementing serialize but saying the Polynomials are to be base64 encoded is weird, so just
    // make it a method.
    pub fn serialize(self) -> Result<serde_json::Value> {
        todo!()
    }
}

/** Calculation stuff ********************************************************/

impl Add for SuperPoly {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        todo!()
    }
}

impl AddAssign for SuperPoly {
    fn add_assign(&mut self, rhs: Self) {
        todo!()
    }
}

/** From *********************************************************************/

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
            coefficients: value.map(|v| v.to_owned()).to_vec(),
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
            let a: SuperPoly = get_spoly(&testcase.arguments, "a")?;
            let b: SuperPoly = get_spoly(&testcase.arguments, "b")?;

            let s = a + b;
            s.serialize()?
        }
        _ => unreachable!(),
    })
}

fn get_spoly(args: &serde_json::Value, key: &str) -> Result<SuperPoly> {
    let raw_parts: Vec<String> = serde_json::from_value(args[key].clone())?;

    let mut coefficients: Vec<[u8; 16]> = Vec::with_capacity(raw_parts.len());
    for raw_part in raw_parts {
        coefficients.push(len_to_const_arr(&maybe_hex(&raw_part)?)?);
    }

    Ok(SuperPoly::from(coefficients.as_slice())) // here error
}

#[cfg(test)]
mod test {
    use super::SuperPoly;

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
}

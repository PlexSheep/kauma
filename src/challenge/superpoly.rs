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

impl Add for SuperPoly {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        let mut new_coefficients: Vec<Polynomial> =
            Vec::with_capacity(self.coefficients.len().max(rhs.coefficients.len()));
        for (ap, bp) in self.coefficients.iter().zip(rhs.coefficients.iter()) {
            new_coefficients.push(ap ^ bp);
        }
        Self::from(new_coefficients.as_slice())
    }
}

impl AddAssign for SuperPoly {
    fn add_assign(&mut self, rhs: Self) {
        for (ap, bp) in self.coefficients.iter_mut().zip(rhs.coefficients) {
            *ap ^= bp;
        }
    }
}

impl BitXor for SuperPoly {
    type Output = Self;
    fn bitxor(self, rhs: Self) -> Self::Output {
        self + rhs
    }
}

impl BitXorAssign for SuperPoly {
    fn bitxor_assign(&mut self, rhs: Self) {
        *self += rhs;
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

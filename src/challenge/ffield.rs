//! multiply / add polynomials in a gallois field

use core::panic;
use std::fmt::Display;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::common::{bit_at_i_inverted_order, byte_to_bits};

use super::{ChallengeLike, SolutionLike};

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
pub const DEFINING_RELATION_F_2_128: Polynomial = 0x87000000_00000000_00000000_00000080;
pub const DEFINING_RELATION_F_2_3: Polynomial = 0xb;
pub const DEFINING_RELATION_F_2_4: Polynomial = 0x13;
pub const DEFINING_RELATION_F_2_8: Polynomial = 0x11b;
/// A finite field over 2^128 with the defining relation [DEFINING_RELATION_F_2_128] as used in
/// AES.
pub const F_2_128: Field = Field::new(2, DEFINING_RELATION_F_2_128);
/// This is a special polynomial used for multiplication in F_2_128
pub const SPECIAL_ELEMENT_R: Polynomial = 0xE1000000_00000000_00000000_00000080;

#[derive(Debug, Deserialize, Serialize, Clone, Copy)]
enum Operation {
    Add,
    Mul,
}

/// Which finite field to use, e.g. F_(2^(128))
///
/// For the purposes of kauma-analyzer, we will focus on binary finite fields, so those with a base
/// of 2^n.
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
pub struct Field {
    /// Forms the base as 2^n
    n: u64,
    // TODO: I'm not totally sure about the machine representation!
    //
    /// The defining relation, represented as a number, where the least significant bit
    /// signifies b * α^0, the second least significant bit signifies b * α^1 and so on, where b is
    /// the value of that bit.
    ///
    /// Note that the byte order is from least to highest, unintuitively.
    defining_relation: Polynomial,
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy)]
pub struct Challenge {
    op: Operation,
    a: Polynomial,
    b: Polynomial,
    field: Field,
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy)]
pub struct Solution {
    op: Operation,
    a: Polynomial,
    b: Polynomial,
    res: Polynomial,
    field: Field,
}

impl Display for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Add => "+",
                Self::Mul => "*",
            }
        )
    }
}

impl Field {
    /// Create a new finite field with a base that is a power of two.
    pub const fn new(n: u64, defining_relation: Polynomial) -> Self {
        Self {
            n,
            defining_relation,
        }
    }
    /// Convert the machine representation of a polynomial to the human representation
    pub fn display_poly(&self, poly: Polynomial) -> String {
        let mut buf = String::new();
        let mut enabled = Vec::new();
        for (i, byte) in poly.to_le_bytes().iter().rev().enumerate() {
            for (j, bit) in byte_to_bits(*byte).iter().rev().enumerate() {
                if *bit {
                    enabled.push(j + (i * 8));
                }
            }
        }

        enabled.sort();
        enabled.reverse();
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

    /// Reduces the given [Polynomial] with the [defining relation](Self::defining_relation)
    pub fn reduce(&self, poly: Polynomial) -> Polynomial {
        poly ^ self.defining_relation
    }
    /// Get the sum of two [polynomials](Polynomial)
    ///
    /// Adds poly a and b together.
    ///
    /// This is not regular addition of two numbers!
    ///
    /// Addition on the finite field with a base of 2^n is the same as xor, therefore no reduction
    /// is needed.
    pub fn add(&self, poly_a: Polynomial, poly_b: Polynomial) -> Polynomial {
        poly_a ^ poly_b
    }
    /// Get the product of two [polynomials](Polynomial)
    ///
    /// Multiplies poly a by poly b together, automatically reducing it with the defining relation.
    ///
    /// This is not regular multiplication of two numbers!
    ///
    /// Multiplication in a finite field is rather complicated, so I use an algorithm from
    /// a research paper.
    ///
    /// # Citation
    /// - The Galois/Counter Mode of Operation (GCM) by McGrew and Viega, Sect. 2.5, Algorithm 1
    ///     <https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf>
    pub fn mul(&self, poly_a: Polynomial, poly_b: Polynomial) -> Polynomial {
        if *self != F_2_128 {
            panic!("I don't know how to multiply if it's not in F_2_128 (well, or in real regular numbers)!")
        }
        let mut z: Polynomial = 0;
        let mut v: Polynomial = poly_a;
        for i in 0..128 {
            if bit_at_i_inverted_order(poly_b, i) {
                z ^= v;
            }
            if bit_at_i_inverted_order(v, 127) {
                v = (v >> 1) ^ SPECIAL_ELEMENT_R;
            } else {
                v >>= 1;
            }
        }
        z
    }
}

impl Default for Field {
    fn default() -> Self {
        Self::new(128, DEFINING_RELATION_F_2_128)
    }
}

impl Display for Field {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "F_2^({}); {}",
            self.n,
            self.display_poly(self.defining_relation)
        )
    }
}

impl ChallengeLike<'_> for Challenge {
    type Solution = Solution;
    fn solve(&self) -> Result<Self::Solution> {
        Ok(match self.op {
            Operation::Add => Solution {
                a: self.a,
                b: self.b,
                op: self.op,
                res: self.field.add(self.a, self.b),
                field: self.field,
            },
            Operation::Mul => Solution {
                a: self.a,
                b: self.b,
                op: self.op,
                res: self.field.mul(self.a, self.b),
                field: self.field,
            },
        })
    }
}
impl SolutionLike<'_> for Solution {}

impl Display for Solution {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} {} in {} = {}",
            self.field.display_poly(self.a),
            self.op,
            self.field.display_poly(self.b),
            self.field,
            self.field.display_poly(self.res)
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_add_alpha() {
        const SOLUTION: Polynomial = 0x14000000_00000000_00000000_00000000; // α^4 + α^2
        let c = Challenge {
            op: Operation::Add,
            a: 0x16000000_00000000_00000000_00000000, // α^4 + α^2 + α
            b: 0x02000000_00000000_00000000_00000000, // α
            field: F_2_128,
        };
        let sol = c.solve().expect("could not solve the challenge");
        assert_eq!(
            sol.res,
            SOLUTION,
            "\n0x{:016X} => {}\nshould be\n0x{SOLUTION:016X} => {}",
            sol.res,
            c.field.display_poly(sol.res),
            c.field.display_poly(SOLUTION),
        );
    }

    #[test]
    fn test_dipsplay_poly() {
        let a: Polynomial = 0x14000000_00000000_00000000_00000000; // α^4 + α^2
        let b: Polynomial = 0x16000000_00000000_00000000_00000000; // α^4 + α^2 + α
        let c: Polynomial = 0x02000000_00000000_00000000_00000000; // α
        assert_eq!(F_2_128.display_poly(1 << 120), "1");
        assert_eq!(F_2_128.display_poly(1 << 121), "α");
        assert_eq!(F_2_128.display_poly(a), "α^4 + α^2");
        assert_eq!(F_2_128.display_poly(b), "α^4 + α^2 + α");
        assert_eq!(F_2_128.display_poly(c), "α");
    }
}

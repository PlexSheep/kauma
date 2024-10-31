//! An unsigned integer type with 256 bits

use std::ops::{Add, Shl, Shr};

use crate::bit_at_i;

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq, PartialOrd, Ord)]
pub struct U256(u128, u128);

impl U256 {
    #[inline]
    fn new(upper: u128, lower: u128) -> Self {
        Self(upper, lower)
    }
}

impl Add for U256 {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        let (carry, lower_overflow) = self.1.overflowing_add(rhs.1 + 1);
        if lower_overflow {
            Self(self.0 + rhs.0 + carry, 0)
        } else {
            Self(self.0 + rhs.0, self.1 + rhs.1)
        }
    }
}

impl Shl for U256 {
    type Output = Self;
    fn shl(self, rhs: Self) -> Self::Output {
        let carry_bit = bit_at_i(self.1, 127);
        if carry_bit {
            Self((self.0 << rhs.0) | 1, self.1 << rhs.1)
        } else {
            Self(self.0 << rhs.0, self.1 << rhs.1)
        }
    }
}

// From conversions

impl From<u128> for U256 {
    fn from(value: u128) -> Self {
        Self::new(0, value)
    }
}

impl From<u64> for U256 {
    fn from(value: u64) -> Self {
        Self::new(0, value as u128)
    }
}

impl From<u32> for U256 {
    fn from(value: u32) -> Self {
        Self::new(0, value as u128)
    }
}

impl From<u16> for U256 {
    fn from(value: u16) -> Self {
        Self::new(0, value as u128)
    }
}

impl From<u8> for U256 {
    fn from(value: u8) -> Self {
        Self::new(0, value as u128)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_u256_add_0() {
        let a = U256::from(1337u16);
        let b = U256::from(1337u16);
        assert_eq!(a + b, U256::from(1337u16 * 2))
    }

    #[test]
    fn test_u256_add_1() {
        let a = U256::from(u128::MAX);
        let b = U256::from(1u8);
        assert_eq!(a + b, U256::new(1, 0))
    }

    #[test]
    fn test_u256_lshift_0() {
        let a = U256(0, 1);
        assert_eq!(a << U256(0, 1), U256(0, 2))
    }

    #[test]
    fn test_u256_lshift_1() {
        let a = U256(0, 1 << 127);
        assert_eq!(a << U256(0, 1), U256(1, 0))
    }

    #[test]
    fn test_u256_lshift_2() {
        let a = U256(0, u128::MAX);
        assert_eq!(a << U256(0, 1), U256(1, u128::MAX << 1))
    }


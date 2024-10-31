//! An unsigned integer type with 256 bits

use std::ops::{Add, Shl, Shr};

use crate::bit_at_i;

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq, PartialOrd, Ord, Default)]
pub struct U256(u128, u128);

impl U256 {
    pub const MAX: Self = U256(u128::MAX, u128::MAX);
    pub const MIN: Self = U256(0, 0);
    pub const BITS: u32 = 256;

    #[inline]
    const fn new(upper: u128, lower: u128) -> Self {
        Self(upper, lower)
    }

    /// to native endian bytes
    pub fn to_ne_bytes(self) -> [u8; 32] {
        let mut buffer: [u8; 32] = [0; 32];
        buffer[0..16]
            .as_mut()
            .copy_from_slice(&self.0.to_ne_bytes());
        buffer[16..32]
            .as_mut()
            .copy_from_slice(&self.0.to_ne_bytes());

        buffer
    }

    /// to big endian bytes
    pub fn to_be_bytes(self) -> [u8; 32] {
        let mut buffer: [u8; 32] = [0; 32];
        buffer[0..16]
            .as_mut()
            .copy_from_slice(&self.0.to_be_bytes());
        buffer[16..32]
            .as_mut()
            .copy_from_slice(&self.0.to_be_bytes());

        buffer
    }

    /// to little endian bytes
    pub fn to_le_bytes(self) -> [u8; 32] {
        let mut buffer: [u8; 32] = [0; 32];
        buffer[0..16]
            .as_mut()
            .copy_from_slice(&self.0.to_le_bytes());
        buffer[16..32]
            .as_mut()
            .copy_from_slice(&self.0.to_le_bytes());

        buffer
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
    // FIXME: only works for rhs==1
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

impl From<U256> for [u128; 2] {
    fn from(value: U256) -> Self {
        [value.0, value.1]
    }
}

impl<'a> From<&'a U256> for [&'a u128; 2] {
    fn from(value: &'a U256) -> Self {
        [&value.0, &value.1]
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

    // this test will fail on a big endian system
    #[test]
    fn test_u256_to_ne_bytes() {
        let a = U256(255, 255);
        assert_eq!(
            a.to_ne_bytes(),
            [
                255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0,
            ]
        )
    }

    #[test]
    fn test_u256_to_le_bytes() {
        let a = U256(255, 255);
        assert_eq!(
            a.to_le_bytes(),
            [
                255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0,
            ]
        )
    }

    #[test]
    fn test_u256_to_be_bytes() {
        let a = U256(255, 255);
        assert_eq!(
            a.to_be_bytes(),
            [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 255,
            ]
        )
    }
}

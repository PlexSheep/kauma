//! An unsigned integer type with 256 bits

use std::cmp::Ordering;
use std::fmt::{Binary, LowerHex, UpperHex};
use std::ops::{Add, Shl, ShlAssign, Shr, ShrAssign};

use crate::bit_at_i;

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq, Default)]
pub struct U256(pub u128, pub u128);

impl U256 {
    pub const MAX: Self = U256(u128::MAX, u128::MAX);
    pub const MIN: Self = U256(0, 0);
    pub const BITS: u32 = 256;

    #[inline]
    pub const fn upper(self) -> u128 {
        self.0
    }

    #[inline]
    pub const fn lower(self) -> u128 {
        self.1
    }

    #[inline]
    pub const fn upper_ref(&self) -> &u128 {
        &self.0
    }

    #[inline]
    pub const fn lower_ref(&self) -> &u128 {
        &self.1
    }

    #[inline]
    pub fn upper_mut(&mut self) -> &mut u128 {
        &mut self.0
    }

    #[inline]
    pub fn lower_mut(&mut self) -> &mut u128 {
        &mut self.1
    }

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

impl std::ops::BitXor for U256 {
    type Output = Self;
    fn bitxor(self, rhs: Self) -> Self::Output {
        U256(self.0 ^ rhs.0, self.1 ^ rhs.1)
    }
}

impl Shl<usize> for U256 {
    type Output = Self;
    // FIXME: only works for rhs==1
    fn shl(self, rhs: usize) -> Self::Output {
        if rhs != 1 {
            panic!("shift only implemented for rhs=1");
        }
        let carry_bit = bit_at_i(self.1, 127);
        if carry_bit {
            Self((self.0 << rhs) | 1, self.1 << rhs)
        } else {
            Self(self.0 << rhs, self.1 << rhs)
        }
    }
}

impl Shr<usize> for U256 {
    type Output = Self;
    // FIXME: only works for rhs==1
    fn shr(self, rhs: usize) -> Self::Output {
        if rhs != 1 {
            panic!("shift only implemented for rhs=1");
        }
        let carry_bit = bit_at_i(self.0, 0);
        if carry_bit {
            Self(self.0 >> rhs, (self.1 >> rhs) | 1 << 127)
        } else {
            Self(self.0 >> rhs, self.1 >> rhs)
        }
    }
}

impl ShlAssign<usize> for U256 {
    fn shl_assign(&mut self, rhs: usize) {
        *self = *self << rhs;
    }
}

impl ShrAssign<usize> for U256 {
    fn shr_assign(&mut self, rhs: usize) {
        *self = *self >> rhs;
    }
}

impl std::ops::BitXorAssign for U256 {
    fn bitxor_assign(&mut self, rhs: Self) {
        *self = *self ^ rhs;
    }
}

impl Ord for U256 {
    #[allow(clippy::comparison_chain)] // I can't use cmp here as that's what I'm implementing
    fn cmp(&self, other: &U256) -> Ordering {
        if self.0 < other.0 {
            return Ordering::Less;
        } else if self.0 > other.0 {
            return Ordering::Greater;
        }
        if self.1 < other.1 {
            return Ordering::Less;
        } else if self.1 > other.1 {
            return Ordering::Greater;
        }
        Ordering::Equal
    }
}

impl PartialOrd for U256 {
    fn partial_cmp(&self, other: &U256) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Binary for U256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Binary::fmt(&self.0, f)?;
        std::fmt::Binary::fmt(&self.1, f)
    }
}

impl LowerHex for U256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0 == 0 {
            std::fmt::LowerHex::fmt(&self.1, f)
        } else {
            std::fmt::LowerHex::fmt(&self.0, f)?;
            write!(f, "{:032x}", self.1)
        }
    }
}

impl UpperHex for U256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0 == 0 {
            std::fmt::LowerHex::fmt(&self.1, f)
        } else {
            std::fmt::LowerHex::fmt(&self.0, f)?;
            write!(f, "{:032X}", self.1)
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

impl TryFrom<U256> for u128 {
    type Error = crate::TryFromIntError;

    fn try_from(value: U256) -> Result<Self, Self::Error> {
        if value.0 != 0 {
            Err(crate::TryFromIntError(()))
        } else {
            Ok(value.1)
        }
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
        assert_eq!(a << 1, U256(0, 2))
    }

    #[test]
    fn test_u256_lshift_1() {
        let a = U256(0, 1 << 127);
        assert_eq!(a << 1, U256(1, 0))
    }

    #[test]
    fn test_u256_lshift_2() {
        let a = U256(0, u128::MAX);
        assert_eq!(a << 1, U256(1, u128::MAX << 1))
    }

    #[test]
    #[ignore = "will do shift with n later"]
    fn test_u256_lshift_3() {
        let a = U256(0, u128::MAX);
        assert_eq!(a << 4, U256(16, u128::MAX << 4))
    }

    #[test]
    fn test_u256_rshift_0() {
        let a = U256(0, 1);
        assert_eq!(a >> 1, U256(0, 0))
    }

    #[test]
    fn test_u256_rshift_1() {
        let a = U256(1, 0);
        assert_eq!(a >> 1, U256(0, 1 << 127))
    }

    #[test]
    #[ignore = "will do shift with n later"]
    fn test_u256_rshift_2() {
        let a = U256(1, 0);
        assert_eq!(a >> 5, U256(0, 1 << (128 - 5)))
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

    #[test]
    fn test_u256_display() {
        assert_eq!(
            format!("{:x}", U256(1, 15)),
            "10000000000000000000000000000000f"
        );
        assert_eq!(
            format!("{:X}", U256(1, 15)),
            "10000000000000000000000000000000F"
        );
    }
}

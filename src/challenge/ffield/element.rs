use std::cmp::Ordering;
use std::fmt::{self, Binary, Display, LowerHex, UpperHex};
use std::ops::{Add, BitOr, BitOrAssign, BitXor, BitXorAssign, Div, Mul};

use bint_easy::u256::U256;
use num::traits::ToBytes;
use serde::{Deserialize, Serialize};

use crate::common::{byte_to_bits, bytes_to_u128_unknown_size};

use super::{Semantic, F_2_128};

pub const DEFINING_RELATION_F_2_128: U256 = U256(1, DEFINING_RELATION_F_2_128_SHORT);
const DEFINING_RELATION_F_2_128_SHORT: u128 = 0x87000000_00000000_00000000_00000000;

#[derive(Debug, Eq, PartialEq, Hash, Clone, Copy)]
pub struct FieldElement {
    inner: u128,
    semantic: Semantic,
}

impl FieldElement {
    pub const ZERO: FieldElement = Self::const_from_raw_xex(0);
    pub const ONE: FieldElement = Self::const_from_raw_xex(0x01000000_00000000_00000000_00000000);
    pub const ALPHA: FieldElement = Self::const_from_raw_xex(0x02000000_00000000_00000000_00000000);
    pub const RELATION_FULL: U256 = DEFINING_RELATION_F_2_128;
    pub const RELATION: FieldElement = Self::const_from_raw_xex(DEFINING_RELATION_F_2_128_SHORT);

    #[inline]
    pub const fn const_from_raw_gcm(inner: u128) -> Self {
        Self {
            inner,
            semantic: Semantic::Gcm,
        }
    }

    pub fn from_gcm_convert_to_xex(raw: u128) -> Self {
        let a = Self::const_from_raw_gcm(raw);
        a.change_semantic(Semantic::Gcm, Semantic::Xex)
    }

    #[inline]
    pub const fn const_from_raw_xex(inner: u128) -> Self {
        Self {
            inner,
            semantic: Semantic::Xex,
        }
    }

    pub fn new(raw: u128, sem: Semantic) -> Self {
        Self {
            inner: raw,
            semantic: sem,
        }
    }

    #[inline]
    pub const fn raw(self) -> u128 {
        self.inner
    }

    #[inline]
    pub const fn sem(self) -> Semantic {
        self.semantic
    }

    pub fn pow(self, mut exp: u128) -> Self {
        if exp == 1 {
            return self;
        }
        if exp == 0 {
            return FieldElement::ONE;
        }

        // just square and multiply
        let mut acc: FieldElement = FieldElement::ONE;
        let mut base = self;
        if base.semantic != Semantic::Xex {
            base = base.change_semantic(base.semantic, Semantic::Xex);
        }
        while exp > 1 {
            if (exp & 1) == 1 {
                acc = acc * base;
            }
            exp /= 2;
            base = base * base;
        }
        acc * base
    }

    pub fn change_semantic(self, source: Semantic, target: Semantic) -> FieldElement {
        match (source, target) {
            (Semantic::Xex, Semantic::Gcm) | (Semantic::Gcm, Semantic::Xex) => {
                let by: Vec<u8> = self
                    .to_be_bytes()
                    .iter()
                    .map(|v| v.reverse_bits())
                    .collect();
                let mut a: Self = bytes_to_u128_unknown_size(&by)
                    .expect("same size u128 is not same size")
                    .into();
                a.semantic = target;
                a
            }
            (Semantic::Gcm, Semantic::Gcm) => self,
            (Semantic::Xex, Semantic::Xex) => self,
        }
    }

    pub fn to_coefficients(&self) -> Vec<usize> {
        let mut base = *self;
        if base.semantic != Semantic::Xex {
            base = base.change_semantic(base.semantic, Semantic::Xex);
        }
        let mut enabled = Vec::new();
        for (byte_idx, byte) in base.to_be_bytes().iter().enumerate() {
            for (bit_idx, bit) in byte_to_bits(*byte).iter().rev().enumerate() {
                if *bit {
                    enabled.push(bit_idx + (byte_idx * 8));
                }
            }
        }

        enabled.sort();
        enabled
    }

    pub fn from_coefficients_xex(coefficients: Vec<usize>) -> FieldElement {
        let mut poly: FieldElement = FieldElement::ZERO;
        for coefficient in coefficients {
            // NOTE: Why does this work? Shouldn't the horrible repr kill everything that uses
            // simple bitshifts and indexing?
            poly |= 1u128 << coefficient as u128;
        }
        // PERF: by using swap bytes we can safe a bit of performance, as we dont need to do
        // (127-coefficient) each time
        poly.swap_bytes()
    }

    /// Convert the machine representation of a polynomial to the human representation, using [XEX Semantic](Semantic::Xex).
    pub fn display_algebra(&self) -> String {
        let mut base = *self;
        if base.semantic != Semantic::Xex {
            base = base.change_semantic(base.semantic, Semantic::Xex);
        }
        let mut buf = String::new();
        let enabled: Vec<_> = base.to_coefficients().into_iter().rev().collect();
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
}

impl ToBytes for FieldElement {
    type Bytes = [u8; 16];
    fn to_be_bytes(&self) -> Self::Bytes {
        self.inner.to_be_bytes()
    }
    fn to_le_bytes(&self) -> Self::Bytes {
        self.inner.to_le_bytes()
    }
    fn to_ne_bytes(&self) -> Self::Bytes {
        self.inner.to_ne_bytes()
    }
}

// pretend to be u128
impl FieldElement {
    pub fn to_be(self) -> Self {
        Self::from(self.inner.to_be())
    }
    pub fn to_le(self) -> Self {
        Self::from(self.inner.to_le())
    }
    pub fn swap_bytes(self) -> Self {
        self.inner.swap_bytes().into()
    }
}

impl PartialOrd for FieldElement {
    fn partial_cmp(&self, other: &FieldElement) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FieldElement {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let self_sem = self.change_semantic(self.semantic, Semantic::Xex);
        let other_sem = other.change_semantic(other.semantic, Semantic::Xex);

        for (byte_a, byte_b) in self_sem
            .raw()
            .to_be_bytes()
            .iter()
            .rev()
            .zip(other_sem.raw().to_be_bytes().iter().rev())
        {
            match byte_a.cmp(byte_b) {
                Ordering::Equal => continue,
                other => return other,
            }
        }
        Ordering::Equal
    }
}

impl Display for FieldElement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt::Display::fmt(&self.inner, f)
    }
}

impl Binary for FieldElement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt::Binary::fmt(&self.inner, f)
    }
}

impl LowerHex for FieldElement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt::LowerHex::fmt(&self.inner, f)
    }
}

impl UpperHex for FieldElement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt::UpperHex::fmt(&self.inner, f)
    }
}

impl BitOrAssign<u128> for FieldElement {
    fn bitor_assign(&mut self, rhs: u128) {
        self.inner |= rhs;
    }
}

impl BitOrAssign for FieldElement {
    fn bitor_assign(&mut self, rhs: Self) {
        self.inner |= rhs.inner;
    }
}

impl BitOr for FieldElement {
    type Output = FieldElement;
    fn bitor(self, rhs: Self) -> Self::Output {
        Self::const_from_raw_xex(self.inner | rhs.inner)
    }
}

impl BitXorAssign<u128> for FieldElement {
    fn bitxor_assign(&mut self, rhs: u128) {
        self.inner ^= rhs;
    }
}

impl BitXorAssign for FieldElement {
    fn bitxor_assign(&mut self, rhs: Self) {
        self.inner ^= rhs.inner;
    }
}

impl Add for FieldElement {
    type Output = FieldElement;
    #[allow(clippy::suspicious)] // I swear this is correct
    fn add(self, rhs: Self) -> Self::Output {
        self ^ rhs
    }
}

impl Div for FieldElement {
    type Output = Self;
    fn div(self, rhs: Self) -> Self::Output {
        let self_sem = self.change_semantic(self.semantic, Semantic::Xex);
        let other_sem = rhs.change_semantic(rhs.semantic, Semantic::Xex);
        F_2_128.div(self_sem, other_sem)
    }
}

impl BitXor for FieldElement {
    type Output = FieldElement;
    fn bitxor(self, rhs: Self) -> Self::Output {
        if rhs.sem() == self.sem() {
            Self::new(self.inner ^ rhs.inner, self.sem())
        } else {
            let tmp = rhs.change_semantic(rhs.sem(), self.sem());
            Self::new(self.inner ^ tmp.inner, self.sem())
        }
    }
}

impl Mul<Self> for FieldElement {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        let self_sem = self.change_semantic(self.semantic, Semantic::Xex);
        let other_sem = rhs.change_semantic(rhs.semantic, Semantic::Xex);
        F_2_128.mul(self_sem, other_sem)
    }
}

impl PartialEq<u128> for FieldElement {
    fn eq(&self, other: &u128) -> bool {
        self.inner == *other
    }
}

impl From<u128> for FieldElement {
    fn from(value: u128) -> Self {
        Self::const_from_raw_xex(value)
    }
}

impl From<FieldElement> for u128 {
    fn from(value: FieldElement) -> Self {
        value.inner
    }
}

impl Serialize for FieldElement {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        u128::serialize(&self.inner, serializer)
    }
}

impl<'d> Deserialize<'d> for FieldElement {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'d>,
    {
        u128::deserialize(deserializer).map(FieldElement::const_from_raw_xex)
    }
}

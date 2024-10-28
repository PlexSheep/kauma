//! Implements some helper functions that I might need in multiple challenges

pub mod interface;

use anyhow::{anyhow, Result};

pub fn veprintln(key: &str, format_args: std::fmt::Arguments) {
    eprintln!("? {key:012}:\t{format_args}");
}

/// Try to downcast any array of [u8] into an array of constant size
pub fn len_to_const_arr<const N: usize>(data: &[u8]) -> Result<[u8; N]> {
    let arr: [u8; N] = match data.try_into() {
        Ok(v) => v,
        Err(e) => {
            let e = anyhow!(
                "! Data is of bad length {}: {:02x?} ; {e:#?}",
                data.len(),
                data
            );
            return Err(e);
        }
    };
    Ok(arr)
}

/// Combine a number of [u8] into a [u128]
///
/// Fails if the [Vec] is too long to fit into a [u128].
pub fn bytes_to_u128(bytes: &[u8]) -> Result<u128> {
    if bytes.len() > (u128::BITS.div_ceil(8)) as usize {
        return Err(anyhow!("input bytes are too long!"));
    }
    let mut ri: u128 = 0;
    for (i, e) in bytes.iter().rev().enumerate() {
        ri += (*e as u128) * 256u128.pow(i as u32);
    }
    Ok(ri)
}

/// Wraps a value in an object with some title
///
/// ```
/// use kauma_analyzer::common::tag_json_value;
/// use serde_json::{json};
/// let v = json!({"foo": 19});
/// assert_eq!(tag_json_value("title", v), json!({"title": {"foo": 19}}));
/// ````
pub fn tag_json_value(tag: &str, value: serde_json::Value) -> serde_json::Value {
    let mut helper_map = serde_json::Map::new();
    helper_map.insert(tag.to_owned(), value);
    serde_json::Value::Object(helper_map)
}

/// Splits a [u8] into a array of bools [bool], where each bool is a bit.
///
/// The LSB is the first bit
pub fn byte_to_bits(byte: u8) -> [bool; 8] {
    let mut buf = [false; 8];
    for (i, bit) in buf.iter_mut().enumerate() {
        *bit = bit_at_i(byte as u128, 7 - i);
    }
    buf
}

/// Get's the bit at position i.
/// ```
/// use kauma_analyzer::common::bit_at_i;
/// assert_eq!(bit_at_i(0b10000000, 7), true);
/// assert_eq!(bit_at_i(0b01000000, 7), false);
/// assert_eq!(bit_at_i(0b11000000, 7), true);
/// assert_eq!(bit_at_i(0b11111111, 7), true);
/// assert_eq!(bit_at_i(0x01ffffff_ffffffff_ffffffff_ffffffff, 120), true);
/// assert_eq!(bit_at_i(0x01ffffff_ffffffff_ffffffff_ffffffff, 127), false);
/// assert_eq!(bit_at_i(0xffffffff_ffffffff_ffffffff_ffffffff, 127), true);
/// ```
#[inline]
pub fn bit_at_i(num: u128, i: usize) -> bool {
    (num & (1 << i)) >> i == 1
}

/// Like [bit_at_i] but with reversed order
/// ```
/// use kauma_analyzer::common::bit_at_i_inverted_order;
/// assert_eq!(bit_at_i_inverted_order(1<<127, 0), true);
/// assert_eq!(bit_at_i_inverted_order(1<<120, 7), true);
/// assert_eq!(bit_at_i_inverted_order(0b00000000, 0), false);
/// assert_eq!(bit_at_i_inverted_order(0b00000000_01111111, 120), false);
/// assert_eq!(bit_at_i_inverted_order(0b00000000_11111111, 120), true);
/// ```
#[inline]
pub fn bit_at_i_inverted_order(num: u128, i: usize) -> bool {
    let i = 127 - i;
    bit_at_i(num, i)
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    #[allow(clippy::bool_assert_comparison)] // disable the hint to use short form asserts
    fn test_bit_at_i() {
        assert_eq!(bit_at_i(1, 0), true);
        assert_eq!(bit_at_i(0, 0), false);
        assert_eq!(bit_at_i(1 << 54, 54), true);
        assert_eq!(bit_at_i((1 << 54) - 1, 54), false);
        assert_eq!(bit_at_i(0b10000000, 7), true);
        assert_eq!(bit_at_i(0b01000000, 7), false);
        assert_eq!(bit_at_i(0b11000000, 7), true);
        assert_eq!(bit_at_i(0b11111111, 7), true);
        assert_eq!(bit_at_i(0x01ffffff_ffffffff_ffffffff_ffffffff, 120), true);
        assert_eq!(bit_at_i(0x01ffffff_ffffffff_ffffffff_ffffffff, 127), false);
        assert_eq!(bit_at_i(0xffffffff_ffffffff_ffffffff_ffffffff, 127), true);
    }
    #[test]
    #[allow(clippy::bool_assert_comparison)] // disable the hint to use short form asserts
    #[rustfmt::skip]
    fn test_bit_at_i_inverted_order() {
        assert_eq!(bit_at_i_inverted_order(1, 127), true);
        assert_eq!(bit_at_i_inverted_order(0, 127), false);
        assert_eq!(bit_at_i_inverted_order(1 << 54, 127 - 54), true);
        assert_eq!(bit_at_i_inverted_order((1 << 54)-1, 127 - 54), false);
        assert_eq!(bit_at_i_inverted_order(0x01000000_00000000_00000000_00000000, 0), false);
        assert_eq!(bit_at_i_inverted_order(0x80000000_00000000_00000000_00000000, 0), true);
        assert_eq!(bit_at_i_inverted_order(0xC8000000_00000000_00000000_00000000, 0), true);
        assert_eq!(bit_at_i_inverted_order(0xFF000000_00000000_00000000_00000000, 0), true);
        assert_eq!(bit_at_i_inverted_order(0x01ffffff_ffffffff_ffffffff_ffffffff, 7), true);
        assert_eq!(bit_at_i_inverted_order(0x01ffffff_ffffffff_ffffffff_ffffffff, 0), false);
        assert_eq!(bit_at_i_inverted_order(0xffffffff_ffffffff_ffffffff_ffffffff, 0), true);
    }
    #[test]
    #[allow(clippy::bool_assert_comparison)] // disable the hint to use short form asserts
    fn test_byte_to_bits() {
        assert_eq!(
            byte_to_bits(0b11010110),
            [true, true, false, true, false, true, true, false]
        );
    }
}

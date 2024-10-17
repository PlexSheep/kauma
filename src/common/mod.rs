//! Implements some helper functions that I might need in multiple challenges

pub fn bit_at_i(num: u128, i: usize) -> bool {
    let b = (num & (1 << i)) >> i;
    b == 1
}

pub fn bit_at_i_inverted_order(num: u128, i: usize) -> bool {
    let i = 127 - i;
    let b = (num & (1 << i)) >> i;
    b == 1
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
}

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


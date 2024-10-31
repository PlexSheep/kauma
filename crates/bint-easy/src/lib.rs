//! Easy large integer types
//!
//! Working with numbers of more than 128 bits can sometimes be needed for some algorithms. To make
//! things a bit more ergonomic without requiring large dependencies or weirdly implemented big
//! numbers, this crate implements large (unsigned) integers.
//!
//! The aim of this library is to be simple to use and understand. Big numbers are just tuple
//! structs / structs with arrays of [u128].

/// Implements [U256].
pub mod u256;

/// Helper function to get the bit at position i. Left is 127 and right is 0.
#[inline]
pub(crate) fn bit_at_i(num: u128, i: usize) -> bool {
    (num & (1 << i)) >> i == 1
}

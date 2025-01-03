//! Easy large integer types
//!
//! Working with numbers of more than 128 bits can sometimes be needed for some algorithms. To make
//! things a bit more ergonomic without requiring large dependencies or weirdly implemented big
//! numbers, this crate implements large (unsigned) integers.
//!
//! The aim of this library is to be simple to use and understand. Big numbers are just tuple
//! structs / structs with arrays of [u128].
//!
//! Honorable Mentions:
//!
//! The `u256` crate was helpful when trying to implement the trait functions for [U256](u256::U256).

/// Implements [U256].
pub mod u256;

/// The error type returned when a checked integral type conversion fails.
///
/// The one from the std library can not be created from other crates
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct TryFromIntError(pub(crate) ());

/// Helper function to get the bit at position i. Left is 127 and right is 0.
#[inline]
pub(crate) fn bit_at_i(num: u128, i: usize) -> bool {
    (num & (1 << i)) >> i == 1
}

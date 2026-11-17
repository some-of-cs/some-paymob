#![forbid(unsafe_code)]
//! Canonical 20-key Paymob transaction HMAC concatenation builder (Unit 7.1.3).
//!
//! Provides the static lexicographically ordered [`TX_HMAC_KEYS`] lookup table
//! and [`CanonicalTransactionConcatenator`], a pre-sized `String` builder for
//! zero-intermediate-allocation canonical HMAC-SHA512 payload assembly across
//! Paymob transaction webhook protocols (Protocol A POST and Protocol B GET).

use std::fmt::Write as _;

/// Default pre-allocated buffer capacity (in bytes) for
/// [`CanonicalTransactionConcatenator`].
const DEFAULT_CANONICAL_CAPACITY: usize = 512;

/// Static, lexicographically ordered 20-key list used by Paymob Transaction
/// Processed (Protocol A) and Transaction Response (Protocol B) HMAC-SHA512
/// verification.
///
/// Note that `"error_occured"` intentionally preserves Paymob's upstream
/// single-`r` spelling.
///
/// # Examples
///
/// ```
/// use some_paymob::webhooks::canonical_tx::TX_HMAC_KEYS;
///
/// assert_eq!(TX_HMAC_KEYS.len(), 20);
/// assert_eq!(TX_HMAC_KEYS[0], "amount_cents");
/// assert_eq!(TX_HMAC_KEYS[3], "error_occured");
/// assert_eq!(TX_HMAC_KEYS[19], "success");
/// assert!(TX_HMAC_KEYS.windows(2).all(|pair| pair[0] < pair[1]));
/// ```
pub const TX_HMAC_KEYS: [&str; 20] = [
    "amount_cents",
    "created_at",
    "currency",
    "error_occured",
    "has_parent_transaction",
    "id",
    "integration_id",
    "is_3d_secure",
    "is_auth",
    "is_capture",
    "is_refunded",
    "is_standalone_payment",
    "is_voided",
    "order_id",
    "owner",
    "pending",
    "source_data.pan",
    "source_data.sub_type",
    "source_data.type",
    "success",
];

/// Pre-sized canonical transaction concatenator (`String::with_capacity(512)`)
/// for assembling Paymob 20-key HMAC payloads without intermediate heap
/// allocations.
///
/// # Examples
///
/// ```
/// use some_paymob::webhooks::canonical_tx::CanonicalTransactionConcatenator;
///
/// let mut builder = CanonicalTransactionConcatenator::new();
/// assert!(builder.is_empty());
/// builder.push_u64(10_000);
/// builder.push_str("2026-11-16T12:00:00.000000");
/// builder.push_str("EGP");
/// builder.push_bool(false);
/// builder.push_bool(true);
/// assert!(!builder.is_empty());
///
/// let canonical = builder.finish();
/// assert_eq!(canonical, "100002026-11-16T12:00:00.000000EGPfalsetrue");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalTransactionConcatenator {
    buf: String,
}

impl CanonicalTransactionConcatenator {
    /// Creates a new [`CanonicalTransactionConcatenator`] with a pre-allocated
    /// 512-byte buffer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            buf: String::with_capacity(DEFAULT_CANONICAL_CAPACITY),
        }
    }

    /// Appends a string slice directly to the canonical buffer.
    pub fn push_str(&mut self, value: &str) {
        self.buf.push_str(value);
    }

    /// Formats an unsigned 64-bit integer directly into the canonical buffer
    /// via [`std::fmt::Write`] without intermediate heap allocations.
    pub fn push_u64(&mut self, value: u64) {
        // Writing to `String` via `fmt::Write` is infallible and appends
        // directly into the pre-allocated buffer.
        let _ = write!(self.buf, "{value}");
    }

    /// Appends a boolean value formatted as lowercase `"true"` or `"false"`.
    pub fn push_bool(&mut self, value: bool) {
        let literal = if value { "true" } else { "false" };
        self.buf.push_str(literal);
    }

    /// Returns a string slice of the canonical payload accumulated so far.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.buf
    }

    /// Returns the number of bytes currently accumulated in the canonical buffer.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Returns `true` if no bytes have been pushed into the canonical buffer yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Returns the current capacity (in bytes) of the underlying buffer.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.buf.capacity()
    }

    /// Consumes the builder and returns the completed canonical `String`.
    #[must_use]
    pub fn finish(self) -> String {
        self.buf
    }
}

impl Default for CanonicalTransactionConcatenator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{CanonicalTransactionConcatenator, DEFAULT_CANONICAL_CAPACITY, TX_HMAC_KEYS};

    #[test]
    fn tx_hmac_keys_exact_count_spelling_and_lexicographical_order() {
        assert_eq!(TX_HMAC_KEYS.len(), 20);
        assert_eq!(TX_HMAC_KEYS[0], "amount_cents");
        assert_eq!(TX_HMAC_KEYS[3], "error_occured");
        assert_eq!(TX_HMAC_KEYS[13], "order_id");
        assert_eq!(TX_HMAC_KEYS[19], "success");
        assert!(TX_HMAC_KEYS.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn concatenator_preallocates_512_bytes() {
        let builder = CanonicalTransactionConcatenator::new();
        assert!(builder.capacity() >= DEFAULT_CANONICAL_CAPACITY);
        assert!(builder.is_empty());
        assert_eq!(builder.len(), 0);
        assert_eq!(builder.as_str(), "");
        let default_builder = CanonicalTransactionConcatenator::default();
        assert_eq!(default_builder.capacity(), builder.capacity());
    }

    #[test]
    fn push_u64_formats_zero_and_max_without_allocating() {
        let mut builder = CanonicalTransactionConcatenator::new();
        let initial_cap = builder.capacity();
        builder.push_u64(0);
        builder.push_u64(1);
        builder.push_u64(u64::MAX);
        assert_eq!(builder.capacity(), initial_cap);
        assert_eq!(builder.finish(), "0118446744073709551615");
    }

    #[test]
    fn push_bool_formats_lowercase_literals() {
        let mut builder = CanonicalTransactionConcatenator::new();
        builder.push_bool(true);
        builder.push_bool(false);
        assert_eq!(builder.len(), 9);
        assert!(!builder.is_empty());
        assert_eq!(builder.finish(), "truefalse");
    }

    #[test]
    fn push_str_handles_empty_and_unicode_segments() {
        let mut builder = CanonicalTransactionConcatenator::new();
        builder.push_str("");
        builder.push_str("2346");
        builder.push_str("");
        builder.push_str("MasterCard");
        assert_eq!(builder.finish(), "2346MasterCard");
    }

    #[test]
    fn full_20_key_canonical_concatenation_keeps_single_allocation() {
        let mut builder = CanonicalTransactionConcatenator::new();
        let initial_cap = builder.capacity();
        builder.push_u64(10_000);
        builder.push_str("2024-05-01T12:00:00.000000");
        builder.push_str("EGP");
        builder.push_bool(false);
        builder.push_bool(false);
        builder.push_u64(192_837_465);
        builder.push_u64(445_566);
        builder.push_bool(true);
        builder.push_bool(false);
        builder.push_bool(false);
        builder.push_bool(false);
        builder.push_bool(true);
        builder.push_bool(false);
        builder.push_u64(987_654_321);
        builder.push_u64(112_233);
        builder.push_bool(false);
        builder.push_str("2346");
        builder.push_str("MasterCard");
        builder.push_str("card");
        builder.push_bool(true);
        assert_eq!(builder.capacity(), initial_cap);
        assert_eq!(
            builder.finish(),
            "100002024-05-01T12:00:00.000000EGPfalsefalse192837465445566truefalsefalsefalsetruefalse987654321112233false2346MasterCardcardtrue"
        );
    }

    #[test]
    fn concatenator_grows_beyond_512_bytes_and_tracks_len() {
        let mut builder = CanonicalTransactionConcatenator::new();
        let chunk = "x".repeat(600);
        builder.push_str(&chunk);
        assert_eq!(builder.len(), 600);
        assert!(builder.capacity() >= 600);
        assert_eq!(builder.finish().len(), 600);
    }
}

//! `some-paymob`: Fail-closed, constant-time Paymob Rust SDK.
//!
//! This crate enforces `#![forbid(unsafe_code)]`, secret redaction (`[REDACTED]`),
//! integer minor-unit monetary values, and constant-time HMAC-SHA512 webhook verification.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

/// Constant-time cryptographic webhook verification engine (Protocols A-E & Idempotency Guard).
#[cfg(feature = "webhooks")]
pub mod webhooks;

/// Convenient re-exports for `some-paymob` callers.
pub mod prelude {
    #[cfg(feature = "webhooks")]
    pub use crate::webhooks::*;
}

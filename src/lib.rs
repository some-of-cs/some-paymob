//! `some-paymob`: Fail-closed, constant-time Paymob Rust SDK.
//!
//! This crate enforces `#![forbid(unsafe_code)]`, secret redaction (`[REDACTED]`),
//! integer minor-unit monetary values, and constant-time HMAC-SHA512 webhook verification.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

/// Constant-time cryptographic webhook verification engine (Protocols A-E & Idempotency Guard).
#[cfg(feature = "webhooks")]
pub mod webhooks;

/// Crate-root re-exports of the core Paymob webhook engine, event, error, and result types.
#[cfg(feature = "webhooks")]
pub use webhooks::{PaymobWebhookEngine, WebhookError, WebhookEvent, WebhookResult};

/// Convenient re-exports for `some-paymob` callers.
pub mod prelude {
    /// Re-exports all public webhook verification types, traits, and helpers.
    #[cfg(feature = "webhooks")]
    pub use crate::webhooks::*;
}

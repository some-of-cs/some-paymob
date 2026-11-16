#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]
#![cfg_attr(docsrs, feature(doc_cfg))]
//! `some-paymob` — Idiomatic, memory-safe, zero-data-race Rust microkernel SDK
//! for the Paymob payment gateway across MENA & Pakistan.
//!
//! This crate enforces `#![forbid(unsafe_code)]`, secret redaction (`[REDACTED]`),
//! integer minor-unit monetary values, and constant-time HMAC-SHA512 webhook verification.

pub mod core;
pub mod prelude;

/// Constant-time cryptographic webhook verification engine (Protocols A-E & Idempotency Guard).
#[cfg(feature = "webhooks")]
pub mod webhooks;

/// Crate-root re-exports of the core Paymob webhook engine, event, error, and result types.
#[cfg(feature = "webhooks")]
pub use webhooks::{PaymobWebhookEngine, WebhookError, WebhookEvent, WebhookResult};

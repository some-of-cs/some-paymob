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

/// Paymob resource services for payment lifecycle management, inquiries, QuickLinks, and splits.
#[cfg(any(
    feature = "manage",
    feature = "inquiries",
    feature = "quicklinks",
    feature = "splits"
))]
pub mod resources;

/// Constant-time cryptographic webhook verification engine (Protocols A-E & Idempotency Guard).
#[cfg(feature = "webhooks")]
pub mod webhooks;

/// Crate-root re-exports of the core Paymob client, configuration, region, error, and money types.
pub use crate::core::client::PaymobClient;
pub use crate::core::config::{ClientConfig, ClientConfigBuilder};
pub use crate::core::error::PaymobError;
pub use crate::core::region::PaymobRegion;
pub use crate::core::types::{Currency, MinorUnitAmount};

/// Crate-root re-exports of the core Paymob webhook engine, event, error, and result types.
#[cfg(feature = "webhooks")]
pub use webhooks::{PaymobWebhookEngine, WebhookError, WebhookEvent, WebhookResult};

/// Crate-root re-export of the payment lifecycle management service (`refund`, `void`, `capture`).
#[cfg(feature = "manage")]
pub use resources::manage::ManageService;

/// Crate-root re-export of the transaction, order, and saved card token inquiry service.
#[cfg(feature = "inquiries")]
pub use resources::inquiries::InquiriesService;

/// Crate-root re-export of the QuickLinks payment links service (`create`, `cancel`).
#[cfg(feature = "quicklinks")]
pub use resources::quicklinks::QuickLinksService;

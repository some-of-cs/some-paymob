#![forbid(unsafe_code)]
//! Saved-card tokenization (CIT/MIT) and headless payment execution (`US-4.1.0`).
//!
//! Pre-scaffolded module index for `feat/module-4-saved-cards-subscriptions`.

/// Unit 4.1.2: CIT token config, MIT charge params, and `use_cvc_with_moto` validation guard.
pub mod cit_mit;
/// Unit 4.1.3: [`SavedCardsService`] executing `POST /api/acceptance/payments/pay`.
pub mod service;
/// Unit 4.1.1: Polymorphic `PaymentSource` enum with `[REDACTED]` formatting.
pub mod sources;

pub use cit_mit::{CitCardTokenConfig, MitChargeParams, validate_use_cvc_with_moto};
pub use service::{
    ACCEPT_PAY_PATH, HeadlessPayResponse, KioskPayParams, MitPayParams, RawPayParams,
    SavedCardsService, WalletPayParams,
};
pub use sources::PaymentSource;

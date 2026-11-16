#![forbid(unsafe_code)]
//! Resource-domain services for `some-paymob`.
//!
//! Pre-scaffolded module index for Module 4 (`saved_cards` and `subscriptions`).

/// Saved-card tokenization (CIT/MIT) and headless payment execution (`US-4.1.0`).
#[cfg(feature = "saved-cards")]
pub mod saved_cards;

/// Subscription plans CRUD, subscription lifecycle, card vault, and history (`US-4.2.0`, `US-4.3.0`).
#[cfg(feature = "subscriptions")]
pub mod subscriptions;

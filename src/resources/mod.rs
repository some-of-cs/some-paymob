#![forbid(unsafe_code)]
//! Paymob API resource modules and checkout builders.

#[cfg(feature = "intentions")]
pub mod checkout;
#[cfg(feature = "intentions")]
pub mod intentions;
#[cfg(feature = "legacy-v2")]
pub mod legacy;

/// Saved-card tokenization (CIT/MIT) and headless payment execution (`US-4.1.0`).
#[cfg(feature = "saved-cards")]
pub mod saved_cards;

/// Subscription plans CRUD, subscription lifecycle, card vault, and history (`US-4.2.0`, `US-4.3.0`).
#[cfg(feature = "subscriptions")]
pub mod subscriptions;

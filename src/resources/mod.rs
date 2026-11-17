#![forbid(unsafe_code)]
//! Paymob API resource modules, checkout builders, payment lifecycle management, inquiries, QuickLinks, splits, saved cards, and subscriptions.

#[cfg(feature = "intentions")]
pub mod checkout;
#[cfg(feature = "inquiries")]
pub mod inquiries;
#[cfg(feature = "intentions")]
pub mod intentions;
#[cfg(feature = "legacy-v2")]
pub mod legacy;
#[cfg(feature = "manage")]
pub mod manage;
#[cfg(feature = "quicklinks")]
pub mod quicklinks;
#[cfg(feature = "saved-cards")]
pub mod saved_cards;
#[cfg(feature = "splits")]
pub mod splits;
#[cfg(feature = "subscriptions")]
pub mod subscriptions;
#[cfg(feature = "onboarding")]
pub mod onboarding;

#![forbid(unsafe_code)]
//! Paymob API resource modules, checkout builders, payment lifecycle management, inquiries, QuickLinks, and splits.

#[cfg(feature = "intentions")]
pub mod checkout;
#[cfg(feature = "intentions")]
pub mod intentions;
#[cfg(feature = "legacy-v2")]
pub mod legacy;
#[cfg(feature = "manage")]
pub mod manage;
#[cfg(feature = "inquiries")]
pub mod inquiries;
#[cfg(feature = "quicklinks")]
pub mod quicklinks;
#[cfg(feature = "splits")]
pub mod splits;

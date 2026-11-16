#![forbid(unsafe_code)]
//! Paymob API resource modules and checkout builders.

#[cfg(feature = "intentions")]
pub mod checkout;
#[cfg(feature = "intentions")]
pub mod intentions;
#[cfg(feature = "legacy-v2")]
pub mod legacy;

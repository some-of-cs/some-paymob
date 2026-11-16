#![forbid(unsafe_code)]
//! Paymob resource services for payment lifecycle management, inquiries, QuickLinks, and splits.

#[cfg(feature = "manage")]
pub mod manage;

#[cfg(feature = "inquiries")]
pub mod inquiries;

#[cfg(feature = "quicklinks")]
pub mod quicklinks;

#[cfg(feature = "splits")]
pub mod splits;

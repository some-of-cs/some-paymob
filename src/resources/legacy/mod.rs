#![forbid(unsafe_code)]
//! Opt-in Legacy Accept v2 3-step checkout flow (`auth_token` -> `order` -> `payment_key` -> `iframe`).

pub mod orders;
pub mod payment_keys;
pub mod service;

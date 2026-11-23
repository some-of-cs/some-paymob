#![forbid(unsafe_code)]
//! Optional [`some_payment_core::PaymentProvider`] adapter for Paymob (`US-9.2.0` Unit 3).
//!
//! Wires the seven `src/alignment/*` primitives into a single northbound adapter:
//! - [`crate::adapter::paymob_provider::PaymobCredentials`] wraps Paymob secret material
//!   in redacted [`secrecy::SecretString`] values.
//! - [`crate::adapter::paymob_provider::PaymobProviderConfig`] holds regional routing,
//!   integration routing (`auth_integration_id` fail-closed Manual capture guard),
//!   redacted credentials, and optional offline `wiremock` overrides.
//! - [`crate::adapter::paymob_provider::PaymobProvider`] implements
//!   [`some_payment_core::PaymentProvider`] across Intention creation, Unified Checkout,
//!   transaction inquiry, capture, void, refund, and triple-HMAC callback dispatch.
//! - [`crate::adapter::paymob_provider::map_synthesized_status`] maps deterministic
//!   Paymob boolean-flag status synthesis into [`some_payment_core::PaymentStatus`].
//!
//! # Example
//!
//! ```rust
//! use some_payment_core::{PaymentCapabilities, PaymentProvider};
//! use some_paymob::adapter::paymob_provider::{
//!     PaymobCredentials, PaymobProvider, PaymobProviderConfig,
//! };
//! use some_paymob::alignment::integration_validation::IntegrationRoutingConfig;
//! use some_paymob::alignment::region_checkout::PaymobRegion;
//!
//! let routing = IntegrationRoutingConfig::new(vec![1001]).with_auth_integration_id(2002);
//! let credentials = PaymobCredentials::new(
//!     "egy_sk_test_example",
//!     "api_key_example",
//!     "hmac_secret_example",
//!     "egy_pk_test_example",
//! );
//! let config = PaymobProviderConfig::new(PaymobRegion::Egypt, routing, credentials);
//! let provider = PaymobProvider::new(config).expect("valid config");
//! assert_eq!(provider.id().as_str(), "paymob");
//! assert!(
//!     !provider
//!         .capabilities()
//!         .contains(PaymentCapabilities::NATIVE_MUTATION_IDEMPOTENCY)
//! );
//! assert!(
//!     provider
//!         .capabilities()
//!         .contains(PaymentCapabilities::AUTH_CAPTURE)
//! );
//! ```

mod config;
mod errors;
mod provider;
mod webhook;
mod wire;

#[cfg(test)]
mod tests;

pub use config::{PaymobCredentials, PaymobProviderConfig};
pub use errors::map_synthesized_status;
pub use provider::PaymobProvider;

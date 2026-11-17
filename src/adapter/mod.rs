#![forbid(unsafe_code)]
//! Northbound `some-payments` cross-gateway unified adapter traits and `PaymobExt` escape hatch (`US-8.1.0`).
//!
//! Pre-scaffolded module index for `feat/module-8-adapter-test-utils`.
//! Each submodule is owned by an independent implementation unit.

/// Unit 8.1.3: `PaymobExt` and `ProviderExt::Paymob(PaymobExt)` escape hatch.
pub mod ext;
/// Unit 8.1.2: `PaymobClient` implementations of `PaymentProvider`, `WebhookVerifier`, `SubscriptionProvider`, and `PayoutProvider`.
pub mod some_payments;
/// Unit 8.1.1: Unified gateway trait definitions and normalized request/response DTOs.
pub mod traits;

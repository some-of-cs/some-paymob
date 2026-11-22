#![forbid(unsafe_code)]
//! `some-payment` orchestrator alignment primitives for `some-paymob`.
//!
//! Pre-scaffolded module index for `feat/module-9-some-payment-alignment`.
//! Each submodule is owned by an independent implementation unit across
//! `US-9.1.0` (`unit-1..5`) and `US-9.2.0` (`unit-1..2`).

/// US-9.2.0 Unit 2: Shared `notification_url` dispatcher routing Transaction, `TOKEN`,
/// and Subscription payloads into normalized callback events.
#[cfg(feature = "webhooks")]
pub mod callback_dispatcher;
/// US-9.1.0 Unit 2: Single-flight `AuthTokenManager` (60-min TTL, 50-min proactive refresh,
/// single 401 retry) and `Token <sk>` scheme router.
pub mod dual_auth;
/// US-9.1.0 Unit 3: `auth_integration_id` Manual-capture guard, named aliases,
/// conditional `items`/`billing_data.phone_number` validation, and `special_reference` mapping.
pub mod integration_validation;
/// US-9.1.0 Unit 1: `PaymobRegion` host router (EG/KSA/UAE/OM/PK/Custom) and
/// Unified Checkout / Pixel URL builders.
pub mod region_checkout;
/// US-9.1.0 Unit 5: Deterministic 9-step boolean-flag status synthesizer and
/// child-vs-parent transaction correlation.
pub mod status_synthesizer;
/// US-9.2.0 Unit 1: Constant-time HMAC-SHA512 verifiers for Transaction (20-key POST/GET),
/// Card `TOKEN` (8-key), and Subscription (body `hmac`).
#[cfg(feature = "webhooks")]
pub mod triple_hmac;
/// US-9.1.0 Unit 4: Numeric `transaction_id` fallback resolution via `transaction_inquiry`
/// and full-refund remaining amount (`amount_cents - refunded_amount_cents`) lookup.
pub mod tx_correlation;

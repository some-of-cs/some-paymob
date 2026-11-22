#![forbid(unsafe_code)]
//! Northbound `some-payment` cross-gateway unified adapter traits and `PaymobExt` escape hatch.
//!
//! Pre-scaffolded module index for `feat/module-9-some-payment-alignment`.
//! Each submodule is owned by an independent implementation unit, with flat
//! re-exports provided at the `adapter` module root for ergonomic imports.

/// US-9.2.0 Unit 4: Offline `wiremock` conformance suite for `PaymobProvider`.
#[cfg(all(test, feature = "some-payment-adapter"))]
mod conformance_tests;
/// Unit 9.2.1: Object-safe (`dyn`-compatible) capability traits and smart reversal helpers for `some-payment`.
pub mod dyn_traits;
/// Unit 8.1.3: `PaymobExt` and `ProviderExt::Paymob(PaymobExt)` escape hatch.
pub mod ext;
/// US-9.2.0 Unit 3: Optional `some_payment_core::PaymentProvider` adapter for Paymob.
#[cfg(feature = "some-payment-adapter")]
pub mod paymob_provider;
/// Unit 9.2.2: Expanded 7-issuer Paymob Send payout, bulk disbursement, and inquiry adapter.
pub mod payout_adapter;
/// Unit 8.1.2: `PaymobClient` implementations of `PaymentProvider`, `WebhookVerifier`, `SubscriptionProvider`, and `PayoutProvider`.
pub mod some_payments;
/// Unit 8.1.1: Unified gateway trait definitions and normalized request/response DTOs.
pub mod traits;
/// Unit 9.2.2: Protocol A–E (including Protocol B GET) webhook verifier and rich normalized event adapter.
pub mod webhook_adapter;

pub use ext::{HeadlessExecutionOption, PaymobExt, ProviderExt};
pub use some_payments::{build_intention_params, normalize_webhook_event};
pub use traits::{
    PaymentProvider, PayoutProvider, SubscriptionProvider, UnifiedCaptureReceipt,
    UnifiedCaptureRequest, UnifiedPaymentSession, UnifiedPaymentSessionRequest,
    UnifiedPayoutReceipt, UnifiedPayoutRequest, UnifiedRefundReceipt, UnifiedRefundRequest,
    UnifiedSavedMethodChargeReceipt, UnifiedSavedMethodChargeRequest,
    UnifiedSubscriptionRefundReceipt, UnifiedSubscriptionRefundRequest, UnifiedVoidReceipt,
    UnifiedVoidRequest, UnifiedWebhookInput, UnifiedWebhookKind, UnifiedWebhookOutcome,
    WebhookVerifier,
};

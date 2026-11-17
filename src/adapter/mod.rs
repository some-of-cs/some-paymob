#![forbid(unsafe_code)]
//! Northbound `some-payments` cross-gateway unified adapter traits and `PaymobExt` escape hatch (`US-8.1.0`).
//!
//! Pre-scaffolded module index for `feat/module-8-adapter-test-utils`.
//! Each submodule is owned by an independent implementation unit, with flat
//! re-exports provided at the `adapter` module root for ergonomic imports.

/// Unit 8.1.3: `PaymobExt` and `ProviderExt::Paymob(PaymobExt)` escape hatch.
pub mod ext;
/// Unit 8.1.2: `PaymobClient` implementations of `PaymentProvider`, `WebhookVerifier`, `SubscriptionProvider`, and `PayoutProvider`.
pub mod some_payments;
/// Unit 8.1.1: Unified gateway trait definitions and normalized request/response DTOs.
pub mod traits;

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

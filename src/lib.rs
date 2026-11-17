#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]
#![cfg_attr(docsrs, feature(doc_cfg))]
//! `some-paymob` — Idiomatic, memory-safe, zero-data-race Rust microkernel SDK
//! for the Paymob payment gateway across MENA & Pakistan.
//!
//! This crate enforces `#![forbid(unsafe_code)]`, secret redaction (`[REDACTED]`),
//! integer minor-unit monetary values, and constant-time HMAC-SHA512 webhook verification.

pub mod core;
pub mod prelude;

/// Paymob API resource modules, checkout builders, payment lifecycle management, inquiries, QuickLinks, splits, saved cards, subscriptions, payouts, and onboarding.
#[cfg(any(
    feature = "intentions",
    feature = "legacy-v2",
    feature = "manage",
    feature = "inquiries",
    feature = "quicklinks",
    feature = "splits",
    feature = "saved-cards",
    feature = "subscriptions",
    feature = "payouts",
    feature = "onboarding"
))]
pub mod resources;

/// Constant-time cryptographic webhook verification engine (Protocols A–E & Idempotency Guard).
#[cfg(feature = "webhooks")]
pub mod webhooks;

/// Northbound `some-payments` cross-gateway unified adapter traits and `PaymobExt` escape hatch.
#[cfg(feature = "some-payments-adapter")]
pub mod adapter;

/// Deterministic offline test vectors, multi-regime `wiremock` server, and sandbox constraint guards.
#[cfg(feature = "test-utils")]
pub mod test_utils;

/// Crate-root re-exports of the core Paymob client, configuration, region, error, and money types.
pub use crate::core::client::PaymobClient;
pub use crate::core::config::{ClientConfig, ClientConfigBuilder};
pub use crate::core::credentials::{resolve_secret_or_env, resolve_secret_or_env_with};
pub use crate::core::error::PaymobError;
pub use crate::core::region::PaymobRegion;
pub use crate::core::types::{Currency, MinorUnitAmount};

/// Crate-root re-exports of the v1 Payment Intentions and Checkout services.
#[cfg(feature = "intentions")]
pub use crate::resources::checkout::{
    AffordabilityWidgetConfig, AffordabilityWidgetConfigBuilder, CheckoutService, PixelConfig,
    PixelConfigBuilder, PixelPaymentMethod,
};
#[cfg(feature = "intentions")]
pub use crate::resources::intentions::{
    BillingData, BillingDataBuilder, CreateIntentionParams, CreateIntentionParamsBuilder,
    IntentionCustomer, IntentionItem, IntentionResponse, IntentionsService, PaymentMethodInput,
    UpdateIntentionParams, UpdateIntentionParamsBuilder,
};

/// Crate-root re-exports of the opt-in Legacy Accept v2 3-step checkout service and models.
#[cfg(feature = "legacy-v2")]
pub use crate::resources::legacy::{
    CreateLegacyOrderParams, CreatePaymentKeyParams, LegacyBillingData, LegacyCheckoutParams,
    LegacyCheckoutSession, LegacyOrder, LegacyOrderItem, LegacyV2Service, PaymentKeyResponse,
};

/// Crate-root re-exports of the core Paymob webhook engine, event, error, and result types.
#[cfg(feature = "webhooks")]
pub use webhooks::{PaymobWebhookEngine, WebhookError, WebhookEvent, WebhookResult};

/// Crate-root re-export of the payment lifecycle management service (`refund`, `void`, `capture`).
#[cfg(feature = "manage")]
pub use resources::manage::ManageService;

/// Crate-root re-export of the transaction, order, and saved card token inquiry service.
#[cfg(feature = "inquiries")]
pub use resources::inquiries::InquiriesService;

/// Crate-root re-export of the QuickLinks payment links service (`create`, `cancel`).
#[cfg(feature = "quicklinks")]
pub use resources::quicklinks::QuickLinksService;

/// Crate-root re-export of saved-card tokenization and headless payment services.
#[cfg(feature = "saved-cards")]
pub use resources::saved_cards::SavedCardsService;

/// Crate-root re-export of subscription plan and recurring billing services.
#[cfg(feature = "subscriptions")]
pub use resources::subscriptions::SubscriptionsService;

/// Crate-root re-export of the Paymob Send Payouts & Disbursement service.
#[cfg(feature = "payouts")]
pub use resources::payouts::PayoutsService;

/// Crate-root re-exports of Partner Merchant Onboarding services and scoped client.
#[cfg(feature = "onboarding")]
pub use resources::onboarding::{
    MerchantScopedClient, OnboardingService, PartnerAuthService, PartnerFlowService,
};

/// Crate-root re-exports of Partner Merchant Onboarding authentication models.
#[cfg(feature = "onboarding")]
pub use resources::onboarding::{
    CreatePartnerApiKeyParams, PartnerApiKeyResponse, PartnerAuthTokenResponse, PartnerHmacBody,
    PartnerHmacEnvelope, PartnerLoginCredentials,
};

/// Crate-root re-exports of Partner Merchant Onboarding flow and inquiry models.
#[cfg(feature = "onboarding")]
pub use resources::onboarding::{
    OnboardingFlowSchema, OnboardingSchemaField, OnboardingSchemaQuery, OnboardingSchemaStep,
    PartnerMerchantInquiryResponse, RegisterMerchantParams, RegisteredMerchantResponse,
    SubmitOnboardingStepParams, SubmitOnboardingStepResponse,
};

/// Crate-root re-export of the sub-merchant scoped Inquiries handle.
#[cfg(all(feature = "onboarding", feature = "inquiries"))]
pub use resources::onboarding::ScopedInquiries;

/// Crate-root re-export of the sub-merchant scoped Payment Intentions handle.
#[cfg(all(feature = "onboarding", feature = "intentions"))]
pub use resources::onboarding::ScopedIntentions;

/// Crate-root re-export of the sub-merchant scoped Payment Lifecycle Management handle.
#[cfg(all(feature = "onboarding", feature = "manage"))]
pub use resources::onboarding::ScopedManage;

/// Crate-root re-exports of the northbound `some-payments` unified adapter traits and `PaymobExt`.
#[cfg(feature = "some-payments-adapter")]
pub use adapter::{
    HeadlessExecutionOption, PaymentProvider, PaymobExt, PayoutProvider, ProviderExt,
    SubscriptionProvider, UnifiedCaptureReceipt, UnifiedCaptureRequest, UnifiedPaymentSession,
    UnifiedPaymentSessionRequest, UnifiedPayoutReceipt, UnifiedPayoutRequest, UnifiedRefundReceipt,
    UnifiedRefundRequest, UnifiedSavedMethodChargeReceipt, UnifiedSavedMethodChargeRequest,
    UnifiedSubscriptionRefundReceipt, UnifiedSubscriptionRefundRequest, UnifiedVoidReceipt,
    UnifiedVoidRequest, UnifiedWebhookInput, UnifiedWebhookKind, UnifiedWebhookOutcome,
    WebhookVerifier, build_intention_params, normalize_webhook_event,
};

/// Crate-root re-exports of the deterministic test harness, official vectors, and sandbox guards.
#[cfg(feature = "test-utils")]
pub use test_utils::{
    MockHost, OfficialWebhookVector, PaymobMockServer, SandboxCheckRequest, SandboxConstraintError,
    SandboxGuard, SandboxPaymentChannel, SandboxReport, SandboxWarning, WebhookVectorProtocol,
    all_official_vectors,
};

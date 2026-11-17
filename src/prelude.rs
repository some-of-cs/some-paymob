#![forbid(unsafe_code)]
//! Convenience prelude re-exporting the core `some-paymob` primitives (`US-1.3.0/unit-4`).
//!
//! Import all essential client, configuration, credential, region, auth,
//! HTTP transport, money, error, pagination, intentions, checkout, legacy-v2,
//! management, inquiries, quicklinks, saved-cards, subscriptions, payouts,
//! onboarding, adapter, test-utils, and webhook types with a single wildcard import:
//!
//! ```
//! use some_paymob::prelude::*;
//!
//! let query = PageQuery::new(1);
//! assert_eq!(query.to_query_string(), "?page=1");
//! ```

pub use crate::core::auth::AuthManager;
pub use crate::core::auth::cache::CachedToken;
pub use crate::core::auth::strategy::AuthStrategy;
pub use crate::core::client::PaymobClient;
pub use crate::core::config::{ClientConfig, ClientConfigBuilder};
pub use crate::core::credentials::{
    ApiKey, EnvironmentMode, HmacSecret, PartnerCredentials, PayoutsCredentials, PublicKey,
    SecretKey, resolve_secret_or_env, resolve_secret_or_env_with,
};
pub use crate::core::error::PaymobError;
pub use crate::core::http::{
    HttpClient, HttpClientConfig, HttpError, HttpRequest, HttpResponse, RetryPolicy,
};
pub use crate::core::pagination::{PageQuery, PaginatedResponse};
pub use crate::core::region::{PaymobRegion, RegionalEndpoints};
pub use crate::core::types::{Currency, MinorUnitAmount, validate_prefixed_id};

/// Re-exports all public Unified Checkout, Pixel JS, and Affordability Widget types.
#[cfg(feature = "intentions")]
pub use crate::resources::checkout::{
    AffordabilityWidgetConfig, AffordabilityWidgetConfigBuilder, ApplePaySettings, CheckoutService,
    GooglePaySettings, PixelConfig, PixelConfigBuilder, PixelPaymentMethod,
};

/// Re-exports all public v1 Payment Intention request, response, and service types.
#[cfg(feature = "intentions")]
pub use crate::resources::intentions::{
    BillingData, BillingDataBuilder, ConfiguredPaymentMethod, CreateIntentionParams,
    CreateIntentionParamsBuilder, IntentionCustomer, IntentionDetail, IntentionItem,
    IntentionPaymentKey, IntentionResponse, IntentionsService, PaymentMethodInput,
    UpdateIntentionParams, UpdateIntentionParamsBuilder,
};

/// Re-exports all public Legacy Accept v2 3-step checkout types and helpers.
#[cfg(feature = "legacy-v2")]
pub use crate::resources::legacy::{
    AuthenticatedLegacyOrderRequest, CreateLegacyOrderParams, CreatePaymentKeyParams,
    DEFAULT_PAYMENT_KEY_EXPIRATION_SECS, LEGACY_ORDERS_PATH, LEGACY_PAYMENT_KEYS_PATH,
    LegacyBillingData, LegacyCheckoutParams, LegacyCheckoutSession, LegacyOrder, LegacyOrderItem,
    LegacyV2Service, PaymentKeyResponse, create_legacy_order, create_legacy_payment_key,
};

/// Re-exports all public webhook verification types, traits, and helpers.
#[cfg(feature = "webhooks")]
pub use crate::webhooks::*;

/// Re-exports payment lifecycle management service (`refund`, `void`, `capture`).
#[cfg(feature = "manage")]
pub use crate::resources::manage::ManageService;

/// Re-exports transaction, order, and saved card token inquiry service.
#[cfg(feature = "inquiries")]
pub use crate::resources::inquiries::InquiriesService;

/// Re-exports QuickLinks payment links service.
#[cfg(feature = "quicklinks")]
pub use crate::resources::quicklinks::QuickLinksService;

/// Re-exports all public saved-card tokenization and headless payment types.
#[cfg(feature = "saved-cards")]
pub use crate::resources::saved_cards::*;

/// Re-exports all public subscription plan, lifecycle, card vault, and history types.
#[cfg(feature = "subscriptions")]
pub use crate::resources::subscriptions::*;

/// Re-exports all public Paymob Send Payouts, Cashin, Inquiries, Budget, and Topup types.
#[cfg(feature = "payouts")]
pub use crate::resources::payouts::{
    AcceptBalanceTopupParams, AmanCashingDetails, BankCardCashinParams, BankTransactionType,
    BankTransferTopupParams, BulkDisbursementItem, BulkDisbursementParams,
    BulkDisbursementResponse, CancelAmanParams, DisburseIssuer, DisbursementResponse,
    EgyptianPostCashinParams, InstantBankCashinParams, MAX_BULK_DISBURSEMENT_ITEMS,
    MAX_INQUIRY_IDS, MAX_TOPUP_PROOF_BYTES, MobileWalletCashinParams, PayoutsAuthService,
    PayoutsCashinService, PayoutsInquiriesService, PayoutsService, PayoutsTokenResponse,
    PayoutsTopupsService, ReferenceInquiryParams, TopupInquiryParams, TopupInquiryResponse,
    TopupRecord, TransactionInquiryParams, TransactionInquiryResponse, UserBudgetResponse,
};

/// Re-exports Partner Merchant Onboarding services and scoped client.
#[cfg(feature = "onboarding")]
pub use crate::resources::onboarding::{
    MerchantScopedClient, OnboardingService, PartnerAuthService, PartnerFlowService,
};

/// Re-exports Partner Merchant Onboarding authentication models.
#[cfg(feature = "onboarding")]
pub use crate::resources::onboarding::{
    CreatePartnerApiKeyParams, PartnerApiKeyResponse, PartnerAuthTokenResponse, PartnerHmacBody,
    PartnerHmacEnvelope, PartnerLoginCredentials,
};

/// Re-exports Partner Merchant Onboarding flow and inquiry models.
#[cfg(feature = "onboarding")]
pub use crate::resources::onboarding::{
    OnboardingFlowSchema, OnboardingSchemaField, OnboardingSchemaQuery, OnboardingSchemaStep,
    PartnerMerchantInquiryResponse, RegisterMerchantParams, RegisteredMerchantResponse,
    SubmitOnboardingStepParams, SubmitOnboardingStepResponse,
};

/// Re-exports the sub-merchant scoped Inquiries handle.
#[cfg(all(feature = "onboarding", feature = "inquiries"))]
pub use crate::resources::onboarding::ScopedInquiries;

/// Re-exports the sub-merchant scoped Payment Intentions handle.
#[cfg(all(feature = "onboarding", feature = "intentions"))]
pub use crate::resources::onboarding::ScopedIntentions;

/// Re-exports the sub-merchant scoped Payment Lifecycle Management handle.
#[cfg(all(feature = "onboarding", feature = "manage"))]
pub use crate::resources::onboarding::ScopedManage;

/// Re-exports all public `some-payments` unified adapter traits, DTOs, and `PaymobExt` types.
#[cfg(feature = "some-payments-adapter")]
pub use crate::adapter::{
    HeadlessExecutionOption, PaymentProvider, PaymobExt, PayoutProvider, ProviderExt,
    SubscriptionProvider, UnifiedCaptureReceipt, UnifiedCaptureRequest, UnifiedPaymentSession,
    UnifiedPaymentSessionRequest, UnifiedPayoutReceipt, UnifiedPayoutRequest,
    UnifiedRefundReceipt, UnifiedRefundRequest, UnifiedSavedMethodChargeReceipt,
    UnifiedSavedMethodChargeRequest, UnifiedSubscriptionRefundReceipt,
    UnifiedSubscriptionRefundRequest, UnifiedVoidReceipt, UnifiedVoidRequest,
    UnifiedWebhookInput, UnifiedWebhookKind, UnifiedWebhookOutcome, WebhookVerifier,
    build_intention_params, normalize_webhook_event,
};

/// Re-exports all public deterministic test vectors, `PaymobMockServer`, and sandbox constraint guards.
#[cfg(feature = "test-utils")]
pub use crate::test_utils::{
    JsonEndpointMockConfig, JwtExpiryMockConfig, MockHost, OfficialWebhookVector,
    PaymobMockServer, PayoutsRateLimitMockConfig, SANDBOX_CREDENTIAL_MAX_AGE_DAYS,
    SANDBOX_CREDENTIAL_WARN_AGE_DAYS, SAMPLE_HMAC_SECRET, SandboxCheckRequest,
    SandboxConstraintError, SandboxGuard, SandboxPaymentChannel, SandboxReport, SandboxWarning,
    SignedSubscriptionRequest, SignedTransactionRequest, SignedWebhookToolPayload,
    WebhookVectorProtocol, all_official_vectors, card_token_15978654,
    generate_signed_subscription_post, generate_signed_transaction_post, sign_hmac_sha512,
    subscription_1264, transaction_processed_192036465, transaction_response_316004,
};

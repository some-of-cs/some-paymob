#![forbid(unsafe_code)]
//! Deterministic offline test vectors, multi-regime `wiremock` server, and sandbox constraint guards (`US-8.2.0`).
//!
//! Pre-scaffolded module index for `feat/module-8-adapter-test-utils`.
//! Each submodule is owned by an independent implementation unit.

/// Unit 8.2.2: Stateful `PaymobMockServer` simulating Accept Acquiring & Payouts hosts.
pub mod mock_server;
/// Unit 8.2.3: Sandbox diagnostic helpers for 30-day credential age, Kiosk/BNPL warnings, and Webhook Testing Tool payloads.
pub mod sandbox;
/// Unit 8.2.1: Verbatim official Paymob JSON payloads and HMAC-SHA512 test vectors.
pub mod vectors;

pub use mock_server::{MockHost, PaymobMockServer};
pub use sandbox::{
    SANDBOX_CREDENTIAL_MAX_AGE_DAYS, SANDBOX_CREDENTIAL_WARN_AGE_DAYS, SandboxCheckRequest,
    SandboxConstraintError, SandboxGuard, SandboxPaymentChannel, SandboxReport, SandboxWarning,
    SignedWebhookToolPayload, generate_signed_subscription_post, generate_signed_transaction_post,
    sign_hmac_sha512,
};
pub use vectors::{
    OFFICIAL_CARD_TOKEN_15978654_CONCAT, OFFICIAL_CARD_TOKEN_15978654_HMAC,
    OFFICIAL_CARD_TOKEN_15978654_JSON, OFFICIAL_REDIRECT_316004_CONCAT,
    OFFICIAL_REDIRECT_316004_QUERY, OFFICIAL_SUBSCRIPTION_1264_CANONICAL,
    OFFICIAL_SUBSCRIPTION_1264_HMAC, OFFICIAL_SUBSCRIPTION_1264_JSON, OFFICIAL_TX_192036465_CONCAT,
    OFFICIAL_TX_192036465_HMAC, OFFICIAL_TX_192036465_JSON, OfficialWebhookVector,
    SAMPLE_CARD_TOKEN_15978654_HMAC, SAMPLE_HMAC_SECRET, SAMPLE_REDIRECT_316004_HMAC,
    SAMPLE_SUBSCRIPTION_1264_HMAC, SAMPLE_SUBSCRIPTION_1264_JSON, SAMPLE_TX_192036465_HMAC,
    WebhookVectorProtocol, all_official_vectors, card_token_15978654, subscription_1264,
    transaction_processed_192036465, transaction_response_316004,
};

//! Constant-time cryptographic webhook verification engine (Protocols A-E & Idempotency Guard).
//!
//! Pre-scaffolded module index for `feat/module-7-webhooks-engine`.
//! Each submodule is owned by an independent implementation unit, with flat
//! re-exports provided at the `webhooks` module root for ergonomic imports.

/// Unit 7.1.3: Static `TX_HMAC_KEYS` table and `CanonicalTransactionConcatenator`.
pub mod canonical_tx;
/// Unit 7.2.4: `WebhookEvent` enum and `PaymobWebhookEngine::construct_event` auto-dispatcher.
pub mod dispatcher;
/// Unit 7.2.5: `IdempotentWebhookGuard` trait and `InMemoryWebhookDeduplicator`.
pub mod idempotency;
/// Unit 7.1.4: Protocol A - Transaction Processed POST 20-key verifier.
pub mod protocol_a_post;
/// Unit 7.1.5: Protocol B - Transaction Response GET 20-key verifier with `order_id`/`order` fallback.
pub mod protocol_b_get;
/// Unit 7.2.1: Protocol C - Card Token 8-key verifier.
pub mod protocol_c_token;
/// Unit 7.2.2: Protocol D - Subscription Lifecycle 12-trigger verifier.
pub mod protocol_d_subscription;
/// Unit 7.2.3: Protocol E - Payouts Disbursement & Topup callbacks.
pub mod protocol_e_payouts;
/// Unit 7.1.2: Transaction webhook models (`TransactionProcessedEvent`, `TransactionWebhookObj`, `TransactionSourceData`).
pub mod tx_models;
/// Unit 7.1.1: Core `WebhookError` enum and `PaymobWebhookEngine::verify_concatenated_str`.
pub mod verifier;

/// Re-export of the 20-key canonical transaction concatenation builder and key table.
pub use canonical_tx::{CanonicalTransactionConcatenator, TX_HMAC_KEYS};
/// Re-export of the unified verified webhook event enum.
pub use dispatcher::WebhookEvent;
/// Re-export of the default in-memory deduplicator capacity constant.
pub use idempotency::DEFAULT_DEDUPLICATOR_CAPACITY;
/// Re-export of webhook idempotency traits and in-memory deduplicator stores.
pub use idempotency::{
    IdempotentWebhookGuard, InMemoryWebhookDeduplicator, InMemoryWebhookIdempotencyStore,
    WebhookIdempotencyStore,
};
/// Re-export of the Protocol A 20-key canonical string builder.
pub use protocol_a_post::build_protocol_a_canonical_string;
/// Re-export of the Protocol B 20-key canonical string builder.
pub use protocol_b_get::build_protocol_b_canonical_string;
/// Re-export of the Protocol B query parameter trait and verified redirect parameters struct.
pub use protocol_b_get::{QueryParams, TransactionRedirectParams};
/// Re-export of the Protocol C 8-key static HMAC key table.
pub use protocol_c_token::TOKEN_HMAC_KEYS;
/// Re-export of the Protocol C 8-key canonical string builder.
pub use protocol_c_token::build_protocol_c_canonical_string;
/// Re-export of Protocol C card token webhook models and type aliases.
pub use protocol_c_token::{
    CardTokenObj, CardTokenObject, CardTokenWebhook, CardTokenWebhookEvent,
};
/// Re-export of the Protocol D 12-trigger static lookup table.
pub use protocol_d_subscription::KNOWN_SUBSCRIPTION_TRIGGERS;
/// Re-export of the Protocol D canonical subscription message builder.
pub use protocol_d_subscription::canonical_subscription_message;
/// Re-export of Protocol D subscription webhook models and trigger enum.
pub use protocol_d_subscription::{
    SubscriptionClientInfo, SubscriptionData, SubscriptionTriggerType, SubscriptionWebhookEvent,
};
/// Re-export of Protocol E payouts disbursement and top-up callback models.
pub use protocol_e_payouts::{
    DisbursementCallback, DisbursementIssuer, TopupCallback, TopupStatus,
};
/// Re-export of Protocol A transaction webhook models and type aliases.
pub use tx_models::{
    TransactionObject, TransactionOrderRef, TransactionProcessedEvent, TransactionSourceData,
    TransactionWebhook, TransactionWebhookObj,
};
/// Re-export of the core webhook verification engine, error enum, and result alias.
pub use verifier::{PaymobWebhookEngine, WebhookError, WebhookResult};

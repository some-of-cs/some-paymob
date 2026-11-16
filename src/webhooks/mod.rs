//! Constant-time cryptographic webhook verification engine (Protocols A-E & Idempotency Guard).
//!
//! Pre-scaffolded module index for `feat/module-7-webhooks-engine`.
//! Each submodule is owned by an independent implementation unit.

/// Unit 7.1.1: Core `WebhookError` enum and `PaymobWebhookEngine::verify_concatenated_str`.
pub mod verifier;
/// Unit 7.1.2: Transaction webhook models (`TransactionProcessedEvent`, `TransactionWebhookObj`, `TransactionSourceData`).
pub mod tx_models;
/// Unit 7.1.3: Static `TX_HMAC_KEYS` table and `CanonicalTransactionConcatenator`.
pub mod canonical_tx;
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
/// Unit 7.2.4: `WebhookEvent` enum and `PaymobWebhookEngine::construct_event` auto-dispatcher.
pub mod dispatcher;
/// Unit 7.2.5: `IdempotentWebhookGuard` trait and `InMemoryWebhookDeduplicator`.
pub mod idempotency;

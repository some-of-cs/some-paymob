#![forbid(unsafe_code)]
//! Tonic gRPC reference server for `some-paymob` covering all 14 services and Protocols A-E.

use std::sync::Arc;

use some_paymob::webhooks::InMemoryWebhookDeduplicator;
use some_paymob::{PaymobClient, PaymobWebhookEngine};

#[path = "tonic_grpc_server/error.rs"]
pub mod error;
#[path = "tonic_grpc_server/proto.rs"]
pub mod proto;
#[path = "tonic_grpc_server/rpc_core_checkout_legacy_manage.rs"]
pub mod rpc_core_checkout_legacy_manage;
#[path = "tonic_grpc_server/rpc_onboarding_webhooks_unified.rs"]
pub mod rpc_onboarding_webhooks_unified;
#[path = "tonic_grpc_server/rpc_saved_cards_subscriptions_payouts.rs"]
pub mod rpc_saved_cards_subscriptions_payouts;

/// Shared Tonic gRPC service state backed by `PaymobClient` and webhook primitives.
#[derive(Clone)]
pub struct PaymobGrpcService {
    /// Core Paymob SDK client.
    pub client: Arc<PaymobClient>,
    /// Constant-time HMAC webhook verification engine.
    pub webhook_engine: Arc<PaymobWebhookEngine>,
    /// In-memory replay deduplicator for webhook deliveries.
    pub deduplicator: Arc<InMemoryWebhookDeduplicator>,
}

impl PaymobGrpcService {
    /// Creates a new `PaymobGrpcService` from the given client, webhook engine, and deduplicator.
    #[must_use]
    pub fn new(
        client: Arc<PaymobClient>,
        webhook_engine: Arc<PaymobWebhookEngine>,
        deduplicator: Arc<InMemoryWebhookDeduplicator>,
    ) -> Self {
        Self {
            client,
            webhook_engine,
            deduplicator,
        }
    }
}

#[cfg(not(test))]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use some_paymob::{ClientConfig, PaymobRegion};

    let config = ClientConfig::builder()
        .region(PaymobRegion::Egypt)
        .try_secret_key("egy_sk_test_placeholder")?
        .try_public_key("egy_pk_test_placeholder")?
        .try_hmac_secret("0123456789abcdef0123456789abcdef")?
        .build()?;
    let client = Arc::new(PaymobClient::new(config)?);
    let webhook_engine = Arc::new(client.webhook_engine()?);
    let deduplicator = Arc::new(InMemoryWebhookDeduplicator::new());
    let _service = PaymobGrpcService::new(client, webhook_engine, deduplicator);
    Ok(())
}

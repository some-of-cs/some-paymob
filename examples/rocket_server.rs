#![forbid(unsafe_code)]
//! Rocket.rs reference server for `some-paymob` covering all 14 services and Protocols A-E.

use std::sync::Arc;

use rocket::{Build, Rocket};
use some_paymob::{InMemoryWebhookDeduplicator, PaymobClient, PaymobWebhookEngine};

pub mod error;
pub mod routes_core_checkout_legacy_manage;
pub mod routes_onboarding_webhooks_unified;
pub mod routes_saved_cards_subscriptions_payouts;

pub use error::ApiServerError;

/// Shared application state managed by Rocket.
#[derive(Clone)]
pub struct AppState {
    pub client: Arc<PaymobClient>,
    pub webhook_engine: Arc<PaymobWebhookEngine>,
    pub deduplicator: Arc<InMemoryWebhookDeduplicator>,
}

/// Builds the Rocket instance with all 14-service and 5-protocol routes mounted.
pub fn build_rocket(state: AppState) -> Rocket<Build> {
    rocket::build()
        .manage(state)
        .mount("/", routes_core_checkout_legacy_manage::routes())
        .mount("/", routes_saved_cards_subscriptions_payouts::routes())
        .mount("/", routes_onboarding_webhooks_unified::routes())
}

#[cfg(not(test))]
#[rocket::main]
async fn main() -> Result<(), rocket::Error> {
    use some_paymob::{ClientConfig, PaymobRegion};
    let config = ClientConfig::builder()
        .region(PaymobRegion::Egypt)
        .try_secret_key("egy_sk_test_placeholder")
        .expect("valid secret key")
        .try_public_key("egy_pk_test_placeholder")
        .expect("valid public key")
        .try_hmac_secret("0123456789abcdef0123456789abcdef")
        .expect("valid hmac secret")
        .build()
        .expect("valid default config");
    let client = Arc::new(PaymobClient::new(config).expect("valid client"));
    let webhook_engine = Arc::new(client.webhook_engine().expect("valid webhook engine"));
    let deduplicator = Arc::new(InMemoryWebhookDeduplicator::new());
    let state = AppState {
        client,
        webhook_engine,
        deduplicator,
    };
    let _rocket = build_rocket(state).launch().await?;
    Ok(())
}

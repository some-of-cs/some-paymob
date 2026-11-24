#![forbid(unsafe_code)]
//! Rocket.rs reference server for `some-paymob` covering all 14 services and Protocols A-E.

use std::sync::Arc;

use rocket::data::ByteUnit;
use rocket::{Build, Rocket};
use some_paymob::webhooks::InMemoryWebhookDeduplicator;
use some_paymob::{PaymobClient, PaymobWebhookEngine};

#[path = "rocket_server/error.rs"]
pub mod error;
#[path = "rocket_server/routes_core_checkout_legacy_manage.rs"]
pub mod routes_core_checkout_legacy_manage;
#[path = "rocket_server/routes_onboarding_webhooks_unified.rs"]
pub mod routes_onboarding_webhooks_unified;
#[path = "rocket_server/routes_saved_cards_subscriptions_payouts.rs"]
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
    let figment = rocket::Config::figment().merge(("limits.json", ByteUnit::Megabyte(16)));
    rocket::custom(figment)
        .manage(state)
        .mount("/", routes_core_checkout_legacy_manage::routes())
        .mount("/", routes_saved_cards_subscriptions_payouts::routes())
        .mount("/", routes_onboarding_webhooks_unified::routes())
}

#[cfg(not(test))]
#[rocket::main]
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
    let state = AppState {
        client,
        webhook_engine,
        deduplicator,
    };
    let _rocket = build_rocket(state).launch().await?;
    Ok(())
}

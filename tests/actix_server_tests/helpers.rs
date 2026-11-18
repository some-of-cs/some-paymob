#![forbid(unsafe_code)]
//! Shared test harness and mock helpers for `actix_server` integration tests.

use actix_web::{App, web};
use serde_json::{Value, json};
use some_paymob::prelude::*;

use crate::actix_server::{AppState, configure_app};

/// Builds a configured `AppState` pointing all base URLs at the given `PaymobMockServer`.
pub fn build_test_state(mock: &PaymobMockServer) -> web::Data<AppState> {
    let cfg = ClientConfig::builder()
        .region(mock.custom_region())
        .secret_key(
            SecretKey::new("egy_sk_test_0123456789abcdef0123456789abcdef").expect("valid sk"),
        )
        .public_key(PublicKey::new("egy_pk_test_0123456789abcdef").expect("valid pk"))
        .api_key(ApiKey::new("test_api_key_regime2").expect("valid api_key"))
        .hmac_secret(HmacSecret::new(SAMPLE_HMAC_SECRET).expect("valid hmac"))
        .payouts_credentials(
            PayoutsCredentials::new(
                "client_id_test",
                "client_secret_test",
                "checker_user",
                "checker_pass",
            )
            .expect("valid payouts creds"),
        )
        .partner_credentials(
            PartnerCredentials::with_bearer_token("partner_api_key_test", "partner_jwt_test")
                .expect("valid partner creds"),
        )
        .build()
        .expect("valid test ClientConfig");
    let client = PaymobClient::new(cfg).expect("valid test PaymobClient");
    web::Data::new(AppState::new(client))
}

/// Mounts a JSON endpoint on the Accept Acquiring mock host (`(method, path)`).
pub async fn mount_accept(mock: &PaymobMockServer, route: (&str, &str), status: u16, body: Value) {
    mock.mount_json(JsonEndpointMockConfig {
        host: MockHost::Accept,
        http_method: route.0,
        endpoint_path: route.1,
        status,
        body,
    })
    .await;
}

/// Mounts a JSON endpoint on the Payouts mock host (`(method, path)`).
pub async fn mount_payouts(mock: &PaymobMockServer, route: (&str, &str), status: u16, body: Value) {
    mock.mount_json(JsonEndpointMockConfig {
        host: MockHost::Payouts,
        http_method: route.0,
        endpoint_path: route.1,
        status,
        body,
    })
    .await;
}

/// Mounts `POST /v1/intention/` returning `201 Created`.
pub async fn mount_intention_ok(mock: &PaymobMockServer) {
    mount_accept(
        mock,
        ("POST", "/v1/intention/"),
        201,
        json!({
            "id": "pi_test_1001",
            "client_secret": "egy_csk_test_secret_1001",
            "intention_order_id": 5001,
            "status": "intended",
            "confirmed": false,
            "payment_keys": [],
            "intention_detail": { "amount": 15000, "currency": "EGP", "items": [] }
        }),
    )
    .await;
}

/// Initializes an Actix test service wired with `configure_app`.
#[macro_export]
macro_rules! init_actix_app {
    ($state:expr) => {
        actix_web::test::init_service(App::new().app_data($state.clone()).configure(configure_app))
            .await
    };
}

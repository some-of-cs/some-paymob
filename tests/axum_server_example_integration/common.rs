#![forbid(unsafe_code)]
//! Shared Axum integration test harness (`US-axum` Unit 4).

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use some_paymob::core::credentials::{
    ApiKey, HmacSecret, PartnerCredentials, PublicKey, SecretKey,
};
use some_paymob::prelude::*;
use some_paymob::test_utils::mock_server::{JsonEndpointMockConfig, MockHost, PaymobMockServer};
use some_paymob::test_utils::vectors::SAMPLE_HMAC_SECRET;
use tower::ServiceExt;

use super::axum_server::{AppState, build_router};

/// Starts a [`PaymobMockServer`], constructs a `PaymobClient` wired to its
/// loopback endpoints, and returns `(server, router, state)`.
pub async fn setup_test_app() -> (PaymobMockServer, Router, Arc<AppState>) {
    let server = PaymobMockServer::start().await;
    let config = ClientConfig::builder()
        .region(server.custom_region())
        .secret_key(SecretKey::new("egy_sk_test_axum_unit4").expect("valid test secret key"))
        .public_key(PublicKey::new("egy_pk_test_axum_unit4").expect("valid test public key"))
        .api_key(ApiKey::new("egy_ak_test_axum_unit4").expect("valid test api key"))
        .hmac_secret(HmacSecret::new(SAMPLE_HMAC_SECRET).expect("valid test hmac secret"))
        .payouts_credentials(
            PayoutsCredentials::new("client_id", "client_secret", "payout_user", "payout_pass")
                .expect("valid payouts credentials"),
        )
        .partner_credentials(
            PartnerCredentials::new("partner_user").expect("valid partner credentials"),
        )
        .timeout(Duration::from_secs(5))
        .max_retries(1)
        .build()
        .expect("valid test client config");
    let client = PaymobClient::new(config).expect("valid PaymobClient");
    let state = Arc::new(AppState::new(client));
    let router = build_router(Arc::clone(&state));
    (server, router, state)
}

async fn send_request(
    router: &Router,
    method: Method,
    uri: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let builder = Request::builder().method(method).uri(uri);
    let req = match body {
        Some(payload) => builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(payload.to_string())),
        None => builder.body(Body::empty()),
    }
    .expect("valid test HTTP request");
    let resp = router.clone().oneshot(req).await.expect("router oneshot");
    let status = resp.status();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .expect("collect response body")
        .to_bytes();
    let json = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
    (status, json)
}

/// Sends an HTTP request with a JSON body through `router` using `oneshot`
/// and returns `(StatusCode, Value)`.
pub async fn send_json(
    router: &Router,
    method: Method,
    uri: &str,
    body: Value,
) -> (StatusCode, Value) {
    send_request(router, method, uri, Some(body)).await
}

/// Sends an HTTP `GET` request through `router` using `oneshot` and returns
/// `(StatusCode, Value)`.
pub async fn send_get(router: &Router, uri: &str) -> (StatusCode, Value) {
    send_request(router, Method::GET, uri, None).await
}

/// Sends an HTTP `POST` request with a JSON body and returns only its [`StatusCode`].
pub async fn post_status(router: &Router, uri: &str, body: Value) -> StatusCode {
    send_json(router, Method::POST, uri, body).await.0
}

/// Mounts `POST /api/auth/tokens` on the Accept mock host.
pub async fn mount_accept_jwt(server: &PaymobMockServer, token: &str) {
    server.mount_accept_auth_sequence(&[token]).await;
}

/// Mounts `POST /api/secure/o/token/` on the Payouts mock host.
pub async fn mount_payouts_token(server: &PaymobMockServer, access_token: &str) {
    server
        .mount_payouts_oauth(access_token, Some("refresh_tok"), 3600)
        .await;
}

async fn mount_json_on_host(
    server: &PaymobMockServer,
    host: MockHost,
    http_method: &str,
    endpoint_path: &str,
    status: u16,
    body: Value,
) {
    server
        .mount_json(JsonEndpointMockConfig {
            host,
            http_method,
            endpoint_path,
            status,
            body,
        })
        .await;
}

/// Mounts a JSON response on the Accept mock host.
pub async fn mount_accept_json(
    server: &PaymobMockServer,
    http_method: &str,
    endpoint_path: &str,
    status: u16,
    body: Value,
) {
    mount_json_on_host(server, MockHost::Accept, http_method, endpoint_path, status, body).await;
}

/// Mounts a `GET` `200 OK` JSON response on the Accept mock host.
pub async fn mount_accept_get(server: &PaymobMockServer, path: &str, body: Value) {
    mount_accept_json(server, "GET", path, 200, body).await;
}

/// Mounts a `POST` JSON response on the Accept mock host.
pub async fn mount_accept_post(server: &PaymobMockServer, path: &str, status: u16, body: Value) {
    mount_accept_json(server, "POST", path, status, body).await;
}

/// Mounts a JSON response on the Payouts mock host.
pub async fn mount_payouts_json(
    server: &PaymobMockServer,
    http_method: &str,
    endpoint_path: &str,
    status: u16,
    body: Value,
) {
    mount_json_on_host(server, MockHost::Payouts, http_method, endpoint_path, status, body).await;
}

/// Returns a minimal valid Paymob Intention response JSON fixture.
pub fn sample_intention_response() -> Value {
    json!({
        "id": "pi_test_1001",
        "intention_order_id": 880011,
        "client_secret": "egy_csk_test_secret_1001",
        "payment_keys": [{
            "integration": 4097558,
            "key": "pk_tok_1001",
            "gateway_type": "VPC",
            "order_id": 880011
        }],
        "payment_methods": [{
            "integration_id": 4097558,
            "name": "Online Card",
            "type": "card",
            "live": false,
            "use_cvc_with_moto": false
        }]
    })
}

/// Returns a minimal valid Paymob Transaction response JSON fixture.
pub fn sample_transaction_response(id: u64, amount_cents: u64) -> Value {
    json!({
        "id": id,
        "pending": false,
        "amount_cents": amount_cents,
        "success": true,
        "is_auth": false,
        "is_capture": false,
        "is_void": false,
        "is_refund": false,
        "currency": "EGP"
    })
}

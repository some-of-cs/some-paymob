#![forbid(unsafe_code)]
//! Negative, security, and error-recovery integration tests for `axum_server` (`US-Axum` Unit 5).

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};
use tower::ServiceExt;
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use some_paymob::core::auth::cache::CachedToken;
use some_paymob::core::auth::payouts_oauth::{PAYOUTS_OAUTH_TOKEN_PATH, PayoutsOAuthProvider};
use some_paymob::core::client::PaymobClient;
use some_paymob::core::config::ClientConfig;
use some_paymob::core::credentials::{
    ApiKey, EnvironmentMode, HmacSecret, PayoutsCredentials, SecretKey,
};
use some_paymob::core::error::PaymobError;
use some_paymob::core::types::Currency;
use some_paymob::resources::intentions::{BillingData, CreateIntentionParams, PaymentMethodInput};
use some_paymob::resources::manage::RefundParams;
use some_paymob::resources::payouts::{
    BankCardCashinParams, BankTransactionType, CancelAmanParams, DisburseIssuer,
    EgyptianPostCashinParams, MobileWalletCashinParams,
};
use some_paymob::resources::saved_cards::cit_mit::{MitChargeParams, validate_use_cvc_with_moto};
use some_paymob::test_utils::mock_server::{
    JsonEndpointMockConfig, JwtExpiryMockConfig, MockHost, PaymobMockServer,
    PayoutsRateLimitMockConfig,
};
use some_paymob::test_utils::vectors::{OFFICIAL_TX_192036465_JSON, SAMPLE_TX_192036465_HMAC};
use some_paymob::webhooks::idempotency::{IdempotentWebhookGuard, InMemoryWebhookDeduplicator};
use some_paymob::webhooks::{PaymobWebhookEngine, WebhookError};

use super::axum_server::{ApiServerError, AppState, build_router};
use super::common::{mount_accept_post, mount_payouts_token, post_status, setup_test_app};

fn mock_client(server: &PaymobMockServer, secret: &str) -> PaymobClient {
    let creds = PayoutsCredentials::new("cid", "csec", "user", "pass").expect("valid creds");
    let cfg = ClientConfig::builder()
        .region(server.custom_region())
        .secret_key(SecretKey::new(secret).expect("valid secret key"))
        .api_key(ApiKey::new("test_api_key_123").expect("valid api key"))
        .hmac_secret(HmacSecret::new("hmac_secret_test_key_123").expect("valid hmac"))
        .payouts_credentials(creds)
        .max_retries(0)
        .build()
        .expect("valid config");
    PaymobClient::new(cfg).expect("valid client")
}

fn valid_billing() -> BillingData {
    BillingData::builder()
        .phone_number("+201116491564")
        .build()
        .expect("valid billing")
}

fn map_error_to_status(err: &PaymobError) -> StatusCode {
    match err {
        PaymobError::AuthenticationError(_) | PaymobError::WebhookError(_) => {
            StatusCode::UNAUTHORIZED
        }
        PaymobError::EnvironmentMismatch(_)
        | PaymobError::RefundExceedsPermissibleAmount { .. }
        | PaymobError::ValidationError { .. } => StatusCode::UNPROCESSABLE_ENTITY,
        PaymobError::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
        PaymobError::ApiError { status, .. } => {
            StatusCode::from_u16(*status).unwrap_or(StatusCode::BAD_GATEWAY)
        }
        PaymobError::TransportError(_) => StatusCode::BAD_GATEWAY,
    }
}

struct SampleWebhookGuard(&'static str, &'static str);

impl IdempotentWebhookGuard for SampleWebhookGuard {
    fn idempotency_tuple(&self) -> (String, String) {
        (self.0.to_owned(), self.1.to_owned())
    }
}

async fn mount_oauth_fallback_mocks(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path(PAYOUTS_OAUTH_TOKEN_PATH))
        .and(body_string_contains("grant_type=refresh_token"))
        .respond_with(ResponseTemplate::new(401))
        .expect(1)
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path(PAYOUTS_OAUTH_TOKEN_PATH))
        .and(body_string_contains("grant_type=password"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "acc-fallback",
            "refresh_token": "ref-new",
            "expires_in": 3600,
            "token_type": "Bearer"
        })))
        .expect(1)
        .mount(server)
        .await;
}

fn build_empty_methods_intention() -> Result<CreateIntentionParams, PaymobError> {
    CreateIntentionParams::builder()
        .amount(10_000_u64)
        .currency(Currency::EGP)
        .payment_methods(vec![])
        .billing_data(valid_billing())
        .build()
}

#[tokio::test]
async fn rejects_empty_and_whitespace_strings() {
    let server = PaymobMockServer::start().await;
    let client = mock_client(&server, "egy_sk_test_mock_key_123");
    let blank_phone = BillingData::builder().phone_number("   ").build();
    assert!(matches!(
        blank_phone,
        Err(PaymobError::ValidationError {
            field: "billing_data.phone_number",
            ..
        })
    ));
    assert!(matches!(
        build_empty_methods_intention(),
        Err(PaymobError::ValidationError {
            field: "payment_methods",
            ..
        })
    ));
    let aman_res = client
        .payouts()
        .cashin()
        .cancel_aman(CancelAmanParams::new(" \t "))
        .await;
    assert!(matches!(
        aman_res,
        Err(PaymobError::ValidationError {
            field: "transaction_id",
            ..
        })
    ));
}

#[tokio::test]
async fn rejects_control_chars_in_fields_and_paths() {
    let server = PaymobMockServer::start().await;
    let client = mock_client(&server, "egy_sk_test_mock_key_123");
    let crlf_path = client.accept_url("/v1/intention/\r\n");
    assert!(matches!(
        crlf_path,
        Err(PaymobError::ValidationError { field: "path", .. })
    ));
    let lf_msisdn = client
        .payouts()
        .cashin()
        .vodafone(MobileWalletCashinParams::new("0102345\n678", 100))
        .await;
    assert!(matches!(
        lf_msisdn,
        Err(PaymobError::ValidationError {
            field: "msisdn",
            ..
        })
    ));
}

#[tokio::test]
async fn rejects_path_traversal_and_protocol_relative_urls() {
    let server = PaymobMockServer::start().await;
    let client = mock_client(&server, "egy_sk_test_mock_key_123");
    assert!(matches!(
        client.accept_url("/v1/../admin"),
        Err(PaymobError::ValidationError { field: "path", .. })
    ));
    assert!(matches!(
        client.checkout_url("//evil.com/steal"),
        Err(PaymobError::ValidationError { field: "path", .. })
    ));
    assert!(matches!(
        client.payouts_url("https://evil.com/disburse"),
        Err(PaymobError::ValidationError { field: "path", .. })
    ));
}

fn sample_bad_pan_params() -> BankCardCashinParams {
    BankCardCashinParams {
        amount: 500,
        bank_card_number: SecretString::from("4111ABCD"),
        bank_code: String::from("CIB"),
        bank_transaction_type: BankTransactionType::Salary,
        full_name: String::from("Test User"),
        client_reference_id: None,
        customer_bears_fees: None,
    }
}

fn sample_bad_nid_params() -> EgyptianPostCashinParams {
    EgyptianPostCashinParams {
        amount: 500,
        msisdn: String::from("01023456789"),
        full_name: String::from("Test User"),
        national_id: SecretString::from("1234567890123"),
        client_reference_id: None,
        customer_bears_fees: None,
    }
}

#[tokio::test]
async fn rejects_invalid_msisdns_pans_and_14_digit_national_ids() {
    let server = PaymobMockServer::start().await;
    let client = mock_client(&server, "egy_sk_test_mock_key_123");
    let bad_msisdn = client
        .payouts()
        .cashin()
        .vodafone(MobileWalletCashinParams::new("12345", 100))
        .await;
    assert!(matches!(
        bad_msisdn,
        Err(PaymobError::ValidationError {
            field: "msisdn",
            ..
        })
    ));
    assert!(matches!(
        client
            .payouts()
            .cashin()
            .bank_card(sample_bad_pan_params())
            .await,
        Err(PaymobError::ValidationError {
            field: "bank_card_number",
            ..
        })
    ));
    assert!(matches!(
        client
            .payouts()
            .cashin()
            .egyptian_post(sample_bad_nid_params())
            .await,
        Err(PaymobError::ValidationError {
            field: "national_id",
            ..
        })
    ));
}

#[test]
fn rejects_use_cvc_with_moto_cvn_mismatches() {
    let cvn = SecretString::from("123");
    assert!(matches!(
        validate_use_cvc_with_moto(true, None),
        Err(PaymobError::ValidationError { field: "cvn", .. })
    ));
    assert!(matches!(
        validate_use_cvc_with_moto(false, Some(&cvn)),
        Err(PaymobError::ValidationError { field: "cvn", .. })
    ));
    let short_cvn = MitChargeParams::with_moto_cvc(
        SecretString::from("pt_1"),
        SecretString::from("tok_1"),
        SecretString::from("12"),
    );
    assert!(matches!(
        short_cvn,
        Err(PaymobError::ValidationError { field: "cvn", .. })
    ));
}

#[test]
fn rejects_unknown_and_kyc_only_payout_issuers() {
    assert_eq!(DisburseIssuer::from_wire("unknown_issuer"), None);
    assert_eq!(DisburseIssuer::from_wire("aman"), None);
    assert_eq!(DisburseIssuer::from_wire("kyc_only"), None);
}

#[test]
fn rejects_tampered_hmac_signatures_and_malformed_hex() {
    let engine = PaymobWebhookEngine::new("hmac_secret_test_key_123").expect("valid engine");
    let tampered = engine
        .verify_concatenated_str("payload", &"0".repeat(128))
        .expect_err("tampered HMAC must fail");
    assert_eq!(tampered, WebhookError::SignatureMismatch);
    assert_eq!(tampered.suggested_http_status_code(), 401);
    let malformed_hex = engine
        .verify_concatenated_str("payload", "zzzz")
        .expect_err("malformed hex must fail");
    assert_eq!(malformed_hex, WebhookError::MalformedSignatureHex);
    let bad_json = WebhookError::InvalidJsonPayload(String::from("unexpected EOF"));
    assert_eq!(bad_json.suggested_http_status_code(), 400);
}

#[test]
fn rejects_duplicate_webhook_replay_with_409_conflict() {
    let dedup = InMemoryWebhookDeduplicator::new();
    let evt = SampleWebhookGuard("192036465", "217503754");
    assert_eq!(dedup.claim_or_reject(&evt), Ok(()));
    let replay_err = dedup
        .claim_or_reject(&evt)
        .expect_err("duplicate webhook delivery must be rejected");
    assert!(matches!(
        replay_err,
        WebhookError::DuplicateWebhookDelivery { .. }
    ));
    assert_eq!(replay_err.suggested_http_status_code(), 409);
}

#[tokio::test]
async fn router_webhooks_tampered_hmac_malformed_hex_and_replay_409() {
    let (_server, router, _state) = setup_test_app().await;
    let tx_val: Value = serde_json::from_str(OFFICIAL_TX_192036465_JSON).expect("valid tx json");
    let bad_hmac = format!("/webhooks/paymob?hmac={}", "0".repeat(128));
    assert_eq!(
        post_status(&router, &bad_hmac, tx_val.clone()).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        post_status(&router, "/webhooks/paymob?hmac=zzzz", tx_val.clone()).await,
        StatusCode::UNAUTHORIZED
    );
    let ok_uri = format!("/webhooks/paymob?hmac={SAMPLE_TX_192036465_HMAC}");
    assert_eq!(
        post_status(&router, &ok_uri, tx_val.clone()).await,
        StatusCode::OK
    );
    assert_eq!(
        post_status(&router, &ok_uri, tx_val).await,
        StatusCode::CONFLICT
    );
}

#[tokio::test]
async fn router_rejects_moto_cvc_mismatch_and_unknown_payout_issuer_400() {
    let (_server, router, _state) = setup_test_app().await;
    let missing_cvn = json!({
        "payment_token": "pk_1",
        "saved_token": "tok_1",
        "use_cvc_with_moto": true
    });
    assert_eq!(
        post_status(&router, "/saved-cards/pay/mit", missing_cvn).await,
        StatusCode::BAD_REQUEST
    );
    let unexpected_cvn = json!({
        "payment_token": "pk_1",
        "saved_token": "tok_1",
        "use_cvc_with_moto": false,
        "cvn": "123"
    });
    assert_eq!(
        post_status(&router, "/saved-cards/pay/mit", unexpected_cvn).await,
        StatusCode::BAD_REQUEST
    );
    let aman = json!({ "amount": 150, "msisdn": "01012345678" });
    assert_eq!(
        post_status(&router, "/payouts/cashin/wallet/aman", aman).await,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn router_maps_over_refund_and_live_integration_mode_to_422() {
    let (server, router, state) = setup_test_app().await;
    let err_json = json!({ "message": "Refund amount exceeds maximum permissible refund balance" });
    mount_accept_post(&server, "/api/acceptance/void_refund/refund", 400, err_json).await;
    let refund_body = json!({ "transaction_id": 192036465, "amount_cents": 999999 });
    assert_eq!(
        post_status(&router, "/manage/refund", refund_body).await,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let live_state = Arc::new(
        AppState::new(state.paymob.clone())
            .with_integration_modes([(4_097_558, EnvironmentMode::Live)]),
    );
    let live_router = build_router(live_state);
    let intent = json!({ "amount": 10000, "currency": "EGP", "payment_methods": [4097558] });
    assert_eq!(
        post_status(&live_router, "/intentions", intent).await,
        StatusCode::UNPROCESSABLE_ENTITY
    );
}

#[tokio::test]
async fn router_propagates_429_retry_after_header() {
    let server = PaymobMockServer::start().await;
    mount_payouts_token(&server, "po_rl_1").await;
    server
        .mount_payouts_429_then_ok(PayoutsRateLimitMockConfig {
            http_method: "GET",
            endpoint_path: "/api/secure/budget/inquire/",
            fail_count: 5,
            retry_after_secs: Some(17),
            status_description: "rate limit exceeded",
            status_code: "429",
            ok_body: json!({ "current_budget": "Your current budget is 100.00 LE" }),
        })
        .await;
    let client = mock_client(&server, "egy_sk_test_mock_key_123");
    let router = build_router(Arc::new(AppState::new(client)));
    let req = Request::builder()
        .method(Method::GET)
        .uri("/payouts/inquiries/budget")
        .body(Body::empty())
        .expect("valid request");
    let resp = router.oneshot(req).await.expect("router oneshot");
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        resp.headers()
            .get(header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok()),
        Some("17")
    );
}

#[tokio::test]
async fn regime2_401_incorrect_credentials_evicts_cache_and_retries_single_flight() {
    let server = PaymobMockServer::start().await;
    server
        .mount_accept_auth_sequence(&["stale-jwt-1", "fresh-jwt-2"])
        .await;
    server
        .mount_jwt_expiry_then_ok(JwtExpiryMockConfig {
            http_method: "GET",
            endpoint_path: "/api/acceptance/transactions/192036465",
            fail_count: 1,
            ok_body: json!({
                "id": 192036465,
                "pending": false,
                "amount_cents": 10000,
                "success": true,
                "currency": "EGP"
            }),
        })
        .await;
    let client = mock_client(&server, "egy_sk_test_mock_key_123");
    let tx = client
        .inquiries()
        .by_transaction_id(192_036_465)
        .await
        .expect("single-flight retry after 401 should succeed");
    assert_eq!(tx.id, 192_036_465);
    assert!(tx.success);
}

#[tokio::test]
async fn regime3_oauth2_refresh_token_and_password_fallback() {
    let server = MockServer::start().await;
    mount_oauth_fallback_mocks(&server).await;
    let creds = PayoutsCredentials::new("cid", "csec", "user", "pass").expect("valid creds");
    let provider = PayoutsOAuthProvider::new(&server.uri(), creds.into()).expect("valid provider");
    provider.cache().store(CachedToken::new(
        "stale",
        Some(SecretString::from("expired-ref")),
        Duration::from_secs(5),
    ));
    let token = provider
        .access_token()
        .await
        .expect("rejected refresh_token should fall back to password grant");
    assert_eq!(token.expose_secret(), "acc-fallback");
}

#[tokio::test]
async fn propagates_http_429_retry_after_header() {
    let err = PaymobError::RateLimited {
        retry_after_secs: Some(17),
        message: String::from("rate limit exceeded"),
    };
    assert!(err.is_rate_limited());
    assert_eq!(err.retry_after_secs(), Some(17));
    assert_eq!(map_error_to_status(&err), StatusCode::TOO_MANY_REQUESTS);
    let resp = axum::response::IntoResponse::into_response(ApiServerError::from(err));
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        resp.headers()
            .get(header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok()),
        Some("17")
    );
}

#[tokio::test]
async fn maps_over_refund_400_to_422_unprocessable_entity() {
    let server = PaymobMockServer::start().await;
    server
        .mount_json(JsonEndpointMockConfig {
            host: MockHost::Accept,
            http_method: "POST",
            endpoint_path: "/api/acceptance/void_refund/refund",
            status: 400,
            body: json!({
                "message": "Refund amount exceeds maximum permissible refund balance"
            }),
        })
        .await;
    let client = mock_client(&server, "egy_sk_test_mock_key_123");
    let err = client
        .manage()
        .refund(RefundParams::new(192_036_465, 999_999))
        .await
        .expect_err("over-refund must fail");
    assert!(matches!(
        err,
        PaymobError::RefundExceedsPermissibleAmount { .. }
    ));
    assert_eq!(map_error_to_status(&err), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn rejects_test_live_environment_mismatch_with_422() {
    let server = PaymobMockServer::start().await;
    let client = mock_client(&server, "egy_sk_test_mock_key_123");
    let svc = client
        .intentions()
        .with_integration_mode(4_097_558, EnvironmentMode::Live);
    let params = CreateIntentionParams::builder()
        .amount(10_000_u64)
        .currency(Currency::EGP)
        .payment_methods(vec![PaymentMethodInput::IntegrationId(4_097_558)])
        .billing_data(valid_billing())
        .build()
        .expect("valid params");
    let err = svc
        .create(params)
        .await
        .expect_err("Test key with Live integration ID must fail");
    assert!(matches!(err, PaymobError::EnvironmentMismatch(_)));
    assert_eq!(map_error_to_status(&err), StatusCode::UNPROCESSABLE_ENTITY);
}

#[test]
fn redacts_secrets_and_pii_in_error_responses() {
    let raw = "egy_sk_live_secret999 Bearer jwt_tok_123 user@example.com";
    let err = PaymobError::AuthenticationError(raw.to_owned());
    let display = err.to_string();
    let debug = format!("{err:?}");
    assert!(display.contains("[REDACTED]") && debug.contains("[REDACTED]"));
    for leak in ["egy_sk_live_secret999", "jwt_tok_123", "user@example.com"] {
        assert!(!display.contains(leak), "Display leaked {leak}");
        assert!(!debug.contains(leak), "Debug leaked {leak}");
    }
    for marker in [
        "Bearer tok",
        "Token sk",
        "Basic Y2lk",
        "refresh_token=1",
        "access_token=1",
        "password=1",
        "client_secret=1",
        "a@b.co",
    ] {
        let srv_err = ApiServerError::from(PaymobError::ValidationError {
            field: "test",
            reason: marker.to_owned(),
        });
        let resp = axum::response::IntoResponse::into_response(srv_err);
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}

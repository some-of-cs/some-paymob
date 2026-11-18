#![forbid(unsafe_code)]
//! Unit 5: Negative validation, security/redaction, and error recovery integration tests.

use std::sync::Arc;
use std::time::Duration;

use rocket::http::Status;
use rocket::local::asynchronous::Client;
use secrecy::{ExposeSecret, SecretString};
use serde_json::json;
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use some_paymob::core::auth::accept_jwt::AcceptJwtProvider;
use some_paymob::core::auth::cache::{CachedToken, TokenCache};
use some_paymob::core::auth::payouts_oauth::{PAYOUTS_OAUTH_TOKEN_PATH, PayoutsOAuthProvider};
use some_paymob::core::credentials::{
    ApiKey, HmacSecret, PayoutsCredentials, PublicKey, SecretKey,
};
use some_paymob::prelude::*;
use some_paymob::resources::manage::RefundParams;
use some_paymob::resources::payouts::{
    BankCardCashinParams, BankTransactionType, DisburseIssuer, DisbursementResponse,
    EgyptianPostCashinParams, MobileWalletCashinParams,
};
use some_paymob::resources::saved_cards::{MitChargeParams, validate_use_cvc_with_moto};
use some_paymob::test_utils::{
    JsonEndpointMockConfig, JwtExpiryMockConfig, MockHost, OFFICIAL_TX_192036465_HMAC,
    OFFICIAL_TX_192036465_JSON, PaymobMockServer, PayoutsRateLimitMockConfig, SAMPLE_HMAC_SECRET,
};
use some_paymob::{
    ClientConfig, InMemoryWebhookDeduplicator, PaymobClient, PaymobError, PaymobRegion,
    WebhookError,
};

use super::rocket_server::{AppState, build_rocket};

async fn build_rocket_harness(server: &PaymobMockServer) -> (Client, AppState) {
    let creds = PayoutsCredentials::new("cid", "csec", "user", "pass").expect("valid creds");
    let config = ClientConfig::builder()
        .region(server.custom_region())
        .secret_key(SecretKey::new("egy_sk_test_rocket_unit5").expect("valid secret key"))
        .public_key(PublicKey::new("egy_pk_test_rocket_unit5").expect("valid public key"))
        .api_key(ApiKey::new("test_api_key_unit5").expect("valid api key"))
        .hmac_secret(HmacSecret::new(SAMPLE_HMAC_SECRET).expect("valid hmac secret"))
        .payouts_credentials(creds)
        .max_retries(0)
        .build()
        .expect("valid client config");
    let client = Arc::new(PaymobClient::new(config).expect("valid client"));
    let webhook_engine = Arc::new(client.webhook_engine().expect("valid webhook engine"));
    let deduplicator = Arc::new(InMemoryWebhookDeduplicator::new());
    let state = AppState {
        client,
        webhook_engine,
        deduplicator,
    };
    let rocket_client = Client::tracked(build_rocket(state.clone()))
        .await
        .expect("valid rocket instance");
    (rocket_client, state)
}

#[tokio::test]
async fn negative_empty_and_whitespace_credentials_rejected() {
    let server = PaymobMockServer::start().await;
    let (rocket_client, _state) = build_rocket_harness(&server).await;
    let resp = rocket_client.get("/unmounted_unit5_probe").dispatch().await;
    assert_eq!(resp.status(), Status::NotFound);

    assert!(SecretKey::new("").is_err());
    assert!(SecretKey::new("   ").is_err());
    assert!(PublicKey::new(" \t ").is_err());
    assert!(ApiKey::new("").is_err());
    assert!(HmacSecret::new("   ").is_err());
    assert!(PayoutsCredentials::new("", "csec", "user", "pass").is_err());
    assert!(PayoutsCredentials::new("cid", "csec", "user", "   ").is_err());
}

#[tokio::test]
async fn negative_control_chars_and_path_traversal_rejected() {
    let server = PaymobMockServer::start().await;
    let (_rocket_client, state) = build_rocket_harness(&server).await;

    for bad_path in [
        "",
        "   ",
        "/v1/intention/\0",
        "/v1/intention/\r\n",
        "../admin/secrets",
        "//evil.com/steal",
        "https://evil.com/steal",
    ] {
        let err = state
            .client
            .accept_url(bad_path)
            .expect_err("unsafe path must be rejected");
        assert!(matches!(
            err,
            PaymobError::ValidationError { field: "path", .. }
        ));
    }
    assert!(state.client.checkout_url("../escape").is_err());
    assert!(state.client.payouts_url("//evil.com/disburse").is_err());
}

#[tokio::test]
async fn negative_invalid_msisdn_pan_and_national_id_rejected() {
    let server = PaymobMockServer::start().await;
    let (_rocket_client, state) = build_rocket_harness(&server).await;
    let cashin = state.client.payouts().cashin();

    let bad_msisdn = cashin
        .vodafone(MobileWalletCashinParams::new("12345", 100))
        .await
        .expect_err("short msisdn rejected");
    assert!(matches!(
        bad_msisdn,
        PaymobError::ValidationError {
            field: "msisdn",
            ..
        }
    ));

    let bad_pan = cashin
        .bank_card(BankCardCashinParams {
            amount: 500,
            bank_card_number: SecretString::from("4111ABCD"),
            bank_code: String::from("CIB"),
            bank_transaction_type: BankTransactionType::Salary,
            full_name: String::from("Test User"),
            client_reference_id: None,
            customer_bears_fees: None,
        })
        .await
        .expect_err("non-digit PAN rejected");
    assert!(matches!(
        bad_pan,
        PaymobError::ValidationError {
            field: "bank_card_number",
            ..
        }
    ));

    let bad_nid = cashin
        .egyptian_post(EgyptianPostCashinParams {
            amount: 500,
            msisdn: String::from("01023456789"),
            full_name: String::from("Test User"),
            national_id: SecretString::from("12345"),
            client_reference_id: None,
            customer_bears_fees: None,
        })
        .await
        .expect_err("non-14-digit national_id rejected");
    assert!(matches!(
        bad_nid,
        PaymobError::ValidationError {
            field: "national_id",
            ..
        }
    ));
}

#[test]
fn negative_use_cvc_with_moto_cvn_mismatch_rejected() {
    let valid_cvn = SecretString::from("123");
    let short_cvn = SecretString::from("12");
    assert!(validate_use_cvc_with_moto(true, None).is_err());
    assert!(validate_use_cvc_with_moto(false, Some(&valid_cvn)).is_err());
    assert!(validate_use_cvc_with_moto(true, Some(&short_cvn)).is_err());

    let err = MitChargeParams::with_moto_cvc("pay_tok", "saved_tok", SecretString::from("ab1"))
        .expect_err("non-digit CVN must fail");
    assert!(matches!(
        err,
        PaymobError::ValidationError { field: "cvn", .. }
    ));
}

#[test]
fn negative_unknown_and_kyc_only_payout_issuers_rejected() {
    assert_eq!(DisburseIssuer::from_wire("unknown_issuer"), None);
    assert_eq!(DisburseIssuer::from_wire("kyc_only"), None);
    assert_eq!(DisburseIssuer::from_wire("aman"), None);

    let bad_json = r#"{"transaction_id":"tx_1","issuer":"kyc_only"}"#;
    assert!(serde_json::from_str::<DisbursementResponse>(bad_json).is_err());
}

#[tokio::test]
async fn security_tampered_hmac_malformed_hex_and_duplicate_replay() {
    let server = PaymobMockServer::start().await;
    let (_rocket_client, state) = build_rocket_harness(&server).await;

    let mut tampered = OFFICIAL_TX_192036465_HMAC.to_owned();
    tampered.replace_range(0..4, "0000");
    let sig_err = state
        .webhook_engine
        .verify_transaction_post(OFFICIAL_TX_192036465_JSON, &tampered)
        .expect_err("tampered HMAC rejected");
    assert_eq!(sig_err.suggested_http_status_code(), 401);

    let hex_err = state
        .webhook_engine
        .verify_transaction_post(OFFICIAL_TX_192036465_JSON, "not-valid-hex!")
        .expect_err("malformed hex rejected");
    assert!(matches!(hex_err, WebhookError::MalformedSignatureHex));

    let bad_payload = state
        .webhook_engine
        .verify_transaction_post("{malformed", OFFICIAL_TX_192036465_HMAC)
        .expect_err("malformed JSON rejected");
    assert_eq!(bad_payload.suggested_http_status_code(), 400);

    let verified = state
        .webhook_engine
        .verify_transaction_post(OFFICIAL_TX_192036465_JSON, OFFICIAL_TX_192036465_HMAC)
        .expect("valid webhook");
    assert!(state.deduplicator.claim_or_reject(&verified).is_ok());
    let dup_err = state
        .deduplicator
        .claim_or_reject(&verified)
        .expect_err("duplicate replay rejected");
    assert_eq!(dup_err.suggested_http_status_code(), 409);
}

#[tokio::test]
async fn recovery_regime2_401_cache_eviction_and_single_flight_retry() {
    let server = PaymobMockServer::start().await;
    server
        .mount_accept_auth_sequence(&["stale-jwt-1", "fresh-jwt-2"])
        .await;
    server
        .mount_jwt_expiry_then_ok(JwtExpiryMockConfig {
            http_method: "POST",
            endpoint_path: "/api/ecommerce/orders/transaction_inquiry",
            fail_count: 1,
            ok_body: json!({ "id": 192_036_465, "success": true }),
        })
        .await;

    let provider = AcceptJwtProvider::new(&server.accept_uri(), SecretString::from("test_api_key"))
        .expect("valid provider");
    let http = reqwest::Client::new();
    let url = format!(
        "{}/api/ecommerce/orders/transaction_inquiry",
        server.accept_uri()
    );
    let resp = provider
        .execute_with_retry(|tok| {
            let c = http.clone();
            let u = url.clone();
            async move {
                Ok(c.post(&u)
                    .json(&json!({ "auth_token": tok.expose_secret() }))
                    .send()
                    .await?)
            }
        })
        .await
        .expect("401 retry succeeds");
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        provider.token().await.expect("cached").expose_secret(),
        "fresh-jwt-2"
    );
}

#[tokio::test]
async fn recovery_regime3_oauth2_refresh_token_and_password_fallback() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(PAYOUTS_OAUTH_TOKEN_PATH))
        .and(body_string_contains("grant_type=refresh_token"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({ "error": "invalid_grant" })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(PAYOUTS_OAUTH_TOKEN_PATH))
        .and(body_string_contains("grant_type=password"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "po-fallback",
            "refresh_token": "po-ref-3",
            "expires_in": 3600
        })))
        .expect(1)
        .mount(&server)
        .await;

    let creds = PayoutsCredentials::new("cid", "csec", "alice", "s3cr3t").expect("valid creds");
    let cache = Arc::new(TokenCache::with_refresh_margin(Duration::from_secs(3600)));
    cache.store(CachedToken::new(
        "stale-acc",
        Some(SecretString::from("stale-ref")),
        Duration::from_secs(5),
    ));
    let provider = PayoutsOAuthProvider::with_client_and_cache(
        &server.uri(),
        creds,
        reqwest::Client::new(),
        cache,
    )
    .expect("valid oauth provider");
    let tok = provider
        .access_token()
        .await
        .expect("password fallback succeeds");
    assert_eq!(tok.expose_secret(), "po-fallback");
}

#[tokio::test]
async fn recovery_http_429_retry_after_header_propagation() {
    let server = PaymobMockServer::start().await;
    server
        .mount_payouts_429_then_ok(PayoutsRateLimitMockConfig {
            http_method: "GET",
            endpoint_path: "/api/secure/budget/inquire/",
            fail_count: 2,
            retry_after_secs: Some(15),
            status_description: "rate limit exceeded",
            status_code: "429",
            ok_body: json!({ "current_budget": "100.00 EGP" }),
        })
        .await;

    let (_rocket_client, state) = build_rocket_harness(&server).await;
    state
        .client
        .auth()
        .payouts_cache()
        .store(CachedToken::with_default_ttl("seeded-oauth-jwt", None));

    let err = state
        .client
        .payouts()
        .inquiries()
        .user_budget()
        .await
        .expect_err("429 must propagate when max_retries is 0");
    assert!(err.is_rate_limited());
    assert_eq!(err.status_code(), Some(429));
    assert_eq!(err.retry_after_secs(), Some(15));
}

#[tokio::test]
async fn recovery_over_refund_400_maps_to_refund_exceeds_permissible_amount() {
    let server = PaymobMockServer::start().await;
    let msg = "Requested Refund Amount is greater than the maximum refund amount permissible.";
    server
        .mount_json(JsonEndpointMockConfig {
            host: MockHost::Accept,
            http_method: "POST",
            endpoint_path: "/api/acceptance/void_refund/refund",
            status: 400,
            body: json!({ "message": msg }),
        })
        .await;

    let (_rocket_client, state) = build_rocket_harness(&server).await;
    let err = state
        .client
        .manage()
        .refund(RefundParams::new(192_036_465, 999_999))
        .await
        .expect_err("over-refund must fail");
    assert_eq!(
        err,
        PaymobError::RefundExceedsPermissibleAmount {
            message: msg.to_owned()
        }
    );
}

#[test]
fn negative_test_live_environment_mismatch_rejected() {
    let err = ClientConfig::builder()
        .region(PaymobRegion::Egypt)
        .secret_key(SecretKey::new("egy_sk_test_unit5").expect("valid test sk"))
        .public_key(PublicKey::new("egy_pk_live_unit5").expect("valid live pk"))
        .build()
        .expect_err("mixed test/live keys must fail");
    assert!(matches!(err, PaymobError::EnvironmentMismatch(_)));
}

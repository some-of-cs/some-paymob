#![forbid(unsafe_code)]
//! Unit 5: Negative validation, security/redaction, and error recovery gRPC integration tests.

use std::sync::Arc;
use std::time::Duration;

use http::uri::PathAndQuery;
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};
use tonic::client::Grpc;
use tonic::codec::ProstCodec;
use tonic::{Code, Request, Response, Status};
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use some_paymob::core::auth::accept_jwt::AcceptJwtProvider;
use some_paymob::core::auth::cache::{CachedToken, TokenCache};
use some_paymob::core::auth::payouts_oauth::{PAYOUTS_OAUTH_TOKEN_PATH, PayoutsOAuthProvider};
use some_paymob::core::credentials::{
    ApiKey, HmacSecret, PayoutsCredentials, PublicKey, SecretKey,
};
use some_paymob::resources::manage::RefundParams;
use some_paymob::resources::payouts::{DisburseIssuer, DisbursementResponse};
use some_paymob::resources::saved_cards::{MitChargeParams, validate_use_cvc_with_moto};
use some_paymob::test_utils::{
    JsonEndpointMockConfig, JwtExpiryMockConfig, MockHost, OFFICIAL_TX_192036465_JSON,
    PaymobMockServer, PayoutsRateLimitMockConfig, SAMPLE_HMAC_SECRET, SAMPLE_TX_192036465_HMAC,
};
use some_paymob::webhooks::InMemoryWebhookDeduplicator;
use some_paymob::{ClientConfig, PaymobClient, PaymobError, PaymobRegion, WebhookError};

use super::tonic_grpc_server::proto::{
    JsonRpcRequest, JsonRpcResponse, PAYMOB_GRPC_SERVICE_NAME,
};
use super::tonic_grpc_server::{PaymobGrpcService, build_grpc_server};

fn build_test_config(server: &PaymobMockServer) -> ClientConfig {
    let creds = PayoutsCredentials::new("cid", "csec", "user", "pass").expect("valid creds");
    ClientConfig::builder()
        .region(server.custom_region())
        .secret_key(SecretKey::new("egy_sk_test_tonic_unit5").expect("valid secret key"))
        .public_key(PublicKey::new("egy_pk_test_tonic_unit5").expect("valid public key"))
        .api_key(ApiKey::new("test_api_key_tonic_unit5").expect("valid api key"))
        .hmac_secret(HmacSecret::new(SAMPLE_HMAC_SECRET).expect("valid hmac secret"))
        .payouts_credentials(creds)
        .max_retries(0)
        .build()
        .expect("valid client config")
}

fn build_grpc_service(server: &PaymobMockServer) -> PaymobGrpcService {
    let client = Arc::new(PaymobClient::new(build_test_config(server)).expect("valid client"));
    let webhook_engine = Arc::new(client.webhook_engine().expect("valid webhook engine"));
    let deduplicator = Arc::new(InMemoryWebhookDeduplicator::new());
    PaymobGrpcService::new(client, webhook_engine, deduplicator)
}

async fn grpc_unary_raw(
    service: PaymobGrpcService,
    method_name: &str,
    payload_json: String,
) -> Result<Response<JsonRpcResponse>, Status> {
    let mut grpc = Grpc::new(build_grpc_server(service));
    grpc.ready()
        .await
        .map_err(|err| Status::internal(err.to_string()))?;
    let path_str = format!("/{PAYMOB_GRPC_SERVICE_NAME}/{method_name}");
    let rpc_path = PathAndQuery::try_from(path_str)
        .map_err(|err| Status::invalid_argument(err.to_string()))?;
    let codec = ProstCodec::<JsonRpcRequest, JsonRpcResponse>::default();
    grpc.unary(Request::new(JsonRpcRequest { payload_json }), rpc_path, codec)
        .await
}

async fn grpc_call(
    service: PaymobGrpcService,
    method_name: &str,
    payload: &Value,
) -> Result<Response<JsonRpcResponse>, Status> {
    grpc_unary_raw(service, method_name, payload.to_string()).await
}

async fn grpc_err(service: PaymobGrpcService, method_name: &str, payload: &Value) -> Status {
    grpc_call(service, method_name, payload)
        .await
        .expect_err("expected gRPC error status")
}

async fn assert_grpc_code(
    service: &PaymobGrpcService,
    method_name: &str,
    payload: &Value,
    expected: Code,
) {
    let status = grpc_err(service.clone(), method_name, payload).await;
    assert_eq!(status.code(), expected, "unexpected code for {method_name}");
}

async fn mount_oauth_fallback_mocks(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path(PAYOUTS_OAUTH_TOKEN_PATH))
        .and(body_string_contains("grant_type=refresh_token"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({ "error": "invalid_grant" })))
        .expect(1)
        .mount(server)
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
        .mount(server)
        .await;
}

async fn mount_jwt_expiry_inquiry_mock(server: &PaymobMockServer) {
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
}

#[tokio::test]
async fn negative_empty_and_whitespace_credentials_rejected() {
    let server = PaymobMockServer::start().await;
    let service = build_grpc_service(&server);
    assert_grpc_code(&service, "UnmountedUnit5Probe", &json!({}), Code::Unimplemented).await;
    assert!(SecretKey::new("").is_err() && SecretKey::new("   ").is_err());
    assert!(PublicKey::new(" \t ").is_err() && ApiKey::new("").is_err());
    assert!(HmacSecret::new("   ").is_err());
    assert!(PayoutsCredentials::new("", "csec", "user", "pass").is_err());
    assert!(PayoutsCredentials::new("cid", "csec", "user", "   ").is_err());
}

#[tokio::test]
async fn negative_control_chars_and_path_traversal_rejected() {
    let server = PaymobMockServer::start().await;
    let service = build_grpc_service(&server);
    let bad_paths = [
        "", "   ", "/v1/intention/\0", "/v1/intention/\r",
        "/v1/intention/\n", "../admin", "//evil.com", "https://evil.com",
    ];
    for bad_path in bad_paths {
        let err = service.client.accept_url(bad_path).expect_err("unsafe path");
        assert!(matches!(err, PaymobError::ValidationError { field: "path", .. }));
    }
    assert!(service.client.checkout_url("../escape").is_err());
    assert!(service.client.payouts_url("//evil.com/disburse").is_err());
    let bad_topup = json!({
        "amount": 500,
        "currency": "egyptian_pound",
        "proof_base64": "AQID",
        "proof_filename": "../passwd"
    });
    assert_grpc_code(&service, "PayoutsTopupBankTransfer", &bad_topup, Code::InvalidArgument).await;
}

#[tokio::test]
async fn negative_invalid_msisdn_pan_and_national_id_rejected() {
    let server = PaymobMockServer::start().await;
    let service = build_grpc_service(&server);
    let bad_wallet = json!({ "issuer": "vodafone", "msisdn": "12345", "amount": 100 });
    let bad_card = json!({
        "amount": 500,
        "bank_card_number": "4111ABCD",
        "bank_code": "CIB",
        "bank_transaction_type": "salary",
        "full_name": "Test User"
    });
    let bad_post = json!({
        "amount": 500,
        "msisdn": "01023456789",
        "full_name": "Test User",
        "national_id": "12345"
    });
    assert_grpc_code(&service, "PayoutsCashinWallet", &bad_wallet, Code::InvalidArgument).await;
    assert_grpc_code(&service, "PayoutsCashinBankCard", &bad_card, Code::InvalidArgument).await;
    assert_grpc_code(&service, "PayoutsCashinEgyptianPost", &bad_post, Code::InvalidArgument).await;
}

#[tokio::test]
async fn negative_use_cvc_with_moto_cvn_mismatch_rejected() {
    let server = PaymobMockServer::start().await;
    let service = build_grpc_service(&server);
    let valid_cvn = SecretString::from("123");
    let short_cvn = SecretString::from("12");
    assert!(validate_use_cvc_with_moto(true, None).is_err());
    assert!(validate_use_cvc_with_moto(false, Some(&valid_cvn)).is_err());
    assert!(validate_use_cvc_with_moto(true, Some(&short_cvn)).is_err());
    let bad_mit = MitChargeParams::with_moto_cvc("p".into(), "s".into(), SecretString::from("ab1"));
    assert!(bad_mit.is_err());
    let mismatch = json!({
        "payment_token": "tok_u5",
        "saved_token": "saved_1",
        "use_cvc_with_moto": true
    });
    assert_grpc_code(&service, "PayMit", &mismatch, Code::InvalidArgument).await;
}

#[tokio::test]
async fn negative_unknown_and_kyc_only_payout_issuers_rejected() {
    let server = PaymobMockServer::start().await;
    let service = build_grpc_service(&server);
    assert_eq!(DisburseIssuer::from_wire("unknown_issuer"), None);
    assert_eq!(DisburseIssuer::from_wire("kyc_only"), None);
    assert_eq!(DisburseIssuer::from_wire("aman"), None);
    let bad_json = r#"{"transaction_id":"tx_1","issuer":"kyc_only"}"#;
    assert!(serde_json::from_str::<DisbursementResponse>(bad_json).is_err());
    for issuer in ["aman", "unknown", "bank_card"] {
        let payload = json!({ "issuer": issuer, "msisdn": "01023456789", "amount": 100 });
        assert_grpc_code(&service, "PayoutsCashinWallet", &payload, Code::InvalidArgument).await;
    }
}

#[tokio::test]
async fn security_tampered_hmac_and_malformed_hex_rejected() {
    let server = PaymobMockServer::start().await;
    let service = build_grpc_service(&server);
    let mut tampered = SAMPLE_TX_192036465_HMAC.to_owned();
    tampered.replace_range(0..4, "0000");
    let hex_res = service
        .webhook_engine
        .verify_transaction_post(OFFICIAL_TX_192036465_JSON, "bad-hex!");
    assert!(matches!(hex_res, Err(WebhookError::MalformedSignatureHex)));
    let bad_wh = json!({ "hmac": tampered, "raw_body": OFFICIAL_TX_192036465_JSON });
    let bad_hex = json!({ "hmac": "bad-hex!", "raw_body": OFFICIAL_TX_192036465_JSON });
    assert_grpc_code(&service, "VerifyWebhookEvent", &bad_wh, Code::Unauthenticated).await;
    assert_grpc_code(&service, "UnifiedVerifyWebhook", &bad_wh, Code::Unauthenticated).await;
    assert_grpc_code(&service, "VerifyWebhookEvent", &bad_hex, Code::InvalidArgument).await;
}

#[tokio::test]
async fn security_duplicate_webhook_replay_rejected() {
    let server = PaymobMockServer::start().await;
    let service = build_grpc_service(&server);
    let valid_wh = json!({
        "hmac": SAMPLE_TX_192036465_HMAC,
        "raw_body": OFFICIAL_TX_192036465_JSON
    });
    let malformed = grpc_unary_raw(
        service.clone(),
        "VerifyWebhookEvent",
        "{malformed".to_owned(),
    )
    .await
    .expect_err("malformed json must fail");
    assert_eq!(malformed.code(), Code::InvalidArgument);
    assert!(grpc_call(service.clone(), "UnifiedVerifyWebhook", &valid_wh).await.is_ok());
    assert_grpc_code(&service, "UnifiedVerifyWebhook", &valid_wh, Code::AlreadyExists).await;
    assert_grpc_code(&service, "VerifyWebhookEvent", &valid_wh, Code::AlreadyExists).await;
}

#[tokio::test]
async fn security_secret_redaction_in_debug_output() {
    let server = PaymobMockServer::start().await;
    let config = build_test_config(&server);
    let creds = PayoutsCredentials::new("cid", "super-secret-csec", "user", "super-secret-pass")
        .expect("valid creds");
    let config_dbg = format!("{config:?}");
    let creds_dbg = format!("{creds:?}");
    assert!(config_dbg.contains("[REDACTED]"));
    assert!(creds_dbg.contains("[REDACTED]"));
    assert!(!config_dbg.contains("egy_sk_test_tonic_unit5"));
    assert!(!config_dbg.contains(SAMPLE_HMAC_SECRET));
    assert!(!creds_dbg.contains("super-secret-csec"));
    assert!(!creds_dbg.contains("super-secret-pass"));
}

#[tokio::test]
async fn recovery_regime2_401_cache_eviction_and_single_flight_retry() {
    let server = PaymobMockServer::start().await;
    mount_jwt_expiry_inquiry_mock(&server).await;
    let provider = AcceptJwtProvider::new(&server.accept_uri(), SecretString::from("test_api_key"))
        .expect("valid provider");
    let http = reqwest::Client::new();
    let url = format!("{}/api/ecommerce/orders/transaction_inquiry", server.accept_uri());
    let resp = provider
        .execute_with_retry(|tok| {
            let (c, u) = (http.clone(), url.clone());
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
    assert_eq!(provider.token().await.expect("cached").expose_secret(), "fresh-jwt-2");
}

#[tokio::test]
async fn recovery_regime3_oauth2_refresh_token_and_password_fallback() {
    let server = MockServer::start().await;
    mount_oauth_fallback_mocks(&server).await;
    let creds = PayoutsCredentials::new("cid", "csec", "alice", "s3cr3t").expect("valid creds");
    let cache = Arc::new(TokenCache::with_refresh_margin(Duration::from_secs(3600)));
    cache.store(CachedToken::new(
        "stale-acc",
        Some(SecretString::from("stale-ref")),
        Duration::from_secs(5),
    ));
    let provider = PayoutsOAuthProvider::with_client_and_cache(
        &server.uri(),
        creds.into(),
        reqwest::Client::new(),
        cache,
    )
    .expect("valid oauth provider");
    let tok = provider.access_token().await.expect("password fallback succeeds");
    assert_eq!(tok.expose_secret(), "po-fallback");
}

#[tokio::test]
async fn recovery_http_429_maps_to_resource_exhausted_with_retry_after() {
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
    let service = build_grpc_service(&server);
    service
        .client
        .auth()
        .payouts_cache()
        .store(CachedToken::with_default_ttl("seeded-oauth-jwt", None));
    let status = grpc_err(service, "PayoutsInquiriesBudget", &json!({})).await;
    assert_eq!(status.code(), Code::ResourceExhausted);
    let retry_after = status
        .metadata()
        .get("retry-after-secs")
        .and_then(|val| val.to_str().ok());
    assert_eq!(retry_after, Some("15"));
}

#[tokio::test]
async fn recovery_over_refund_400_maps_to_failed_precondition() {
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
    let service = build_grpc_service(&server);
    let err = service
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
    let req = json!({ "transaction_id": 192_036_465, "amount_cents": 999_999 });
    assert_grpc_code(&service, "ManageRefund", &req, Code::FailedPrecondition).await;
}

#[tokio::test]
async fn recovery_http_404_and_5xx_map_to_not_found_and_unavailable() {
    let server = PaymobMockServer::start().await;
    server
        .mount_json(JsonEndpointMockConfig {
            host: MockHost::Accept,
            http_method: "GET",
            endpoint_path: "/api/acceptance/transactions/404040",
            status: 404,
            body: json!({ "detail": "Not found." }),
        })
        .await;
    server
        .mount_json(JsonEndpointMockConfig {
            host: MockHost::Accept,
            http_method: "GET",
            endpoint_path: "/api/acceptance/transactions/503503",
            status: 503,
            body: json!({ "detail": "Service unavailable." }),
        })
        .await;
    let service = build_grpc_service(&server);
    assert_grpc_code(&service, "InquiryByTxId", &json!({ "tx_id": 404_040 }), Code::NotFound).await;
    assert_grpc_code(&service, "InquiryByTxId", &json!({ "tx_id": 503_503 }), Code::Unavailable)
        .await;
}

#[tokio::test]
async fn negative_test_live_environment_mismatch_maps_to_failed_precondition() {
    let err = ClientConfig::builder()
        .region(PaymobRegion::Egypt)
        .secret_key(SecretKey::new("egy_sk_test_unit5").expect("valid test sk"))
        .public_key(PublicKey::new("egy_pk_live_unit5").expect("valid live pk"))
        .build()
        .expect_err("mixed test/live keys must fail");
    assert!(matches!(err, PaymobError::EnvironmentMismatch(_)));
    let server = PaymobMockServer::start().await;
    let service = build_grpc_service(&server);
    let sandbox_req = json!({
        "is_sandbox": true,
        "credential_age_days": 0,
        "channel": "live_only"
    });
    let status = grpc_err(service, "SandboxCheck", &sandbox_req).await;
    assert!(matches!(
        status.code(),
        Code::FailedPrecondition | Code::InvalidArgument
    ));
}

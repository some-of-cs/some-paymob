#![forbid(unsafe_code)]
//! Integration tests for `US-3.1.0`: Payment Management (Refund, Void, Auth/Capture).
//!
//! Covers `AC-1..4` and `TC-3.1.1..4` end-to-end against `wiremock` HTTP mocks.

use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use some_paymob::core::client::PaymobClient;
use some_paymob::core::config::ClientConfig;
use some_paymob::core::credentials::{ApiKey, SecretKey};
use some_paymob::core::error::PaymobError;
use some_paymob::core::region::PaymobRegion;
use some_paymob::resources::manage::models::{Transaction, TransactionSourceData};
use some_paymob::resources::manage::refund::RefundParams;
use some_paymob::resources::manage::void_capture::{CaptureParams, VoidParams};

fn build_client(base_url: &str, legacy_v2_capture: bool) -> PaymobClient {
    let region = PaymobRegion::Custom {
        accept_base_url: base_url.to_owned(),
        checkout_base_url: base_url.to_owned(),
        payouts_base_url: None,
        payouts_staging_base_url: None,
    };
    let config = ClientConfig::builder()
        .region(region)
        .secret_key(SecretKey::new("egy_sk_test_us310_integration").expect("valid secret key"))
        .api_key(
            ApiKey::new("ZXlKaGJHY2lPaUpJVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5").expect("valid api key"),
        )
        .use_legacy_v2_bearer_for_capture(legacy_v2_capture)
        .max_retries(0)
        .build()
        .expect("valid config");
    PaymobClient::new(config).expect("valid client")
}

#[tokio::test]
async fn ac1_tc311_tc312_partial_and_full_refund_returns_child_transaction() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/acceptance/void_refund/refund"))
        .and(header(
            "authorization",
            "Token egy_sk_test_us310_integration",
        ))
        .and(body_json(serde_json::json!({
            "transaction_id": 192036465,
            "amount_cents": 25000
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": 192036466,
            "pending": false,
            "amount_cents": 25000,
            "success": true,
            "is_auth": false,
            "is_capture": false,
            "is_void": false,
            "is_refund": true,
            "is_voided": false,
            "is_refunded": false,
            "is_captured": false,
            "parent_transaction": 192036465,
            "refunded_amount_cents": 0,
            "captured_amount": 0,
            "integration_id": 12345,
            "currency": "EGP",
            "source_data": {
                "type": "card",
                "pan": "2346",
                "sub_type": "MasterCard"
            },
            "order": {
                "id": 889900,
                "amount_cents": 100000,
                "currency": "EGP"
            },
            "created_at": "2026-11-16T18:00:00Z"
        })))
        .mount(&server)
        .await;

    let client = build_client(&server.uri(), false);
    let tx: Transaction = client
        .manage()
        .refund(RefundParams::new(192_036_465, 25_000))
        .await
        .expect("refund succeeds");

    assert_eq!(tx.id, 192_036_466);
    assert!(tx.is_refund);
    assert_eq!(tx.parent_transaction, Some(192_036_465));
    assert_eq!(tx.amount_cents, 25_000);
    assert_eq!(tx.order_id(), Some(889_900));
}

#[tokio::test]
async fn ac2_tc312_over_refund_maps_to_refund_exceeds_permissible_amount() {
    let server = MockServer::start().await;
    let gateway_msg = "Requested Refund Amount is greater than the maximum refund amount permissible. Maximum Refund Amount is EGP 100.0";
    Mock::given(method("POST"))
        .and(path("/api/acceptance/void_refund/refund"))
        .respond_with(
            ResponseTemplate::new(400).set_body_json(serde_json::json!({ "message": gateway_msg })),
        )
        .mount(&server)
        .await;

    let client = build_client(&server.uri(), false);
    let err = client
        .manage()
        .refund(RefundParams::new(192_036_465, 200_000))
        .await
        .expect_err("over-refund must fail");

    assert_eq!(
        err,
        PaymobError::RefundExceedsPermissibleAmount {
            message: gateway_msg.to_owned()
        }
    );
}

#[tokio::test]
async fn ac3_tc313_void_and_capture_support_regime1_and_legacy_v2_bearer() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/acceptance/void_refund/void"))
        .and(header(
            "authorization",
            "Token egy_sk_test_us310_integration",
        ))
        .and(body_json(serde_json::json!({ "transaction_id": 574588 })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": 574589,
            "amount_cents": 1000,
            "success": true,
            "is_void": true,
            "is_voided": true,
            "parent_transaction": 574588
        })))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/api/auth/tokens"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "token": "jwt_legacy_v2_integration"
        })))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/api/acceptance/capture"))
        .and(header("authorization", "Bearer jwt_legacy_v2_integration"))
        .and(body_json(serde_json::json!({
            "transaction_id": 574588,
            "amount_cents": 1000
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": 574590,
            "amount_cents": 1000,
            "success": true,
            "is_capture": true,
            "is_captured": true,
            "captured_amount": 1000,
            "parent_transaction": 574588
        })))
        .mount(&server)
        .await;

    let regime1_client = build_client(&server.uri(), false);
    let void_tx = regime1_client
        .manage()
        .void(VoidParams::new(574_588))
        .await
        .expect("void succeeds");
    assert!(void_tx.is_void);
    assert_eq!(void_tx.parent_transaction, Some(574_588));

    let legacy_client = build_client(&server.uri(), true);
    let capture_tx = legacy_client
        .manage()
        .capture(CaptureParams::new(574_588, 1_000))
        .await
        .expect("legacy v2 capture succeeds");
    assert!(capture_tx.is_capture);
    assert_eq!(capture_tx.captured_amount, 1_000);
    assert_eq!(capture_tx.parent_transaction, Some(574_588));
}

#[test]
fn ac4_tc314_redacts_pan_and_secrets_in_debug_output() {
    let source = TransactionSourceData {
        source_type: Some(String::from("card")),
        pan: Some(String::from("5123450000002346")),
        sub_type: Some(String::from("MasterCard")),
    };
    let debug_str = format!("{source:?}");
    assert!(debug_str.contains("[REDACTED]"));
    assert!(!debug_str.contains("5123450000002346"));
    assert!(!debug_str.contains("2346"));

    let client = build_client("https://accept.paymob.com", false);
    let client_debug = format!("{client:?}");
    assert!(client_debug.contains("[REDACTED]"));
    assert!(!client_debug.contains("egy_sk_test_us310_integration"));
}

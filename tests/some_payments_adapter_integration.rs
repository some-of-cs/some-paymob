#![forbid(unsafe_code)]
#![cfg(feature = "some-payments-adapter")]
//! Integration tests for `US-8.1.0`: `some-payments` Unified Gateway Trait
//! Implementations & `PaymobExt` Escape Hatch.

use secrecy::SecretString;
use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use some_paymob::adapter::{
    HeadlessExecutionOption, PaymentProvider, PaymobExt, PayoutProvider, ProviderExt,
    UnifiedCaptureRequest, UnifiedPaymentSessionRequest, UnifiedPayoutRequest,
    UnifiedRefundRequest, UnifiedSavedMethodChargeRequest, UnifiedVoidRequest,
    UnifiedWebhookInput, WebhookVerifier,
};
use some_paymob::core::client::PaymobClient;
use some_paymob::core::config::ClientConfig;
use some_paymob::core::credentials::{ApiKey, SecretKey};
use some_paymob::core::region::PaymobRegion;
use some_paymob::core::types::{Currency, MinorUnitAmount};
use some_paymob::resources::splits::models::SplitRecipientRule;

fn build_mock_client(base_url: &str) -> PaymobClient {
    let region = PaymobRegion::Custom {
        accept_base_url: base_url.to_owned(),
        checkout_base_url: base_url.to_owned(),
        payouts_base_url: base_url.to_owned(),
        payouts_staging_base_url: base_url.to_owned(),
    };
    let config = ClientConfig::builder()
        .region(region)
        .secret_key(SecretKey::new("egy_sk_test_us810_integration").expect("secret key"))
        .api_key(ApiKey::new("ZXlKaGJHY2lPaUpJVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5").expect("api key"))
        .max_retries(0)
        .build()
        .expect("valid config");
    PaymobClient::new(config).expect("valid client")
}

#[tokio::test]
async fn ac1_create_payment_session_and_paymob_ext_wire_into_intention() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/intention/"))
        .and(header(
            "authorization",
            "Token egy_sk_test_us810_integration",
        ))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": "pi_us810_001",
            "intention_order_id": 990011,
            "client_secret": "egy_csk_test_secret_810",
            "payment_keys": [],
            "payment_methods": [],
            "special_reference": "ORD-810",
            "confirmed": false,
            "status": "intended"
        })))
        .mount(&server)
        .await;

    let client = build_mock_client(&server.uri());
    let ext = ProviderExt::Paymob(
        PaymobExt::new()
            .with_pre_selected_plan(42)
            .with_special_reference("ORD-810")
            .with_split_description(vec![SplitRecipientRule::fixed("sub_merchant_1", 5_000)]),
    );
    let base_req = UnifiedPaymentSessionRequest::new(MinorUnitAmount::new(15_000), Currency::EGP)
        .with_payment_methods(vec!["4097558".to_owned()]);
    let wired_req = ext
        .paymob()
        .expect("paymob ext")
        .apply_to_session_request(base_req)
        .expect("wired request");

    let session = client
        .create_payment_session(&wired_req)
        .await
        .expect("session created");

    assert_eq!(session.session_id, "pi_us810_001");
    assert_eq!(session.order_id, "990011");
    assert_eq!(session.status, "intended");
    assert!(!session.confirmed);
    assert!(session.checkout_url.contains("egy_csk_test_secret_810"));

    let dbg = format!("{session:?}");
    assert!(!dbg.contains("egy_csk_test_secret_810"));
    assert!(dbg.contains("[REDACTED]"));
}

#[tokio::test]
async fn ac1_capture_refund_and_void_delegate_to_manage_service() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/acceptance/capture"))
        .and(body_json(serde_json::json!({
            "transaction_id": 1001,
            "amount_cents": 5000
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": 1002,
            "pending": false,
            "amount_cents": 5000,
            "success": true,
            "is_capture": true,
            "is_captured": true
        })))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/api/acceptance/void_refund/refund"))
        .and(body_json(serde_json::json!({
            "transaction_id": 1002,
            "amount_cents": 2500
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": 1003,
            "pending": false,
            "amount_cents": 2500,
            "success": true,
            "is_refund": true,
            "is_refunded": true
        })))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/api/acceptance/void_refund/void"))
        .and(body_json(serde_json::json!({
            "transaction_id": 1004
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": 1005,
            "pending": false,
            "amount_cents": 5000,
            "success": true,
            "is_void": true,
            "is_voided": true
        })))
        .mount(&server)
        .await;

    let client = build_mock_client(&server.uri());

    let cap = client
        .capture_payment(&UnifiedCaptureRequest::new(1001, MinorUnitAmount::new(5000)))
        .await
        .expect("capture");
    assert_eq!(cap.transaction_id, 1002);
    assert_eq!(cap.amount.as_u64(), 5000);
    assert!(cap.success);

    let refund = client
        .refund_payment(&UnifiedRefundRequest::new(1002, MinorUnitAmount::new(2500)))
        .await
        .expect("refund");
    assert_eq!(refund.refund_id, 1003);
    assert_eq!(refund.amount.as_u64(), 2500);
    assert!(refund.is_refunded);

    let voided = client
        .void_payment(&UnifiedVoidRequest::new(1004))
        .await
        .expect("void");
    assert_eq!(voided.transaction_id, 1005);
    assert!(voided.is_voided);
}

#[tokio::test]
async fn ac2_charge_saved_method_delegates_to_headless_mit_pay() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/acceptance/payments/pay"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": 778899,
            "pending": false,
            "amount_cents": 12000,
            "success": true,
            "is_auth": false,
            "is_capture": false,
            "is_void": false,
            "is_refund": false
        })))
        .mount(&server)
        .await;

    let client = build_mock_client(&server.uri());
    let req = UnifiedSavedMethodChargeRequest::new(
        SecretString::from("payment_key_test_810"),
        SecretString::from("saved_card_token_810"),
    );
    let receipt = client
        .charge_saved_method(&req)
        .await
        .expect("mit charge succeeds");

    assert_eq!(receipt.transaction_id, 778899);
    assert_eq!(receipt.amount.as_u64(), 12_000);
    assert!(receipt.success);
}

#[tokio::test]
async fn ac3_and_ac4_headless_options_and_fail_closed_webhook_and_payout() {
    let ext = PaymobExt::new().with_mobile_wallet("01012345678");
    assert!(matches!(
        ext.headless_execution,
        Some(HeadlessExecutionOption::MobileWallet { .. })
    ));
    let dbg = format!("{ext:?}");
    assert!(!dbg.contains("01012345678"));
    assert!(dbg.contains("[REDACTED]"));

    let client = build_mock_client("https://accept.paymob.com");
    let wh_err = client.verify_webhook(&UnifiedWebhookInput::new("{}", None));
    assert!(wh_err.is_err());

    let payout_err = client
        .execute_payout(&UnifiedPayoutRequest::new(
            "01012345678",
            MinorUnitAmount::new(5_000),
            Currency::EGP,
            "vodafone",
        ))
        .await;
    assert!(payout_err.is_err());
}

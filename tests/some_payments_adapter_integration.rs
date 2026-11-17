#![forbid(unsafe_code)]
#![cfg(feature = "some-payments-adapter")]
//! Integration tests for `US-8.1.0`: `some-payments` Unified Gateway Trait
//! Implementations & `PaymobExt` Escape Hatch.

use secrecy::SecretString;
use wiremock::matchers::{body_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use some_paymob::adapter::{
    HeadlessExecutionOption, PaymentProvider, PaymobExt, PayoutProvider, ProviderExt,
    UnifiedCaptureRequest, UnifiedPaymentSession, UnifiedPaymentSessionRequest,
    UnifiedPayoutRequest, UnifiedRefundRequest, UnifiedSavedMethodChargeRequest,
    UnifiedVoidRequest, UnifiedWebhookInput, WebhookVerifier, build_intention_params,
};
use some_paymob::core::client::PaymobClient;
use some_paymob::core::config::ClientConfig;
use some_paymob::core::credentials::{ApiKey, SecretKey};
use some_paymob::core::error::PaymobError;
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
async fn ac1_and_ac3_paymob_ext_wires_into_intention_params_and_redacts_session() {
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

    let params = build_intention_params(&wired_req).expect("valid intention params");
    assert_eq!(params.special_reference(), Some("ORD-810"));
    assert_eq!(params.pre_selected_plan(), Some(42));
    assert!(wired_req.extras.is_some());

    let client = build_mock_client("http://127.0.0.1:9");
    let https_err = client.create_payment_session(&wired_req).await;
    assert!(matches!(
        https_err,
        Err(PaymobError::ValidationError {
            field: "http_config",
            ..
        })
    ));

    let session = UnifiedPaymentSession {
        session_id: "pi_us810_001".to_owned(),
        order_id: "990011".to_owned(),
        client_secret: SecretString::from("egy_csk_test_secret_810"),
        checkout_url:
            "https://accept.paymob.com/unifiedcheckout/?clientSecret=egy_csk_test_secret_810"
                .to_owned(),
        status: "intended".to_owned(),
        confirmed: false,
    };
    let dbg = format!("{session:?}");
    assert!(!dbg.contains("egy_csk_test_secret_810"));
    assert!(dbg.contains("[REDACTED]"));
}

async fn start_manage_mock(
    endpoint: &str,
    expected_body: serde_json::Value,
    response_body: serde_json::Value,
) -> (MockServer, PaymobClient) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(endpoint))
        .and(body_json(expected_body))
        .respond_with(ResponseTemplate::new(200).set_body_json(response_body))
        .mount(&server)
        .await;
    let client = build_mock_client(&server.uri());
    (server, client)
}

#[tokio::test]
async fn ac1_capture_delegates_to_manage_service() {
    let (_server, client) = start_manage_mock(
        "/api/acceptance/capture",
        serde_json::json!({ "transaction_id": 1001, "amount_cents": 5000 }),
        serde_json::json!({
            "id": 1002, "pending": false, "amount_cents": 5000,
            "success": true, "is_capture": true, "is_captured": true
        }),
    )
    .await;

    let cap = client
        .capture_payment(&UnifiedCaptureRequest::new(1001, MinorUnitAmount::new(5000)))
        .await
        .expect("capture");
    assert_eq!(cap.transaction_id, 1002);
    assert_eq!(cap.amount.as_u64(), 5000);
    assert!(cap.success);
}

#[tokio::test]
async fn ac1_refund_delegates_to_manage_service() {
    let (_server, client) = start_manage_mock(
        "/api/acceptance/void_refund/refund",
        serde_json::json!({ "transaction_id": 1002, "amount_cents": 2500 }),
        serde_json::json!({
            "id": 1003, "pending": false, "amount_cents": 2500,
            "success": true, "is_refund": true, "is_refunded": true
        }),
    )
    .await;

    let refund = client
        .refund_payment(&UnifiedRefundRequest::new(1002, MinorUnitAmount::new(2500)))
        .await
        .expect("refund");
    assert_eq!(refund.refund_id, 1003);
    assert_eq!(refund.amount.as_u64(), 2500);
    assert!(refund.is_refunded);
}

#[tokio::test]
async fn ac1_void_delegates_to_manage_service() {
    let (_server, client) = start_manage_mock(
        "/api/acceptance/void_refund/void",
        serde_json::json!({ "transaction_id": 1004 }),
        serde_json::json!({
            "id": 1005, "pending": false, "amount_cents": 5000,
            "success": true, "is_void": true, "is_voided": true
        }),
    )
    .await;

    let voided = client
        .void_payment(&UnifiedVoidRequest::new(1004))
        .await
        .expect("void");
    assert_eq!(voided.transaction_id, 1005);
    assert!(voided.is_voided);
}

#[tokio::test]
async fn ac2_charge_saved_method_redacts_secrets_and_enforces_https() {
    let client = build_mock_client("http://127.0.0.1:9");
    let req = UnifiedSavedMethodChargeRequest::new(
        SecretString::from("payment_key_test_810"),
        SecretString::from("saved_card_token_810"),
    )
    .with_cvn("999");
    let dbg = format!("{req:?}");
    assert!(!dbg.contains("payment_key_test_810"));
    assert!(!dbg.contains("saved_card_token_810"));
    assert!(!dbg.contains("999"));
    assert!(dbg.contains("[REDACTED]"));

    let res = client.charge_saved_method(&req).await;
    assert!(matches!(
        res,
        Err(PaymobError::ValidationError {
            field: "http_config",
            ..
        })
    ));
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

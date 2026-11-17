#![forbid(unsafe_code)]
#![cfg(feature = "some-payments-adapter")]
//! Integration tests for `US-8.1.0`: `some-payments` Unified Gateway Trait
//! Implementations & `PaymobExt` Escape Hatch.

use secrecy::SecretString;
use wiremock::matchers::{body_json, body_partial_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use some_paymob::adapter::{
    HeadlessExecutionOption, PaymentProvider, PaymobExt, PayoutProvider, ProviderExt,
    SubscriptionProvider, UnifiedCaptureRequest, UnifiedPaymentSession,
    UnifiedPaymentSessionRequest, UnifiedPayoutRequest, UnifiedRefundRequest,
    UnifiedSavedMethodChargeRequest, UnifiedSubscriptionRefundRequest, UnifiedVoidRequest,
    UnifiedWebhookInput, UnifiedWebhookKind, WebhookVerifier, build_intention_params,
};
use some_paymob::core::auth::CachedToken;
use some_paymob::core::client::PaymobClient;
use some_paymob::core::config::ClientConfig;
use some_paymob::core::credentials::{ApiKey, HmacSecret, PublicKey, SecretKey};
use some_paymob::core::error::PaymobError;
use some_paymob::core::region::PaymobRegion;
use some_paymob::core::types::{Currency, MinorUnitAmount};
use some_paymob::resources::splits::models::SplitRecipientRule;

fn build_mock_client(base_url: &str) -> PaymobClient {
    let region = PaymobRegion::Custom {
        accept_base_url: base_url.to_owned(),
        checkout_base_url: format!("{base_url}/unifiedcheckout"),
        payouts_base_url: base_url.to_owned(),
        payouts_staging_base_url: base_url.to_owned(),
    };
    let config = ClientConfig::builder()
        .region(region)
        .secret_key(SecretKey::new("egy_sk_test_us810_integration").expect("secret key"))
        .public_key(PublicKey::new("egy_pk_test_us810_integration").expect("public key"))
        .api_key(ApiKey::new("ZXlKaGJHY2lPaUpJVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5").expect("api key"))
        .hmac_secret(HmacSecret::new("3qUAg2xx6JW89Qav5GzzmXoalgjf5XxE").expect("hmac secret"))
        .max_retries(0)
        .build()
        .expect("valid config");
    PaymobClient::new(config).expect("valid client")
}

fn assert_https_required<T: std::fmt::Debug>(res: Result<T, PaymobError>) {
    assert!(matches!(
        res,
        Err(PaymobError::ValidationError {
            field: "http_config",
            ..
        })
    ));
}

async fn assert_manage_op<T, F, Fut>(
    endpoint: &str,
    expected_body: serde_json::Value,
    response_body: serde_json::Value,
    call: F,
) -> T
where
    F: FnOnce(PaymobClient) -> Fut,
    Fut: std::future::Future<Output = Result<T, PaymobError>>,
{
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(endpoint))
        .and(body_json(expected_body))
        .respond_with(ResponseTemplate::new(200).set_body_json(response_body))
        .mount(&server)
        .await;
    call(build_mock_client(&server.uri()))
        .await
        .expect("manage operation")
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
        .with_payment_methods(vec!["4097558".to_owned()])
        .with_customer_contact("buyer@example.com", "+201001234567")
        .with_customer_name("Oscar", "Arena");
    let wired_req = ext
        .paymob()
        .expect("paymob ext")
        .apply_to_session_request(base_req)
        .expect("wired request");

    let params = build_intention_params(&wired_req).expect("valid intention params");
    assert_eq!(params.special_reference(), Some("ORD-810"));
    assert_eq!(params.pre_selected_plan(), Some(42));
    assert!(params.billing_data().is_some());
    assert!(params.customer().is_some());
    assert!(wired_req.extras.is_some());

    let client = build_mock_client("http://untrusted-gateway.local");
    assert_https_required(client.create_payment_session(&wired_req).await);

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

#[tokio::test]
async fn ac1_capture_refund_and_void_delegate_to_manage_service() {
    let cap = assert_manage_op(
        "/api/acceptance/capture",
        serde_json::json!({ "transaction_id": 1001, "amount_cents": 5000 }),
        serde_json::json!({
            "id": 1002, "pending": false, "amount_cents": 5000,
            "success": true, "is_capture": true, "is_captured": true
        }),
        |c| async move {
            c.capture_payment(&UnifiedCaptureRequest::new(
                1001,
                MinorUnitAmount::new(5000),
            ))
            .await
        },
    )
    .await;
    assert_eq!(
        (cap.transaction_id, cap.amount.as_u64(), cap.success),
        (1002, 5000, true)
    );

    let refund = assert_manage_op(
        "/api/acceptance/void_refund/refund",
        serde_json::json!({ "transaction_id": 1002, "amount_cents": 2500 }),
        serde_json::json!({
            "id": 1003, "pending": false, "amount_cents": 2500,
            "success": true, "is_refund": true, "is_refunded": true
        }),
        |c| async move {
            c.refund_payment(&UnifiedRefundRequest::new(1002, MinorUnitAmount::new(2500)))
                .await
        },
    )
    .await;
    assert_eq!(
        (refund.refund_id, refund.amount.as_u64(), refund.is_refunded),
        (1003, 2500, true)
    );

    let voided = assert_manage_op(
        "/api/acceptance/void_refund/void",
        serde_json::json!({ "transaction_id": 1004 }),
        serde_json::json!({
            "id": 1005, "pending": false, "amount_cents": 5000,
            "success": true, "is_void": true, "is_voided": true
        }),
        |c| async move { c.void_payment(&UnifiedVoidRequest::new(1004)).await },
    )
    .await;
    assert_eq!((voided.transaction_id, voided.is_voided), (1005, true));
}

#[tokio::test]
async fn ac2_charge_saved_method_redacts_secrets_and_enforces_https() {
    let client = build_mock_client("http://untrusted-gateway.local");
    client
        .auth()
        .accept_cache()
        .store(CachedToken::with_default_ttl("seeded-accept-jwt", None));
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

    assert_https_required(client.charge_saved_method(&req).await);
}

#[tokio::test]
async fn ac2_payout_provider_delegates_to_payouts_service() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/secure/disburse/"))
        .and(body_partial_json(serde_json::json!({
            "issuer": "vodafone",
            "msisdn": "01012345678",
            "amount": 5000,
            "client_reference_id": "payout-ref-810"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "transaction_id": "tx_payout_810",
            "issuer": "vodafone",
            "amount": 5000,
            "disbursement_status": "successful"
        })))
        .mount(&server)
        .await;

    let client = build_mock_client(&server.uri());
    client
        .auth()
        .payouts_cache()
        .store(CachedToken::with_default_ttl("seeded-payouts-bearer", None));

    let req = UnifiedPayoutRequest::new(
        "01012345678",
        MinorUnitAmount::new(5_000),
        Currency::EGP,
        "vodafone",
    )
    .with_reference("payout-ref-810");

    let receipt = client
        .execute_payout(&req)
        .await
        .expect("payout succeeds via PayoutsService");
    assert_eq!(receipt.payout_id, "tx_payout_810");
    assert_eq!(receipt.amount, MinorUnitAmount::new(5_000));
    assert_eq!(receipt.status, "successful");
    assert_eq!(receipt.issuer, "vodafone");
}

#[tokio::test]
async fn ac4_payout_provider_rejects_invalid_msisdn_and_bank_only_issuer() {
    let client = build_mock_client("https://accept.paymob.com");
    let bad_msisdn = UnifiedPayoutRequest::new(
        "123",
        MinorUnitAmount::new(5_000),
        Currency::EGP,
        "vodafone",
    );
    assert!(matches!(
        client.execute_payout(&bad_msisdn).await,
        Err(PaymobError::ValidationError {
            field: "msisdn",
            ..
        })
    ));

    let bank_only = UnifiedPayoutRequest::new(
        "01012345678",
        MinorUnitAmount::new(5_000),
        Currency::EGP,
        "instant_bank",
    );
    assert!(matches!(
        client.execute_payout(&bank_only).await,
        Err(PaymobError::ValidationError {
            field: "issuer",
            ..
        })
    ));
}

#[tokio::test]
async fn ac2_and_ac3_webhook_verifier_subscription_refund_and_headless_options() {
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

    let sub_json = r#"{
        "paymob_request_id": "df9e4ecf-12e0-4925-b258-65423f32bc98",
        "subscription_data": { "id": 1264, "state": "suspended", "amount_cents": 330 },
        "trigger_type": "suspended",
        "hmac": "8b71a98409eeb1540e400a69d4f776ca93ef2a109e72c7e76651b1d306c39b77b8417f073b9d5fb98d45df8c390ebbd71d85ce18916250c465f578daef63022a"
    }"#;
    let outcome = client
        .verify_webhook(&UnifiedWebhookInput::new(sub_json, None))
        .expect("valid subscription webhook");
    assert_eq!(outcome.kind, UnifiedWebhookKind::SubscriptionLifecycle);
    assert_eq!(outcome.correlation_id, "1264");

    assert!(
        client
            .refund_last_transaction(&UnifiedSubscriptionRefundRequest::new(0, None))
            .await
            .is_err()
    );
}

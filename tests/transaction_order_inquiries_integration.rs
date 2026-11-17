#![forbid(unsafe_code)]
#![cfg(feature = "inquiries")]
//! Cross-unit integration tests for `US-3.2.0` (Transaction, Order & Saved Card
//! Token Reconciliation Inquiries), covering `AC-1..4` and `TC-3.2.1..5`.

use secrecy::ExposeSecret;
use serde_json::json;
use wiremock::matchers::{body_partial_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use some_paymob::core::client::PaymobClient;
use some_paymob::core::config::ClientConfig;
use some_paymob::core::credentials::ApiKey;
use some_paymob::core::error::PaymobError;
use some_paymob::core::region::PaymobRegion;
use some_paymob::resources::inquiries::by_order::TransactionInquiryParams;

fn build_mock_client(base_url: &str) -> PaymobClient {
    let region = PaymobRegion::Custom {
        accept_base_url: base_url.to_owned(),
        checkout_base_url: format!("{base_url}/unifiedcheckout/"),
        payouts_base_url: base_url.to_owned(),
        payouts_staging_base_url: base_url.to_owned(),
    };
    let config = ClientConfig::builder()
        .region(region)
        .api_key(ApiKey::new("test_integration_api_key").expect("valid api key"))
        .max_retries(0)
        .build()
        .expect("valid config");
    PaymobClient::new(config).expect("valid client")
}

async fn mount_auth_token(server: &MockServer, token: &str) {
    Mock::given(method("POST"))
        .and(path("/api/auth/tokens"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({ "token": token })))
        .mount(server)
        .await;
}

#[tokio::test]
async fn ac1_tc_3_2_1_transaction_inquiry_by_id_with_bearer_header() {
    let server = MockServer::start().await;
    mount_auth_token(&server, "jwt_ac1").await;

    Mock::given(method("GET"))
        .and(path("/api/acceptance/transactions/192036465"))
        .and(header("Authorization", "Bearer jwt_ac1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 192036465,
            "pending": false,
            "amount_cents": 10000,
            "success": true,
            "currency": "EGP",
            "created_at": "2026-11-16T10:00:00Z",
            "order": {
                "id": 212245716,
                "amount_cents": 10000,
                "currency": "EGP",
                "merchant_order_id": "order_estatestack_2026_001",
                "payment_status": "PAID"
            }
        })))
        .mount(&server)
        .await;

    let client = build_mock_client(&server.uri());
    let tx = client
        .inquiries()
        .by_transaction_id(192_036_465)
        .await
        .expect("by_transaction_id should succeed");
    assert_eq!(tx.id, 192_036_465);
    assert_eq!(tx.amount_cents, 10_000);
    assert!(tx.success);
}

#[tokio::test]
async fn ac2_tc_3_2_2_order_and_reference_inquiry_with_body_auth_token() {
    let server = MockServer::start().await;
    mount_auth_token(&server, "jwt_ac2").await;

    Mock::given(method("POST"))
        .and(path("/api/ecommerce/orders/transaction_inquiry"))
        .and(body_partial_json(json!({
            "auth_token": "jwt_ac2",
            "order_id": 212245716
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 192036465,
            "pending": false,
            "amount_cents": 25000,
            "success": true,
            "currency": "EGP",
            "paid_at": "2026-11-16T10:01:00Z",
            "fees": 500,
            "vat": 70,
            "accept_fees_cents_int": 500,
            "vat_cents_int": 70,
            "settlement_amount_cents_int": 24430,
            "is_settled": true,
            "is_reconciled": true,
            "reconciliation_id": 9901,
            "cogs": 1000,
            "installment_info": null,
            "split_description": [{"merchant": "sub_1", "amount_cents": 24430}],
            "is_split_payment": true,
            "allow_cardless_refund": true,
            "public_customer_fingerprint": "fp_sensitive_123"
        })))
        .mount(&server)
        .await;

    let client = build_mock_client(&server.uri());
    let tx = client
        .inquiries()
        .by_order_or_reference(TransactionInquiryParams::by_order_id(212_245_716))
        .await
        .expect("by_order_or_reference should succeed");
    assert_eq!(tx.accept_fees_cents_int, Some(500));
    assert_eq!(tx.vat_cents_int, Some(70));
    assert_eq!(tx.settlement_amount_cents_int, Some(24_430));
    assert!(tx.is_settled);
    assert!(tx.is_reconciled);
    assert!(tx.is_split_payment);

    let dbg = format!("{tx:?}");
    assert!(dbg.contains("[REDACTED]"));
    assert!(!dbg.contains("fp_sensitive_123"));
}

#[tokio::test]
async fn ac3_tc_3_2_3_rejects_empty_params_and_redacts_card_tokens() {
    let server = MockServer::start().await;
    mount_auth_token(&server, "jwt_ac3").await;

    Mock::given(method("POST"))
        .and(path("/api/acceptance/order_card_tokens"))
        .and(body_partial_json(json!({
            "auth_token": "jwt_ac3",
            "order_id": 523360093
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {
                "type": "TOKEN",
                "obj": {
                    "id": 77,
                    "token": "tok_secret_saved_card_001",
                    "masked_pan": "xxxx-xxxx-xxxx-2346",
                    "merchant_id": 4455,
                    "card_subtype": "MasterCard",
                    "created_at": "2026-11-16T10:02:00Z",
                    "email": "reconcile@example.com",
                    "order_id": "523360093",
                    "next_payment_intention": "pi_next_999"
                }
            }
        ])))
        .mount(&server)
        .await;

    let client = build_mock_client(&server.uri());
    let empty_err = client
        .inquiries()
        .by_order_or_reference(TransactionInquiryParams::default())
        .await
        .expect_err("empty params must be rejected locally");
    assert!(matches!(
        empty_err,
        PaymobError::ValidationError {
            field: "order_id",
            ..
        }
    ));

    let tokens = client
        .inquiries()
        .card_tokens_by_order(523_360_093)
        .await
        .expect("card_tokens_by_order should succeed");
    assert_eq!(tokens.len(), 1);
    assert_eq!(
        tokens[0].obj.token.expose_secret(),
        "tok_secret_saved_card_001"
    );

    let dbg = format!("{:?}", tokens[0]);
    assert!(dbg.contains("[REDACTED]"));
    assert!(dbg.contains("xxxx-xxxx-xxxx-2346"));
    assert!(!dbg.contains("tok_secret_saved_card_001"));
    assert!(!dbg.contains("reconcile@example.com"));
}

#[tokio::test]
async fn ac4_tc_3_2_4_tc_3_2_5_order_inquiry_and_redaction() {
    let server = MockServer::start().await;
    mount_auth_token(&server, "jwt_ac4").await;

    Mock::given(method("GET"))
        .and(path("/api/ecommerce/orders/212245716"))
        .and(header("Authorization", "Bearer jwt_ac4"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 212245716,
            "created_at": "2026-11-16T09:50:00Z",
            "delivery_needed": false,
            "amount_cents": 25000,
            "paid_amount_cents": 25000,
            "currency": "EGP",
            "merchant_order_id": "order_estatestack_2026_001",
            "payment_status": "PAID",
            "transactions": [
                {
                    "id": 192036465,
                    "pending": false,
                    "amount_cents": 25000,
                    "success": true,
                    "created_at": "2026-11-16T10:00:00Z",
                    "currency": "EGP"
                }
            ],
            "shipping_data": {
                "first_name": "Maher",
                "last_name": "Alaa",
                "email": "maher@example.com",
                "phone_number": "+201000000000",
                "city": "Mansoura",
                "country": "EG"
            }
        })))
        .mount(&server)
        .await;

    let client = build_mock_client(&server.uri());
    let order = client
        .inquiries()
        .order(212_245_716)
        .await
        .expect("order inquiry should succeed");
    assert_eq!(order.id, 212_245_716);
    assert_eq!(order.transactions.len(), 1);
    assert!(order.transactions[0].success);

    let dbg = format!("{order:?}");
    assert!(dbg.contains("[REDACTED]"));
    assert!(!dbg.contains("maher@example.com"));
    assert!(!dbg.contains("+201000000000"));
}

#[tokio::test]
async fn inquiries_evict_stale_jwt_and_retry_once_on_401_incorrect_credentials() {
    let server = MockServer::start().await;
    mount_auth_token(&server, "jwt_fresh_retry").await;

    Mock::given(method("GET"))
        .and(path("/api/acceptance/transactions/192036465"))
        .and(header("Authorization", "Bearer stale_jwt_token"))
        .respond_with(
            ResponseTemplate::new(401).set_body_json(json!({"detail": "incorrect credentials"})),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/acceptance/transactions/192036465"))
        .and(header("Authorization", "Bearer jwt_fresh_retry"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_transaction_json()))
        .mount(&server)
        .await;

    let client = build_mock_client(&server.uri());
    let stale =
        some_paymob::core::auth::cache::CachedToken::with_default_ttl("stale_jwt_token", None);
    client.auth().accept_cache().store(stale);

    let tx = client
        .inquiries()
        .by_transaction_id(192_036_465)
        .await
        .expect("401 incorrect credentials should evict stale JWT and retry");
    assert_eq!(tx.id, 192_036_465);
}

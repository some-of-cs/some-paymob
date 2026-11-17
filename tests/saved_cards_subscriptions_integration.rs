#![forbid(unsafe_code)]
#![cfg(all(feature = "saved-cards", feature = "subscriptions"))]
//! Integration tests for Module 4 (`US-4.1.0`, `US-4.2.0`, `US-4.3.0`):
//! Saved-card tokenization (`saved_cards()` & `tokens()`), headless payments
//! (`TOKEN`, `WALLET`, `AGGREGATOR` Kiosk), Subscription Plans CRUD, Subscription
//! Lifecycle, Card Vault (`SubscriptionCard`), History, and `refund_last_transaction`.

use secrecy::SecretString;
use serde_json::json;
use some_paymob::prelude::*;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn build_module4_client(base_url: &str) -> PaymobClient {
    let config = ClientConfig::builder()
        .region(PaymobRegion::Custom {
            accept_base_url: base_url.to_owned(),
            checkout_base_url: format!("{base_url}/unifiedcheckout/"),
            payouts_base_url: base_url.to_owned(),
            payouts_staging_base_url: base_url.to_owned(),
        })
        .secret_key(SecretKey::new("egy_sk_test_m4_secret").expect("valid secret key"))
        .api_key(ApiKey::new("egy_api_key_m4_value").expect("valid api key"))
        .max_retries(0)
        .build()
        .expect("valid config");
    let client = PaymobClient::new(config).expect("valid client");
    client
        .auth()
        .accept_cache()
        .store(CachedToken::with_default_ttl("m4_bearer_jwt", None));
    client
}

#[cfg(feature = "saved-cards")]
#[tokio::test]
async fn us_4_1_0_tokens_alias_kiosk_pay_and_moto_cvc_guard() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/acceptance/payments/pay"))
        .and(header("authorization", "Bearer m4_bearer_jwt"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 550011,
            "pending": true,
            "amount_cents": 25000,
            "success": false,
            "currency": "EGP",
            "data": { "bill_reference": "99887766" }
        })))
        .mount(&server)
        .await;

    let client = build_module4_client(&server.uri());
    let kiosk = KioskPayParams::new("pay_tok_kiosk_1").expect("valid kiosk params");
    let resp = client
        .tokens()
        .pay_with_kiosk(&kiosk)
        .await
        .expect("kiosk pay via client.tokens() succeeds");
    assert_eq!(resp.kiosk_bill_reference.as_deref(), Some("99887766"));
    let dbg = format!("{resp:?}");
    assert!(dbg.contains("[REDACTED]"));
    assert!(!dbg.contains("99887766"));

    assert!(validate_use_cvc_with_moto(true, None).is_err());
    let cvn = SecretString::from("123".to_owned());
    assert!(validate_use_cvc_with_moto(false, Some(&cvn)).is_err());
    assert!(validate_use_cvc_with_moto(true, Some(&cvn)).is_ok());
}

#[cfg(feature = "subscriptions")]
#[tokio::test]
async fn us_4_2_0_and_4_3_0_subscription_plans_cards_and_refund_last_transaction() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/acceptance/subscriptions/1264/cards"))
        .and(header("authorization", "Bearer m4_bearer_jwt"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{
            "id": 374,
            "card_data": "Visa",
            "token": "tok_secret_card_374",
            "created_at": "2026-11-17T00:00:00Z",
            "is_primary": true,
            "masked_pan": "xxxx-xxxx-xxxx-2346",
            "failed_attempts": 0
        }])))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/acceptance/subscriptions/1264/last-transaction"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 998877,
            "success": true,
            "pending": false,
            "is_refunded": false,
            "amount_cents": 50000,
            "api_source": "SUBSCRIPTION",
            "currency": "EGP"
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/acceptance/void_refund/refund"))
        .and(header("authorization", "Token egy_sk_test_m4_secret"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": 998878,
            "success": true,
            "pending": false,
            "is_refunded": true,
            "amount_cents": 20000,
            "parent_transaction": 998877
        })))
        .mount(&server)
        .await;

    let client = build_module4_client(&server.uri());
    let cards: Vec<SubscriptionCard> = client
        .subscriptions()
        .cards()
        .list(1264)
        .await
        .expect("list cards succeeds");
    assert_eq!(cards.len(), 1);
    assert!(!format!("{:?}", cards[0]).contains("tok_secret_card_374"));

    let refund = client
        .subscriptions()
        .refund_last_transaction(1264, Some(20_000))
        .await
        .expect("partial refund succeeds");
    assert_eq!(refund.amount_cents, 20_000);
}

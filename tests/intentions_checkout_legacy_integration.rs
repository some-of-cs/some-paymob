#![forbid(unsafe_code)]
#![cfg(feature = "intentions")]
//! Integration tests for Module 2 (`US-2.1.0`, `US-2.2.0`, `US-2.3.0`):
//! v1 Payment Intentions (`POST`/`PUT /v1/intention/`), Unified Checkout, Pixel JS,
//! Affordability Widget, and Legacy Accept v2 3-step checkout flow.

#[cfg(feature = "legacy-v2")]
use secrecy::ExposeSecret;
use secrecy::SecretString;
use serde_json::json;
use some_paymob::prelude::*;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn build_module2_client(base_url: &str) -> PaymobClient {
    let config = ClientConfig::builder()
        .region(PaymobRegion::Custom {
            accept_base_url: base_url.to_owned(),
            checkout_base_url: format!("{base_url}/unifiedcheckout/"),
            payouts_base_url: base_url.to_owned(),
            payouts_staging_base_url: base_url.to_owned(),
        })
        .secret_key(SecretKey::new("egy_sk_test_m2_secret").expect("valid secret key"))
        .public_key(PublicKey::new("egy_pk_test_m2_public").expect("valid public key"))
        .api_key(ApiKey::new("egy_api_key_m2_value").expect("valid api key"))
        .max_retries(0)
        .build()
        .expect("valid config");
    PaymobClient::new(config).expect("valid client")
}

fn sample_intention_response_json() -> serde_json::Value {
    json!({
        "id": "pi_test_990011",
        "intention_order_id": 880011,
        "client_secret": "egy_csk_test_secret_990011",
        "payment_keys": [{
            "integration": 4097558,
            "key": "pk_tok_single_use_990011",
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

fn sample_create_intention_params() -> CreateIntentionParams {
    CreateIntentionParams::builder()
        .amount(MinorUnitAmount::new(100_000))
        .currency(Currency::EGP)
        .payment_methods(vec![PaymentMethodInput::IntegrationId(4_097_558)])
        .items(vec![
            IntentionItem::new("Pro Plan", MinorUnitAmount::new(100_000)).expect("valid item"),
        ])
        .billing_data(
            BillingData::builder()
                .phone_number("+201116491564")
                .first_name("Maher")
                .last_name("Mansour")
                .email("maher@example.com")
                .build()
                .expect("valid billing"),
        )
        .special_reference("ORD-M2-1001")
        .build()
        .expect("valid create params")
}

#[tokio::test]
async fn us_2_1_0_create_and_update_intention_with_checkout_url_and_redaction() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/intention/"))
        .and(header("authorization", "Token egy_sk_test_m2_secret"))
        .respond_with(ResponseTemplate::new(201).set_body_json(sample_intention_response_json()))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/v1/intention/"))
        .and(header("authorization", "Token egy_sk_test_m2_secret"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_intention_response_json()))
        .mount(&server)
        .await;

    let client = build_module2_client(&server.uri());
    let created = client
        .intentions()
        .create(sample_create_intention_params())
        .await
        .expect("create intention succeeds");
    assert_eq!(created.id, "pi_test_990011");
    assert!(!format!("{created:?}").contains("egy_csk_test_secret_990011"));

    let update_params = UpdateIntentionParams::builder()
        .amount(MinorUnitAmount::new(150_000))
        .build()
        .expect("valid update params");
    let updated = client
        .intentions()
        .update(update_params)
        .await
        .expect("update intention succeeds");
    let checkout_url = client
        .checkout()
        .unified_url(&updated.client_secret)
        .expect("unified checkout url builds");
    assert!(
        checkout_url
            .as_str()
            .contains("publicKey=egy_pk_test_m2_public")
    );
}

#[tokio::test]
async fn us_2_1_0_and_2_2_0_environment_parity_pixel_and_affordability_guards() {
    let client = build_module2_client("http://127.0.0.1:9");
    let mismatch_err = client
        .intentions()
        .with_integration_mode(4_097_558, EnvironmentMode::Live)
        .create(sample_create_intention_params())
        .await
        .expect_err("Test secret key with Live integration must fail pre-flight");
    assert!(matches!(
        mismatch_err,
        PaymobError::EnvironmentMismatch { .. }
    ));

    let csk = SecretString::from("egy_csk_test_secret_990011".to_owned());
    let pixel = client
        .checkout()
        .pixel_config(csk)
        .expect("pixel builder")
        .payment_methods([PixelPaymentMethod::Card, PixelPaymentMethod::ApplePay])
        .apple_pay(ApplePaySettings::new("merchant.com.example"))
        .build()
        .expect("valid pixel config");
    assert!(!format!("{pixel:?}").contains("egy_csk_test_secret_990011"));

    let widget = client
        .checkout()
        .affordability_widget(MinorUnitAmount::new(300_000), Currency::EGP)
        .expect("affordability builder")
        .pre_selected_plan(6001)
        .tenure_months(6)
        .build()
        .expect("valid affordability widget");
    assert_eq!(widget.selected_plan_id(), Some(6001));
}

#[cfg(feature = "legacy-v2")]
#[tokio::test]
async fn us_2_3_0_legacy_v2_endpoint_cache_isolation_and_iframe_builder() {
    let client = build_module2_client("http://127.0.0.1:9");
    client
        .auth()
        .accept_cache()
        .store(CachedToken::with_default_ttl("default_endpoint_jwt", None));

    let same_ep = LegacyV2Service::new(client.clone()).expect("default legacy service");
    let tok_same = same_ep
        .generate_auth_token()
        .await
        .expect("reuses default endpoint cache");
    assert_eq!(tok_same.expose_secret(), "default_endpoint_jwt");

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/auth/tokens"))
        .respond_with(
            ResponseTemplate::new(201).set_body_json(json!({ "token": "overridden_endpoint_jwt" })),
        )
        .expect(1)
        .mount(&server)
        .await;

    let overridden =
        LegacyV2Service::with_base_url(client.clone(), server.uri()).expect("overridden service");
    let tok_overridden = overridden
        .generate_auth_token()
        .await
        .expect("fetches isolated token for overridden endpoint");
    assert_eq!(tok_overridden.expose_secret(), "overridden_endpoint_jwt");
    assert_eq!(
        client
            .auth()
            .accept_cache()
            .peek()
            .expect("default cache intact")
            .access_token
            .expose_secret(),
        "default_endpoint_jwt"
    );
}

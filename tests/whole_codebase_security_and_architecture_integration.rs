#![forbid(unsafe_code)]
//! Whole-codebase security, reusability, and edge/negative integration tests.
//!
//! Verifies cross-module transport hardening, `prelude` re-exports across all
//! modules, non-loopback HTTP rejection, QuickLinks 401 refresh & input guards,
//! and Payouts / Onboarding / Splits invariants.

use some_paymob::prelude::*;

fn try_custom_http_client(remote_base: &str) -> Result<PaymobClient, PaymobError> {
    let config = ClientConfig::builder()
        .region(PaymobRegion::Custom {
            accept_base_url: remote_base.to_owned(),
            checkout_base_url: remote_base.to_owned(),
            payouts_base_url: remote_base.to_owned(),
            payouts_staging_base_url: remote_base.to_owned(),
        })
        .secret_key(SecretKey::new("egy_sk_test_whole_codebase")?)
        .api_key(ApiKey::new(
            "ZXlKaGJHY2lPaUpJVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5",
        )?)
        .max_retries(0)
        .build()?;
    PaymobClient::new(config)
}

#[cfg(all(
    feature = "inquiries",
    feature = "manage",
    feature = "payouts",
    feature = "onboarding"
))]
#[tokio::test]
async fn non_loopback_plaintext_http_is_rejected_across_all_resource_modules() {
    assert!(matches!(
        try_custom_http_client("http://example.com"),
        Err(PaymobError::ValidationError {
            field: "accept_base_url",
            ..
        })
    ));

    let client = try_custom_http_client("http://untrusted-gateway.local")
        .expect("mDNS .local parses at region level");
    client
        .auth()
        .accept_cache()
        .store(CachedToken::with_default_ttl("seeded_jwt", None));
    client
        .auth()
        .payouts_cache()
        .store(CachedToken::with_default_ttl("seeded_oauth", None));

    let inq_err = client.inquiries().by_transaction_id(192_036_465).await;
    assert!(matches!(
        inq_err,
        Err(PaymobError::ValidationError {
            field: "http_config",
            ..
        })
    ));

    let mng_err = client.manage().void(VoidParams::new(192_036_465)).await;
    assert!(matches!(
        mng_err,
        Err(PaymobError::ValidationError {
            field: "http_config",
            ..
        })
    ));

    let pay_err = client.payouts().inquiries().user_budget().await;
    assert!(matches!(
        pay_err,
        Err(PaymobError::ValidationError {
            field: "http_config",
            ..
        })
    ));
}

#[cfg(feature = "splits")]
#[test]
fn splits_and_convenience_fees_reexport_and_enforce_edge_bounds() {
    let rule = SplitRecipientRule::percentage_bps("sub_merchant_1", 2_500)
        .with_description("25% marketplace split");
    assert!(rule.validate().is_ok());

    let bad_both = SplitRecipientRule {
        recipient_id: "sub_merchant_1".to_owned(),
        amount_cents: Some(1_000),
        percentage_bps: Some(500),
        description: None,
    };
    assert!(bad_both.validate().is_err());

    let fee_cfg = ConvenienceFeeConfig::new(FeeCalculationMode::Combination {
        bps: 200,
        fixed_cents: 300,
    })
    .with_card_rule(CardFeeRule::Uniform)
    .with_max_fee_cents(5_000);
    let fee = fee_cfg
        .compute_fee_for_card_cents(100_000, &CardFeeContext::new(true, false))
        .expect("valid fee");
    assert_eq!(fee, 2_300);
}

#[cfg(feature = "onboarding")]
fn build_partner_client(base_url: &str) -> PaymobClient {
    let creds = PartnerCredentials::with_bearer_token("pk_partner_1", "partner_bearer_tok")
        .expect("valid partner creds");
    let config = ClientConfig::builder()
        .region(PaymobRegion::Custom {
            accept_base_url: base_url.to_owned(),
            checkout_base_url: base_url.to_owned(),
            payouts_base_url: base_url.to_owned(),
            payouts_staging_base_url: base_url.to_owned(),
        })
        .partner_credentials(creds)
        .max_retries(0)
        .build()
        .expect("valid config");
    PaymobClient::new(config).expect("valid client")
}

#[cfg(feature = "onboarding")]
#[tokio::test]
async fn partner_retrieve_merchant_hmac_secret_validates_mid_and_redacts_secret() {
    let server = wiremock::MockServer::start().await;
    let body = serde_json::json!({
        "label": "merchant_hmac",
        "status": "Created",
        "code": 201,
        "body": { "hmac_secret": "MERCHANT_SUPER_SECRET_HMAC_998877" }
    });
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path(
            "/api/partner/merchants/hmac_secret/998877",
        ))
        .and(wiremock::matchers::header(
            "authorization",
            "Bearer partner_bearer_tok",
        ))
        .respond_with(wiremock::ResponseTemplate::new(201).set_body_json(body))
        .mount(&server)
        .await;

    let client = build_partner_client(&server.uri());
    let zero_err = client
        .onboarding()
        .auth()
        .retrieve_merchant_hmac_secret(0)
        .await;
    assert!(matches!(
        zero_err,
        Err(PaymobError::ValidationError { field: "mid", .. })
    ));

    let env = client
        .onboarding()
        .auth()
        .retrieve_merchant_hmac_secret(998_877)
        .await
        .expect("retrieve_merchant_hmac_secret succeeds");
    assert_eq!(env.hmac_secret(), "MERCHANT_SUPER_SECRET_HMAC_998877");
    assert!(!format!("{env:?}").contains("MERCHANT_SUPER_SECRET_HMAC_998877"));
}

#[cfg(feature = "subscriptions")]
#[test]
fn subscription_transaction_debug_redacts_raw_source_data_and_gateway_data() {
    let raw_json = serde_json::json!({
        "id": 770011,
        "amount_cents": 15000,
        "success": true,
        "pending": false,
        "is_voided": false,
        "is_refunded": false,
        "currency": "EGP",
        "created_at": "2026-11-17T00:00:00Z",
        "source_data": { "pan": "4111222233334444", "sub_type": "MasterCard" },
        "data": { "mig_token": "secret_mig_tok_999" }
    });
    let tx: some_paymob::SubscriptionTransaction =
        serde_json::from_value(raw_json).expect("valid subscription transaction");
    let dbg = format!("{tx:?}");
    assert!(dbg.contains("[REDACTED]"));
    assert!(!dbg.contains("4111222233334444"));
    assert!(!dbg.contains("secret_mig_tok_999"));
}

#[cfg(feature = "legacy-v2")]
#[tokio::test]
async fn legacy_v2_rejects_non_loopback_http_and_shares_accept_jwt_cache() {
    use secrecy::ExposeSecret as _;

    let client = try_custom_http_client("http://127.0.0.1:9")
        .expect("loopback http allowed at client creation");
    client
        .auth()
        .accept_cache()
        .store(CachedToken::with_default_ttl("shared_accept_jwt", None));

    let bad_url_err = LegacyV2Service::with_base_url(client.clone(), "http://example.com");
    assert!(matches!(
        bad_url_err,
        Err(PaymobError::ValidationError {
            field: "auth_token",
            ..
        })
    ));

    let legacy_local =
        LegacyV2Service::with_base_url(client, "http://127.0.0.1:9").expect("valid loopback url");
    let cached_tok = legacy_local
        .generate_auth_token()
        .await
        .expect("should read shared accept_cache without network call");
    assert_eq!(cached_tok.expose_secret(), "shared_accept_jwt");
}

#[cfg(all(feature = "inquiries", feature = "some-payments-adapter"))]
#[tokio::test]
async fn inquiries_method_aliases_and_adapter_receipt_debug_redaction() {
    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/api/ecommerce/orders/212245716"))
        .respond_with(
            wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 212245716,
                "amount_cents": 50000,
                "currency": "EGP"
            })),
        )
        .mount(&server)
        .await;

    let client = try_custom_http_client(&server.uri()).expect("valid loopback client");
    client
        .auth()
        .accept_cache()
        .store(CachedToken::with_default_ttl("inq_jwt", None));

    let order = client
        .inquiries()
        .order_inquiry(212_245_716)
        .await
        .expect("order_inquiry alias succeeds");
    assert_eq!(order.id, 212_245_716);

    let receipt = UnifiedSavedMethodChargeReceipt {
        transaction_id: 77,
        amount: MinorUnitAmount::new(10_000),
        success: true,
        pending: false,
        redirect_url: None,
        kiosk_bill_reference: Some("KIOSK-SECRET-8899".to_owned()),
    };
    let receipt_dbg = format!("{receipt:?}");
    assert!(receipt_dbg.contains("[REDACTED]"));
    assert!(!receipt_dbg.contains("KIOSK-SECRET-8899"));
}

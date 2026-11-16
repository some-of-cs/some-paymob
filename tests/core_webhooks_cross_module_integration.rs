#![forbid(unsafe_code)]
#![cfg(feature = "webhooks")]
//! Cross-module integration suite verifying bridges between `core` (Module 1)
//! and `webhooks` (Module 7).

use some_paymob::core::auth::payouts_oauth::PayoutsOAuthProvider;
use some_paymob::core::auth::{AuthManager, CachedToken};
use some_paymob::core::credentials::PayoutsCredentials as CorePayoutsCredentials;
use some_paymob::webhooks::protocol_b_get::TransactionRedirectParams;
use some_paymob::webhooks::protocol_d_subscription::SubscriptionData;
use some_paymob::webhooks::protocol_e_payouts::{
    DisbursementCallback, DisbursementIssuer, TopupCallback, TopupStatus,
};
use some_paymob::webhooks::tx_models::TransactionProcessedEvent;
use some_paymob::{
    ClientConfig, Currency, MinorUnitAmount, PaymobClient, PaymobError, PaymobRegion,
    PaymobWebhookEngine, WebhookError, WebhookEvent,
};

const TEST_HMAC_SECRET: &str = "3qUAg2xx6JW89Qav5GzzmXoalgjf5XxE";

const PROTOCOL_A_TX_JSON: &str = r#"{
    "obj": {
        "id": 192036465,
        "pending": false,
        "amount_cents": 100000,
        "success": true,
        "is_auth": false,
        "is_capture": false,
        "is_standalone_payment": true,
        "is_voided": false,
        "is_refunded": false,
        "is_3d_secure": true,
        "integration_id": 4097558,
        "has_parent_transaction": false,
        "order": { "id": 217503754 },
        "created_at": "2024-06-13T11:33:44.592345",
        "currency": "EGP",
        "source_data": {
            "pan": "2346",
            "type": "card",
            "sub_type": "MasterCard"
        },
        "error_occured": false,
        "owner": 302852
    }
}"#;

const PROTOCOL_A_TX_HMAC: &str = "28f19ec85986d4534f77201b00bf750948334753847f437b538cc699f3de447cd0d62a5f521c7b20069bd255f48e8d891f0033167ad35b434d532b61e85a3da7";

const PROTOCOL_C_TOKEN_JSON: &str = r#"{
    "type": "TOKEN",
    "obj": {
        "id": 15978654,
        "token": "tok_test_15978654_abcdef",
        "masked_pan": "xxxx-xxxx-xxxx-2346",
        "merchant_id": 302852,
        "card_subtype": "MasterCard",
        "created_at": "2024-06-13T11:33:44.592345",
        "email": "customer@example.com",
        "order_id": "593881581"
    }
}"#;

const PROTOCOL_C_TOKEN_HMAC: &str = "38ac96769330ae1b446ba94220b4a0fbf4a536ff407710d0637b32efc1c17cc17dde92a831467724a16e09ea7b7054806275d78ce726ba243cc2fea25f30be0d";

fn sample_redirect_params() -> TransactionRedirectParams {
    TransactionRedirectParams {
        amount_cents: "25000".to_owned(),
        created_at: "2026-11-16T12:00:00".to_owned(),
        currency: "sar".to_owned(),
        error_occured: "false".to_owned(),
        has_parent_transaction: "false".to_owned(),
        id: "192036465".to_owned(),
        integration_id: "4097558".to_owned(),
        is_3d_secure: "true".to_owned(),
        is_auth: "false".to_owned(),
        is_capture: "false".to_owned(),
        is_refunded: "false".to_owned(),
        is_standalone_payment: "true".to_owned(),
        is_voided: "false".to_owned(),
        order_id: "217503754".to_owned(),
        owner: "302852".to_owned(),
        pending: "false".to_owned(),
        source_data_pan: "2346".to_owned(),
        source_data_sub_type: "MasterCard".to_owned(),
        source_data_type: "card".to_owned(),
        success: "true".to_owned(),
    }
}

fn sample_payout_callbacks() -> (SubscriptionData, DisbursementCallback, TopupCallback) {
    let sub = SubscriptionData {
        id: 1264,
        amount_cents: Some(330),
        ..Default::default()
    };
    let disb = DisbursementCallback {
        transaction_id: "disb_1".to_owned(),
        issuer: DisbursementIssuer::BankWallet,
        amount_cents: 50_000,
        currency: "aed".to_owned(),
        status: "success".to_owned(),
        recipient_identifier: None,
    };
    let topup = TopupCallback {
        topup_id: "top_1".to_owned(),
        amount_cents: 120_000,
        currency: "omr".to_owned(),
        status: TopupStatus::Approved,
    };
    (sub, disb, topup)
}

fn assert_payout_money(disb: &DisbursementCallback, topup: &TopupCallback) {
    assert_eq!(disb.amount(), MinorUnitAmount::new(50_000));
    assert_eq!(disb.parsed_currency(), Currency::AED);
    assert_eq!(topup.amount(), MinorUnitAmount::new(120_000));
    assert_eq!(topup.parsed_currency(), Currency::OMR);
}

fn propagate_webhook_failure(raw_body: &str, hmac: &str) -> Result<WebhookEvent, PaymobError> {
    let engine = PaymobWebhookEngine::new(TEST_HMAC_SECRET)?;
    let event = engine.construct_event(raw_body, Some(hmac))?;
    Ok(event)
}

#[test]
fn client_config_and_paymob_client_webhooks_bridge() -> Result<(), PaymobError> {
    let config = ClientConfig::builder()
        .try_secret_key("egy_sk_test_626supersecret")?
        .try_public_key("egy_pk_test_999public")?
        .try_hmac_secret(format!("  {TEST_HMAC_SECRET}  "))?
        .build()?;
    assert_eq!(config.region(), &PaymobRegion::Egypt);

    let client = PaymobClient::new(config)?;
    let engine = client.webhooks()?;
    let tx_event = engine.construct_event(PROTOCOL_A_TX_JSON, Some(PROTOCOL_A_TX_HMAC))?;
    let tok_event = engine.construct_event(PROTOCOL_C_TOKEN_JSON, Some(PROTOCOL_C_TOKEN_HMAC))?;

    assert!(tx_event.is_transaction_processed());
    assert!(tok_event.is_card_token());
    assert!(client.webhook_engine().is_ok());
    Ok(())
}

#[test]
fn webhook_error_into_paymob_error_question_mark_propagation() {
    let bad_sig = "a".repeat(128);
    let sig_err = propagate_webhook_failure(PROTOCOL_C_TOKEN_JSON, &bad_sig)
        .expect_err("mismatched signature must propagate as PaymobError");
    assert!(sig_err.is_webhook_error());
    assert!(!sig_err.is_retryable());
    assert_eq!(sig_err, PaymobError::from(WebhookError::SignatureMismatch));

    let pan_json = r#"{"type":"TOKEN","obj":{"id":"4111222233334444"}}"#;
    let parse_err = propagate_webhook_failure(pan_json, PROTOCOL_C_TOKEN_HMAC)
        .expect_err("invalid JSON scalar must fail and redact quoted literal");
    let rendered = format!("{parse_err} | {parse_err:?}");
    assert!(rendered.contains("[REDACTED]") && !rendered.contains("4111222233334444"));
}

#[test]
fn webhook_models_minor_unit_amount_and_currency_helpers() {
    let mut tx: TransactionProcessedEvent =
        serde_json::from_str(PROTOCOL_A_TX_JSON).expect("valid transaction JSON");
    tx.obj.refunded_amount_cents = Some(25_000);
    assert_eq!(tx.amount(), MinorUnitAmount::new(100_000));
    assert_eq!(tx.net_settled_amount(), MinorUnitAmount::new(75_000));
    assert_eq!(tx.parsed_currency(), Currency::EGP);

    let redirect = sample_redirect_params();
    assert_eq!(redirect.amount().unwrap(), MinorUnitAmount::new(25_000));
    assert_eq!(redirect.parsed_currency(), Currency::SAR);

    let (sub, disb, topup) = sample_payout_callbacks();
    assert_eq!(sub.amount(), Some(MinorUnitAmount::new(330)));
    assert_payout_money(&disb, &topup);
}

#[test]
fn payouts_credentials_bridge_and_auth_manager() {
    let base = "https://accept.paymob.com";
    let core_creds = CorePayoutsCredentials::new("cid_1", "csec_1", "user_1", "pass_1")
        .expect("valid core payouts credentials");
    let provider = PayoutsOAuthProvider::from_core_credentials(base, &core_creds)
        .expect("valid payouts oauth provider");
    assert_eq!(
        provider.token_url().as_str(),
        "https://accept.paymob.com/api/secure/o/token/"
    );

    let manager = AuthManager::new();
    manager
        .accept_cache()
        .store(CachedToken::with_default_ttl("jwt-1", None));
    manager
        .payouts_cache()
        .store(CachedToken::with_default_ttl("oauth-1", None));
    assert!(manager.accept_cache().peek().is_some() && manager.payouts_cache().peek().is_some());

    manager.invalidate_all();
    assert!(manager.accept_cache().peek().is_none() && manager.payouts_cache().peek().is_none());
}

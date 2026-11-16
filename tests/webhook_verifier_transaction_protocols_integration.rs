//! Integration tests for User Story `US-7.1.0`:
//! Constant-time `HMAC-SHA512` core verifier, Protocol A (`POST` transaction),
//! Protocol B (`GET` redirect), and `WebhookError` classification workflow.

use std::collections::BTreeMap;

use some_paymob::prelude::*;
use some_paymob::{PaymobWebhookEngine, WebhookError, WebhookResult};

const TEST_SECRET: &str = "3qUAg2xx6JW89Qav5GzzmXoalgjf5XxE";

const VECTOR_192036465_JSON: &str = r#"{
    "type": "TRANSACTION",
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
        "is_captured": false,
        "integration_id": 4097558,
        "has_parent_transaction": false,
        "order": { "id": 217503754 },
        "created_at": "2024-06-13T11:33:44.592345",
        "currency": "EGP",
        "source_data": { "pan": "2346", "type": "card", "sub_type": "MasterCard" },
        "error_occured": false,
        "owner": 302852,
        "payment_key_claims": { "email": "secret-buyer@example.com" }
    }
}"#;

const VECTOR_192036465_HMAC: &str =
    "28f19ec85986d4534f77201b00bf750948334753847f437b538cc699f3de447c\
     d0d62a5f521c7b20069bd255f48e8d891f0033167ad35b434d532b61e85a3da7";

const VECTOR_316004_HMAC: &str =
    "5839e3844172a1ce57a5e05dc8a47d57235d080bd7f497ed2ae7cc54bc6249d5\
     826ef93f1d502f8d354d775ecb5bd519a02ee730028137b07e66fed2bb6c1812";

fn sample_redirect_map() -> BTreeMap<String, String> {
    [
        ("amount_cents", "50000"),
        ("created_at", "2024-06-25T15:16:25.910710+04:00"),
        ("currency", "EGP"),
        ("error_occured", "false"),
        ("has_parent_transaction", "false"),
        ("id", "316004"),
        ("integration_id", "2936"),
        ("is_3d_secure", "true"),
        ("is_auth", "false"),
        ("is_capture", "false"),
        ("is_refunded", "false"),
        ("is_standalone_payment", "true"),
        ("is_voided", "false"),
        ("order", "378804"),
        ("owner", "211"),
        ("pending", "false"),
        ("source_data.pan", "2346"),
        ("source_data.sub_type", "MasterCard"),
        ("source_data.type", "card"),
        ("success", "true"),
        ("hmac", VECTOR_316004_HMAC),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect()
}

#[test]
fn protocol_a_post_end_to_end_verification_and_ergonomic_getters() -> WebhookResult<()> {
    let engine = PaymobWebhookEngine::new(TEST_SECRET)?;
    let event: TransactionWebhook = engine.verify_transaction_post_bytes(
        VECTOR_192036465_JSON.as_bytes(),
        VECTOR_192036465_HMAC,
    )?;

    assert_eq!((event.transaction_id(), event.order_id()), (192_036_465, 217_503_754));
    assert_eq!((event.amount_cents(), event.net_settled_cents()), (100_000, 100_000));
    assert_eq!(event.currency(), "EGP");
    assert!(event.is_approved() && event.is_3ds_authenticated());
    assert_eq!(
        event.canonical_hmac_string(),
        build_protocol_a_canonical_string(&event.obj)
    );
    Ok(())
}

#[test]
fn protocol_a_debug_redacts_pan_and_payment_key_claims() -> WebhookResult<()> {
    let engine = PaymobWebhookEngine::new(TEST_SECRET)?;
    let event = engine.verify_transaction_post(VECTOR_192036465_JSON, VECTOR_192036465_HMAC)?;
    let debug_str = format!("{event:?}");

    assert!(debug_str.contains("[REDACTED]"));
    assert!(!debug_str.contains("2346"));
    assert!(!debug_str.contains("secret-buyer@example.com"));
    Ok(())
}

#[test]
fn protocol_b_get_redirect_map_and_query_str_verification() -> WebhookResult<()> {
    let engine = PaymobWebhookEngine::new(TEST_SECRET)?;
    let map = sample_redirect_map();
    let verified = engine.verify_transaction_get(&map)?;

    assert_eq!((verified.transaction_id_u64()?, verified.order_id_u64()?), (316_004, 378_804));
    assert_eq!(verified.amount_cents_u64()?, 50_000);
    assert!(verified.is_approved() && verified.is_3ds_authenticated());

    let query_str = map
        .iter()
        .map(|(k, v)| format!("{k}={}", v.replace('+', "%2B")))
        .collect::<Vec<_>>()
        .join("&");
    let from_query = engine.verify_transaction_get_query_str(&format!("?{query_str}"))?;
    assert_eq!(from_query, verified);
    Ok(())
}

#[test]
fn protocol_b_rejects_conflicting_order_id_and_order_parameters() -> WebhookResult<()> {
    let engine = PaymobWebhookEngine::new(TEST_SECRET)?;
    let mut map = sample_redirect_map();
    map.insert("order_id".to_string(), "111111".to_string());

    let err = engine.verify_transaction_get(&map).unwrap_err();
    assert!(err.is_malformed_payload());
    assert_eq!(err.suggested_http_status_code(), 400);
    Ok(())
}

#[test]
fn webhook_error_workflow_status_codes_and_redaction() {
    let sig_err = WebhookError::MalformedSignatureHex;
    let payload_err = WebhookError::from(
        serde_json::from_str::<u64>("\"4111-9999-8888-7777\"").unwrap_err(),
    );
    let cfg_err = WebhookError::InvalidSecretKeyLength;

    assert_eq!(
        (sig_err.suggested_http_status_code(), sig_err.is_retryable()),
        (401, false)
    );
    assert_eq!(
        (payload_err.suggested_http_status_code(), payload_err.is_retryable()),
        (400, false)
    );
    assert_eq!(
        (cfg_err.suggested_http_status_code(), cfg_err.is_retryable()),
        (500, true)
    );
    assert!(!payload_err.to_string().contains("4111-9999-8888-7777"));
    assert!(payload_err.to_string().contains("[REDACTED]"));
}

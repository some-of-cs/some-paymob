#![forbid(unsafe_code)]
//! Integration tests for User Story `US-7.2.0`:
//! Card Token (Protocol C), Subscription Lifecycle (Protocol D), Payouts (Protocol E),
//! Auto-Dispatcher (`construct_event`), and `IdempotentWebhookGuard` / `InMemoryWebhookDeduplicator`.

use std::collections::BTreeMap;
use std::time::Duration;

use hmac::{Hmac, Mac};
use sha2::Sha512;
use some_paymob::prelude::*;
use some_paymob::{PaymobWebhookEngine, WebhookError, WebhookEvent, WebhookResult};

const TEST_SECRET: &str = "3qUAg2xx6JW89Qav5GzzmXoalgjf5XxE";
const PAYOUT_SECRET: &str = "payout_secret_key_for_integration";

const TOKEN_VECTOR_JSON: &str = r#"{
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

const TOKEN_VECTOR_HMAC: &str = "38ac96769330ae1b446ba94220b4a0fbf4a536ff407710d0637b32efc1c17cc1\
     7dde92a831467724a16e09ea7b7054806275d78ce726ba243cc2fea25f30be0d";

const TX_VECTOR_JSON: &str = r#"{
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
        "owner": 302852
    }
}"#;

const TX_VECTOR_HMAC: &str = "28f19ec85986d4534f77201b00bf750948334753847f437b538cc699f3de447c\
     d0d62a5f521c7b20069bd255f48e8d891f0033167ad35b434d532b61e85a3da7";

const REDIRECT_316004_HMAC: &str = "5839e3844172a1ce57a5e05dc8a47d57235d080bd7f497ed2ae7cc54bc6249d5\
     826ef93f1d502f8d354d775ecb5bd519a02ee730028137b07e66fed2bb6c1812";

fn sign_hex(secret: &str, message: &str) -> String {
    let mut mac = Hmac::<Sha512>::new_from_slice(secret.as_bytes()).expect("valid key");
    mac.update(message.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn sample_redirect_params(engine: &PaymobWebhookEngine) -> TransactionRedirectParams {
    let map: BTreeMap<&str, &str> = [
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
        ("hmac", REDIRECT_316004_HMAC),
    ]
    .into_iter()
    .collect();
    engine.verify_transaction_get(&map).expect("valid redirect")
}

#[test]
fn construct_event_dispatches_protocols_a_c_d_and_e() -> WebhookResult<()> {
    let engine = PaymobWebhookEngine::new(TEST_SECRET)?.with_payouts_secret(PAYOUT_SECRET)?;

    let tx_evt = engine.construct_event(TX_VECTOR_JSON, Some(TX_VECTOR_HMAC))?;
    let tok_evt =
        engine.construct_event_from_slice(TOKEN_VECTOR_JSON.as_bytes(), Some(TOKEN_VECTOR_HMAC))?;

    let sub_sig = sign_hex(TEST_SECRET, "suspendedfor1264");
    let sub_body = format!(
        "{{\"paymob_request_id\":\"req-1264\",\"subscription_data\":{{\"id\":1264}},\
         \"trigger_type\":\"suspended\",\"hmac\":\"{sub_sig}\"}}"
    );
    let sub_evt = engine.construct_event(&sub_body, None)?;

    let disb_body = "{\"transaction_id\":\"disb_1\",\"issuer\":\"bank_wallet\",\
        \"amount_cents\":2500,\"currency\":\"EGP\",\"status\":\"ok\"}";
    let disb_sig = sign_hex(PAYOUT_SECRET, disb_body);
    let disb_evt = engine.construct_event(disb_body, Some(&disb_sig))?;

    assert!(tx_evt.is_transaction_processed() && tok_evt.is_card_token());
    assert!(sub_evt.is_subscription() && disb_evt.is_payout_disbursement());
    Ok(())
}

#[test]
fn idempotency_tuples_work_across_all_six_webhook_event_variants() -> WebhookResult<()> {
    let engine = PaymobWebhookEngine::new(TEST_SECRET)?;
    let tx_evt = engine.construct_event(TX_VECTOR_JSON, Some(TX_VECTOR_HMAC))?;
    let redir_evt = WebhookEvent::TransactionResponseRedirect(sample_redirect_params(&engine));
    let tok_evt = engine.construct_event(TOKEN_VECTOR_JSON, Some(TOKEN_VECTOR_HMAC))?;

    let sub_sig = sign_hex(TEST_SECRET, "resumedfor77");
    let sub_body = format!(
        "{{\"paymob_request_id\":\"req-77\",\"subscription_data\":{{\"id\":77}},\
         \"trigger_type\":\"resumed\",\"hmac\":\"{sub_sig}\"}}"
    );
    let sub_evt = engine.construct_event(&sub_body, None)?;
    let disb_body = "{\"transaction_id\":\"d_9\",\"issuer\":\"instant_bank\",\
        \"amount_cents\":100,\"currency\":\"EGP\",\"status\":\"ok\"}";
    let disb_evt = engine.construct_event(disb_body, None)?;
    let top_body = "{\"topup_id\":\"t_9\",\"amount_cents\":100,\
        \"currency\":\"EGP\",\"status\":\"Approved\"}";
    let top_evt = engine.construct_event(top_body, None)?;

    assert_eq!(
        tx_evt.idempotency_tuple(),
        ("192036465".into(), "217503754".into())
    );
    assert_eq!(
        redir_evt.idempotency_tuple(),
        ("316004".into(), "378804".into())
    );
    assert_eq!(
        tok_evt.idempotency_tuple(),
        ("15978654".into(), "593881581".into())
    );
    assert_eq!(sub_evt.idempotency_tuple(), ("req-77".into(), "77".into()));
    assert_eq!(disb_evt.idempotency_tuple(), ("d_9".into(), "d_9".into()));
    assert_eq!(top_evt.idempotency_tuple(), ("t_9".into(), "t_9".into()));
    Ok(())
}

#[test]
fn deduplicator_claim_or_reject_and_process_with_rollback() -> WebhookResult<()> {
    let engine = PaymobWebhookEngine::new(TEST_SECRET)?;
    let tok_evt = engine.verify_card_token(TOKEN_VECTOR_JSON, TOKEN_VECTOR_HMAC)?;
    let store = InMemoryWebhookIdempotencyStore::with_capacity_and_ttl(4, Duration::from_secs(60));

    let err_res: Result<Option<()>, &str> =
        store.process_with_rollback(&tok_evt, || Err("transient failure"));
    assert_eq!(err_res, Err("transient failure"));
    assert!(!WebhookIdempotencyStore::contains(&store, &tok_evt));

    let ok_res: Result<Option<&str>, &str> =
        store.process_with_rollback(&tok_evt, || Ok("committed"));
    assert_eq!(ok_res, Ok(Some("committed")));

    let dup_err: WebhookError = store.claim_or_reject(&tok_evt).unwrap_err();
    assert!(dup_err.is_replay_or_duplicate());
    assert_eq!(dup_err.suggested_http_status_code(), 409);
    Ok(())
}

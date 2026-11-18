#![forbid(unsafe_code)]
//! Positive E2E and boundary integration tests for `examples/axum_server.rs` (`US-axum` Unit 4).

use axum::http::{Method, StatusCode};
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::Sha512;
use some_paymob::test_utils::vectors::{
    OFFICIAL_CARD_TOKEN_15978654_JSON, OFFICIAL_REDIRECT_316004_QUERY,
    OFFICIAL_SUBSCRIPTION_1264_JSON, OFFICIAL_TX_192036465_JSON, SAMPLE_CARD_TOKEN_15978654_HMAC,
    SAMPLE_HMAC_SECRET, SAMPLE_TX_192036465_HMAC,
};

use super::common::{
    mount_accept_json, mount_accept_jwt, mount_payouts_json, mount_payouts_token,
    sample_intention_response, sample_transaction_response, send_get, send_json, setup_test_app,
};

type HmacSha512 = Hmac<Sha512>;

fn sign_hmac_hex(secret: &str, msg: &str) -> String {
    let mut mac = HmacSha512::new_from_slice(secret.as_bytes()).expect("valid HMAC key");
    mac.update(msg.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

// ============================================================================
// 1. Positive E2E Tests Across All 14 Services
// ============================================================================

#[tokio::test]
async fn e2e_health_and_sandbox_check_ok() {
    let (_server, router, _state) = setup_test_app().await;
    let (status, _) = send_get(&router, "/health").await;
    assert_eq!(status, StatusCode::OK);
    let body = json!({ "is_sandbox": true, "credential_age_days": 10, "channel": "card" });
    let (sb_status, sb_json) = send_json(&router, Method::POST, "/sandbox/check", body).await;
    assert_eq!(sb_status, StatusCode::OK);
    assert_eq!(sb_json["ok"], true);
}

#[tokio::test]
async fn e2e_intentions_create_and_update_ok() {
    let (server, router, _state) = setup_test_app().await;
    mount_accept_json(&server, "POST", "/v1/intention/", 201, sample_intention_response()).await;
    mount_accept_json(&server, "PUT", "/v1/intention/", 200, sample_intention_response()).await;
    let payload = json!({ "amount_cents": 10000, "currency": "EGP", "payment_methods": [4097558] });
    let (c_status, _) = send_json(&router, Method::POST, "/intentions", payload).await;
    assert!(c_status == StatusCode::CREATED || c_status == StatusCode::OK);
    let upd = json!({ "amount_cents": 15000, "currency": "EGP" });
    let (u_status, _) = send_json(&router, Method::PUT, "/intentions/pi_test_1001", upd).await;
    assert_eq!(u_status, StatusCode::OK);
}

#[tokio::test]
async fn e2e_checkout_pixel_and_affordability_ok() {
    let (_server, router, _state) = setup_test_app().await;
    let px = json!({ "public_key": "egy_pk_test_1", "client_secret": "egy_csk_test_1" });
    let (px_status, _) = send_json(&router, Method::POST, "/checkout/pixel", px).await;
    assert_eq!(px_status, StatusCode::OK);
    let aff = json!({ "amount_cents": 50000, "currency": "EGP" });
    let (af_status, _) = send_json(&router, Method::POST, "/checkout/affordability", aff).await;
    assert_eq!(af_status, StatusCode::OK);
}

#[tokio::test]
async fn e2e_legacy_v2_orders_keys_and_checkout_ok() {
    let (server, router, _state) = setup_test_app().await;
    mount_accept_jwt(&server, "jwt_legacy_1").await;
    mount_accept_json(&server, "POST", "/api/ecommerce/orders", 201, json!({ "id": 7711 })).await;
    mount_accept_json(&server, "POST", "/api/acceptance/payment_keys", 201, json!({ "token": "pk_leg_1" })).await;
    let ord = json!({ "amount_cents": 25000, "currency": "EGP" });
    let (o_st, _) = send_json(&router, Method::POST, "/legacy/orders", ord).await;
    assert!(o_st == StatusCode::CREATED || o_st == StatusCode::OK);
    let key = json!({ "amount_cents": 25000, "currency": "EGP", "order_id": 7711, "integration_id": 4097558 });
    let (k_st, _) = send_json(&router, Method::POST, "/legacy/payment-keys", key).await;
    assert!(k_st == StatusCode::CREATED || k_st == StatusCode::OK);
    let chk = json!({ "amount_cents": 25000, "currency": "EGP", "integration_id": 4097558, "iframe_id": 123 });
    let (c_st, _) = send_json(&router, Method::POST, "/legacy/checkout", chk).await;
    assert_eq!(c_st, StatusCode::OK);
}

#[tokio::test]
async fn e2e_manage_refund_void_capture_ok() {
    let (server, router, _state) = setup_test_app().await;
    let tx = sample_transaction_response(192036466, 25000);
    mount_accept_json(&server, "POST", "/api/acceptance/void_refund/refund", 200, tx.clone()).await;
    mount_accept_json(&server, "POST", "/api/acceptance/void_refund/void", 200, tx.clone()).await;
    mount_accept_json(&server, "POST", "/api/acceptance/capture", 200, tx).await;
    let (r_st, _) = send_json(&router, Method::POST, "/manage/refund", json!({ "transaction_id": 192036465, "amount_cents": 25000 })).await;
    let (v_st, _) = send_json(&router, Method::POST, "/manage/void", json!({ "transaction_id": 192036465 })).await;
    let (c_st, _) = send_json(&router, Method::POST, "/manage/capture", json!({ "transaction_id": 192036465, "amount_cents": 25000 })).await;
    assert_eq!((r_st, v_st, c_st), (StatusCode::OK, StatusCode::OK, StatusCode::OK));
}

#[tokio::test]
async fn e2e_inquiries_all_endpoints_ok() {
    let (server, router, _state) = setup_test_app().await;
    mount_accept_jwt(&server, "jwt_inq_1").await;
    let tx = sample_transaction_response(192036465, 10000);
    mount_accept_json(&server, "GET", "/api/acceptance/transactions/192036465", 200, tx.clone()).await;
    mount_accept_json(&server, "POST", "/api/ecommerce/orders/transaction_inquiry", 200, tx).await;
    mount_accept_json(&server, "POST", "/api/acceptance/order_card_tokens", 200, json!([])).await;
    mount_accept_json(&server, "GET", "/api/ecommerce/orders/212245716", 200, json!({ "id": 212245716, "amount_cents": 10000, "currency": "EGP" })).await;
    assert_eq!(send_get(&router, "/inquiries/transactions/192036465").await.0, StatusCode::OK);
    assert_eq!(send_json(&router, Method::POST, "/inquiries/transactions/by-order", json!({ "order_id": 212245716 })).await.0, StatusCode::OK);
    assert_eq!(send_json(&router, Method::POST, "/inquiries/order-card-tokens", json!({ "order_id": 212245716 })).await.0, StatusCode::OK);
    assert_eq!(send_get(&router, "/inquiries/orders/212245716").await.0, StatusCode::OK);
}

#[tokio::test]
async fn e2e_quicklinks_and_splits_ok() {
    let (server, router, _state) = setup_test_app().await;
    mount_accept_jwt(&server, "jwt_ql_1").await;
    mount_accept_json(&server, "POST", "/api/ecommerce/payment-links", 201, json!({ "id": "ql_1", "url": "https://accept.paymob.com/standalone/?ref=ql_1" })).await;
    mount_accept_json(&server, "POST", "/api/ecommerce/payment-links/cancel", 200, json!({ "detail": "cancelled" })).await;
    let ql = json!({ "amount_cents": 15000, "currency": "EGP", "payment_methods": [4097558] });
    let (c_st, _) = send_json(&router, Method::POST, "/quicklinks", ql).await;
    assert!(c_st == StatusCode::CREATED || c_st == StatusCode::OK);
    assert_eq!(send_json(&router, Method::POST, "/quicklinks/cancel", json!({ "quicklink_id": "ql_1" })).await.0, StatusCode::OK);
    let split = json!({ "amount_cents": 10000, "recipients": [{ "merchant_id": 1, "basis_points": 10000 }], "cards": [{ "amount_cents": 10000 }] });
    assert_eq!(send_json(&router, Method::POST, "/splits/validate-and-quote", split).await.0, StatusCode::OK);
}

#[tokio::test]
async fn e2e_saved_cards_all_modes_ok() {
    let (server, router, _state) = setup_test_app().await;
    mount_accept_jwt(&server, "jwt_sc_1").await;
    let pay_resp = json!({ "id": 550011, "pending": false, "amount_cents": 25000, "success": true, "currency": "EGP" });
    mount_accept_json(&server, "POST", "/api/acceptance/payments/pay", 200, pay_resp).await;
    mount_accept_json(&server, "POST", "/v1/intention/", 201, sample_intention_response()).await;
    assert_eq!(send_json(&router, Method::POST, "/saved-cards/mit-charge", json!({ "amount_cents": 25000, "currency": "EGP", "card_token": "tok_1", "integration_id": 4097558 })).await.0, StatusCode::OK);
    assert_eq!(send_json(&router, Method::POST, "/saved-cards/wallet-pay", json!({ "payment_token": "pk_1", "wallet_identifier": "01010101010" })).await.0, StatusCode::OK);
    assert_eq!(send_json(&router, Method::POST, "/saved-cards/kiosk-pay", json!({ "payment_token": "pk_1" })).await.0, StatusCode::OK);
}

#[tokio::test]
async fn e2e_subscriptions_lifecycle_ok() {
    let (server, router, _state) = setup_test_app().await;
    mount_accept_jwt(&server, "jwt_sub_1").await;
    let plan = json!({ "id": 42, "name": "Pro", "amount_cents": 50000, "frequency": 30 });
    let sub = json!({ "id": 1264, "state": "active", "plan_id": 42 });
    mount_accept_json(&server, "POST", "/api/acceptance/subscription-plans", 201, plan.clone()).await;
    mount_accept_json(&server, "GET", "/api/acceptance/subscription-plans/42", 200, plan).await;
    mount_accept_json(&server, "POST", "/api/acceptance/subscriptions", 201, sub.clone()).await;
    mount_accept_json(&server, "POST", "/api/acceptance/subscriptions/1264/suspend", 200, sub.clone()).await;
    mount_accept_json(&server, "POST", "/api/acceptance/subscriptions/1264/resume", 200, sub).await;
    mount_accept_json(&server, "GET", "/api/acceptance/subscriptions/1264/cards", 200, json!([])).await;
    mount_accept_json(&server, "GET", "/api/acceptance/subscriptions/1264/transactions", 200, json!([])).await;
    mount_accept_json(&server, "GET", "/api/acceptance/subscriptions/1264/last-transaction", 200, sample_transaction_response(998877, 50000)).await;
    mount_accept_json(&server, "POST", "/api/acceptance/void_refund/refund", 200, sample_transaction_response(998878, 50000)).await;
    let p_st = send_json(&router, Method::POST, "/subscriptions/plans", json!({ "name": "Pro", "amount_cents": 50000, "frequency": 30, "webhook_url": "https://example.com/wh" })).await.0;
    assert!(p_st == StatusCode::CREATED || p_st == StatusCode::OK);
    assert_eq!(send_get(&router, "/subscriptions/plans/42").await.0, StatusCode::OK);
    assert_eq!(send_json(&router, Method::POST, "/subscriptions/1264/suspend", json!({})).await.0, StatusCode::OK);
    assert_eq!(send_json(&router, Method::POST, "/subscriptions/1264/resume", json!({})).await.0, StatusCode::OK);
    assert_eq!(send_get(&router, "/subscriptions/1264/cards").await.0, StatusCode::OK);
    assert_eq!(send_get(&router, "/subscriptions/1264/transactions").await.0, StatusCode::OK);
    assert_eq!(send_json(&router, Method::POST, "/subscriptions/1264/refund-last", json!({})).await.0, StatusCode::OK);
}

#[tokio::test]
async fn e2e_payouts_instant_bulk_inquiries_budget_topup_ok() {
    let (server, router, _state) = setup_test_app().await;
    mount_payouts_token(&server, "po_acc_1").await;
    mount_payouts_json(&server, "POST", "/api/secure/disburse/", 200, json!({ "transaction_id": "tx_p1", "issuer": "vodafone", "amount": 150, "disbursement_status": "successful" })).await;
    mount_payouts_json(&server, "POST", "/disburse/api/v1/disburse/bulk_transaction", 200, json!({ "status": "ok", "results": [] })).await;
    mount_payouts_json(&server, "POST", "/disburse/api/v1/bulk_transaction/inquire", 200, json!({ "results": [] })).await;
    mount_payouts_json(&server, "GET", "/api/secure/budget/inquire/", 200, json!({ "current_balance": 500000 })).await;
    mount_payouts_json(&server, "POST", "/api/secure/topup/request/", 200, json!({ "status": "pending", "reference_id": "top_1" })).await;
    assert_eq!(send_json(&router, Method::POST, "/payouts/instant", json!({ "issuer": "vodafone", "amount": 150, "msisdn": "01012345678" })).await.0, StatusCode::OK);
    assert_eq!(send_json(&router, Method::POST, "/payouts/bulk", json!({ "items": [{ "issuer": "vodafone", "amount": 150, "msisdn": "01012345678" }] })).await.0, StatusCode::OK);
    assert_eq!(send_json(&router, Method::POST, "/payouts/inquiries/transactions", json!({ "transaction_ids": ["tx_p1"] })).await.0, StatusCode::OK);
    assert_eq!(send_get(&router, "/payouts/budget").await.0, StatusCode::OK);
    assert_eq!(send_json(&router, Method::POST, "/payouts/topups/request", json!({ "amount": 1000, "proof_bytes_len": 128 })).await.0, StatusCode::OK);
}

#[tokio::test]
async fn e2e_onboarding_and_scoped_merchants_ok() {
    let (server, router, _state) = setup_test_app().await;
    mount_accept_jwt(&server, "jwt_ob_1").await;
    mount_accept_json(&server, "POST", "/api/auth/api_keys", 201, json!({ "api_key": "pk_partner_1" })).await;
    mount_accept_json(&server, "POST", "/api/onboarding/register", 201, json!({ "paymob_mid": 777888, "status": "PENDING" })).await;
    mount_accept_json(&server, "GET", "/api/onboarding/flow/schema", 200, json!({ "partner": "KeyPartner", "resubmission": false, "steps": [] })).await;
    mount_accept_json(&server, "POST", "/api/onboarding/flow/step", 200, json!({ "status": "SUBMITTED" })).await;
    mount_accept_json(&server, "GET", "/api/onboarding/merchant/777888", 200, json!({ "paymob_mid": 777888, "status": "APPROVED", "is_live": true, "live_integration_ids": [4097558], "test_integration_ids": [], "pending_steps": [] })).await;
    mount_accept_json(&server, "POST", "/v1/intention/", 201, sample_intention_response()).await;
    mount_accept_json(&server, "GET", "/api/acceptance/transactions/555", 200, sample_transaction_response(555, 15000)).await;
    let r_st = send_json(&router, Method::POST, "/onboarding/register", json!({ "email": "m@example.com", "phone": "01010101010" })).await.0;
    assert!(r_st == StatusCode::CREATED || r_st == StatusCode::OK);
    assert_eq!(send_get(&router, "/onboarding/schema?partner=KeyPartner&paymob_mid=777888").await.0, StatusCode::OK);
    assert_eq!(send_json(&router, Method::POST, "/onboarding/step", json!({ "paymob_mid": 777888, "step_id": "kyc" })).await.0, StatusCode::OK);
    assert_eq!(send_get(&router, "/onboarding/merchants/777888").await.0, StatusCode::OK);
    assert!(matches!(send_json(&router, Method::POST, "/merchants/777888/intentions", json!({ "amount_cents": 15000, "currency": "EGP", "payment_methods": [4097558] })).await.0, StatusCode::OK | StatusCode::CREATED));
    assert_eq!(send_get(&router, "/merchants/777888/inquiries/transactions/555").await.0, StatusCode::OK);
}

#[tokio::test]
async fn e2e_unified_adapter_all_operations_ok() {
    let (server, router, _state) = setup_test_app().await;
    mount_accept_json(&server, "POST", "/v1/intention/", 201, sample_intention_response()).await;
    let tx = sample_transaction_response(192036466, 25000);
    mount_accept_json(&server, "POST", "/api/acceptance/void_refund/refund", 200, tx.clone()).await;
    mount_accept_json(&server, "POST", "/api/acceptance/void_refund/void", 200, tx.clone()).await;
    mount_accept_json(&server, "POST", "/api/acceptance/capture", 200, tx).await;
    mount_payouts_token(&server, "po_uni_1").await;
    mount_payouts_json(&server, "POST", "/api/secure/disburse/", 200, json!({ "transaction_id": "tx_u1", "issuer": "vodafone", "amount": 150, "disbursement_status": "successful" })).await;
    let s_st = send_json(&router, Method::POST, "/unified/sessions", json!({ "amount_cents": 25000, "currency": "EGP", "integration_id": 4097558 })).await.0;
    assert!(s_st == StatusCode::CREATED || s_st == StatusCode::OK);
    assert_eq!(send_json(&router, Method::POST, "/unified/refund", json!({ "transaction_id": "192036465", "amount_cents": 25000 })).await.0, StatusCode::OK);
    assert_eq!(send_json(&router, Method::POST, "/unified/void", json!({ "transaction_id": "192036465" })).await.0, StatusCode::OK);
    assert_eq!(send_json(&router, Method::POST, "/unified/capture", json!({ "transaction_id": "192036465", "amount_cents": 25000 })).await.0, StatusCode::OK);
    assert_eq!(send_json(&router, Method::POST, "/unified/payout", json!({ "issuer": "vodafone", "amount": 150, "msisdn": "01012345678" })).await.0, StatusCode::OK);
}

#[tokio::test]
async fn e2e_webhooks_protocols_a_b_c_d_e_ok() {
    let (_server, router, _state) = setup_test_app().await;
    let tx_val: Value = serde_json::from_str(OFFICIAL_TX_192036465_JSON).expect("valid tx json");
    let tok_val: Value = serde_json::from_str(OFFICIAL_CARD_TOKEN_15978654_JSON).expect("valid tok json");
    let sub_val: Value = serde_json::from_str(OFFICIAL_SUBSCRIPTION_1264_JSON).expect("valid sub json");
    let pa_uri = format!("/webhooks/transaction-processed?hmac={SAMPLE_TX_192036465_HMAC}");
    assert_eq!(send_json(&router, Method::POST, &pa_uri, tx_val).await.0, StatusCode::OK);
    let pb_uri = format!("/webhooks/transaction-response?{OFFICIAL_REDIRECT_316004_QUERY}");
    assert_eq!(send_get(&router, &pb_uri).await.0, StatusCode::OK);
    let pc_uri = format!("/webhooks/card-token?hmac={SAMPLE_CARD_TOKEN_15978654_HMAC}");
    assert_eq!(send_json(&router, Method::POST, &pc_uri, tok_val).await.0, StatusCode::OK);
    assert_eq!(send_json(&router, Method::POST, "/webhooks/subscription", sub_val).await.0, StatusCode::OK);
    let payout_body = json!({ "transaction_id": "tx_e_1", "disbursement_status": "successful", "amount": 150 });
    let pe_sig = sign_hmac_hex(SAMPLE_HMAC_SECRET, &payout_body.to_string());
    let pe_uri = format!("/webhooks/payouts?hmac={pe_sig}");
    assert_eq!(send_json(&router, Method::POST, &pe_uri, payout_body).await.0, StatusCode::OK);
}

// ============================================================================
// 2. Boundary Condition Tests
// ============================================================================

#[tokio::test]
async fn boundary_amount_zero_one_and_u64_max_overflow() {
    let (server, router, _state) = setup_test_app().await;
    mount_accept_json(&server, "POST", "/v1/intention/", 201, sample_intention_response()).await;
    let zero = json!({ "amount_cents": 0, "currency": "EGP", "payment_methods": [4097558] });
    assert_eq!(send_json(&router, Method::POST, "/intentions", zero).await.0, StatusCode::BAD_REQUEST);
    let one = json!({ "amount_cents": 1, "currency": "EGP", "payment_methods": [4097558] });
    let one_st = send_json(&router, Method::POST, "/intentions", one).await.0;
    assert!(one_st == StatusCode::CREATED || one_st == StatusCode::OK);
    let max = json!({ "amount_cents": u64::MAX, "currency": "EGP", "payment_methods": [4097558] });
    assert_eq!(send_json(&router, Method::POST, "/intentions", max).await.0, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn boundary_bulk_disbursements_0_1_1000_1001() {
    let (server, router, _state) = setup_test_app().await;
    mount_payouts_token(&server, "po_bulk_1").await;
    mount_payouts_json(&server, "POST", "/disburse/api/v1/disburse/bulk_transaction", 200, json!({ "status": "ok", "results": [] })).await;
    let mk_items = |n: usize| -> Value {
        let items: Vec<Value> = (0..n)
            .map(|i| json!({ "issuer": "vodafone", "amount": 100, "msisdn": format!("010{:08}", i) }))
            .collect();
        json!({ "items": items })
    };
    assert_eq!(send_json(&router, Method::POST, "/payouts/bulk", mk_items(0)).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(send_json(&router, Method::POST, "/payouts/bulk", mk_items(1)).await.0, StatusCode::OK);
    assert_eq!(send_json(&router, Method::POST, "/payouts/bulk", mk_items(1_000)).await.0, StatusCode::OK);
    assert_eq!(send_json(&router, Method::POST, "/payouts/bulk", mk_items(1_001)).await.0, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn boundary_payout_inquiry_ids_0_1_500_501() {
    let (server, router, _state) = setup_test_app().await;
    mount_payouts_token(&server, "po_inq_1").await;
    mount_payouts_json(&server, "POST", "/disburse/api/v1/bulk_transaction/inquire", 200, json!({ "results": [] })).await;
    let mk_ids = |n: usize| -> Value {
        let ids: Vec<String> = (0..n).map(|i| format!("tx_{i}")).collect();
        json!({ "transaction_ids": ids })
    };
    assert_eq!(send_json(&router, Method::POST, "/payouts/inquiries/transactions", mk_ids(0)).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(send_json(&router, Method::POST, "/payouts/inquiries/transactions", mk_ids(1)).await.0, StatusCode::OK);
    assert_eq!(send_json(&router, Method::POST, "/payouts/inquiries/transactions", mk_ids(500)).await.0, StatusCode::OK);
    assert_eq!(send_json(&router, Method::POST, "/payouts/inquiries/transactions", mk_ids(501)).await.0, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn boundary_bank_transfer_proof_size_0_2936012_2936013() {
    let (server, router, _state) = setup_test_app().await;
    mount_payouts_token(&server, "po_top_1").await;
    mount_payouts_json(&server, "POST", "/api/secure/topup/request/", 200, json!({ "status": "pending", "reference_id": "top_b" })).await;
    let mk_topup = |bytes: usize| json!({ "amount": 1000, "proof_bytes_len": bytes });
    assert_eq!(send_json(&router, Method::POST, "/payouts/topups/request", mk_topup(0)).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(send_json(&router, Method::POST, "/payouts/topups/request", mk_topup(2_936_012)).await.0, StatusCode::OK);
    assert_eq!(send_json(&router, Method::POST, "/payouts/topups/request", mk_topup(2_936_013)).await.0, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn boundary_split_payments_cards_0_1_3_4_and_bps_not_10000() {
    let (_server, router, _state) = setup_test_app().await;
    let mk_split = |cards: usize, bps: u16| -> Value {
        let card_list: Vec<Value> = (0..cards).map(|_| json!({ "amount_cents": 1000 })).collect();
        json!({
            "amount_cents": 10000,
            "recipients": [{ "merchant_id": 1, "basis_points": bps }],
            "cards": card_list
        })
    };
    assert_eq!(send_json(&router, Method::POST, "/splits/validate-and-quote", mk_split(0, 10_000)).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(send_json(&router, Method::POST, "/splits/validate-and-quote", mk_split(1, 10_000)).await.0, StatusCode::OK);
    assert_eq!(send_json(&router, Method::POST, "/splits/validate-and-quote", mk_split(3, 10_000)).await.0, StatusCode::OK);
    assert_eq!(send_json(&router, Method::POST, "/splits/validate-and-quote", mk_split(4, 10_000)).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(send_json(&router, Method::POST, "/splits/validate-and-quote", mk_split(1, 9_999)).await.0, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn boundary_sandbox_guard_credential_age_24_25_30() {
    let (_server, router, _state) = setup_test_app().await;
    let mk_req = |age: u64| json!({ "is_sandbox": true, "credential_age_days": age, "channel": "card" });
    let (st24, b24) = send_json(&router, Method::POST, "/sandbox/check", mk_req(24)).await;
    assert_eq!(st24, StatusCode::OK);
    assert!(b24["warnings"].as_array().is_none_or(Vec::is_empty));
    let (st25, b25) = send_json(&router, Method::POST, "/sandbox/check", mk_req(25)).await;
    assert_eq!(st25, StatusCode::OK);
    assert!(!b25["warnings"].as_array().is_none_or(Vec::is_empty));
    let (st30, _) = send_json(&router, Method::POST, "/sandbox/check", mk_req(30)).await;
    assert_eq!(st30, StatusCode::UNPROCESSABLE_ENTITY);
}

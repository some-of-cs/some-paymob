#![forbid(unsafe_code)]
//! Positive E2E and boundary integration tests for `examples/axum_server.rs` (`US-axum` Unit 4).

use axum::Router;
use axum::http::{Method, StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use serde_json::{Value, json};
use some_paymob::test_utils::mock_server::PaymobMockServer;
use some_paymob::test_utils::vectors::{
    OFFICIAL_CARD_TOKEN_15978654_JSON, OFFICIAL_REDIRECT_316004_QUERY,
    OFFICIAL_SUBSCRIPTION_1264_JSON, OFFICIAL_TX_192036465_JSON, SAMPLE_CARD_TOKEN_15978654_HMAC,
    SAMPLE_TX_192036465_HMAC,
};

use super::common::{
    mount_accept_json, mount_accept_jwt, mount_payouts_json, mount_payouts_token,
    sample_intention_response, sample_transaction_response, send_get, send_json, setup_test_app,
};

fn sample_legacy_billing() -> Value {
    json!({
        "first_name": "Ali",
        "last_name": "Hassan",
        "email": "ali@example.com",
        "phone_number": "+201010101010",
        "apartment": "NA",
        "floor": "NA",
        "street": "NA",
        "building": "NA",
        "shipping_method": "NA",
        "postal_code": "NA",
        "city": "Cairo",
        "country": "EG",
        "state": "Cairo"
    })
}

fn sample_scoped_billing() -> Value {
    json!({
        "phone_number": "+201010101010",
        "first_name": "Ali",
        "last_name": "Hassan",
        "email": "ali@example.com"
    })
}

async fn mount_accept_get(server: &PaymobMockServer, path: &str, body: Value) {
    mount_accept_json(server, "GET", path, 200, body).await;
}

async fn mount_accept_post(server: &PaymobMockServer, path: &str, status: u16, body: Value) {
    mount_accept_json(server, "POST", path, status, body).await;
}

async fn mount_subscription_mocks(server: &PaymobMockServer) {
    let plan = json!({
        "id": 42,
        "name": "Pro",
        "frequency": 30,
        "integration": 4097558,
        "amount_cents": 50000
    });
    let sub = json!({ "id": 1264, "state": "active", "plan_id": 42 });
    mount_accept_post(
        server,
        "/api/acceptance/subscription-plans",
        201,
        plan.clone(),
    )
    .await;
    let plans = json!({ "results": [plan], "count": 1 });
    mount_accept_get(server, "/api/acceptance/subscription-plans", plans).await;
    mount_accept_post(
        server,
        "/api/acceptance/subscriptions/1264/suspend",
        200,
        sub.clone(),
    )
    .await;
    mount_accept_post(
        server,
        "/api/acceptance/subscriptions/1264/resume",
        200,
        sub,
    )
    .await;
    mount_accept_get(
        server,
        "/api/acceptance/subscriptions/1264/cards",
        json!([]),
    )
    .await;
    mount_accept_get(
        server,
        "/api/acceptance/subscriptions/1264/transactions",
        json!([]),
    )
    .await;
    let tx1 = sample_transaction_response(998877, 50000);
    mount_accept_get(
        server,
        "/api/acceptance/subscriptions/1264/last-transaction",
        tx1,
    )
    .await;
    let tx2 = sample_transaction_response(998878, 50000);
    mount_accept_post(server, "/api/acceptance/void_refund/refund", 200, tx2).await;
}

async fn mount_payouts_mocks(server: &PaymobMockServer) {
    let cashin = json!({
        "transaction_id": "tx_p1",
        "issuer": "vodafone",
        "amount": 150,
        "disbursement_status": "successful"
    });
    mount_payouts_json(server, "POST", "/api/secure/disburse/", 200, cashin).await;
    let bulk_resp = json!({ "status": "ok", "results": [] });
    let bulk_path = "/disburse/api/v1/disburse/bulk_transaction/";
    mount_payouts_json(server, "POST", bulk_path, 200, bulk_resp).await;
    let inq_resp = json!({ "results": [] });
    mount_payouts_json(
        server,
        "POST",
        "/disburse/api/v1/bulk_transaction/inquire/",
        200,
        inq_resp,
    )
    .await;
    let budget = json!({ "current_budget": "Your current budget is 5000.00 LE" });
    mount_payouts_json(server, "GET", "/api/secure/budget/inquire/", 200, budget).await;
    let topup = json!({ "status": "pending", "id": 101 });
    mount_payouts_json(server, "POST", "/api/secure/topup/request/", 200, topup).await;
}

async fn mount_onboarding_mocks(server: &PaymobMockServer) {
    let reg = json!({ "paymob_mid": 777888, "partner": "KeyPartner", "status": "PENDING" });
    mount_accept_post(server, "/api/onboarding/register", 201, reg).await;
    let schema = json!({ "partner": "KeyPartner", "resubmission": false, "steps": [] });
    mount_accept_get(server, "/api/onboarding/flow/schema", schema).await;
    mount_accept_post(
        server,
        "/api/onboarding/flow/step",
        200,
        json!({ "status": "SUBMITTED" }),
    )
    .await;
    let merchant = json!({
        "paymob_mid": 777888,
        "status": "APPROVED",
        "is_live": true,
        "live_integration_ids": [4097558],
        "test_integration_ids": [],
        "pending_steps": []
    });
    mount_accept_get(server, "/api/onboarding/merchant/777888", merchant).await;
    mount_accept_post(server, "/v1/intention/", 201, sample_intention_response()).await;
    let tx = sample_transaction_response(555, 15000);
    mount_accept_get(server, "/api/acceptance/transactions/555", tx).await;
}

async fn mount_unified_mocks(server: &PaymobMockServer) {
    let tx = sample_transaction_response(192036466, 25000);
    mount_accept_post(server, "/v1/intention/", 201, sample_intention_response()).await;
    mount_accept_post(
        server,
        "/api/acceptance/void_refund/refund",
        200,
        tx.clone(),
    )
    .await;
    mount_accept_post(server, "/api/acceptance/void_refund/void", 200, tx.clone()).await;
    mount_accept_post(server, "/api/acceptance/capture", 200, tx).await;
    mount_payouts_token(server, "po_uni_1").await;
    let payout = json!({
        "transaction_id": "tx_u1",
        "issuer": "vodafone",
        "amount": 150,
        "disbursement_status": "successful"
    });
    mount_payouts_json(server, "POST", "/api/secure/disburse/", 200, payout).await;
}

async fn post_status(router: &Router, uri: &str, body: Value) -> StatusCode {
    send_json(router, Method::POST, uri, body).await.0
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
    mount_accept_post(&server, "/v1/intention/", 201, sample_intention_response()).await;
    mount_accept_json(
        &server,
        "PUT",
        "/v1/intention/",
        200,
        sample_intention_response(),
    )
    .await;
    let payload = json!({ "amount": 10000, "currency": "EGP", "payment_methods": [4097558] });
    let c_status = post_status(&router, "/intentions", payload).await;
    assert!(c_status == StatusCode::CREATED || c_status == StatusCode::OK);
    let upd = json!({ "amount": 15000, "currency": "EGP" });
    let (u_status, _) = send_json(&router, Method::PUT, "/intentions", upd).await;
    assert_eq!(u_status, StatusCode::OK);
}

#[tokio::test]
async fn e2e_checkout_pixel_and_affordability_ok() {
    let (_server, router, _state) = setup_test_app().await;
    let px = json!({ "client_secret": "egy_csk_test_1", "payment_methods": ["card"] });
    assert_eq!(
        post_status(&router, "/checkout/pixel", px).await,
        StatusCode::OK
    );
    let aff = json!({ "amount_cents": 50000, "currency": "EGP" });
    assert_eq!(
        post_status(&router, "/checkout/affordability", aff).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn e2e_legacy_v2_orders_keys_and_checkout_ok() {
    let (server, router, _state) = setup_test_app().await;
    mount_accept_jwt(&server, "jwt_legacy_1").await;
    let order = json!({ "id": 7711, "amount_cents": 25000, "currency": "EGP" });
    mount_accept_post(&server, "/api/ecommerce/orders", 201, order).await;
    mount_accept_post(
        &server,
        "/api/acceptance/payment_keys",
        201,
        json!({ "token": "pk_leg_1" }),
    )
    .await;
    let ord = json!({ "amount_cents": 25000, "currency": "EGP", "delivery_needed": false });
    let o_st = post_status(&router, "/legacy/orders", ord).await;
    assert!(o_st == StatusCode::CREATED || o_st == StatusCode::OK);
    let key = json!({
        "order_id": 7711,
        "amount_cents": 25000,
        "currency": "EGP",
        "integration_id": 4097558,
        "billing_data": sample_legacy_billing(),
        "expiration": 3600,
        "lock_order_when_paid": false
    });
    let k_st = post_status(&router, "/legacy/payment-keys", key).await;
    assert!(k_st == StatusCode::CREATED || k_st == StatusCode::OK);
    let chk = json!({
        "amount_cents": 25000,
        "currency": "EGP",
        "integration_id": 4097558,
        "iframe_id": 123,
        "billing_data": sample_legacy_billing()
    });
    assert_eq!(
        post_status(&router, "/legacy/checkout", chk).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn e2e_manage_refund_void_capture_ok() {
    let (server, router, _state) = setup_test_app().await;
    let tx = sample_transaction_response(192036466, 25000);
    mount_accept_post(
        &server,
        "/api/acceptance/void_refund/refund",
        200,
        tx.clone(),
    )
    .await;
    mount_accept_post(&server, "/api/acceptance/void_refund/void", 200, tx.clone()).await;
    mount_accept_post(&server, "/api/acceptance/capture", 200, tx).await;
    let ref_body = json!({ "transaction_id": 192036465, "amount_cents": 25000 });
    let r_st = post_status(&router, "/manage/refund", ref_body.clone()).await;
    let v_st = post_status(
        &router,
        "/manage/void",
        json!({ "transaction_id": 192036465 }),
    )
    .await;
    let c_st = post_status(&router, "/manage/capture", ref_body).await;
    assert_eq!(
        (r_st, v_st, c_st),
        (StatusCode::OK, StatusCode::OK, StatusCode::OK)
    );
}

#[tokio::test]
async fn e2e_inquiries_all_endpoints_ok() {
    let (server, router, _state) = setup_test_app().await;
    mount_accept_jwt(&server, "jwt_inq_1").await;
    let tx = sample_transaction_response(192036465, 10000);
    mount_accept_get(
        &server,
        "/api/acceptance/transactions/192036465",
        tx.clone(),
    )
    .await;
    mount_accept_post(
        &server,
        "/api/ecommerce/orders/transaction_inquiry",
        200,
        tx,
    )
    .await;
    mount_accept_post(&server, "/api/acceptance/order_card_tokens", 200, json!([])).await;
    let ord = json!({ "id": 212245716, "amount_cents": 10000, "currency": "EGP" });
    mount_accept_get(&server, "/api/ecommerce/orders/212245716", ord).await;
    assert_eq!(
        send_get(&router, "/inquiries/transactions/192036465")
            .await
            .0,
        StatusCode::OK
    );
    let by_ord_body = json!({ "order_id": 212245716 });
    assert_eq!(
        post_status(&router, "/inquiries/by-order", by_ord_body).await,
        StatusCode::OK
    );
    let tok_st = post_status(
        &router,
        "/inquiries/orders/212245716/card-tokens",
        json!({}),
    )
    .await;
    assert_eq!(tok_st, StatusCode::OK);
    assert_eq!(
        send_get(&router, "/inquiries/orders/212245716").await.0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn e2e_quicklinks_and_splits_ok() {
    let (server, router, _state) = setup_test_app().await;
    mount_accept_jwt(&server, "jwt_ql_1").await;
    let ql_resp = json!({
        "id": "ql_1",
        "url": "https://accept.paymob.com/standalone/?ref=ql_1",
        "client_url": "https://accept.paymob.com/api/acceptance/post_pay?ref=ql_1"
    });
    mount_accept_post(&server, "/api/ecommerce/payment-links", 201, ql_resp).await;
    let cancel_resp = json!({ "detail": "cancelled" });
    mount_accept_post(
        &server,
        "/api/ecommerce/payment-links/cancel",
        200,
        cancel_resp,
    )
    .await;
    let ql = json!({ "amount_cents": 15000, "currency": "EGP", "integrations": [4097558] });
    let c_st = post_status(&router, "/quicklinks", ql).await;
    assert!(c_st == StatusCode::CREATED || c_st == StatusCode::OK);
    assert_eq!(
        post_status(&router, "/quicklinks/ql_1/cancel", json!({})).await,
        StatusCode::OK
    );
    let split = json!({
        "amount_cents": 10000,
        "split_description": { "recipients": [{ "recipient_id": "1", "percentage_bps": 10000 }] },
        "split_payment": { "cards": [{ "amount_cents": 10000 }] }
    });
    assert_eq!(
        post_status(&router, "/splits/validate-and-quote", split).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn e2e_saved_cards_all_modes_ok() {
    let (server, router, _state) = setup_test_app().await;
    mount_accept_jwt(&server, "jwt_sc_1").await;
    let pay_resp = json!({
        "id": 550011,
        "pending": false,
        "amount_cents": 25000,
        "success": true,
        "currency": "EGP"
    });
    mount_accept_post(&server, "/api/acceptance/payments/pay", 200, pay_resp).await;
    let mit = json!({ "payment_token": "pk_1", "saved_token": "tok_1" });
    assert_eq!(
        post_status(&router, "/saved-cards/pay/mit", mit).await,
        StatusCode::OK
    );
    let wallet = json!({ "payment_token": "pk_1", "wallet_phone": "01010101010" });
    assert_eq!(
        post_status(&router, "/saved-cards/pay/wallet", wallet).await,
        StatusCode::OK
    );
    let kiosk = json!({ "payment_token": "pk_1" });
    assert_eq!(
        post_status(&router, "/saved-cards/pay/kiosk", kiosk).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn e2e_subscriptions_lifecycle_ok() {
    let (server, router, _state) = setup_test_app().await;
    mount_accept_jwt(&server, "jwt_sub_1").await;
    mount_subscription_mocks(&server).await;
    let plan_req = json!({
        "name": "Pro",
        "amount_cents": 50000,
        "frequency": 30,
        "integration": 4097558,
        "webhook_url": "https://example.com/wh"
    });
    let p_st = post_status(&router, "/subscriptions/plans", plan_req).await;
    assert!(p_st == StatusCode::CREATED || p_st == StatusCode::OK);
    assert_eq!(
        send_get(&router, "/subscriptions/plans").await.0,
        StatusCode::OK
    );
    let susp = post_status(&router, "/subscriptions/1264/suspend", json!({})).await;
    assert_eq!(susp, StatusCode::OK);
    assert_eq!(
        post_status(&router, "/subscriptions/1264/resume", json!({})).await,
        StatusCode::OK
    );
    assert_eq!(
        send_get(&router, "/subscriptions/1264/cards").await.0,
        StatusCode::OK
    );
    assert_eq!(
        send_get(&router, "/subscriptions/1264/transactions")
            .await
            .0,
        StatusCode::OK
    );
    let ref_uri = "/subscriptions/1264/refund-last-transaction";
    assert_eq!(
        post_status(&router, ref_uri, json!({})).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn e2e_payouts_instant_bulk_inquiries_budget_topup_ok() {
    let (server, router, _state) = setup_test_app().await;
    mount_payouts_token(&server, "po_acc_1").await;
    mount_payouts_mocks(&server).await;
    let wallet = json!({ "amount": 150, "msisdn": "01012345678" });
    let w_st = post_status(&router, "/payouts/cashin/wallet/vodafone", wallet).await;
    assert_eq!(w_st, StatusCode::OK);
    let item = json!({ "issuer": "vodafone", "amount": 150, "msisdn": "01012345678" });
    let bulk = json!({ "transactions": [item] });
    assert_eq!(
        post_status(&router, "/payouts/cashin/bulk", bulk).await,
        StatusCode::OK
    );
    let inq = json!({ "transactions_ids": ["tx_p1"], "is_bulk": true });
    assert_eq!(
        post_status(&router, "/payouts/inquiries/transactions", inq).await,
        StatusCode::OK
    );
    assert_eq!(
        send_get(&router, "/payouts/inquiries/budget").await.0,
        StatusCode::OK
    );
    let topup = json!({
        "amount": 1000,
        "currency": "egyptian_pound",
        "to_attach_proof_base64": BASE64_STANDARD.encode(b"proof-bytes"),
        "proof_filename": "receipt.pdf"
    });
    assert_eq!(
        post_status(&router, "/payouts/topups/bank-transfer", topup).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn e2e_onboarding_and_scoped_merchants_ok() {
    let (server, router, _state) = setup_test_app().await;
    mount_accept_jwt(&server, "jwt_ob_1").await;
    mount_onboarding_mocks(&server).await;
    let reg = json!({
        "partner": "KeyPartner",
        "email": "m@example.com",
        "phone_number": "01010101010",
        "first_name": "Ali",
        "last_name": "Hassan"
    });
    let r_st = post_status(&router, "/onboarding/flow/register", reg).await;
    assert!(r_st == StatusCode::CREATED || r_st == StatusCode::OK);
    let schema_uri = "/onboarding/flow/schema?partner=KeyPartner&paymob_mid=777888";
    assert_eq!(send_get(&router, schema_uri).await.0, StatusCode::OK);
    let step = json!({ "paymob_mid": 777888, "step_id": "kyc", "data": {} });
    assert_eq!(
        post_status(&router, "/onboarding/flow/submit-step", step).await,
        StatusCode::OK
    );
    assert_eq!(
        send_get(&router, "/onboarding/flow/merchants/777888")
            .await
            .0,
        StatusCode::OK
    );
    let intent = json!({
        "amount_cents": 15000,
        "currency": "EGP",
        "payment_methods": [4097558],
        "billing_data": sample_scoped_billing()
    });
    let i_st = post_status(&router, "/merchants/777888/intentions", intent).await;
    assert!(i_st == StatusCode::OK || i_st == StatusCode::CREATED);
    assert_eq!(
        send_get(&router, "/merchants/777888/transactions/555")
            .await
            .0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn e2e_unified_adapter_all_operations_ok() {
    let (server, router, _state) = setup_test_app().await;
    mount_unified_mocks(&server).await;
    let sess = json!({ "amount_cents": 25000, "currency": "EGP", "payment_methods": ["4097558"] });
    let s_st = post_status(&router, "/unified/sessions", sess).await;
    assert!(s_st == StatusCode::CREATED || s_st == StatusCode::OK);
    let tx_amt = json!({ "transaction_id": 192036465, "amount_cents": 25000 });
    assert_eq!(
        post_status(&router, "/unified/refund", tx_amt.clone()).await,
        StatusCode::OK
    );
    let void_body = json!({ "transaction_id": 192036465 });
    assert_eq!(
        post_status(&router, "/unified/void", void_body).await,
        StatusCode::OK
    );
    assert_eq!(
        post_status(&router, "/unified/capture", tx_amt).await,
        StatusCode::OK
    );
    let payout = json!({
        "recipient_identifier": "01012345678",
        "amount_cents": 15000,
        "currency": "EGP",
        "issuer": "vodafone"
    });
    assert_eq!(
        post_status(&router, "/unified/payouts", payout).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn e2e_webhooks_protocols_a_b_c_d_e_ok() {
    let (_server, router, _state) = setup_test_app().await;
    let tx_val: Value = serde_json::from_str(OFFICIAL_TX_192036465_JSON).expect("valid tx json");
    let tok_val: Value =
        serde_json::from_str(OFFICIAL_CARD_TOKEN_15978654_JSON).expect("valid tok json");
    let sub_val: Value =
        serde_json::from_str(OFFICIAL_SUBSCRIPTION_1264_JSON).expect("valid sub json");
    let pa_uri = format!("/webhooks/paymob?hmac={SAMPLE_TX_192036465_HMAC}");
    assert_eq!(post_status(&router, &pa_uri, tx_val).await, StatusCode::OK);
    let pb_uri = format!("/webhooks/paymob/redirect?{OFFICIAL_REDIRECT_316004_QUERY}");
    assert_eq!(send_get(&router, &pb_uri).await.0, StatusCode::OK);
    let pc_uri = format!("/webhooks/paymob?hmac={SAMPLE_CARD_TOKEN_15978654_HMAC}");
    assert_eq!(post_status(&router, &pc_uri, tok_val).await, StatusCode::OK);
    assert_eq!(
        post_status(&router, "/webhooks/paymob", sub_val).await,
        StatusCode::OK
    );
    let payout_body = json!({
        "transaction_id": "tx_e_1",
        "issuer": "vodafone",
        "disbursement_status": "successful",
        "amount": 150
    });
    assert_eq!(
        post_status(&router, "/webhooks/paymob", payout_body).await,
        StatusCode::OK
    );
}

// ============================================================================
// 2. Boundary Condition Tests
// ============================================================================

#[tokio::test]
async fn boundary_amount_zero_one_and_u64_max_overflow() {
    let (server, router, _state) = setup_test_app().await;
    mount_accept_post(&server, "/v1/intention/", 201, sample_intention_response()).await;
    let zero = json!({ "amount": 0, "currency": "EGP", "payment_methods": [4097558] });
    let z_st = post_status(&router, "/intentions", zero).await;
    assert_eq!(z_st, StatusCode::UNPROCESSABLE_ENTITY);
    let one = json!({ "amount": 1, "currency": "EGP", "payment_methods": [4097558] });
    let one_st = post_status(&router, "/intentions", one).await;
    assert!(one_st == StatusCode::CREATED || one_st == StatusCode::OK);
    let max = json!({
        "amount_cents": u64::MAX,
        "convenience_fee": {
            "mode": { "FixedCents": 1 },
            "is_refundable": false,
            "card_rule": "Uniform"
        }
    });
    let max_st = post_status(&router, "/splits/validate-and-quote", max).await;
    assert_eq!(max_st, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn boundary_bulk_disbursements_0_1_1000_1001() {
    let (server, router, _state) = setup_test_app().await;
    mount_payouts_token(&server, "po_bulk_1").await;
    let ok_resp = json!({ "status": "ok", "results": [] });
    mount_payouts_json(
        &server,
        "POST",
        "/disburse/api/v1/disburse/bulk_transaction/",
        200,
        ok_resp,
    )
    .await;
    let mk_items = |n: usize| -> Value {
        let items: Vec<Value> = (0..n)
            .map(|i| json!({ "issuer": "vodafone", "amount": 100, "msisdn": format!("010{i:08}") }))
            .collect();
        json!({ "transactions": items })
    };
    let st0 = post_status(&router, "/payouts/cashin/bulk", mk_items(0)).await;
    let st1 = post_status(&router, "/payouts/cashin/bulk", mk_items(1)).await;
    let st1000 = post_status(&router, "/payouts/cashin/bulk", mk_items(1_000)).await;
    let st1001 = post_status(&router, "/payouts/cashin/bulk", mk_items(1_001)).await;
    assert_eq!(st0, StatusCode::BAD_REQUEST);
    assert_eq!(st1, StatusCode::OK);
    assert_eq!(st1000, StatusCode::OK);
    assert_eq!(st1001, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn boundary_payout_inquiry_ids_0_1_500_501() {
    let (server, router, _state) = setup_test_app().await;
    mount_payouts_token(&server, "po_inq_1").await;
    let ok_resp = json!({ "results": [] });
    mount_payouts_json(
        &server,
        "POST",
        "/disburse/api/v1/bulk_transaction/inquire/",
        200,
        ok_resp,
    )
    .await;
    let mk_ids = |n: usize| -> Value {
        let ids: Vec<String> = (0..n).map(|i| format!("tx_{i}")).collect();
        json!({ "transactions_ids": ids, "is_bulk": true })
    };
    let st0 = post_status(&router, "/payouts/inquiries/transactions", mk_ids(0)).await;
    let st1 = post_status(&router, "/payouts/inquiries/transactions", mk_ids(1)).await;
    let st500 = post_status(&router, "/payouts/inquiries/transactions", mk_ids(500)).await;
    let st501 = post_status(&router, "/payouts/inquiries/transactions", mk_ids(501)).await;
    assert_eq!(st0, StatusCode::BAD_REQUEST);
    assert_eq!(st1, StatusCode::OK);
    assert_eq!(st500, StatusCode::OK);
    assert_eq!(st501, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn boundary_bank_transfer_proof_size_0_2936012_2936013() {
    let (server, router, _state) = setup_test_app().await;
    mount_payouts_token(&server, "po_top_1").await;
    let ok_resp = json!({ "status": "pending", "id": 102 });
    mount_payouts_json(&server, "POST", "/api/secure/topup/request/", 200, ok_resp).await;
    let mk_topup = |bytes: usize| -> Value {
        json!({
            "amount": 1000,
            "currency": "egyptian_pound",
            "to_attach_proof_base64": BASE64_STANDARD.encode(vec![b'a'; bytes]),
            "proof_filename": "receipt.pdf"
        })
    };
    let st0 = post_status(&router, "/payouts/topups/bank-transfer", mk_topup(0)).await;
    let st_max = post_status(
        &router,
        "/payouts/topups/bank-transfer",
        mk_topup(2_936_012),
    )
    .await;
    let st_over = post_status(
        &router,
        "/payouts/topups/bank-transfer",
        mk_topup(2_936_013),
    )
    .await;
    assert_eq!(st0, StatusCode::BAD_REQUEST);
    assert_eq!(st_max, StatusCode::OK);
    assert_eq!(st_over, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn boundary_split_payments_cards_0_1_3_4_and_bps_not_10000() {
    let (_server, router, _state) = setup_test_app().await;
    let mk_split = |cards: usize, bps: u16| -> Value {
        let card_list: Vec<Value> = (0..cards)
            .map(|_| json!({ "amount_cents": 1000 }))
            .collect();
        json!({
            "amount_cents": 10000,
            "split_description": { "recipients": [{ "recipient_id": "1", "percentage_bps": bps }] },
            "split_payment": { "cards": card_list }
        })
    };
    let st0 = post_status(&router, "/splits/validate-and-quote", mk_split(0, 10_000)).await;
    let st1 = post_status(&router, "/splits/validate-and-quote", mk_split(1, 10_000)).await;
    let st3 = post_status(&router, "/splits/validate-and-quote", mk_split(3, 10_000)).await;
    let st4 = post_status(&router, "/splits/validate-and-quote", mk_split(4, 10_000)).await;
    let st_bps = post_status(&router, "/splits/validate-and-quote", mk_split(1, 10_001)).await;
    assert_eq!(st0, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(st1, StatusCode::OK);
    assert_eq!(st3, StatusCode::OK);
    assert_eq!(st4, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(st_bps, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn boundary_sandbox_guard_credential_age_24_25_30() {
    let (_server, router, _state) = setup_test_app().await;
    let mk_req =
        |age: u64| json!({ "is_sandbox": true, "credential_age_days": age, "channel": "card" });
    let (st24, b24) = send_json(&router, Method::POST, "/sandbox/check", mk_req(24)).await;
    assert_eq!(st24, StatusCode::OK);
    assert!(b24["warnings"].as_array().is_none_or(Vec::is_empty));
    let (st25, b25) = send_json(&router, Method::POST, "/sandbox/check", mk_req(25)).await;
    assert_eq!(st25, StatusCode::OK);
    assert!(!b25["warnings"].as_array().is_none_or(Vec::is_empty));
    let (st30, _) = send_json(&router, Method::POST, "/sandbox/check", mk_req(30)).await;
    assert_eq!(st30, StatusCode::UNPROCESSABLE_ENTITY);
}

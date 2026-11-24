#![forbid(unsafe_code)]
//! Positive E2E integration tests across all 14 services of `examples/axum_server.rs`.

use axum::Router;
use axum::http::{Method, StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use serde_json::{Value, json};
use some_paymob::test_utils::mock_server::PaymobMockServer;
use some_paymob::test_utils::vectors::{
    OFFICIAL_CARD_TOKEN_15978654_JSON, OFFICIAL_REDIRECT_316004_QUERY, OFFICIAL_TX_192036465_JSON,
    SAMPLE_CARD_TOKEN_15978654_HMAC, SAMPLE_SUBSCRIPTION_1264_HMAC, SAMPLE_SUBSCRIPTION_1264_JSON,
    SAMPLE_TX_192036465_HMAC,
};

use super::common::{
    mount_accept_get, mount_accept_json, mount_accept_jwt, mount_accept_post, mount_payouts_json,
    mount_payouts_token, post_status, sample_intention_response, sample_transaction_response,
    send_delete, send_get, send_json, setup_test_app,
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

async fn assert_post_ok(router: &Router, uri: &str, body: Value) {
    assert_eq!(
        post_status(router, uri, body).await,
        StatusCode::OK,
        "POST {uri}"
    );
}

async fn assert_put_ok(router: &Router, uri: &str, body: Value) {
    assert_eq!(
        send_json(router, Method::PUT, uri, body).await.0,
        StatusCode::OK,
        "PUT {uri}"
    );
}

async fn assert_post_created_or_ok(router: &Router, uri: &str, body: Value) {
    let status = post_status(router, uri, body).await;
    assert!(
        status == StatusCode::CREATED || status == StatusCode::OK,
        "POST {uri} returned {status}"
    );
}

async fn assert_get_ok(router: &Router, uri: &str) {
    assert_eq!(send_get(router, uri).await.0, StatusCode::OK, "GET {uri}");
}

async fn mount_tx_manage_mocks(server: &PaymobMockServer, tx: Value) {
    mount_accept_post(
        server,
        "/api/acceptance/void_refund/refund",
        200,
        tx.clone(),
    )
    .await;
    mount_accept_post(server, "/api/acceptance/void_refund/void", 200, tx.clone()).await;
    mount_accept_post(server, "/api/acceptance/capture", 200, tx).await;
}

async fn mount_subscription_plan_mocks(server: &PaymobMockServer) {
    let plan = json!({
        "id": 42,
        "name": "Pro",
        "frequency": 30,
        "integration": 4097558,
        "amount_cents": 50000
    });
    let base = "/api/acceptance/subscription-plans";
    mount_accept_post(server, base, 201, plan.clone()).await;
    let list = json!({ "results": [plan.clone()], "count": 1 });
    mount_accept_get(server, base, list).await;
    let p42 = "/api/acceptance/subscription-plans/42";
    mount_accept_json(server, "PUT", p42, 200, plan.clone()).await;
    let susp = "/api/acceptance/subscription-plans/42/suspend";
    mount_accept_post(server, susp, 200, plan.clone()).await;
    let res = "/api/acceptance/subscription-plans/42/resume";
    mount_accept_post(server, res, 200, plan).await;
}

async fn mount_subscription_lifecycle_mocks(server: &PaymobMockServer) {
    let sub = json!({ "id": 1264, "state": "active", "plan_id": 42, "amount_cents": 50000 });
    mount_accept_post(server, "/v1/intention/", 201, sample_intention_response()).await;
    let s1264 = "/api/acceptance/subscriptions/1264";
    mount_accept_get(server, s1264, sub.clone()).await;
    let list = json!({ "results": [sub.clone()], "count": 1 });
    mount_accept_get(server, "/api/acceptance/subscriptions", list).await;
    mount_accept_json(server, "PUT", s1264, 200, sub.clone()).await;
    for action in ["suspend", "resume", "cancel"] {
        let path = format!("/api/acceptance/subscriptions/1264/{action}");
        mount_accept_post(server, &path, 200, sub.clone()).await;
    }
}

async fn mount_subscription_card_mocks(server: &PaymobMockServer) {
    let card = json!({
        "id": 374,
        "card_data": "Visa",
        "token": "tok_sec_374",
        "created_at": "2026-11-16T10:00:00Z",
        "is_primary": true,
        "masked_pan": "xxxx-xxxx-xxxx-1111",
        "failed_attempts": 0
    });
    let cards_path = "/api/acceptance/subscriptions/1264/cards";
    mount_accept_get(server, cards_path, json!([card.clone()])).await;
    let add_path = "/api/acceptance/subscriptions/1264/add-secondary-card";
    mount_accept_post(server, add_path, 200, card.clone()).await;
    let pri_path = "/api/acceptance/subscriptions/1264/change-primary-card";
    mount_accept_post(server, pri_path, 200, card).await;
    let del_path = "/api/acceptance/subscriptions/1264/delete-card";
    mount_accept_post(server, del_path, 200, json!({ "detail": "deleted" })).await;
}

async fn mount_subscription_history_mocks(server: &PaymobMockServer) {
    let wh_body = json!({ "id": 1264, "webhook_url": "https://example.com/wh" });
    let wh_path = "/api/acceptance/subscriptions/1264/webhook";
    mount_accept_post(server, wh_path, 200, wh_body).await;
    let txs_path = "/api/acceptance/subscriptions/1264/transactions";
    mount_accept_get(server, txs_path, json!([])).await;
    let tx1 = sample_transaction_response(998877, 50000);
    let last_path = "/api/acceptance/subscriptions/1264/last-transaction";
    mount_accept_get(server, last_path, tx1).await;
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
    mount_payouts_json(server, "POST", "/api/secure/disburse/", 200, cashin.clone()).await;
    let aman_path = "/api/secure/transaction/aman/cancel/";
    mount_payouts_json(server, "POST", aman_path, 200, cashin).await;
    let bulk_path = "/disburse/api/v1/disburse/bulk_transaction";
    let bulk_resp = json!({ "status": "ok", "results": [] });
    mount_payouts_json(server, "POST", bulk_path, 200, bulk_resp).await;
    for path in [
        "/api/secure/transaction/inquire/",
        "/disburse/api/v1/bulk_transaction/inquire",
        "/disburse/api/v1/bulk_transaction/inquire_by_reference",
    ] {
        mount_payouts_json(server, "POST", path, 200, json!({ "results": [] })).await;
    }
    let budget = json!({ "current_budget": "Your current budget is 5000.00 LE" });
    mount_payouts_json(server, "GET", "/api/secure/budget/inquire/", 200, budget).await;
    let topups = json!({ "results": [{ "id": 101, "amount": 1000 }], "count": 1 });
    mount_payouts_json(server, "GET", "/api/secure/topup/inquire/", 200, topups).await;
    let topup = json!({ "status": "pending", "id": 101 });
    mount_payouts_json(server, "POST", "/api/secure/topup/request/", 200, topup).await;
}

async fn mount_onboarding_auth_mocks(server: &PaymobMockServer) {
    let key_resp = json!({ "api_key": "pk_partner_prov_1", "label": "ci" });
    mount_accept_post(server, "/api/auth/api_keys", 201, key_resp).await;
    let hmac_env = json!({
        "label": "partner",
        "status": "Created",
        "code": 201,
        "body": { "hmac_secret": "ABC123HMAC" }
    });
    let p_hmac = "/api/auth/hmac_secret/get_hmac";
    mount_accept_get(server, p_hmac, hmac_env.clone()).await;
    let m_hmac = "/api/partner/merchants/hmac_secret/777888";
    mount_accept_get(server, m_hmac, hmac_env).await;
}

async fn mount_onboarding_flow_mocks(server: &PaymobMockServer) {
    let reg = json!({ "paymob_mid": 777888, "partner": "KeyPartner", "status": "PENDING" });
    mount_accept_post(server, "/api/onboarding/register", 201, reg).await;
    let schema = json!({ "partner": "KeyPartner", "resubmission": false, "steps": [] });
    mount_accept_get(server, "/api/onboarding/flow/schema", schema).await;
    let step_resp = json!({ "status": "SUBMITTED" });
    mount_accept_post(server, "/api/onboarding/flow/step", 200, step_resp).await;
    let merchant = json!({
        "paymob_mid": 777888,
        "status": "APPROVED",
        "is_live": true,
        "live_integration_ids": [4097558],
        "test_integration_ids": [],
        "pending_steps": []
    });
    mount_accept_get(server, "/api/onboarding/merchant/777888", merchant).await;
}

async fn mount_scoped_merchant_mocks(server: &PaymobMockServer) {
    let tx = sample_transaction_response(555, 15000);
    mount_accept_post(server, "/v1/intention/", 201, sample_intention_response()).await;
    let intent_resp = sample_intention_response();
    mount_accept_json(server, "PUT", "/v1/intention/", 200, intent_resp).await;
    mount_accept_get(server, "/api/acceptance/transactions/555", tx.clone()).await;
    let inq_path = "/api/ecommerce/orders/transaction_inquiry";
    mount_accept_post(server, inq_path, 200, tx.clone()).await;
    mount_tx_manage_mocks(server, tx).await;
}

async fn mount_unified_mocks(server: &PaymobMockServer) {
    let tx = sample_transaction_response(192036466, 25000);
    mount_accept_jwt(server, "jwt_uni_1").await;
    mount_accept_post(server, "/v1/intention/", 201, sample_intention_response()).await;
    mount_accept_post(server, "/api/acceptance/payments/pay", 200, tx.clone()).await;
    let last_tx_path = "/api/acceptance/subscriptions/1264/last-transaction";
    mount_accept_get(server, last_tx_path, tx.clone()).await;
    mount_tx_manage_mocks(server, tx).await;
    mount_payouts_token(server, "po_uni_1").await;
    let payout = json!({
        "transaction_id": "tx_u1",
        "issuer": "vodafone",
        "amount": 150,
        "disbursement_status": "successful"
    });
    mount_payouts_json(server, "POST", "/api/secure/disburse/", 200, payout).await;
}

#[tokio::test]
async fn e2e_health_and_sandbox_check_ok() {
    let (_server, router, _state) = setup_test_app().await;
    assert_get_ok(&router, "/health").await;
    let body = json!({ "is_sandbox": true, "credential_age_days": 10, "channel": "card" });
    let (sb_status, sb_json) = send_json(&router, Method::POST, "/sandbox/check", body).await;
    assert_eq!(sb_status, StatusCode::OK);
    assert_eq!(sb_json["ok"], true);
}

#[tokio::test]
async fn e2e_intentions_create_and_update_ok() {
    let (server, router, _state) = setup_test_app().await;
    let resp = sample_intention_response();
    mount_accept_post(&server, "/v1/intention/", 201, resp.clone()).await;
    mount_accept_json(&server, "PUT", "/v1/intention/", 200, resp).await;
    let payload = json!({ "amount": 10000, "currency": "EGP", "payment_methods": [4097558] });
    let (c_st, c_json) = send_json(&router, Method::POST, "/intentions", payload).await;
    assert!(c_st == StatusCode::CREATED || c_st == StatusCode::OK);
    assert_eq!(c_json["client_secret"], "[REDACTED]");
    let c_url = c_json["unified_checkout_url"].as_str().unwrap_or_default();
    assert!(c_url.contains("unifiedcheckout"));
    let upd = json!({ "amount": 15000, "currency": "EGP" });
    let (u_st, u_json) = send_json(&router, Method::PUT, "/intentions", upd).await;
    assert_eq!(u_st, StatusCode::OK);
    let u_url = u_json["unified_checkout_url"].as_str().unwrap_or_default();
    assert!(u_url.contains("unifiedcheckout"));
}

#[tokio::test]
async fn e2e_checkout_pixel_and_affordability_ok() {
    let (_server, router, _state) = setup_test_app().await;
    let px = json!({ "client_secret": "egy_csk_test_1", "payment_methods": ["card"] });
    assert_post_ok(&router, "/checkout/pixel", px).await;
    let aff = json!({ "amount_cents": 50000, "currency": "EGP" });
    assert_post_ok(&router, "/checkout/affordability", aff).await;
}

#[tokio::test]
async fn e2e_legacy_v2_orders_keys_and_checkout_ok() {
    let (server, router, _state) = setup_test_app().await;
    mount_accept_jwt(&server, "jwt_legacy_1").await;
    let order = json!({ "id": 7711, "amount_cents": 25000, "currency": "EGP" });
    mount_accept_post(&server, "/api/ecommerce/orders", 201, order).await;
    let pk_resp = json!({ "token": "pk_leg_1" });
    mount_accept_post(&server, "/api/acceptance/payment_keys", 201, pk_resp).await;
    let ord = json!({ "amount_cents": 25000, "currency": "EGP", "delivery_needed": false });
    assert_post_created_or_ok(&router, "/legacy/orders", ord).await;
    let key = json!({
        "order_id": 7711,
        "amount_cents": 25000,
        "currency": "EGP",
        "integration_id": 4097558,
        "billing_data": sample_legacy_billing(),
        "expiration": 3600,
        "lock_order_when_paid": false
    });
    assert_post_created_or_ok(&router, "/legacy/payment-keys", key).await;
    let chk = json!({
        "amount_cents": 25000,
        "currency": "EGP",
        "integration_id": 4097558,
        "iframe_id": 123,
        "billing_data": sample_legacy_billing()
    });
    assert_post_ok(&router, "/legacy/checkout", chk).await;
}

#[tokio::test]
async fn e2e_manage_refund_void_capture_ok() {
    let (server, router, _state) = setup_test_app().await;
    mount_accept_jwt(&server, "jwt_manage_1").await;
    mount_tx_manage_mocks(&server, sample_transaction_response(192036466, 25000)).await;
    let ref_body = json!({ "transaction_id": 192036465, "amount_cents": 25000 });
    assert_post_ok(&router, "/manage/refund", ref_body.clone()).await;
    let void_body = json!({ "transaction_id": 192036465 });
    assert_post_ok(&router, "/manage/void", void_body).await;
    let void_v2 = json!({ "transaction_id": 192036465, "legacy_v2_bearer": true });
    assert_post_ok(&router, "/manage/void", void_v2).await;
    assert_post_ok(&router, "/manage/capture", ref_body).await;
}

#[tokio::test]
async fn e2e_inquiries_all_endpoints_ok() {
    let (server, router, _state) = setup_test_app().await;
    mount_accept_jwt(&server, "jwt_inq_1").await;
    let tx = sample_transaction_response(192036465, 10000);
    let tx_path = "/api/acceptance/transactions/192036465";
    mount_accept_get(&server, tx_path, tx.clone()).await;
    let inq_path = "/api/ecommerce/orders/transaction_inquiry";
    mount_accept_post(&server, inq_path, 200, tx).await;
    mount_accept_post(&server, "/api/acceptance/order_card_tokens", 200, json!([])).await;
    let ord = json!({ "id": 212245716, "amount_cents": 10000, "currency": "EGP" });
    mount_accept_get(&server, "/api/ecommerce/orders/212245716", ord).await;
    assert_get_ok(&router, "/inquiries/transactions/192036465").await;
    let by_ord = json!({ "order_id": 212245716 });
    assert_post_ok(&router, "/inquiries/by-order", by_ord).await;
    let tok_uri = "/inquiries/orders/212245716/card-tokens";
    assert_post_ok(&router, tok_uri, json!({})).await;
    assert_get_ok(&router, "/inquiries/orders/212245716").await;
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
    let cancel_path = "/api/ecommerce/payment-links/cancel";
    mount_accept_post(&server, cancel_path, 200, json!({ "detail": "cancelled" })).await;
    let ql = json!({ "amount_cents": 15000, "currency": "EGP", "integrations": [4097558] });
    assert_post_created_or_ok(&router, "/quicklinks", ql).await;
    assert_post_ok(&router, "/quicklinks/ql_1/cancel", json!({})).await;
    let split = json!({
        "amount_cents": 10000,
        "split_description": { "recipients": [{ "recipient_id": "1", "percentage_bps": 10000 }] },
        "split_payment": { "cards": [{ "amount_cents": 10000 }] }
    });
    assert_post_ok(&router, "/splits/validate-and-quote", split).await;
}

#[tokio::test]
async fn e2e_saved_cards_all_modes_ok() {
    let (server, router, _state) = setup_test_app().await;
    mount_accept_jwt(&server, "jwt_sc_1").await;
    let pay_resp = sample_transaction_response(550011, 25000);
    mount_accept_post(&server, "/api/acceptance/payments/pay", 200, pay_resp).await;
    let mit = json!({ "payment_token": "pk_1", "saved_token": "tok_1" });
    assert_post_ok(&router, "/saved-cards/pay/mit", mit).await;
    let wallet = json!({ "payment_token": "pk_1", "wallet_phone": "01010101010" });
    assert_post_ok(&router, "/saved-cards/pay/wallet", wallet).await;
    let kiosk = json!({ "payment_token": "pk_1" });
    assert_post_ok(&router, "/saved-cards/pay/kiosk", kiosk).await;
    let raw = json!({
        "payment_token": "pk_1",
        "source": { "identifier": "AGGREGATOR", "subtype": "AGGREGATOR" }
    });
    assert_post_ok(&router, "/saved-cards/pay/raw", raw).await;
}

#[tokio::test]
async fn e2e_subscription_plans_and_lifecycle_ok() {
    let (server, router, _state) = setup_test_app().await;
    mount_accept_jwt(&server, "jwt_sub_1").await;
    mount_subscription_plan_mocks(&server).await;
    mount_subscription_lifecycle_mocks(&server).await;
    let plan_req = json!({
        "name": "Pro",
        "amount_cents": 50000,
        "frequency": 30,
        "integration": 4097558,
        "webhook_url": "https://example.com/wh"
    });
    assert_post_created_or_ok(&router, "/subscriptions/plans", plan_req).await;
    assert_get_ok(&router, "/subscriptions/plans").await;
    assert_put_ok(
        &router,
        "/subscriptions/plans/42",
        json!({ "name": "Pro+" }),
    )
    .await;
    assert_post_ok(&router, "/subscriptions/plans/42/suspend", json!({})).await;
    assert_post_ok(&router, "/subscriptions/plans/42/resume", json!({})).await;
    let sub_req = json!({
        "subscription_plan_id": 42,
        "amount": 50000,
        "currency": "EGP",
        "payment_methods": [4097558]
    });
    assert_post_created_or_ok(&router, "/subscriptions", sub_req).await;
    assert_get_ok(&router, "/subscriptions/1264").await;
    assert_get_ok(&router, "/subscriptions").await;
    let sub_upd = json!({ "amount_cents": 60000 });
    assert_put_ok(&router, "/subscriptions/1264", sub_upd).await;
    assert_post_ok(&router, "/subscriptions/1264/suspend", json!({})).await;
    assert_post_ok(&router, "/subscriptions/1264/resume", json!({})).await;
    assert_post_ok(&router, "/subscriptions/1264/cancel", json!({})).await;
}

#[tokio::test]
async fn e2e_subscription_cards_and_history_ok() {
    let (server, router, _state) = setup_test_app().await;
    mount_accept_jwt(&server, "jwt_sub_cards_1").await;
    mount_subscription_card_mocks(&server).await;
    mount_subscription_history_mocks(&server).await;
    assert_get_ok(&router, "/subscriptions/1264/cards").await;
    let sec_card = json!({ "token": "tok_sec_374" });
    assert_post_ok(&router, "/subscriptions/1264/cards/secondary", sec_card).await;
    let pri_card = json!({ "card": 374 });
    assert_post_ok(&router, "/subscriptions/1264/cards/primary", pri_card).await;
    let (del_st, _) = send_delete(&router, "/subscriptions/1264/cards/374").await;
    assert_eq!(del_st, StatusCode::OK);
    let wh_req = json!({ "webhook_url": "https://example.com/wh" });
    assert_post_ok(&router, "/subscriptions/1264/webhook", wh_req).await;
    assert_get_ok(&router, "/subscriptions/1264/last-transaction").await;
    assert_get_ok(&router, "/subscriptions/1264/transactions").await;
    let ref_uri = "/subscriptions/1264/refund-last-transaction";
    assert_post_ok(&router, ref_uri, json!({})).await;
}

#[tokio::test]
async fn e2e_payouts_auth_and_wallet_cashin_ok() {
    let (server, router, _state) = setup_test_app().await;
    mount_payouts_token(&server, "po_acc_1").await;
    mount_payouts_mocks(&server).await;
    let (tok_st, tok_json) =
        send_json(&router, Method::POST, "/payouts/auth/token", json!({})).await;
    assert_eq!(tok_st, StatusCode::OK);
    assert_eq!(tok_json["access_token"], "[REDACTED]");
    assert_eq!(tok_json["refresh_token"], "[REDACTED]");
    assert_eq!(tok_json["access_token_present"], true);
    assert_eq!(tok_json["refresh_token_present"], true);
    let ref_req = json!({ "refresh_token": "refresh_tok" });
    let (ref_st, ref_json) =
        send_json(&router, Method::POST, "/payouts/auth/refresh", ref_req).await;
    assert_eq!(ref_st, StatusCode::OK);
    assert_eq!(ref_json["access_token"], "[REDACTED]");
    let wallet = json!({ "amount": 150, "msisdn": "01012345678" });
    for issuer in ["vodafone", "etisalat", "orange", "bank_wallet"] {
        let uri = format!("/payouts/cashin/wallet/{issuer}");
        assert_post_ok(&router, &uri, wallet.clone()).await;
    }
}

#[tokio::test]
async fn e2e_payouts_bank_post_aman_and_bulk_ok() {
    let (server, router, _state) = setup_test_app().await;
    mount_payouts_token(&server, "po_acc_2").await;
    mount_payouts_mocks(&server).await;
    let bc = json!({
        "amount": 500,
        "bank_card_number": "4111111111111234",
        "bank_code": "CIB",
        "bank_transaction_type": "salary",
        "full_name": "Ali Hassan"
    });
    assert_post_ok(&router, "/payouts/cashin/bank-card", bc).await;
    let bi = json!({
        "amount": 500,
        "bank_code": "CIB",
        "bank_account_number": "EG120001234567890",
        "full_name": "Ali Hassan"
    });
    assert_post_ok(&router, "/payouts/cashin/bank-instant", bi).await;
    let ep = json!({
        "amount": 500,
        "msisdn": "01012345678",
        "full_name": "Ali Hassan",
        "national_id": "29001011234567"
    });
    assert_post_ok(&router, "/payouts/cashin/egyptian-post", ep).await;
    let aman = json!({ "transaction_id": "tx_aman_1" });
    assert_post_ok(&router, "/payouts/cashin/aman/cancel", aman).await;
    let item = json!({ "issuer": "vodafone", "amount": 150, "msisdn": "01012345678" });
    assert_post_ok(
        &router,
        "/payouts/cashin/bulk",
        json!({ "transactions": [item] }),
    )
    .await;
}

#[tokio::test]
async fn e2e_payouts_inquiries_budget_and_topups_ok() {
    let (server, router, _state) = setup_test_app().await;
    mount_payouts_token(&server, "po_acc_3").await;
    mount_payouts_mocks(&server).await;
    let inq_bulk = json!({ "transactions_ids": ["tx_p1"], "is_bulk": true });
    assert_post_ok(&router, "/payouts/inquiries/transactions", inq_bulk).await;
    let inq_single = json!({ "transactions_ids": ["tx_p1"], "is_bulk": false });
    assert_post_ok(&router, "/payouts/inquiries/transactions", inq_single).await;
    let by_ref = json!({ "client_reference_ids": ["ref_1"] });
    assert_post_ok(&router, "/payouts/inquiries/by-reference", by_ref).await;
    assert_get_ok(&router, "/payouts/inquiries/budget").await;
    assert_get_ok(&router, "/payouts/inquiries/topups").await;
    let topup = json!({
        "amount": 1000,
        "currency": "egyptian_pound",
        "to_attach_proof_base64": BASE64_STANDARD.encode(b"proof-bytes"),
        "proof_filename": "receipt.pdf"
    });
    assert_post_ok(&router, "/payouts/topups/bank-transfer", topup).await;
    let acc = json!({
        "amount": 500,
        "currency": "egyptian_pound",
        "username": "payout_user"
    });
    assert_post_ok(&router, "/payouts/topups/accept-balance", acc).await;
}

#[tokio::test]
async fn e2e_onboarding_auth_and_flow_ok() {
    let (server, router, _state) = setup_test_app().await;
    mount_accept_jwt(&server, "jwt_ob_1").await;
    mount_onboarding_auth_mocks(&server).await;
    mount_onboarding_flow_mocks(&server).await;
    let login = json!({ "username": "partner@example.com", "password": "secret-password" });
    assert_post_ok(&router, "/onboarding/auth/login", login).await;
    let key_req = json!({ "label": "ci" });
    assert_post_created_or_ok(&router, "/onboarding/auth/api-keys", key_req).await;
    assert_get_ok(&router, "/onboarding/auth/hmac-secret").await;
    assert_get_ok(&router, "/onboarding/auth/merchants/777888/hmac-secret").await;
    let reg = json!({
        "partner": "KeyPartner",
        "email": "m@example.com",
        "phone_number": "01010101010",
        "first_name": "Ali",
        "last_name": "Hassan"
    });
    assert_post_created_or_ok(&router, "/onboarding/flow/register", reg).await;
    let schema_uri = "/onboarding/flow/schema?partner=KeyPartner&paymob_mid=777888";
    assert_get_ok(&router, schema_uri).await;
    let step = json!({ "paymob_mid": 777888, "step_id": "kyc", "data": {} });
    assert_post_ok(&router, "/onboarding/flow/submit-step", step).await;
    assert_get_ok(&router, "/onboarding/flow/merchants/777888").await;
}

#[tokio::test]
async fn e2e_scoped_merchants_all_operations_ok() {
    let (server, router, _state) = setup_test_app().await;
    mount_scoped_merchant_mocks(&server).await;
    let intent = json!({
        "amount_cents": 15000,
        "currency": "EGP",
        "payment_methods": [4097558],
        "billing_data": sample_scoped_billing()
    });
    assert_post_created_or_ok(&router, "/merchants/777888/intentions", intent).await;
    let upd = json!({ "amount_cents": 20000, "currency": "EGP" });
    assert_put_ok(&router, "/merchants/777888/intentions", upd).await;
    assert_get_ok(&router, "/merchants/777888/transactions/555").await;
    let inq = json!({ "order_id": 212245716 });
    assert_post_ok(&router, "/merchants/777888/orders/inquiry", inq).await;
    let tx_amt = json!({ "transaction_id": 555, "amount_cents": 15000 });
    assert_post_ok(&router, "/merchants/777888/manage/refund", tx_amt.clone()).await;
    let void_req = json!({ "transaction_id": 555 });
    assert_post_ok(&router, "/merchants/777888/manage/void", void_req).await;
    assert_post_ok(&router, "/merchants/777888/manage/capture", tx_amt).await;
}

#[tokio::test]
async fn e2e_unified_adapter_all_operations_ok() {
    let (server, router, _state) = setup_test_app().await;
    mount_unified_mocks(&server).await;
    let sess = json!({ "amount_cents": 25000, "currency": "EGP", "payment_methods": ["4097558"] });
    assert_post_created_or_ok(&router, "/unified/sessions", sess).await;
    let tx_amt = json!({ "transaction_id": 192036465, "amount_cents": 25000 });
    assert_post_ok(&router, "/unified/refund", tx_amt.clone()).await;
    let void_req = json!({ "transaction_id": 192036465 });
    assert_post_ok(&router, "/unified/void", void_req).await;
    assert_post_ok(&router, "/unified/capture", tx_amt).await;
    let charge = json!({ "payment_token": "pk_1", "saved_method_token": "tok_1" });
    assert_post_ok(&router, "/unified/charge-saved", charge).await;
    let sub_ref = json!({ "subscription_id": 1264, "amount_cents": 25000 });
    assert_post_ok(&router, "/unified/subscriptions/refund", sub_ref).await;
    let payout = json!({
        "recipient_identifier": "01012345678",
        "amount_cents": 15000,
        "currency": "EGP",
        "issuer": "vodafone"
    });
    assert_post_ok(&router, "/unified/payouts", payout).await;
    let wh_uri = format!("/unified/webhooks?hmac={SAMPLE_TX_192036465_HMAC}");
    let tx_val: Value = serde_json::from_str(OFFICIAL_TX_192036465_JSON).expect("valid tx json");
    assert_post_ok(&router, &wh_uri, tx_val).await;
}

#[tokio::test]
async fn e2e_webhooks_protocols_a_b_c_d_e_ok() {
    let (_server, router, _state) = setup_test_app().await;
    let tx_val: Value = serde_json::from_str(OFFICIAL_TX_192036465_JSON).expect("valid tx json");
    let tok_val: Value =
        serde_json::from_str(OFFICIAL_CARD_TOKEN_15978654_JSON).expect("valid tok json");
    let sub_val: Value =
        serde_json::from_str(SAMPLE_SUBSCRIPTION_1264_JSON).expect("valid sub json");
    let pa_uri = format!("/webhooks/paymob?hmac={SAMPLE_TX_192036465_HMAC}");
    assert_post_ok(&router, &pa_uri, tx_val).await;
    let pb_uri = format!("/webhooks/paymob/redirect?{OFFICIAL_REDIRECT_316004_QUERY}");
    assert_get_ok(&router, &pb_uri).await;
    let pc_uri = format!("/webhooks/paymob?hmac={SAMPLE_CARD_TOKEN_15978654_HMAC}");
    assert_post_ok(&router, &pc_uri, tok_val).await;
    let pd_uri = format!("/webhooks/paymob?hmac={SAMPLE_SUBSCRIPTION_1264_HMAC}");
    assert_post_ok(&router, &pd_uri, sub_val).await;
    // WHK-01: Unsigned Protocol E fails closed when no payouts HMAC secret is configured.
    let payout_body = json!({
        "transaction_id": "tx_e_1",
        "issuer": "bank_wallet",
        "status": "successful",
        "amount_cents": 15000,
        "currency": "EGP"
    });
    assert_eq!(
        super::common::post_status(&router, "/webhooks/paymob", payout_body).await,
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    );
}

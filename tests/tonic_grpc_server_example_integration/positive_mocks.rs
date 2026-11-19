#![forbid(unsafe_code)]
//! Wiremock endpoint setups for Unit 4 positive E2E and boundary integration tests.

use serde_json::{Value, json};
use some_paymob::test_utils::PaymobMockServer;

use super::positive_helpers::{
    mount_accept, mount_payouts, sample_subscription_card_json, sample_subscription_json,
    sample_subscription_tx_json,
};

pub(super) async fn setup_legacy_v2_mocks(server: &PaymobMockServer) {
    server
        .mount_accept_auth_sequence(&["jwt-leg-1", "jwt-leg-2", "jwt-leg-3", "jwt-leg-4"])
        .await;
    mount_accept(
        server,
        "POST",
        "/api/ecommerce/orders",
        201,
        json!({
            "id": 378804,
            "amount_cents": 50_000,
            "currency": "EGP",
            "merchant_order_id": "ORD-L1"
        }),
    )
    .await;
    mount_accept(
        server,
        "POST",
        "/api/acceptance/payment_keys",
        201,
        json!({ "token": "paykey_unit4_token" }),
    )
    .await;
}

pub(super) async fn setup_manage_mocks(server: &PaymobMockServer) {
    server
        .mount_accept_auth_sequence(&["jwt-manage-1", "jwt-manage-2"])
        .await;
    let refund_tx = json!({
        "id": 101,
        "success": true,
        "is_refund": true,
        "is_refunded": true,
        "amount_cents": 5000
    });
    let void_tx = json!({
        "id": 102,
        "success": true,
        "is_void": true,
        "is_voided": true,
        "amount_cents": 5000
    });
    let cap_tx = json!({
        "id": 103,
        "success": true,
        "is_capture": true,
        "is_captured": true,
        "amount_cents": 5000
    });
    mount_accept(
        server,
        "POST",
        "/api/acceptance/void_refund/refund",
        200,
        refund_tx,
    )
    .await;
    mount_accept(
        server,
        "POST",
        "/api/acceptance/void_refund/void",
        200,
        void_tx,
    )
    .await;
    mount_accept(server, "POST", "/api/acceptance/capture", 200, cap_tx).await;
}

pub(super) async fn setup_inquiries_mocks(server: &PaymobMockServer) {
    server
        .mount_accept_auth_sequence(&["jwt-inq-1", "jwt-inq-2", "jwt-inq-3"])
        .await;
    let tx_body = json!({
        "id": 192036465,
        "success": true,
        "amount_cents": 100_000,
        "currency": "EGP"
    });
    let ord_body = json!({
        "id": 217503754,
        "amount_cents": 100_000,
        "paid_amount_cents": 100_000,
        "payment_status": "PAID"
    });
    let tok_body = json!([{
        "type": "TOKEN",
        "obj": {
            "id": 15978654,
            "token": "tok_secret_15978654",
            "masked_pan": "xxxx-xxxx-xxxx-0008",
            "merchant_id": 12345,
            "card_subtype": "MasterCard",
            "order_id": "217503754"
        }
    }]);
    mount_accept(
        server,
        "GET",
        "/api/acceptance/transactions/192036465",
        200,
        tx_body.clone(),
    )
    .await;
    mount_accept(
        server,
        "POST",
        "/api/ecommerce/orders/transaction_inquiry",
        200,
        tx_body,
    )
    .await;
    mount_accept(
        server,
        "GET",
        "/api/ecommerce/orders/217503754",
        200,
        ord_body,
    )
    .await;
    mount_accept(
        server,
        "POST",
        "/api/acceptance/order_card_tokens",
        200,
        tok_body,
    )
    .await;
}

pub(super) async fn setup_quicklinks_mocks(server: &PaymobMockServer) {
    server.mount_accept_auth_sequence(&["jwt-ql-1"]).await;
    let ql_body = json!({
        "id": "ql_u4",
        "url": "https://accept.paymob.com/standalone/?ref=ql_u4",
        "client_url": "https://accept.paymob.com/api/acceptance/post_pay?ref=ql_u4"
    });
    mount_accept(server, "POST", "/api/ecommerce/payment-links", 201, ql_body).await;
    mount_accept(
        server,
        "POST",
        "/api/ecommerce/payment-links/cancel",
        200,
        json!({ "detail": "cancelled" }),
    )
    .await;
}

pub(super) async fn setup_subscription_plans_mocks(server: &PaymobMockServer) {
    server
        .mount_accept_auth_sequence(&["jwt-pl-1", "jwt-pl-2", "jwt-pl-3", "jwt-pl-4", "jwt-pl-5"])
        .await;
    let plan = json!({
        "id": 701,
        "name": "Pro Plan",
        "frequency": 30,
        "integration": 4097558,
        "amount_cents": 20_000,
        "is_active": true
    });
    let page = json!({ "count": 1, "next": null, "previous": null, "results": [plan.clone()] });
    mount_accept(
        server,
        "POST",
        "/api/acceptance/subscription-plans",
        201,
        plan.clone(),
    )
    .await;
    mount_accept(
        server,
        "PUT",
        "/api/acceptance/subscription-plans/701",
        200,
        plan.clone(),
    )
    .await;
    mount_accept(
        server,
        "GET",
        "/api/acceptance/subscription-plans",
        200,
        page,
    )
    .await;
    mount_accept(
        server,
        "POST",
        "/api/acceptance/subscription-plans/701/suspend",
        200,
        plan.clone(),
    )
    .await;
    mount_accept(
        server,
        "POST",
        "/api/acceptance/subscription-plans/701/resume",
        200,
        plan,
    )
    .await;
}

pub(super) async fn setup_subscriptions_lifecycle_mocks(server: &PaymobMockServer) {
    server
        .mount_accept_auth_sequence(&["jwt-s1", "jwt-s2", "jwt-s3", "jwt-s4", "jwt-s5", "jwt-s6"])
        .await;
    let enroll = json!({
        "id": "pi_sub_1",
        "client_secret": "egy_csk_sub_1",
        "intention_order_id": 5001,
        "status": "intended"
    });
    let sub = sample_subscription_json(1264, "active");
    let list = json!({ "count": 1, "next": null, "previous": null, "results": [sub.clone()] });
    mount_accept(server, "POST", "/v1/intention/", 201, enroll).await;
    mount_accept(
        server,
        "GET",
        "/api/acceptance/subscriptions/1264",
        200,
        sub.clone(),
    )
    .await;
    mount_accept(server, "GET", "/api/acceptance/subscriptions", 200, list).await;
    setup_sub_state_mocks(server, sub).await;
}

async fn setup_sub_state_mocks(server: &PaymobMockServer, sub: Value) {
    mount_accept(
        server,
        "PUT",
        "/api/acceptance/subscriptions/1264",
        200,
        sub.clone(),
    )
    .await;
    mount_accept(
        server,
        "POST",
        "/api/acceptance/subscriptions/1264/suspend",
        200,
        sub.clone(),
    )
    .await;
    mount_accept(
        server,
        "POST",
        "/api/acceptance/subscriptions/1264/resume",
        200,
        sub.clone(),
    )
    .await;
    mount_accept(
        server,
        "POST",
        "/api/acceptance/subscriptions/1264/cancel",
        200,
        sub,
    )
    .await;
}

async fn setup_sub_cards_mocks(server: &PaymobMockServer) {
    let card = sample_subscription_card_json(374, true);
    mount_accept(
        server,
        "GET",
        "/api/acceptance/subscriptions/1264/cards",
        200,
        json!([card.clone()]),
    )
    .await;
    mount_accept(
        server,
        "POST",
        "/api/acceptance/subscriptions/1264/add-secondary-card",
        200,
        card.clone(),
    )
    .await;
    mount_accept(
        server,
        "POST",
        "/api/acceptance/subscriptions/1264/change-primary-card",
        200,
        card,
    )
    .await;
    mount_accept(
        server,
        "POST",
        "/api/acceptance/subscriptions/1264/delete-card",
        200,
        json!({ "detail": "deleted" }),
    )
    .await;
}

async fn setup_sub_history_mocks(server: &PaymobMockServer) {
    let tx = sample_subscription_tx_json(998877);
    let refund = json!({
        "id": 998878,
        "success": true,
        "is_refund": true,
        "is_refunded": true,
        "amount_cents": 20_000,
        "parent_transaction": 998877
    });
    mount_accept(
        server,
        "POST",
        "/api/acceptance/subscriptions/1264/webhook",
        200,
        json!({ "id": 1264, "webhook_url": "https://merchant.example.com/hook" }),
    )
    .await;
    mount_accept(
        server,
        "GET",
        "/api/acceptance/subscriptions/1264/last-transaction",
        200,
        tx.clone(),
    )
    .await;
    mount_accept(
        server,
        "GET",
        "/api/acceptance/subscriptions/1264/transactions",
        200,
        json!([tx]),
    )
    .await;
    mount_accept(
        server,
        "POST",
        "/api/acceptance/void_refund/refund",
        200,
        refund,
    )
    .await;
}

pub(super) async fn setup_subscription_cards_and_history_mocks(server: &PaymobMockServer) {
    server
        .mount_accept_auth_sequence(&[
            "jwt-c1", "jwt-c2", "jwt-c3", "jwt-c4", "jwt-c5", "jwt-c6", "jwt-c7", "jwt-c8",
        ])
        .await;
    setup_sub_cards_mocks(server).await;
    setup_sub_history_mocks(server).await;
}

pub(super) async fn setup_payouts_cashin_mocks(server: &PaymobMockServer) {
    let tok = json!({
        "access_token": "po_acc_1",
        "refresh_token": "po_ref_1",
        "expires_in": 3600,
        "scope": "read write",
        "token_type": "Bearer"
    });
    let disb = json!({
        "transaction_id": "tx_po_1",
        "issuer": "vodafone",
        "amount": 200,
        "disbursement_status": "successful",
        "status_code": "200"
    });
    mount_payouts(server, "POST", "/api/secure/o/token/", 200, tok).await;
    mount_payouts(server, "POST", "/api/secure/disburse/", 200, disb.clone()).await;
    mount_payouts(
        server,
        "POST",
        "/api/secure/transaction/aman/cancel/",
        200,
        disb.clone(),
    )
    .await;
    mount_payouts(
        server,
        "POST",
        "/disburse/api/v1/disburse/bulk_transaction",
        200,
        json!({ "status": "ok", "results": [disb] }),
    )
    .await;
}

pub(super) async fn setup_payouts_inquiries_and_topups_mocks(server: &PaymobMockServer) {
    let inq = json!({
        "results": [{ "transaction_id": "tx_po_1", "amount": 200 }],
        "status_code": "200"
    });
    let topup_rec = json!({
        "id": 55,
        "amount": 500,
        "status": "pending",
        "type": "from_bank_transfer",
        "currency": "egyptian_pound"
    });
    mount_payouts(
        server,
        "POST",
        "/api/secure/transaction/inquire/",
        200,
        inq.clone(),
    )
    .await;
    mount_payouts(
        server,
        "POST",
        "/disburse/api/v1/bulk_transaction/inquire_by_reference",
        200,
        inq,
    )
    .await;
    mount_payouts(
        server,
        "GET",
        "/api/secure/budget/inquire/",
        200,
        json!({ "current_budget": "1000.00 EGP" }),
    )
    .await;
    mount_payouts(
        server,
        "GET",
        "/api/secure/topup/inquire/",
        200,
        json!({ "results": [topup_rec.clone()], "count": 1 }),
    )
    .await;
    mount_payouts(server, "POST", "/api/secure/topup/request/", 200, topup_rec).await;
}

async fn setup_onboarding_auth_mocks(server: &PaymobMockServer) {
    let hmac_env = json!({
        "label": "sub",
        "status": "Created",
        "code": 201,
        "body": { "hmac_secret": "HMAC_SECRET_999" }
    });
    mount_accept(
        server,
        "POST",
        "/api/auth/tokens",
        200,
        json!({ "token": "partner_jwt_tok" }),
    )
    .await;
    mount_accept(
        server,
        "POST",
        "/api/auth/api_keys",
        200,
        json!({ "api_key": "pk_partner_999", "label": "main" }),
    )
    .await;
    mount_accept(
        server,
        "GET",
        "/api/auth/hmac_secret/get_hmac",
        200,
        hmac_env.clone(),
    )
    .await;
    mount_accept(
        server,
        "GET",
        "/api/partner/merchants/hmac_secret/12345",
        200,
        hmac_env,
    )
    .await;
}

pub(super) async fn setup_onboarding_mocks(server: &PaymobMockServer) {
    setup_onboarding_auth_mocks(server).await;
    let schema = json!({
        "partner": "acme-partner",
        "resubmission": false,
        "steps": [{ "step_id": "kyc_1", "order": 1, "fields": [] }]
    });
    mount_accept(server, "GET", "/api/onboarding/flow/schema", 200, schema).await;
    mount_accept(
        server,
        "POST",
        "/api/onboarding/register",
        201,
        json!({ "paymob_mid": 12345, "status": "registered" }),
    )
    .await;
    mount_accept(
        server,
        "POST",
        "/api/onboarding/flow/step",
        200,
        json!({ "paymob_mid": 12345, "step_id": "kyc_1", "completed": true }),
    )
    .await;
    mount_accept(
        server,
        "GET",
        "/api/onboarding/merchant/12345",
        200,
        json!({ "paymob_mid": 12345, "status": "approved", "is_live": true }),
    )
    .await;
}

pub(super) async fn setup_scoped_and_unified_mocks(server: &PaymobMockServer) {
    let pi = json!({
        "id": "pi_u4",
        "client_secret": "egy_csk_u4",
        "status": "intended",
        "intention_order_id": 88001,
        "confirmed": false
    });
    let tx_ok = json!({ "id": 192036465, "success": true, "amount_cents": 100_000 });
    let pay_ok = json!({ "id": 501, "success": true, "pending": false, "amount_cents": 5000 });
    mount_accept(server, "POST", "/v1/intention/", 201, pi.clone()).await;
    mount_accept(server, "PUT", "/v1/intention/", 200, pi.clone()).await;
    mount_accept(server, "PUT", "/v1/intention/egy_csk_u4", 200, pi).await;
    mount_accept(
        server,
        "GET",
        "/api/acceptance/transactions/192036465",
        200,
        tx_ok.clone(),
    )
    .await;
    mount_accept(
        server,
        "POST",
        "/api/ecommerce/orders/transaction_inquiry",
        200,
        tx_ok,
    )
    .await;
    mount_accept(server, "POST", "/api/acceptance/payments/pay", 200, pay_ok).await;
    setup_manage_mocks(server).await;
    setup_subscription_cards_and_history_mocks(server).await;
    setup_payouts_cashin_mocks(server).await;
}

#![forbid(unsafe_code)]
//! Core, legacy, manage, inquiries, onboarding, and unified wiremock setups for Unit 4.

use serde_json::json;
use some_paymob::test_utils::PaymobMockServer;

use super::positive_helpers::mount_accept;
use super::positive_mocks_recurring::{
    setup_payouts_cashin_mocks, setup_subscription_cards_and_history_mocks,
};

pub(super) async fn setup_legacy_v2_mocks(server: &PaymobMockServer) {
    server
        .mount_accept_auth_sequence(&["jwt-leg-1", "jwt-leg-2", "jwt-leg-3", "jwt-leg-4"])
        .await;
    let ord = json!({
        "id": 378804,
        "amount_cents": 50_000,
        "currency": "EGP",
        "merchant_order_id": "ORD-L1"
    });
    mount_accept(server, ("POST", "/api/ecommerce/orders", 201, ord)).await;
    let key = json!({ "token": "paykey_unit4_token" });
    mount_accept(server, ("POST", "/api/acceptance/payment_keys", 201, key)).await;
}

pub(super) async fn setup_manage_mocks(server: &PaymobMockServer) {
    server
        .mount_accept_auth_sequence(&["jwt-manage-1", "jwt-manage-2"])
        .await;
    let ref_tx = json!({
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
    let ref_route = ("POST", "/api/acceptance/void_refund/refund", 200, ref_tx);
    let void_route = ("POST", "/api/acceptance/void_refund/void", 200, void_tx);
    mount_accept(server, ref_route).await;
    mount_accept(server, void_route).await;
    mount_accept(server, ("POST", "/api/acceptance/capture", 200, cap_tx)).await;
}

pub(super) async fn setup_inquiries_mocks(server: &PaymobMockServer) {
    server
        .mount_accept_auth_sequence(&["jwt-inq-1", "jwt-inq-2", "jwt-inq-3"])
        .await;
    let tx =
        json!({ "id": 192036465, "success": true, "amount_cents": 100_000, "currency": "EGP" });
    let ord = json!({
        "id": 217503754,
        "amount_cents": 100_000,
        "paid_amount_cents": 100_000,
        "payment_status": "PAID"
    });
    let tok = json!([{
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
    let tx_get = (
        "GET",
        "/api/acceptance/transactions/192036465",
        200,
        tx.clone(),
    );
    let tx_post = ("POST", "/api/ecommerce/orders/transaction_inquiry", 200, tx);
    mount_accept(server, tx_get).await;
    mount_accept(server, tx_post).await;
    mount_accept(server, ("GET", "/api/ecommerce/orders/217503754", 200, ord)).await;
    mount_accept(
        server,
        ("POST", "/api/acceptance/order_card_tokens", 200, tok),
    )
    .await;
}

pub(super) async fn setup_quicklinks_mocks(server: &PaymobMockServer) {
    server.mount_accept_auth_sequence(&["jwt-ql-1"]).await;
    let ql = json!({
        "id": "ql_u4",
        "url": "https://accept.paymob.com/standalone/?ref=ql_u4",
        "client_url": "https://accept.paymob.com/api/acceptance/post_pay?ref=ql_u4"
    });
    mount_accept(server, ("POST", "/api/ecommerce/payment-links", 201, ql)).await;
    let cancel = json!({ "detail": "cancelled" });
    mount_accept(
        server,
        ("POST", "/api/ecommerce/payment-links/cancel", 200, cancel),
    )
    .await;
}

async fn setup_onboarding_auth_mocks(server: &PaymobMockServer) {
    let hmac = json!({
        "label": "sub",
        "status": "Created",
        "code": 201,
        "body": { "hmac_secret": "HMAC_SECRET_999" }
    });
    let tok = json!({ "token": "partner_jwt_tok" });
    let key = json!({ "api_key": "pk_partner_999", "label": "main" });
    mount_accept(server, ("POST", "/api/auth/tokens", 200, tok)).await;
    mount_accept(server, ("POST", "/api/auth/api_keys", 200, key)).await;
    mount_accept(
        server,
        ("GET", "/api/auth/hmac_secret/get_hmac", 200, hmac.clone()),
    )
    .await;
    let merch_hmac = ("GET", "/api/partner/merchants/hmac_secret/12345", 200, hmac);
    mount_accept(server, merch_hmac).await;
}

pub(super) async fn setup_onboarding_mocks(server: &PaymobMockServer) {
    setup_onboarding_auth_mocks(server).await;
    let schema = json!({
        "partner": "acme-partner",
        "resubmission": false,
        "steps": [{ "step_id": "kyc_1", "order": 1, "fields": [] }]
    });
    let reg = json!({ "paymob_mid": 12345, "status": "registered" });
    let step = json!({ "paymob_mid": 12345, "step_id": "kyc_1", "completed": true });
    let merch = json!({ "paymob_mid": 12345, "status": "approved", "is_live": true });
    mount_accept(server, ("GET", "/api/onboarding/flow/schema", 200, schema)).await;
    mount_accept(server, ("POST", "/api/onboarding/register", 201, reg)).await;
    mount_accept(server, ("POST", "/api/onboarding/flow/step", 200, step)).await;
    mount_accept(
        server,
        ("GET", "/api/onboarding/merchant/12345", 200, merch),
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
    mount_accept(server, ("POST", "/v1/intention/", 201, pi.clone())).await;
    mount_accept(server, ("PUT", "/v1/intention/", 200, pi.clone())).await;
    mount_accept(server, ("PUT", "/v1/intention/egy_csk_u4", 200, pi)).await;
    let tx_get = (
        "GET",
        "/api/acceptance/transactions/192036465",
        200,
        tx_ok.clone(),
    );
    let tx_post = (
        "POST",
        "/api/ecommerce/orders/transaction_inquiry",
        200,
        tx_ok,
    );
    mount_accept(server, tx_get).await;
    mount_accept(server, tx_post).await;
    mount_accept(
        server,
        ("POST", "/api/acceptance/payments/pay", 200, pay_ok),
    )
    .await;
    setup_manage_mocks(server).await;
    setup_subscription_cards_and_history_mocks(server).await;
    setup_payouts_cashin_mocks(server).await;
}

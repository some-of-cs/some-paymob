#![forbid(unsafe_code)]
//! Subscription and payouts wiremock endpoint setups for Unit 4 tests.

use serde_json::{Value, json};
use some_paymob::test_utils::PaymobMockServer;

use super::positive_helpers::{
    mount_accept, mount_payouts, sample_subscription_card_json, sample_subscription_json,
    sample_subscription_tx_json,
};

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
    let post_plan = ("POST", "/api/acceptance/subscription-plans", 201, plan.clone());
    let put_plan = ("PUT", "/api/acceptance/subscription-plans/701", 200, plan.clone());
    let get_plans = ("GET", "/api/acceptance/subscription-plans", 200, page);
    let susp = ("POST", "/api/acceptance/subscription-plans/701/suspend", 200, plan.clone());
    let res = ("POST", "/api/acceptance/subscription-plans/701/resume", 200, plan);
    mount_accept(server, post_plan).await;
    mount_accept(server, put_plan).await;
    mount_accept(server, get_plans).await;
    mount_accept(server, susp).await;
    mount_accept(server, res).await;
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
    mount_accept(server, ("POST", "/v1/intention/", 201, enroll)).await;
    mount_accept(server, ("GET", "/api/acceptance/subscriptions/1264", 200, sub.clone())).await;
    mount_accept(server, ("GET", "/api/acceptance/subscriptions", 200, list)).await;
    setup_sub_state_mocks(server, sub).await;
}

async fn setup_sub_state_mocks(server: &PaymobMockServer, sub: Value) {
    let put_sub = ("PUT", "/api/acceptance/subscriptions/1264", 200, sub.clone());
    let susp = ("POST", "/api/acceptance/subscriptions/1264/suspend", 200, sub.clone());
    let res = ("POST", "/api/acceptance/subscriptions/1264/resume", 200, sub.clone());
    let can = ("POST", "/api/acceptance/subscriptions/1264/cancel", 200, sub);
    mount_accept(server, put_sub).await;
    mount_accept(server, susp).await;
    mount_accept(server, res).await;
    mount_accept(server, can).await;
}

async fn setup_sub_cards_mocks(server: &PaymobMockServer) {
    let card = sample_subscription_card_json(374, true);
    let get_cards = ("GET", "/api/acceptance/subscriptions/1264/cards", 200, json!([card.clone()]));
    let add_sec = ("POST", "/api/acceptance/subscriptions/1264/add-secondary-card", 200, card.clone());
    let chg_pri = ("POST", "/api/acceptance/subscriptions/1264/change-primary-card", 200, card);
    let del_card = ("POST", "/api/acceptance/subscriptions/1264/delete-card", 200, json!({ "detail": "deleted" }));
    mount_accept(server, get_cards).await;
    mount_accept(server, add_sec).await;
    mount_accept(server, chg_pri).await;
    mount_accept(server, del_card).await;
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
    let wh = json!({ "id": 1264, "webhook_url": "https://merchant.example.com/hook" });
    mount_accept(server, ("POST", "/api/acceptance/subscriptions/1264/webhook", 200, wh)).await;
    let last_tx = ("GET", "/api/acceptance/subscriptions/1264/last-transaction", 200, tx.clone());
    let tx_list = ("GET", "/api/acceptance/subscriptions/1264/transactions", 200, json!([tx]));
    mount_accept(server, last_tx).await;
    mount_accept(server, tx_list).await;
    mount_accept(server, ("POST", "/api/acceptance/void_refund/refund", 200, refund)).await;
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
    let bulk = json!({ "status": "ok", "results": [disb] });
    mount_payouts(server, ("POST", "/api/secure/o/token/", 200, tok)).await;
    mount_payouts(server, ("POST", "/api/secure/disburse/", 200, disb.clone())).await;
    mount_payouts(server, ("POST", "/api/secure/transaction/aman/cancel/", 200, disb)).await;
    mount_payouts(server, ("POST", "/disburse/api/v1/disburse/bulk_transaction", 200, bulk)).await;
}

pub(super) async fn setup_payouts_inquiries_and_topups_mocks(server: &PaymobMockServer) {
    let inq = json!({
        "results": [{ "transaction_id": "tx_po_1", "amount": 200 }],
        "status_code": "200"
    });
    let topup = json!({
        "id": 55,
        "amount": 500,
        "status": "pending",
        "type": "from_bank_transfer",
        "currency": "egyptian_pound"
    });
    let budget = json!({ "current_budget": "1000.00 EGP" });
    let topups = json!({ "results": [topup.clone()], "count": 1 });
    mount_payouts(server, ("POST", "/api/secure/transaction/inquire/", 200, inq.clone())).await;
    let bulk_inq = ("POST", "/disburse/api/v1/bulk_transaction/inquire_by_reference", 200, inq);
    mount_payouts(server, bulk_inq).await;
    mount_payouts(server, ("GET", "/api/secure/budget/inquire/", 200, budget)).await;
    mount_payouts(server, ("GET", "/api/secure/topup/inquire/", 200, topups)).await;
    mount_payouts(server, ("POST", "/api/secure/topup/request/", 200, topup)).await;
}

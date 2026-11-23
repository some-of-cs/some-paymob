#![forbid(unsafe_code)]
//! Positive E2E integration tests across all 14 services and Protocols A-E (`Code::Ok`).

use serde_json::json;
use some_paymob::test_utils::{
    PaymobMockServer, card_token_15978654, subscription_1264, transaction_processed_192036465,
    transaction_response_316004,
};

use super::positive_helpers::{
    assert_non_wallet_cashin_rpcs, assert_rpc_ok, build_grpc_service, mount_accept,
    sample_billing_json, topup_b64_json,
};
use super::positive_mocks_core::{
    setup_inquiries_mocks, setup_legacy_v2_mocks, setup_manage_mocks, setup_onboarding_mocks,
    setup_quicklinks_mocks, setup_scoped_and_unified_mocks,
};
use super::positive_mocks_recurring::{
    setup_payouts_cashin_mocks, setup_payouts_inquiries_and_topups_mocks,
    setup_subscription_cards_and_history_mocks, setup_subscription_plans_mocks,
    setup_subscriptions_lifecycle_mocks,
};

/// Verifies `GetHealth` and `CheckSandboxConstraints` return `Code::Ok`.
#[tokio::test]
async fn e2e_health_and_sandbox_check_return_ok() {
    let server = PaymobMockServer::start().await;
    let service = build_grpc_service(&server);
    assert_rpc_ok(&service, "GetHealth", &json!({})).await;
    let check_body = json!({
        "is_sandbox": true,
        "credential_age_days": 10,
        "channel": "card"
    });
    assert_rpc_ok(&service, "CheckSandboxConstraints", &check_body).await;
}

/// Verifies `CreateIntention` and `UpdateIntention` return `Code::Ok`.
#[tokio::test]
async fn e2e_intentions_create_and_update_return_ok() {
    let server = PaymobMockServer::start().await;
    let body = json!({
        "id": "pi_unit4_001",
        "client_secret": "egy_csk_test_unit4",
        "status": "intended",
        "intention_order_id": 99001
    });
    mount_accept(&server, ("POST", "/v1/intention/", 201, body.clone())).await;
    mount_accept(&server, ("PUT", "/v1/intention/", 200, body)).await;
    let service = build_grpc_service(&server);
    let create_req = json!({
        "amount_cents": 10_000,
        "currency": "EGP",
        "payment_methods": [4097558],
        "billing_data": sample_billing_json()
    });
    let update_req = json!({ "special_reference": "ref-u4", "amount_cents": 12_000 });
    assert_rpc_ok(&service, "CreateIntention", &create_req).await;
    assert_rpc_ok(&service, "UpdateIntention", &update_req).await;
}

/// Verifies `BuildPixelConfig` and `BuildAffordabilityWidget` return `Code::Ok`.
#[tokio::test]
async fn e2e_checkout_pixel_and_affordability_return_ok() {
    let server = PaymobMockServer::start().await;
    let service = build_grpc_service(&server);
    let pixel_req = json!({ "client_secret": "egy_csk_test_unit4", "locale": "en" });
    let afford_req = json!({ "amount_cents": 50_000, "currency": "EGP" });
    assert_rpc_ok(&service, "BuildPixelConfig", &pixel_req).await;
    assert_rpc_ok(&service, "BuildAffordabilityWidget", &afford_req).await;
}

/// Verifies legacy v2 order, payment key, and checkout RPCs return `Code::Ok`.
#[tokio::test]
async fn e2e_legacy_v2_orders_payment_keys_and_checkout_return_ok() {
    let server = PaymobMockServer::start().await;
    setup_legacy_v2_mocks(&server).await;
    let service = build_grpc_service(&server);
    let ord_req = json!({ "amount_cents": 50_000, "currency": "EGP", "merchant_order_id": "O1" });
    let key_req = json!({
        "order_id": 378804,
        "amount_cents": 50_000,
        "currency": "EGP",
        "integration_id": 2936,
        "billing_data": sample_billing_json()
    });
    let chk_req = json!({
        "amount_cents": 50_000,
        "currency": "EGP",
        "integration_id": 2936,
        "iframe_id": 7890,
        "billing_data": sample_billing_json()
    });
    assert_rpc_ok(&service, "CreateLegacyOrder", &ord_req).await;
    assert_rpc_ok(&service, "CreateLegacyPaymentKey", &key_req).await;
    assert_rpc_ok(&service, "CreateLegacyCheckout", &chk_req).await;
}

/// Verifies refund, void, and capture RPCs across Regime 1 and Legacy v2 bearer.
#[tokio::test]
async fn e2e_manage_refund_void_capture_and_legacy_bearer_return_ok() {
    let server = PaymobMockServer::start().await;
    setup_manage_mocks(&server).await;
    let service = build_grpc_service(&server);
    let ref_req = json!({ "transaction_id": 100, "amount_cents": 5000 });
    let void_v1 = json!({ "transaction_id": 100 });
    let void_v2 = json!({ "transaction_id": 100, "use_legacy_v2_bearer": true });
    let cap_v1 = json!({ "transaction_id": 100, "amount_cents": 5000 });
    let cap_v2 = json!({
        "transaction_id": 100,
        "amount_cents": 5000,
        "use_legacy_v2_bearer": true
    });
    assert_rpc_ok(&service, "RefundTransaction", &ref_req).await;
    assert_rpc_ok(&service, "VoidTransaction", &void_v1).await;
    assert_rpc_ok(&service, "VoidTransaction", &void_v2).await;
    assert_rpc_ok(&service, "CaptureTransaction", &cap_v1).await;
    assert_rpc_ok(&service, "CaptureTransaction", &cap_v2).await;
}

/// Verifies transaction, order, and card token inquiry RPCs return `Code::Ok`.
#[tokio::test]
async fn e2e_inquiries_tx_order_and_card_tokens_return_ok() {
    let server = PaymobMockServer::start().await;
    setup_inquiries_mocks(&server).await;
    let service = build_grpc_service(&server);
    assert_rpc_ok(
        &service,
        "InquireTransactionById",
        &json!({ "transaction_id": 192036465 }),
    )
    .await;
    assert_rpc_ok(
        &service,
        "InquireTransactionByOrder",
        &json!({ "order_id": 217503754 }),
    )
    .await;
    assert_rpc_ok(&service, "InquireOrder", &json!({ "order_id": 217503754 })).await;
    assert_rpc_ok(
        &service,
        "ListOrderCardTokens",
        &json!({ "order_id": 217503754 }),
    )
    .await;
}

/// Verifies QuickLinks create/cancel and split fee calculation RPCs return `Code::Ok`.
#[tokio::test]
async fn e2e_quicklinks_and_splits_return_ok() {
    let server = PaymobMockServer::start().await;
    setup_quicklinks_mocks(&server).await;
    let service = build_grpc_service(&server);
    let ql_req = json!({ "amount_cents": 15_000, "currency": "EGP", "integrations": [4097558] });
    let sp_req = json!({
        "amount_cents": 100_000,
        "recipients": [{ "recipient_id": "sub_1", "percentage_bps": 10_000 }]
    });
    assert_rpc_ok(&service, "CreateQuickLink", &ql_req).await;
    assert_rpc_ok(&service, "CancelQuickLink", &json!({ "link_id": "ql_u4" })).await;
    assert_rpc_ok(&service, "ValidateSplitsAndCalculateFee", &sp_req).await;
}

/// Verifies saved-card MIT, wallet, kiosk, and raw pay RPCs return `Code::Ok`.
#[tokio::test]
async fn e2e_saved_cards_mit_wallet_kiosk_and_raw_return_ok() {
    let server = PaymobMockServer::start().await;
    server.mount_accept_auth_sequence(&["jwt-sc-1"]).await;
    let pay_resp = json!({
        "id": 501,
        "success": true,
        "pending": false,
        "data": { "bill_reference": "998877" }
    });
    let pay_route = ("POST", "/api/acceptance/payments/pay", 200, pay_resp);
    mount_accept(&server, pay_route).await;
    let service = build_grpc_service(&server);
    let mit = json!({ "payment_token": "tok_u4", "saved_token": "saved_tok_1" });
    let wal = json!({ "payment_token": "tok_u4", "wallet_phone": "01023456789" });
    let ksk = json!({ "payment_token": "tok_u4" });
    let raw = json!({
        "payment_token": "tok_u4",
        "source": { "identifier": "AGGREGATOR", "subtype": "AGGREGATOR" }
    });
    assert_rpc_ok(&service, "PayWithTokenMit", &mit).await;
    assert_rpc_ok(&service, "PayWithWallet", &wal).await;
    assert_rpc_ok(&service, "PayWithKiosk", &ksk).await;
    assert_rpc_ok(&service, "PayRaw", &raw).await;
}

/// Verifies subscription plan CRUD, list, suspend, and resume RPCs return `Code::Ok`.
#[tokio::test]
async fn e2e_subscription_plans_crud_and_suspend_resume_return_ok() {
    let server = PaymobMockServer::start().await;
    setup_subscription_plans_mocks(&server).await;
    let service = build_grpc_service(&server);
    let create_req = json!({
        "name": "Pro Plan",
        "amount_cents": 20_000,
        "frequency": 30,
        "integration": 4097558
    });
    let upd_req = json!({ "plan_id": 701, "name": "Pro Plan v2" });
    let plan_ref = json!({ "plan_id": 701 });
    assert_rpc_ok(&service, "CreateSubscriptionPlan", &create_req).await;
    assert_rpc_ok(&service, "UpdateSubscriptionPlan", &upd_req).await;
    assert_rpc_ok(&service, "ListSubscriptionPlans", &json!({ "page": 1 })).await;
    assert_rpc_ok(&service, "SuspendSubscriptionPlan", &plan_ref).await;
    assert_rpc_ok(&service, "ResumeSubscriptionPlan", &plan_ref).await;
}

/// Verifies subscription lifecycle RPCs return `Code::Ok`.
#[tokio::test]
async fn e2e_subscriptions_lifecycle_rpcs_return_ok() {
    let server = PaymobMockServer::start().await;
    setup_subscriptions_lifecycle_mocks(&server).await;
    let service = build_grpc_service(&server);
    let create_req = json!({
        "subscription_plan_id": 701,
        "amount": 20_000,
        "currency": "EGP",
        "payment_methods": [4097558]
    });
    let sub_ref = json!({ "subscription_id": 1264 });
    let list_req = json!({ "plan_id": 701, "state": "active", "page": 1 });
    let upd_req = json!({ "subscription_id": 1264, "amount_cents": 25_000 });
    assert_rpc_ok(&service, "CreateSubscription", &create_req).await;
    assert_rpc_ok(&service, "RetrieveSubscription", &sub_ref).await;
    assert_rpc_ok(&service, "ListSubscriptions", &list_req).await;
    assert_rpc_ok(&service, "UpdateSubscription", &upd_req).await;
    assert_rpc_ok(&service, "SuspendSubscription", &sub_ref).await;
    assert_rpc_ok(&service, "ResumeSubscription", &sub_ref).await;
    assert_rpc_ok(&service, "CancelSubscription", &sub_ref).await;
}

/// Verifies subscription cards, webhook, history, and last-tx refund RPCs return `Code::Ok`.
#[tokio::test]
async fn e2e_subscription_cards_and_history_rpcs_return_ok() {
    let server = PaymobMockServer::start().await;
    setup_subscription_cards_and_history_mocks(&server).await;
    let service = build_grpc_service(&server);
    let sub_ref = json!({ "subscription_id": 1264 });
    let sec_req = json!({
        "subscription_id": 1264,
        "card_token": "tok_sec_2",
        "integration_id": 4097558
    });
    let pri_req = json!({ "subscription_id": 1264, "card_id": 374 });
    let del_req = json!({ "subscription_id": 1264, "card_id": 374 });
    let wh_req = json!({
        "subscription_id": 1264,
        "webhook_url": "https://merchant.example.com/hook"
    });
    let ref_req = json!({ "subscription_id": 1264, "amount_cents": 5000 });
    assert_rpc_ok(&service, "ListSubscriptionCards", &sub_ref).await;
    assert_rpc_ok(&service, "AddSecondarySubscriptionCard", &sec_req).await;
    assert_rpc_ok(&service, "ChangePrimarySubscriptionCard", &pri_req).await;
    assert_rpc_ok(&service, "DeleteSecondarySubscriptionCard", &del_req).await;
    assert_rpc_ok(&service, "RegisterSubscriptionWebhook", &wh_req).await;
    assert_rpc_ok(&service, "GetSubscriptionLastTransaction", &sub_ref).await;
    assert_rpc_ok(&service, "ListSubscriptionTransactions", &sub_ref).await;
    assert_rpc_ok(&service, "RefundSubscriptionLastTransaction", &ref_req).await;
}

/// Verifies payouts auth token, 7 cashin issuers, Aman cancel, and bulk cashin return `Code::Ok`.
#[tokio::test]
async fn e2e_payouts_auth_and_all_7_cashin_issuers_return_ok() {
    let server = PaymobMockServer::start().await;
    setup_payouts_cashin_mocks(&server).await;
    let service = build_grpc_service(&server);
    let ref_req = json!({ "refresh_token": "ref_tok_1" });
    assert_rpc_ok(&service, "GeneratePayoutsToken", &json!({})).await;
    assert_rpc_ok(&service, "RefreshPayoutsToken", &ref_req).await;
    for issuer in ["vodafone", "etisalat", "orange", "bank_wallet"] {
        let wal_req = json!({ "issuer": issuer, "msisdn": "01023456789", "amount": 200 });
        assert_rpc_ok(&service, "DisburseMobileWallet", &wal_req).await;
    }
    assert_non_wallet_cashin_rpcs(&service).await;
}

/// Verifies payouts inquiry, budget, and topup RPCs return `Code::Ok`.
#[tokio::test]
async fn e2e_payouts_inquiries_budget_and_topups_return_ok() {
    let server = PaymobMockServer::start().await;
    setup_payouts_inquiries_and_topups_mocks(&server).await;
    let service = build_grpc_service(&server);
    let tx_req = json!({ "transactions_ids": ["tx_po_1"] });
    let ref_req = json!({ "client_reference_ids": ["ref_1"] });
    let topup_inq = json!({ "page": 1, "id": 55 });
    let acc_req = json!({
        "amount": 500,
        "currency": "egyptian_pound",
        "username": "merchant_user"
    });
    assert_rpc_ok(&service, "InquirePayoutTransactions", &tx_req).await;
    assert_rpc_ok(&service, "InquirePayoutByReference", &ref_req).await;
    assert_rpc_ok(&service, "InquirePayoutUserBudget", &json!({})).await;
    assert_rpc_ok(&service, "InquirePayoutTopups", &topup_inq).await;
    assert_rpc_ok(
        &service,
        "RequestBankTransferTopup",
        &topup_b64_json("AQIDBA=="),
    )
    .await;
    assert_rpc_ok(&service, "RequestAcceptBalanceTopup", &acc_req).await;
}

/// Verifies partner onboarding auth RPCs return `Code::Ok`.
#[tokio::test]
async fn e2e_onboarding_auth_rpcs_return_ok() {
    let server = PaymobMockServer::start().await;
    setup_onboarding_mocks(&server).await;
    let service = build_grpc_service(&server);
    let login = json!({ "username": "partner@example.com", "password": "secret-password" });
    assert_rpc_ok(&service, "PartnerLogin", &login).await;
    assert_rpc_ok(&service, "CreatePartnerApiKey", &json!({ "label": "main" })).await;
    assert_rpc_ok(&service, "RetrievePartnerHmacSecret", &json!({})).await;
    assert_rpc_ok(
        &service,
        "RetrieveMerchantHmacSecret",
        &json!({ "mid": 12345 }),
    )
    .await;
}

/// Verifies partner onboarding flow RPCs return `Code::Ok`.
#[tokio::test]
async fn e2e_onboarding_flow_rpcs_return_ok() {
    let server = PaymobMockServer::start().await;
    setup_onboarding_mocks(&server).await;
    let service = build_grpc_service(&server);
    let reg = json!({
        "partner": "acme-partner",
        "email": "partner@example.com",
        "phone_number": "+201001234567",
        "first_name": "Maher",
        "last_name": "Aladdin"
    });
    let step = json!({ "paymob_mid": 12345, "step_id": "kyc_1", "data": { "cr": "123" } });
    assert_rpc_ok(
        &service,
        "GetOnboardingSchema",
        &json!({ "partner": "acme-partner" }),
    )
    .await;
    assert_rpc_ok(&service, "RegisterPartnerMerchant", &reg).await;
    assert_rpc_ok(&service, "SubmitOnboardingStep", &step).await;
    assert_rpc_ok(&service, "InquirePartnerMerchant", &json!({ "mid": 12345 })).await;
}

/// Verifies merchant-scoped intention, inquiry, and manage RPCs return `Code::Ok`.
#[tokio::test]
async fn e2e_merchant_scoped_rpcs_return_ok() {
    let server = PaymobMockServer::start().await;
    setup_scoped_and_unified_mocks(&server).await;
    let service = build_grpc_service(&server);
    let create = json!({
        "mid": 12345,
        "amount": 10_000,
        "currency": "EGP",
        "payment_methods": [4097558]
    });
    let upd = json!({ "mid": 12345, "special_reference": "ref-m", "amount": 12_000 });
    let upd_cs = json!({
        "mid": 12345,
        "client_secret": "egy_csk_u4",
        "special_reference": "ref-m",
        "amount": 12_000
    });
    let tx_inq = json!({ "mid": 12345, "tx_id": 192036465 });
    let ord_inq = json!({ "mid": 12345, "order_id": 1 });
    let tx_void = json!({ "mid": 12345, "transaction_id": 100 });
    let tx_amt = json!({ "mid": 12345, "transaction_id": 100, "amount_cents": 5000 });
    assert_rpc_ok(&service, "ScopedCreateIntention", &create).await;
    assert_rpc_ok(&service, "ScopedUpdateIntention", &upd).await;
    assert_rpc_ok(&service, "ScopedUpdateIntention", &upd_cs).await;
    assert_rpc_ok(&service, "ScopedInquireTransaction", &tx_inq).await;
    assert_rpc_ok(&service, "ScopedInquireTransaction", &tx_inq).await;
    assert_rpc_ok(&service, "ScopedInquireByOrder", &ord_inq).await;
    assert_rpc_ok(&service, "ScopedVoid", &tx_void).await;
    assert_rpc_ok(&service, "ScopedVoid", &tx_void).await;
    assert_rpc_ok(&service, "ScopedCapture", &tx_amt).await;
    assert_rpc_ok(&service, "ScopedRefund", &tx_amt).await;
}

/// Verifies all unified payment adapter RPCs return `Code::Ok`.
#[tokio::test]
async fn e2e_unified_adapter_all_rpcs_return_ok() {
    let server = PaymobMockServer::start().await;
    setup_scoped_and_unified_mocks(&server).await;
    let service = build_grpc_service(&server);
    let sess = json!({ "amount": 15_000, "currency": "EGP", "payment_methods": ["4097558"] });
    let tx_amt = json!({ "transaction_id": 100, "amount": 5000 });
    let chg = json!({ "payment_token": "tok_u4", "saved_method_token": "saved_tok_1" });
    let sub_ref = json!({ "subscription_id": 1264, "amount": 5000 });
    let po = json!({
        "recipient_identifier": "01023456789",
        "amount": 200,
        "currency": "EGP",
        "issuer": "vodafone"
    });
    assert_rpc_ok(&service, "UnifiedCreateSession", &sess).await;
    assert_rpc_ok(&service, "UnifiedCapture", &tx_amt).await;
    assert_rpc_ok(&service, "UnifiedRefund", &tx_amt).await;
    assert_rpc_ok(&service, "UnifiedVoid", &json!({ "transaction_id": 100 })).await;
    assert_rpc_ok(&service, "UnifiedChargeSavedMethod", &chg).await;
    assert_rpc_ok(&service, "UnifiedRefundSubscription", &sub_ref).await;
    assert_rpc_ok(&service, "UnifiedExecutePayout", &po).await;
    let tx_vec = transaction_processed_192036465();
    let wh_req = json!({ "hmac": tx_vec.expected_hmac_hex, "raw_body": tx_vec.payload_or_query });
    assert_rpc_ok(&service, "UnifiedVerifyWebhook", &wh_req).await;
}

/// Verifies webhook verification across Protocols A through E returns `Code::Ok`.
#[tokio::test]
async fn e2e_webhooks_protocols_a_through_e_return_ok() {
    let server = PaymobMockServer::start().await;
    let service = build_grpc_service(&server);
    for vec in [
        transaction_processed_192036465(),
        card_token_15978654(),
        subscription_1264(),
    ] {
        let req = json!({ "hmac": vec.expected_hmac_hex, "raw_body": vec.payload_or_query });
        assert_rpc_ok(&service, "VerifyWebhookEvent", &req).await;
    }
    let redir = transaction_response_316004();
    let redir_req = json!({ "query": redir.payload_or_query });
    assert_rpc_ok(&service, "VerifyWebhookRedirect", &redir_req).await;
    let proto_e = json!({
        "transaction_id": "tx_e1",
        "issuer": "bank_card",
        "amount_cents": 20_000,
        "currency": "EGP",
        "status": "successful"
    });
    let proto_e_req = json!({ "raw_body": proto_e.to_string() });
    let proto_e_err = grpc_unary(&service, "VerifyWebhookEvent", &proto_e_req)
        .await
        .expect_err("unsigned Protocol E without payouts secret must fail closed");
    assert_eq!(proto_e_err.code(), tonic::Code::Internal);
}

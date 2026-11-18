#![forbid(unsafe_code)]
//! Unit 4: Positive E2E and boundary condition integration tests for `examples/rocket_server.rs`.

use std::sync::Arc;

use rocket::http::{ContentType, Status};
use rocket::local::asynchronous::Client;
use serde_json::{Value, json};
use some_paymob::core::auth::CachedToken;
use some_paymob::core::credentials::{
    ApiKey, HmacSecret, PartnerCredentials, PayoutsCredentials, PublicKey, SecretKey,
};
use some_paymob::test_utils::{
    JsonEndpointMockConfig, MockHost, PaymobMockServer, SAMPLE_HMAC_SECRET, SandboxCheckRequest,
    SandboxConstraintError, SandboxGuard, SandboxPaymentChannel, SandboxWarning,
    card_token_15978654, subscription_1264, transaction_processed_192036465,
    transaction_response_316004,
};
use some_paymob::webhooks::InMemoryWebhookDeduplicator;
use some_paymob::{
    ClientConfig, MAX_TOPUP_PROOF_BYTES, MinorUnitAmount, PaymobClient, PaymobError,
    PaymobWebhookEngine, RefundParams, SplitCardPortion, SplitDescription, SplitPaymentConfig,
    SplitRecipientRule,
};

use super::rocket_server::{AppState, build_rocket};

fn build_test_client(server: &PaymobMockServer) -> PaymobClient {
    let payouts_creds =
        PayoutsCredentials::new("cid", "csec", "user", "pass").expect("valid payouts creds");
    let partner_creds =
        PartnerCredentials::with_bearer_token("partner_api_key_123", "partner_bearer_jwt_123")
            .expect("valid partner creds");
    let config = ClientConfig::builder()
        .region(server.custom_region())
        .secret_key(SecretKey::new("egy_sk_test_rocket_unit4").expect("valid secret key"))
        .public_key(PublicKey::new("egy_pk_test_rocket_unit4").expect("valid public key"))
        .api_key(
            ApiKey::new("ZXlKaGJHY2lPaUpJVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5").expect("valid api key"),
        )
        .hmac_secret(HmacSecret::new(SAMPLE_HMAC_SECRET).expect("valid hmac secret"))
        .payouts_credentials(payouts_creds)
        .partner_credentials(partner_creds)
        .max_retries(0)
        .build()
        .expect("valid client config");
    let client = PaymobClient::new(config).expect("valid paymob client");
    client
        .auth()
        .payouts_cache()
        .store(CachedToken::with_default_ttl("unit4-payouts-jwt", None));
    client
}

async fn tracked_rocket(server: &PaymobMockServer) -> Client {
    let client = build_test_client(server);
    let webhook_engine =
        PaymobWebhookEngine::new(SAMPLE_HMAC_SECRET).expect("valid webhook engine");
    let state = AppState {
        client: Arc::new(client),
        webhook_engine: Arc::new(webhook_engine),
        deduplicator: Arc::new(InMemoryWebhookDeduplicator::new()),
    };
    Client::tracked(build_rocket(state))
        .await
        .expect("valid tracked rocket client")
}

async fn mount_accept(
    server: &PaymobMockServer,
    method: &str,
    path: &str,
    status: u16,
    body: Value,
) {
    server
        .mount_json(JsonEndpointMockConfig {
            host: MockHost::Accept,
            http_method: method,
            endpoint_path: path,
            status,
            body,
        })
        .await;
}

async fn mount_payouts(
    server: &PaymobMockServer,
    method: &str,
    path: &str,
    status: u16,
    body: Value,
) {
    server
        .mount_json(JsonEndpointMockConfig {
            host: MockHost::Payouts,
            http_method: method,
            endpoint_path: path,
            status,
            body,
        })
        .await;
}

async fn get_status(rocket: &Client, uri: &str) -> Status {
    rocket.get(uri).dispatch().await.status()
}

async fn delete_status(rocket: &Client, uri: &str) -> Status {
    rocket.delete(uri).dispatch().await.status()
}

async fn post_json(rocket: &Client, uri: &str, payload: &Value) -> Status {
    rocket
        .post(uri)
        .header(ContentType::JSON)
        .body(payload.to_string())
        .dispatch()
        .await
        .status()
}

async fn put_json(rocket: &Client, uri: &str, payload: &Value) -> Status {
    rocket
        .put(uri)
        .header(ContentType::JSON)
        .body(payload.to_string())
        .dispatch()
        .await
        .status()
}

async fn post_raw(rocket: &Client, uri: &str, raw_body: &str) -> Status {
    rocket
        .post(uri)
        .header(ContentType::JSON)
        .body(raw_body)
        .dispatch()
        .await
        .status()
}

async fn assert_get_ok(rocket: &Client, uri: &str) {
    assert_eq!(get_status(rocket, uri).await, Status::Ok);
}

async fn assert_post_ok(rocket: &Client, uri: &str, payload: &Value) {
    assert_eq!(post_json(rocket, uri, payload).await, Status::Ok);
}

async fn assert_post_201(rocket: &Client, uri: &str, payload: &Value) {
    assert_eq!(post_json(rocket, uri, payload).await, Status::Created);
}

async fn assert_post_400(rocket: &Client, uri: &str, payload: &Value) {
    assert_eq!(post_json(rocket, uri, payload).await, Status::BadRequest);
}

async fn assert_put_ok(rocket: &Client, uri: &str, payload: &Value) {
    assert_eq!(put_json(rocket, uri, payload).await, Status::Ok);
}

fn sample_billing_json() -> Value {
    json!({
        "phone_number": "+201001234567",
        "first_name": "Maher",
        "last_name": "Aladdin",
        "email": "buyer@example.com",
        "city": "Cairo",
        "country": "EG"
    })
}

fn sample_subscription_json(id: u64, state: &str) -> Value {
    json!({
        "id": id,
        "plan_id": 701,
        "state": state,
        "amount_cents": 20_000,
        "created_at": "2026-11-01T00:00:00Z"
    })
}

fn sample_subscription_card_json(id: u64, is_primary: bool) -> Value {
    json!({
        "id": id,
        "token": "tok_sub_card_secret",
        "created_at": "2026-11-01T00:00:00Z",
        "is_primary": is_primary,
        "masked_pan": "xxxx-xxxx-xxxx-1111",
        "failed_attempts": 0
    })
}

fn sample_subscription_tx_json(id: u64) -> Value {
    json!({
        "id": id,
        "pending": false,
        "amount_cents": 20_000,
        "success": true,
        "is_refunded": false,
        "is_voided": false,
        "currency": "EGP",
        "api_source": "SUBSCRIPTION"
    })
}

async fn setup_legacy_v2_mocks(server: &PaymobMockServer) {
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

async fn setup_manage_mocks(server: &PaymobMockServer) {
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

async fn setup_inquiries_mocks(server: &PaymobMockServer) {
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

async fn setup_subscription_plans_mocks(server: &PaymobMockServer) {
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
    let page = json!({
        "count": 1,
        "next": null,
        "previous": null,
        "results": [plan.clone()]
    });
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

async fn setup_subscriptions_lifecycle_mocks(server: &PaymobMockServer) {
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
    let list = json!({
        "count": 1,
        "next": null,
        "previous": null,
        "results": [sub.clone()]
    });
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

async fn setup_subscription_cards_and_history_mocks(server: &PaymobMockServer) {
    server
        .mount_accept_auth_sequence(&[
            "jwt-c1", "jwt-c2", "jwt-c3", "jwt-c4", "jwt-c5", "jwt-c6", "jwt-c7", "jwt-c8",
        ])
        .await;
    let card = sample_subscription_card_json(374, true);
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

async fn setup_payouts_cashin_mocks(server: &PaymobMockServer) {
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

async fn setup_payouts_inquiries_and_topups_mocks(server: &PaymobMockServer) {
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

async fn setup_onboarding_mocks(server: &PaymobMockServer) {
    let hmac_env = json!({
        "label": "sub",
        "status": "Created",
        "code": 201,
        "body": { "hmac_secret": "HMAC_SECRET_999" }
    });
    let schema = json!({
        "partner": "acme-partner",
        "resubmission": false,
        "steps": [{ "step_id": "kyc_1", "order": 1, "fields": [] }]
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

async fn setup_scoped_and_unified_mocks(server: &PaymobMockServer) {
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

fn bulk_items_json(count: usize) -> Value {
    let items: Vec<Value> = (0..count)
        .map(|i| {
            json!({
                "issuer": "vodafone",
                "amount": 200,
                "msisdn": "01023456789",
                "client_reference_id": format!("r_{i}")
            })
        })
        .collect();
    json!({ "transactions": items })
}

fn inquiry_ids_json(count: usize) -> Value {
    let ids: Vec<String> = (0..count).map(|i| format!("tx_{i}")).collect();
    json!({ "transactions_ids": ids })
}

fn topup_raw_json(len: usize) -> Value {
    json!({
        "amount": 500,
        "currency": "egyptian_pound",
        "to_attach_proof": vec![1u8; len],
        "proof_filename": "receipt.pdf"
    })
}

fn topup_b64_json(b64: &str) -> Value {
    json!({
        "amount": 500,
        "currency": "egyptian_pound",
        "proof_base64": b64,
        "proof_filename": "receipt.pdf"
    })
}

async fn assert_non_wallet_cashin_routes(rocket: &Client) {
    let card_req = json!({
        "amount": 500,
        "bank_card_number": "4111111111111111",
        "bank_code": "CIB",
        "bank_transaction_type": "salary",
        "full_name": "Maher Aladdin"
    });
    let inst_req = json!({
        "amount": 500,
        "bank_code": "CIB",
        "bank_account_number": "EG380019000500000000263180002",
        "full_name": "Maher Aladdin"
    });
    let post_req = json!({
        "amount": 500,
        "msisdn": "01023456789",
        "full_name": "Maher Aladdin",
        "national_id": "29501011234567"
    });
    let aman_req = json!({ "transaction_id": "tx_aman_1" });
    assert_post_ok(rocket, "/payouts/cashin/bank-card", &card_req).await;
    assert_post_ok(rocket, "/payouts/cashin/bank-instant", &inst_req).await;
    assert_post_ok(rocket, "/payouts/cashin/egyptian-post", &post_req).await;
    assert_post_ok(rocket, "/payouts/cashin/aman/cancel", &aman_req).await;
    assert_post_ok(rocket, "/payouts/cashin/bulk", &bulk_items_json(1)).await;
}

// ---------------------------------------------------------------------------
// Positive E2E Tests: 100% Route Coverage Across All 14 Services & Protocols A-E
// ---------------------------------------------------------------------------

#[tokio::test]
async fn e2e_health_and_sandbox_check_return_200() {
    let server = PaymobMockServer::start().await;
    let rocket = tracked_rocket(&server).await;
    assert_get_ok(&rocket, "/health").await;
    let check_body = json!({
        "is_sandbox": true,
        "credential_age_days": 10,
        "channel": "card"
    });
    assert_post_ok(&rocket, "/sandbox/check", &check_body).await;
}

#[tokio::test]
async fn e2e_intentions_create_201_and_update_200() {
    let server = PaymobMockServer::start().await;
    let body = json!({
        "id": "pi_unit4_001",
        "client_secret": "egy_csk_test_unit4",
        "status": "intended",
        "intention_order_id": 99001
    });
    mount_accept(&server, "POST", "/v1/intention/", 201, body.clone()).await;
    mount_accept(&server, "PUT", "/v1/intention/", 200, body).await;
    let rocket = tracked_rocket(&server).await;
    let create_req = json!({
        "amount_cents": 10_000,
        "currency": "EGP",
        "payment_methods": [4097558],
        "billing_data": sample_billing_json()
    });
    let update_req = json!({ "special_reference": "ref-u4", "amount_cents": 12_000 });
    assert_post_201(&rocket, "/intentions", &create_req).await;
    assert_put_ok(&rocket, "/intentions", &update_req).await;
}

#[tokio::test]
async fn e2e_checkout_pixel_and_affordability_return_200() {
    let server = PaymobMockServer::start().await;
    let rocket = tracked_rocket(&server).await;
    let pixel_req = json!({ "client_secret": "egy_csk_test_unit4", "locale": "en" });
    let afford_req = json!({ "amount_cents": 50_000, "currency": "EGP" });
    assert_post_ok(&rocket, "/checkout/pixel", &pixel_req).await;
    assert_post_ok(&rocket, "/checkout/affordability", &afford_req).await;
}

#[tokio::test]
async fn e2e_legacy_v2_orders_payment_keys_and_checkout_return_201() {
    let server = PaymobMockServer::start().await;
    setup_legacy_v2_mocks(&server).await;
    let rocket = tracked_rocket(&server).await;
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
    assert_post_201(&rocket, "/legacy/orders", &ord_req).await;
    assert_post_201(&rocket, "/legacy/payment-keys", &key_req).await;
    assert_post_201(&rocket, "/legacy/checkout", &chk_req).await;
}

#[tokio::test]
async fn e2e_manage_refund_void_capture_and_legacy_bearer_return_200() {
    let server = PaymobMockServer::start().await;
    setup_manage_mocks(&server).await;
    let rocket = tracked_rocket(&server).await;
    let ref_req = json!({ "transaction_id": 100, "amount_cents": 5000 });
    let void_v1 = json!({ "transaction_id": 100 });
    let void_v2 = json!({ "transaction_id": 100, "use_legacy_v2_bearer": true });
    let cap_v1 = json!({ "transaction_id": 100, "amount_cents": 5000 });
    let cap_v2 = json!({
        "transaction_id": 100,
        "amount_cents": 5000,
        "use_legacy_v2_bearer": true
    });
    assert_post_ok(&rocket, "/manage/refund", &ref_req).await;
    assert_post_ok(&rocket, "/manage/void", &void_v1).await;
    assert_post_ok(&rocket, "/manage/void", &void_v2).await;
    assert_post_ok(&rocket, "/manage/capture", &cap_v1).await;
    assert_post_ok(&rocket, "/manage/capture", &cap_v2).await;
}

#[tokio::test]
async fn e2e_inquiries_tx_order_and_card_tokens_return_200() {
    let server = PaymobMockServer::start().await;
    setup_inquiries_mocks(&server).await;
    let rocket = tracked_rocket(&server).await;
    let by_ord = json!({ "order_id": 217503754 });
    assert_get_ok(&rocket, "/inquiries/transactions/192036465").await;
    assert_post_ok(&rocket, "/inquiries/by-order", &by_ord).await;
    assert_get_ok(&rocket, "/inquiries/orders/217503754").await;
    assert_post_ok(
        &rocket,
        "/inquiries/orders/217503754/card-tokens",
        &json!({}),
    )
    .await;
}

async fn setup_quicklinks_mocks(server: &PaymobMockServer) {
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

#[tokio::test]
async fn e2e_quicklinks_and_splits_return_200_201() {
    let server = PaymobMockServer::start().await;
    setup_quicklinks_mocks(&server).await;
    let rocket = tracked_rocket(&server).await;
    let ql_req = json!({ "amount_cents": 15_000, "currency": "EGP", "integrations": [4097558] });
    let sp_req = json!({
        "amount_cents": 100_000,
        "recipients": [{ "recipient_id": "sub_1", "percentage_bps": 10_000 }]
    });
    assert_post_201(&rocket, "/quicklinks", &ql_req).await;
    assert_post_ok(&rocket, "/quicklinks/ql_u4/cancel", &json!({})).await;
    assert_post_ok(&rocket, "/splits/validate-and-quote", &sp_req).await;
}

#[tokio::test]
async fn e2e_saved_cards_mit_wallet_kiosk_and_raw_return_200() {
    let server = PaymobMockServer::start().await;
    server.mount_accept_auth_sequence(&["jwt-sc-1"]).await;
    let pay_resp = json!({
        "id": 501,
        "success": true,
        "pending": false,
        "data": { "bill_reference": "998877" }
    });
    mount_accept(
        &server,
        "POST",
        "/api/acceptance/payments/pay",
        200,
        pay_resp,
    )
    .await;
    let rocket = tracked_rocket(&server).await;
    let mit = json!({ "payment_token": "tok_u4", "saved_token": "saved_tok_1" });
    let wal = json!({ "payment_token": "tok_u4", "wallet_phone": "01023456789" });
    let ksk = json!({ "payment_token": "tok_u4" });
    let raw = json!({
        "payment_token": "tok_u4",
        "source": { "identifier": "AGGREGATOR", "subtype": "AGGREGATOR" }
    });
    assert_post_ok(&rocket, "/saved-cards/pay/mit", &mit).await;
    assert_post_ok(&rocket, "/saved-cards/pay/wallet", &wal).await;
    assert_post_ok(&rocket, "/saved-cards/pay/kiosk", &ksk).await;
    assert_post_ok(&rocket, "/saved-cards/pay/raw", &raw).await;
}

#[tokio::test]
async fn e2e_subscription_plans_crud_and_suspend_resume_return_200_201() {
    let server = PaymobMockServer::start().await;
    setup_subscription_plans_mocks(&server).await;
    let rocket = tracked_rocket(&server).await;
    let create_req = json!({
        "name": "Pro Plan",
        "amount_cents": 20_000,
        "frequency": 30,
        "integration": 4097558
    });
    let upd_req = json!({ "name": "Pro Plan v2" });
    assert_post_201(&rocket, "/subscriptions/plans", &create_req).await;
    assert_put_ok(&rocket, "/subscriptions/plans/701", &upd_req).await;
    assert_get_ok(&rocket, "/subscriptions/plans?page=1").await;
    assert_post_ok(&rocket, "/subscriptions/plans/701/suspend", &json!({})).await;
    assert_post_ok(&rocket, "/subscriptions/plans/701/resume", &json!({})).await;
}

#[tokio::test]
async fn e2e_subscriptions_lifecycle_routes_return_200_201() {
    let server = PaymobMockServer::start().await;
    setup_subscriptions_lifecycle_mocks(&server).await;
    let rocket = tracked_rocket(&server).await;
    let create_req = json!({
        "subscription_plan_id": 701,
        "amount": 20_000,
        "currency": "EGP",
        "payment_methods": [4097558]
    });
    let upd_req = json!({ "amount_cents": 25_000 });
    assert_post_201(&rocket, "/subscriptions", &create_req).await;
    assert_get_ok(&rocket, "/subscriptions/1264").await;
    assert_get_ok(&rocket, "/subscriptions?plan_id=701&state=active&page=1").await;
    assert_put_ok(&rocket, "/subscriptions/1264", &upd_req).await;
    assert_post_ok(&rocket, "/subscriptions/1264/suspend", &json!({})).await;
    assert_post_ok(&rocket, "/subscriptions/1264/resume", &json!({})).await;
    assert_post_ok(&rocket, "/subscriptions/1264/cancel", &json!({})).await;
}

#[tokio::test]
async fn e2e_subscription_cards_and_history_routes_return_200() {
    let server = PaymobMockServer::start().await;
    setup_subscription_cards_and_history_mocks(&server).await;
    let rocket = tracked_rocket(&server).await;
    let sec_req = json!({ "card_token": "tok_sec_2", "integration_id": 4097558 });
    let pri_req = json!({ "card_id": 374 });
    let wh_req = json!({ "webhook_url": "https://merchant.example.com/hook" });
    let ref_req = json!({ "amount_cents": 5000 });
    assert_get_ok(&rocket, "/subscriptions/1264/cards").await;
    assert_post_ok(&rocket, "/subscriptions/1264/cards/secondary", &sec_req).await;
    assert_post_ok(&rocket, "/subscriptions/1264/cards/primary", &pri_req).await;
    assert_eq!(
        delete_status(&rocket, "/subscriptions/1264/cards/374").await,
        Status::Ok
    );
    assert_post_ok(&rocket, "/subscriptions/1264/webhook", &wh_req).await;
    assert_get_ok(&rocket, "/subscriptions/1264/last-transaction").await;
    assert_get_ok(&rocket, "/subscriptions/1264/transactions").await;
    let ref_uri = "/subscriptions/1264/refund-last-transaction";
    assert_post_ok(&rocket, ref_uri, &ref_req).await;
}

#[tokio::test]
async fn e2e_payouts_auth_and_all_7_cashin_issuers_return_200() {
    let server = PaymobMockServer::start().await;
    setup_payouts_cashin_mocks(&server).await;
    let rocket = tracked_rocket(&server).await;
    let ref_req = json!({ "refresh_token": "ref_tok_1" });
    let wal_req = json!({ "msisdn": "01023456789", "amount": 200 });
    assert_post_ok(&rocket, "/payouts/auth/token", &json!({})).await;
    assert_post_ok(&rocket, "/payouts/auth/refresh", &ref_req).await;
    for issuer in ["vodafone", "etisalat", "orange", "bank_wallet"] {
        let uri = format!("/payouts/cashin/wallet/{issuer}");
        assert_post_ok(&rocket, &uri, &wal_req).await;
    }
    assert_non_wallet_cashin_routes(&rocket).await;
}

#[tokio::test]
async fn e2e_payouts_inquiries_budget_and_topups_return_200() {
    let server = PaymobMockServer::start().await;
    setup_payouts_inquiries_and_topups_mocks(&server).await;
    let rocket = tracked_rocket(&server).await;
    let tx_req = json!({ "transactions_ids": ["tx_po_1"] });
    let ref_req = json!({ "client_reference_ids": ["ref_1"] });
    let acc_req = json!({
        "amount": 500,
        "currency": "egyptian_pound",
        "username": "merchant_user"
    });
    assert_post_ok(&rocket, "/payouts/inquiries/transactions", &tx_req).await;
    assert_post_ok(&rocket, "/payouts/inquiries/by-reference", &ref_req).await;
    assert_get_ok(&rocket, "/payouts/inquiries/budget").await;
    assert_get_ok(&rocket, "/payouts/inquiries/topups?page=1&id=55").await;
    let b64_req = topup_b64_json("AQIDBA==");
    assert_post_ok(&rocket, "/payouts/topups/bank-transfer", &b64_req).await;
    assert_post_ok(&rocket, "/payouts/topups/accept-balance", &acc_req).await;
}

#[tokio::test]
async fn e2e_onboarding_auth_and_flow_routes_return_200_201() {
    let server = PaymobMockServer::start().await;
    setup_onboarding_mocks(&server).await;
    let rocket = tracked_rocket(&server).await;
    let login = json!({ "username": "partner@example.com", "password": "secret-password" });
    let reg = json!({
        "partner": "acme-partner",
        "email": "partner@example.com",
        "phone_number": "+201001234567",
        "first_name": "Maher",
        "last_name": "Aladdin"
    });
    let step = json!({ "paymob_mid": 12345, "step_id": "kyc_1", "data": { "cr": "123" } });
    assert_post_ok(&rocket, "/onboarding/auth/login", &login).await;
    let key_req = json!({ "label": "main" });
    assert_post_ok(&rocket, "/onboarding/auth/api-key", &key_req).await;
    assert_get_ok(&rocket, "/onboarding/auth/hmac-secret").await;
    assert_get_ok(&rocket, "/onboarding/auth/merchants/12345/hmac-secret").await;
    assert_get_ok(&rocket, "/onboarding/flow/schema?partner=acme-partner").await;
    assert_post_201(&rocket, "/onboarding/flow/register", &reg).await;
    assert_post_ok(&rocket, "/onboarding/flow/submit-step", &step).await;
    assert_get_ok(&rocket, "/onboarding/flow/inquiry/12345").await;
}

#[tokio::test]
async fn e2e_merchant_scoped_routes_return_200_201() {
    let server = PaymobMockServer::start().await;
    setup_scoped_and_unified_mocks(&server).await;
    let rocket = tracked_rocket(&server).await;
    let create = json!({ "amount": 10_000, "currency": "EGP", "payment_methods": [4097558] });
    let upd = json!({ "special_reference": "ref-m", "amount": 12_000 });
    let tx_amt = json!({ "transaction_id": 100, "amount_cents": 5000 });
    assert_post_201(&rocket, "/merchants/12345/intentions", &create).await;
    assert_put_ok(&rocket, "/merchants/12345/intentions", &upd).await;
    assert_put_ok(&rocket, "/merchants/12345/intentions/egy_csk_u4", &upd).await;
    let tx_uri = "/merchants/12345/inquiries/transactions/192036465";
    let raw_uri = "/merchants/12345/inquiries/transactions/192036465/raw";
    let ord_req = json!({ "order_id": 1 });
    let void_req = json!({ "transaction_id": 100 });
    assert_get_ok(&rocket, tx_uri).await;
    assert_get_ok(&rocket, raw_uri).await;
    assert_post_ok(&rocket, "/merchants/12345/inquiries/by-order", &ord_req).await;
    assert_post_ok(&rocket, "/merchants/12345/manage/void", &void_req).await;
    assert_post_ok(&rocket, "/merchants/12345/manage/void/100", &json!({})).await;
    assert_post_ok(&rocket, "/merchants/12345/manage/capture", &tx_amt).await;
    assert_post_ok(&rocket, "/merchants/12345/manage/refund", &tx_amt).await;
}

#[tokio::test]
async fn e2e_unified_adapter_all_routes_return_200_201() {
    let server = PaymobMockServer::start().await;
    setup_scoped_and_unified_mocks(&server).await;
    let rocket = tracked_rocket(&server).await;
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
    assert_post_201(&rocket, "/unified/sessions", &sess).await;
    assert_post_ok(&rocket, "/unified/capture", &tx_amt).await;
    assert_post_ok(&rocket, "/unified/refund", &tx_amt).await;
    assert_post_ok(&rocket, "/unified/void", &json!({ "transaction_id": 100 })).await;
    assert_post_ok(&rocket, "/unified/charge-saved", &chg).await;
    assert_post_ok(&rocket, "/unified/subscriptions/refund", &sub_ref).await;
    assert_post_ok(&rocket, "/unified/payouts", &po).await;
    let tx_vec = transaction_processed_192036465();
    let wh_uri = format!("/unified/webhooks?hmac={}", tx_vec.expected_hmac_hex);
    assert_eq!(
        post_raw(&rocket, &wh_uri, tx_vec.payload_or_query).await,
        Status::Ok
    );
}

#[tokio::test]
async fn e2e_webhooks_protocols_a_through_e_return_200() {
    let server = PaymobMockServer::start().await;
    let rocket = tracked_rocket(&server).await;
    for vec in [
        transaction_processed_192036465(),
        card_token_15978654(),
        subscription_1264(),
    ] {
        let uri = format!("/webhooks/paymob?hmac={}", vec.expected_hmac_hex);
        assert_eq!(
            post_raw(&rocket, &uri, vec.payload_or_query).await,
            Status::Ok
        );
    }
    let redir = transaction_response_316004();
    let redir_uri = format!("/webhooks/paymob/redirect?{}", redir.payload_or_query);
    assert_get_ok(&rocket, &redir_uri).await;
    let proto_e = json!({
        "transaction_id": "tx_e1",
        "issuer": "bank_card",
        "amount_cents": 20_000,
        "currency": "EGP",
        "status": "successful"
    });
    assert_post_ok(&rocket, "/webhooks/paymob", &proto_e).await;
}

// ---------------------------------------------------------------------------
// Boundary Condition Tests (SDK + Rocket HTTP Status Verification)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn boundary_amount_zero_one_and_u64_max_overflow() {
    let server = PaymobMockServer::start().await;
    setup_manage_mocks(&server).await;
    let rocket = tracked_rocket(&server).await;
    assert_eq!(MinorUnitAmount::new(0).as_u64(), 0);
    assert_eq!(MinorUnitAmount::new(1).as_u64(), 1);
    assert!(RefundParams::try_new(100, 0).is_err());
    assert!(RefundParams::try_new(100, 1).is_ok());
    let max = MinorUnitAmount::new(u64::MAX);
    assert!(max.checked_add(MinorUnitAmount::new(1)).is_err());
    assert!(max.checked_mul(2).is_err());
    let zero_ref = json!({ "transaction_id": 100, "amount_cents": 0 });
    let one_ref = json!({ "transaction_id": 100, "amount_cents": 1 });
    assert_post_400(&rocket, "/manage/refund", &zero_ref).await;
    assert_post_ok(&rocket, "/manage/refund", &one_ref).await;
}

#[tokio::test]
async fn boundary_bulk_disbursements_0_1_1000_1001_items() {
    let server = PaymobMockServer::start().await;
    setup_payouts_cashin_mocks(&server).await;
    let rocket = tracked_rocket(&server).await;
    assert_post_400(&rocket, "/payouts/cashin/bulk", &bulk_items_json(0)).await;
    assert_post_ok(&rocket, "/payouts/cashin/bulk", &bulk_items_json(1)).await;
    assert_post_ok(&rocket, "/payouts/cashin/bulk", &bulk_items_json(1_000)).await;
    assert_post_400(&rocket, "/payouts/cashin/bulk", &bulk_items_json(1_001)).await;
}

#[tokio::test]
async fn boundary_inquiry_ids_0_1_500_501() {
    let server = PaymobMockServer::start().await;
    setup_payouts_inquiries_and_topups_mocks(&server).await;
    let rocket = tracked_rocket(&server).await;
    let uri = "/payouts/inquiries/transactions";
    assert_post_400(&rocket, uri, &inquiry_ids_json(0)).await;
    for count in [1usize, 500, 501, 1_000] {
        assert_post_ok(&rocket, uri, &inquiry_ids_json(count)).await;
    }
    assert_post_400(&rocket, uri, &inquiry_ids_json(1_001)).await;
}

#[tokio::test]
async fn boundary_bank_transfer_proof_sizes_0_max_and_over() {
    let server = PaymobMockServer::start().await;
    setup_payouts_inquiries_and_topups_mocks(&server).await;
    let rocket = tracked_rocket(&server).await;
    let uri = "/payouts/topups/bank-transfer";
    assert_eq!(MAX_TOPUP_PROOF_BYTES, 2_936_012);
    assert_post_400(&rocket, uri, &topup_raw_json(0)).await;
    assert_post_ok(&rocket, uri, &topup_raw_json(2_936_012)).await;
    assert_post_400(&rocket, uri, &topup_raw_json(2_936_013)).await;
    let over_b64 = "A".repeat(MAX_TOPUP_PROOF_BYTES.div_ceil(3) * 4 + 4);
    assert_post_400(&rocket, uri, &topup_b64_json(&over_b64)).await;
}

#[tokio::test]
async fn boundary_split_payments_cards_and_bps_not_10000() {
    let server = PaymobMockServer::start().await;
    let rocket = tracked_rocket(&server).await;
    assert!(matches!(
        SplitPaymentConfig::new(vec![]),
        Err(PaymobError::ValidationError { .. })
    ));
    assert!(SplitPaymentConfig::new(vec![SplitCardPortion::new(1_000)]).is_ok());
    assert!(SplitPaymentConfig::new(vec![SplitCardPortion::new(1_000); 3]).is_ok());
    assert!(SplitPaymentConfig::new(vec![SplitCardPortion::new(1_000); 4]).is_err());
    assert!(SplitDescription::new(vec![SplitRecipientRule::percentage_bps("s1", 9_999)]).is_ok());
    let empty_sp = json!({ "amount_cents": 100_000, "recipients": [] });
    let ok_sp = json!({
        "amount_cents": 100_000,
        "recipients": [{ "recipient_id": "s1", "percentage_bps": 9_999 }]
    });
    let over_sp = json!({
        "amount_cents": 100_000,
        "recipients": [
            { "recipient_id": "s1", "percentage_bps": 6_000 },
            { "recipient_id": "s2", "percentage_bps": 4_001 }
        ]
    });
    assert_post_400(&rocket, "/splits/validate-and-quote", &empty_sp).await;
    assert_post_ok(&rocket, "/splits/validate-and-quote", &ok_sp).await;
    assert_post_400(&rocket, "/splits/validate-and-quote", &over_sp).await;
}

fn sandbox_card_report(age: u64) -> some_paymob::SandboxReport {
    SandboxGuard::check_constraints(&SandboxCheckRequest {
        is_sandbox: true,
        credential_age_days: age,
        channel: SandboxPaymentChannel::Card,
    })
}

fn sandbox_card_json(age: u64) -> Value {
    json!({
        "is_sandbox": true,
        "credential_age_days": age,
        "channel": "card"
    })
}

#[tokio::test]
async fn boundary_sandbox_guard_credential_age_24_25_30_days() {
    let server = PaymobMockServer::start().await;
    let rocket = tracked_rocket(&server).await;
    assert!(sandbox_card_report(24).is_ok() && sandbox_card_report(24).warnings.is_empty());
    assert_eq!(
        sandbox_card_report(25).warnings,
        vec![SandboxWarning::CredentialExpiringSoon {
            age_days: 25,
            days_remaining: 5
        }]
    );
    assert_eq!(
        sandbox_card_report(30).errors,
        vec![SandboxConstraintError::CredentialExpired { age_days: 30 }]
    );
    assert_post_ok(&rocket, "/sandbox/check", &sandbox_card_json(24)).await;
    assert_post_ok(&rocket, "/sandbox/check", &sandbox_card_json(25)).await;
    assert_eq!(
        post_json(&rocket, "/sandbox/check", &sandbox_card_json(30)).await,
        Status::UnprocessableEntity
    );
}

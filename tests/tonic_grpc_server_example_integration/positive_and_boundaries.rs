#![forbid(unsafe_code)]
//! Unit 4: Positive E2E and boundary condition integration tests for `examples/tonic_grpc_server.rs`.

use std::sync::Arc;

use http::uri::PathAndQuery;
use serde_json::{Value, json};
use some_paymob::core::auth::CachedToken;
use some_paymob::core::credentials::{
    ApiKey, HmacSecret, PartnerCredentials, PayoutsCredentials, PublicKey, SecretKey,
};
use some_paymob::test_utils::{
    JsonEndpointMockConfig, MockHost, PaymobMockServer, SAMPLE_HMAC_SECRET, SandboxCheckRequest,
    SandboxConstraintError, SandboxGuard, SandboxPaymentChannel, SandboxReport, SandboxWarning,
    card_token_15978654, subscription_1264, transaction_processed_192036465,
    transaction_response_316004,
};
use some_paymob::webhooks::InMemoryWebhookDeduplicator;
use some_paymob::{
    ClientConfig, MAX_TOPUP_PROOF_BYTES, MinorUnitAmount, PaymobClient, PaymobError,
    PaymobWebhookEngine, RefundParams, SplitCardPortion, SplitDescription, SplitPaymentConfig,
    SplitRecipientRule,
};
use tonic::client::Grpc;
use tonic::codec::ProstCodec;
use tonic::{Code, Request, Status};

use super::tonic_grpc_server::proto::{
    JsonRpcRequest, JsonRpcResponse, PAYMOB_GRPC_SERVICE_NAME,
};
use super::tonic_grpc_server::{PaymobGrpcService, build_grpc_server};

fn build_test_client(server: &PaymobMockServer) -> PaymobClient {
    let payouts_creds =
        PayoutsCredentials::new("cid", "csec", "user", "pass").expect("valid payouts creds");
    let partner_creds =
        PartnerCredentials::with_bearer_token("partner_api_key_123", "partner_bearer_jwt_123")
            .expect("valid partner creds");
    let config = ClientConfig::builder()
        .region(server.custom_region())
        .secret_key(SecretKey::new("egy_sk_test_tonic_unit4").expect("valid secret key"))
        .public_key(PublicKey::new("egy_pk_test_tonic_unit4").expect("valid public key"))
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

fn build_grpc_service(server: &PaymobMockServer) -> PaymobGrpcService {
    let client = Arc::new(build_test_client(server));
    let webhook_engine =
        Arc::new(PaymobWebhookEngine::new(SAMPLE_HMAC_SECRET).expect("valid webhook engine"));
    let deduplicator = Arc::new(InMemoryWebhookDeduplicator::new());
    PaymobGrpcService::new(client, webhook_engine, deduplicator)
}

async fn call_rpc(
    service: &PaymobGrpcService,
    method: &str,
    payload: &Value,
) -> Result<Value, Status> {
    let mut grpc = Grpc::new(build_grpc_server(service.clone()));
    grpc.ready()
        .await
        .map_err(|err| Status::internal(format!("grpc_not_ready: {err}")))?;
    let codec = ProstCodec::<JsonRpcRequest, JsonRpcResponse>::default();
    let path = PathAndQuery::from_shared(format!("/{PAYMOB_GRPC_SERVICE_NAME}/{method}"))
        .map_err(|err| Status::invalid_argument(format!("invalid_grpc_path: {err}")))?;
    let req = Request::new(JsonRpcRequest {
        payload_json: payload.to_string(),
    });
    let resp = grpc.unary(req, path, codec).await?.into_inner();
    serde_json::from_str(&resp.payload_json)
        .map_err(|err| Status::internal(format!("invalid_response_json: {err}")))
}

async fn assert_rpc_ok(service: &PaymobGrpcService, method: &str, payload: &Value) -> Value {
    match call_rpc(service, method, payload).await {
        Ok(val) => val,
        Err(status) => panic!("expected Code::Ok for {method}, got {status:?}"),
    }
}

async fn assert_rpc_code(
    service: &PaymobGrpcService,
    method: &str,
    payload: &Value,
    expected: Code,
) {
    let err = call_rpc(service, method, payload)
        .await
        .expect_err("expected gRPC error status");
    assert_eq!(err.code(), expected, "unexpected status for {method}: {err:?}");
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

async fn assert_non_wallet_cashin_rpcs(service: &PaymobGrpcService) {
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
    assert_rpc_ok(service, "CashinBankCard", &card_req).await;
    assert_rpc_ok(service, "CashinBankInstant", &inst_req).await;
    assert_rpc_ok(service, "CashinEgyptianPost", &post_req).await;
    assert_rpc_ok(service, "CancelAmanCashin", &aman_req).await;
    assert_rpc_ok(service, "BulkCashin", &bulk_items_json(1)).await;
}

// ---------------------------------------------------------------------------
// Positive E2E Tests: All 14 Services & Protocols A-E (Code::Ok)
// ---------------------------------------------------------------------------

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

#[tokio::test]
async fn e2e_intentions_create_and_update_return_ok() {
    let server = PaymobMockServer::start().await;
    let body = json!({
        "id": "pi_unit4_001",
        "client_secret": "egy_csk_test_unit4",
        "status": "intended",
        "intention_order_id": 99001
    });
    mount_accept(&server, "POST", "/v1/intention/", 201, body.clone()).await;
    mount_accept(&server, "PUT", "/v1/intention/", 200, body).await;
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

#[tokio::test]
async fn e2e_checkout_pixel_and_affordability_return_ok() {
    let server = PaymobMockServer::start().await;
    let service = build_grpc_service(&server);
    let pixel_req = json!({ "client_secret": "egy_csk_test_unit4", "locale": "en" });
    let afford_req = json!({ "amount_cents": 50_000, "currency": "EGP" });
    assert_rpc_ok(&service, "BuildPixelConfig", &pixel_req).await;
    assert_rpc_ok(&service, "BuildAffordabilityWidget", &afford_req).await;
}

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
    assert_rpc_ok(&service, "CancelQuickLink", &json!({ "quick_link_id": "ql_u4" })).await;
    assert_rpc_ok(&service, "ValidateSplitsAndCalculateFee", &sp_req).await;
}

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
    mount_accept(&server, "POST", "/api/acceptance/payments/pay", 200, pay_resp).await;
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
    assert_rpc_ok(&service, "GetSubscription", &sub_ref).await;
    assert_rpc_ok(&service, "ListSubscriptions", &list_req).await;
    assert_rpc_ok(&service, "UpdateSubscription", &upd_req).await;
    assert_rpc_ok(&service, "SuspendSubscription", &sub_ref).await;
    assert_rpc_ok(&service, "ResumeSubscription", &sub_ref).await;
    assert_rpc_ok(&service, "CancelSubscription", &sub_ref).await;
}

#[tokio::test]
async fn e2e_subscription_cards_and_history_rpcs_return_ok() {
    let server = PaymobMockServer::start().await;
    setup_subscription_cards_and_history_mocks(&server).await;
    let service = build_grpc_service(&server);
    let sub_ref = json!({ "subscription_id": 1264 });
    let sec_req = json!({ "subscription_id": 1264, "card_token": "tok_sec_2", "integration_id": 4097558 });
    let pri_req = json!({ "subscription_id": 1264, "card_id": 374 });
    let del_req = json!({ "subscription_id": 1264, "card_id": 374 });
    let wh_req = json!({ "subscription_id": 1264, "webhook_url": "https://merchant.example.com/hook" });
    let ref_req = json!({ "subscription_id": 1264, "amount_cents": 5000 });
    assert_rpc_ok(&service, "ListSubscriptionCards", &sub_ref).await;
    assert_rpc_ok(&service, "AddSecondarySubscriptionCard", &sec_req).await;
    assert_rpc_ok(&service, "ChangePrimarySubscriptionCard", &pri_req).await;
    assert_rpc_ok(&service, "DeleteSubscriptionCard", &del_req).await;
    assert_rpc_ok(&service, "UpdateSubscriptionWebhook", &wh_req).await;
    assert_rpc_ok(&service, "GetSubscriptionLastTransaction", &sub_ref).await;
    assert_rpc_ok(&service, "ListSubscriptionTransactions", &sub_ref).await;
    assert_rpc_ok(&service, "RefundSubscriptionLastTransaction", &ref_req).await;
}

#[tokio::test]
async fn e2e_payouts_auth_and_all_7_cashin_issuers_return_ok() {
    let server = PaymobMockServer::start().await;
    setup_payouts_cashin_mocks(&server).await;
    let service = build_grpc_service(&server);
    let ref_req = json!({ "refresh_token": "ref_tok_1" });
    assert_rpc_ok(&service, "CreatePayoutsToken", &json!({})).await;
    assert_rpc_ok(&service, "RefreshPayoutsToken", &ref_req).await;
    for issuer in ["vodafone", "etisalat", "orange", "bank_wallet"] {
        let wal_req = json!({ "issuer": issuer, "msisdn": "01023456789", "amount": 200 });
        assert_rpc_ok(&service, "CashinWallet", &wal_req).await;
    }
    assert_non_wallet_cashin_rpcs(&service).await;
}

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
    assert_rpc_ok(&service, "InquirePayoutsTransactions", &tx_req).await;
    assert_rpc_ok(&service, "InquirePayoutsByReference", &ref_req).await;
    assert_rpc_ok(&service, "InquirePayoutsBudget", &json!({})).await;
    assert_rpc_ok(&service, "InquirePayoutsTopups", &topup_inq).await;
    assert_rpc_ok(&service, "RequestBankTransferTopup", &topup_b64_json("AQIDBA==")).await;
    assert_rpc_ok(&service, "RequestAcceptBalanceTopup", &acc_req).await;
}

#[tokio::test]
async fn e2e_onboarding_auth_and_flow_rpcs_return_ok() {
    let server = PaymobMockServer::start().await;
    setup_onboarding_mocks(&server).await;
    let service = build_grpc_service(&server);
    let login = json!({ "username": "partner@example.com", "password": "secret-password" });
    let reg = json!({
        "partner": "acme-partner",
        "email": "partner@example.com",
        "phone_number": "+201001234567",
        "first_name": "Maher",
        "last_name": "Aladdin"
    });
    let step = json!({ "paymob_mid": 12345, "step_id": "kyc_1", "data": { "cr": "123" } });
    assert_rpc_ok(&service, "OnboardingLogin", &login).await;
    assert_rpc_ok(&service, "CreateOnboardingApiKey", &json!({ "label": "main" })).await;
    assert_rpc_ok(&service, "GetOnboardingHmacSecret", &json!({})).await;
    assert_rpc_ok(&service, "GetMerchantHmacSecret", &json!({ "merchant_id": 12345 })).await;
    assert_rpc_ok(&service, "GetOnboardingFlowSchema", &json!({ "partner": "acme-partner" })).await;
    assert_rpc_ok(&service, "RegisterOnboardingMerchant", &reg).await;
    assert_rpc_ok(&service, "SubmitOnboardingFlowStep", &step).await;
    assert_rpc_ok(&service, "InquireOnboardingMerchant", &json!({ "merchant_id": 12345 })).await;
}

#[tokio::test]
async fn e2e_merchant_scoped_rpcs_return_ok() {
    let server = PaymobMockServer::start().await;
    setup_scoped_and_unified_mocks(&server).await;
    let service = build_grpc_service(&server);
    let create = json!({ "merchant_id": 12345, "amount": 10_000, "currency": "EGP", "payment_methods": [4097558] });
    let upd = json!({ "merchant_id": 12345, "special_reference": "ref-m", "amount": 12_000 });
    let upd_cs = json!({ "merchant_id": 12345, "client_secret": "egy_csk_u4", "special_reference": "ref-m", "amount": 12_000 });
    let tx_inq = json!({ "merchant_id": 12345, "transaction_id": 192036465 });
    let tx_amt = json!({ "merchant_id": 12345, "transaction_id": 100, "amount_cents": 5000 });
    assert_rpc_ok(&service, "ScopedCreateIntention", &create).await;
    assert_rpc_ok(&service, "ScopedUpdateIntention", &upd).await;
    assert_rpc_ok(&service, "ScopedUpdateIntentionByClientSecret", &upd_cs).await;
    assert_rpc_ok(&service, "ScopedInquireTransactionById", &tx_inq).await;
    assert_rpc_ok(&service, "ScopedInquireTransactionRaw", &tx_inq).await;
    assert_rpc_ok(&service, "ScopedInquireTransactionByOrder", &json!({ "merchant_id": 12345, "order_id": 1 })).await;
    assert_rpc_ok(&service, "ScopedVoidTransaction", &json!({ "merchant_id": 12345, "transaction_id": 100 })).await;
    assert_rpc_ok(&service, "ScopedVoidTransactionById", &json!({ "merchant_id": 12345, "transaction_id": 100 })).await;
    assert_rpc_ok(&service, "ScopedCaptureTransaction", &tx_amt).await;
    assert_rpc_ok(&service, "ScopedRefundTransaction", &tx_amt).await;
}

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
    assert_rpc_ok(&service, "UnifiedChargeSaved", &chg).await;
    assert_rpc_ok(&service, "UnifiedRefundSubscription", &sub_ref).await;
    assert_rpc_ok(&service, "UnifiedPayout", &po).await;
    let tx_vec = transaction_processed_192036465();
    let wh_req = json!({ "hmac": tx_vec.expected_hmac_hex, "payload": tx_vec.payload_or_query });
    assert_rpc_ok(&service, "UnifiedVerifyWebhook", &wh_req).await;
}

#[tokio::test]
async fn e2e_webhooks_protocols_a_through_e_return_ok() {
    let server = PaymobMockServer::start().await;
    let service = build_grpc_service(&server);
    for vec in [
        transaction_processed_192036465(),
        card_token_15978654(),
        subscription_1264(),
    ] {
        let req = json!({ "hmac": vec.expected_hmac_hex, "payload": vec.payload_or_query });
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
    let proto_e_req = json!({ "payload": proto_e.to_string() });
    assert_rpc_ok(&service, "VerifyWebhookEvent", &proto_e_req).await;
}

// ---------------------------------------------------------------------------
// Boundary Condition Tests (SDK + Tonic gRPC Status Verification)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn boundary_amount_zero_one_and_u64_max_overflow() {
    let server = PaymobMockServer::start().await;
    setup_manage_mocks(&server).await;
    let service = build_grpc_service(&server);
    assert_eq!(MinorUnitAmount::new(0).as_u64(), 0);
    assert_eq!(MinorUnitAmount::new(1).as_u64(), 1);
    assert!(RefundParams::try_new(100, 0).is_err());
    assert!(RefundParams::try_new(100, 1).is_ok());
    let max = MinorUnitAmount::new(u64::MAX);
    assert!(max.checked_add(MinorUnitAmount::new(1)).is_err());
    assert!(max.checked_mul(2).is_err());
    let zero_ref = json!({ "transaction_id": 100, "amount_cents": 0 });
    let one_ref = json!({ "transaction_id": 100, "amount_cents": 1 });
    assert_rpc_code(&service, "RefundTransaction", &zero_ref, Code::InvalidArgument).await;
    assert_rpc_ok(&service, "RefundTransaction", &one_ref).await;
}

#[tokio::test]
async fn boundary_bulk_disbursements_0_1_1000_1001_items() {
    let server = PaymobMockServer::start().await;
    setup_payouts_cashin_mocks(&server).await;
    let service = build_grpc_service(&server);
    assert_rpc_code(&service, "BulkCashin", &bulk_items_json(0), Code::InvalidArgument).await;
    assert_rpc_ok(&service, "BulkCashin", &bulk_items_json(1)).await;
    assert_rpc_ok(&service, "BulkCashin", &bulk_items_json(1_000)).await;
    assert_rpc_code(&service, "BulkCashin", &bulk_items_json(1_001), Code::InvalidArgument).await;
}

#[tokio::test]
async fn boundary_inquiry_ids_0_1_500_501() {
    let server = PaymobMockServer::start().await;
    setup_payouts_inquiries_and_topups_mocks(&server).await;
    let service = build_grpc_service(&server);
    let method = "InquirePayoutsTransactions";
    assert_rpc_code(&service, method, &inquiry_ids_json(0), Code::InvalidArgument).await;
    for count in [1usize, 500, 501, 1_000] {
        assert_rpc_ok(&service, method, &inquiry_ids_json(count)).await;
    }
    assert_rpc_code(&service, method, &inquiry_ids_json(1_001), Code::InvalidArgument).await;
}

#[tokio::test]
async fn boundary_bank_transfer_proof_sizes_0_max_and_over() {
    let server = PaymobMockServer::start().await;
    setup_payouts_inquiries_and_topups_mocks(&server).await;
    let service = build_grpc_service(&server);
    let method = "RequestBankTransferTopup";
    assert_eq!(MAX_TOPUP_PROOF_BYTES, 2_936_012);
    assert_rpc_code(&service, method, &topup_raw_json(0), Code::InvalidArgument).await;
    assert_rpc_ok(&service, method, &topup_raw_json(2_936_012)).await;
    assert_rpc_code(&service, method, &topup_raw_json(2_936_013), Code::InvalidArgument).await;
    let over_b64 = "A".repeat(MAX_TOPUP_PROOF_BYTES.div_ceil(3) * 4 + 4);
    assert_rpc_code(&service, method, &topup_b64_json(&over_b64), Code::InvalidArgument).await;
}

#[tokio::test]
async fn boundary_split_payments_cards_and_bps_not_10000() {
    let server = PaymobMockServer::start().await;
    let service = build_grpc_service(&server);
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
    let method = "ValidateSplitsAndCalculateFee";
    assert_rpc_code(&service, method, &empty_sp, Code::InvalidArgument).await;
    assert_rpc_ok(&service, method, &ok_sp).await;
    assert_rpc_code(&service, method, &over_sp, Code::InvalidArgument).await;
}

fn sandbox_card_report(age: u64) -> SandboxReport {
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
    let service = build_grpc_service(&server);
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
    let method = "CheckSandboxConstraints";
    assert_rpc_ok(&service, method, &sandbox_card_json(24)).await;
    assert_rpc_ok(&service, method, &sandbox_card_json(25)).await;
    assert_rpc_code(&service, method, &sandbox_card_json(30), Code::FailedPrecondition).await;
}

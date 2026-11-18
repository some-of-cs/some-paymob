#![forbid(unsafe_code)]
//! Unit 4: Positive E2E and boundary condition integration tests for `examples/rocket_server.rs`.

use std::sync::Arc;

use rocket::http::{ContentType, Status};
use rocket::local::asynchronous::Client;
use serde_json::{Value, json};
use some_paymob::core::auth::CachedToken;
use some_paymob::core::credentials::{ApiKey, HmacSecret, PublicKey, SecretKey};
use some_paymob::test_utils::{
    JsonEndpointMockConfig, MockHost, PaymobMockServer, SAMPLE_HMAC_SECRET, SandboxCheckRequest,
    SandboxConstraintError, SandboxGuard, SandboxPaymentChannel, SandboxWarning,
    card_token_15978654, subscription_1264, transaction_processed_192036465,
    transaction_response_316004,
};
use some_paymob::{
    BankTransferTopupParams, BulkDisbursementItem, BulkDisbursementParams, ClientConfig,
    DisburseIssuer, InMemoryWebhookDeduplicator, MAX_TOPUP_PROOF_BYTES, MinorUnitAmount,
    PaymobClient, PaymobError, PaymobWebhookEngine, RefundParams, SplitCardPortion,
    SplitDescription, SplitPaymentConfig, SplitRecipientRule, TransactionInquiryParams,
};

use super::rocket_server::{AppState, build_rocket};

fn build_test_client(server: &PaymobMockServer) -> PaymobClient {
    let config = ClientConfig::builder()
        .region(server.custom_region())
        .secret_key(SecretKey::new("egy_sk_test_rocket_unit4").expect("valid secret key"))
        .public_key(PublicKey::new("egy_pk_test_rocket_unit4").expect("valid public key"))
        .api_key(
            ApiKey::new("ZXlKaGJHY2lPaUpJVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5").expect("valid api key"),
        )
        .hmac_secret(HmacSecret::new(SAMPLE_HMAC_SECRET).expect("valid hmac secret"))
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

fn sample_bulk_item(idx: usize) -> BulkDisbursementItem {
    BulkDisbursementItem {
        issuer: DisburseIssuer::Vodafone,
        amount: 200,
        msisdn: Some(String::from("01023456789")),
        full_name: Some(format!("User {idx}")),
        bank_code: None,
        client_reference_id: Some(format!("ref_{idx}")),
    }
}

fn sample_topup_params(proof_len: usize) -> BankTransferTopupParams {
    BankTransferTopupParams {
        amount: 500,
        currency: String::from("egyptian_pound"),
        to_attach_proof: vec![1u8; proof_len],
        proof_filename: String::from("receipt.pdf"),
        from_bank_name: Some(String::from("CIB")),
        reference_number: Some(String::from("REF-UNIT4")),
    }
}

// ---------------------------------------------------------------------------
// Positive E2E Tests: All 14 Services & Protocols A-E
// ---------------------------------------------------------------------------

#[tokio::test]
async fn e2e_health_and_sandbox_check_return_200() {
    let server = PaymobMockServer::start().await;
    let rocket = tracked_rocket(&server).await;

    let health = rocket.get("/health").dispatch().await;
    assert_eq!(health.status(), Status::Ok);

    let check = post_json(
        &rocket,
        "/sandbox/check",
        &json!({ "is_sandbox": true, "credential_age_days": 10, "channel": "card" }),
    )
    .await;
    assert_eq!(check, Status::Ok);
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
    let created = post_json(
        &rocket,
        "/intentions",
        &json!({
            "amount_cents": 10_000,
            "currency": "EGP",
            "payment_methods": [4097558],
            "billing_data": sample_billing_json(),
        }),
    )
    .await;
    assert_eq!(created, Status::Created);

    let updated = put_json(
        &rocket,
        "/intentions",
        &json!({ "client_secret": "egy_csk_test_unit4", "amount_cents": 12_000 }),
    )
    .await;
    assert_eq!(updated, Status::Ok);
}

#[tokio::test]
async fn e2e_checkout_pixel_and_affordability_return_200() {
    let server = PaymobMockServer::start().await;
    let rocket = tracked_rocket(&server).await;

    let pixel = post_json(
        &rocket,
        "/checkout/pixel",
        &json!({
            "public_key": "egy_pk_test_rocket_unit4",
            "client_secret": "egy_csk_test_unit4",
            "show_save_card": true,
        }),
    )
    .await;
    assert_eq!(pixel, Status::Ok);

    let afford = post_json(
        &rocket,
        "/checkout/affordability",
        &json!({
            "public_key": "egy_pk_test_rocket_unit4",
            "amount_cents": 50_000,
            "currency": "EGP",
            "tenure_months": 12,
        }),
    )
    .await;
    assert_eq!(afford, Status::Ok);
}

#[tokio::test]
async fn e2e_legacy_v2_orders_payment_keys_and_checkout_return_201() {
    let server = PaymobMockServer::start().await;
    server.mount_accept_auth_sequence(&["jwt-legacy-1"]).await;
    mount_accept(
        &server,
        "POST",
        "/api/ecommerce/orders",
        201,
        json!({ "id": 378804, "amount_cents": 50_000, "merchant_order_id": "ORD-L1" }),
    )
    .await;
    mount_accept(
        &server,
        "POST",
        "/api/acceptance/payment_keys",
        201,
        json!({ "token": "paykey_unit4_token" }),
    )
    .await;

    let rocket = tracked_rocket(&server).await;
    let order = post_json(
        &rocket,
        "/legacy/orders",
        &json!({ "amount_cents": 50_000, "currency": "EGP", "merchant_order_id": "ORD-L1" }),
    )
    .await;
    assert_eq!(order, Status::Created);

    let key = post_json(
        &rocket,
        "/legacy/payment-keys",
        &json!({
            "order_id": 378804, "amount_cents": 50_000, "currency": "EGP",
            "integration_id": 2936, "first_name": "Maher", "last_name": "Aladdin",
            "email": "buyer@example.com", "phone_number": "+201001234567"
        }),
    )
    .await;
    assert_eq!(key, Status::Created);
}

#[tokio::test]
async fn e2e_manage_refund_void_capture_return_200() {
    let server = PaymobMockServer::start().await;
    mount_accept(
        &server,
        "POST",
        "/api/acceptance/void_refund/refund",
        200,
        json!({ "id": 101, "success": true, "is_refund": true, "amount_cents": 5000 }),
    )
    .await;
    mount_accept(
        &server,
        "POST",
        "/api/acceptance/void_refund/void",
        200,
        json!({ "id": 102, "success": true, "is_void": true, "amount_cents": 5000 }),
    )
    .await;
    mount_accept(
        &server,
        "POST",
        "/api/acceptance/capture",
        200,
        json!({ "id": 103, "success": true, "is_capture": true, "amount_cents": 5000 }),
    )
    .await;

    let rocket = tracked_rocket(&server).await;
    assert_eq!(
        post_json(
            &rocket,
            "/manage/refund",
            &json!({ "transaction_id": 100, "amount_cents": 5000 })
        )
        .await,
        Status::Ok
    );
    assert_eq!(
        post_json(&rocket, "/manage/void", &json!({ "transaction_id": 100 })).await,
        Status::Ok
    );
    assert_eq!(
        post_json(
            &rocket,
            "/manage/capture",
            &json!({ "transaction_id": 100, "amount_cents": 5000 })
        )
        .await,
        Status::Ok
    );
}

#[tokio::test]
async fn e2e_inquiries_tx_order_and_card_tokens_return_200() {
    let server = PaymobMockServer::start().await;
    server.mount_accept_auth_sequence(&["jwt-inq-1"]).await;
    mount_accept(
        &server,
        "GET",
        "/api/acceptance/transactions/192036465",
        200,
        json!({ "id": 192036465, "success": true, "amount_cents": 100_000, "currency": "EGP" }),
    )
    .await;
    mount_accept(
        &server,
        "POST",
        "/api/ecommerce/orders/transaction_inquiry",
        200,
        json!({ "id": 192036465, "success": true, "amount_cents": 100_000 }),
    )
    .await;
    mount_accept(
        &server,
        "GET",
        "/api/ecommerce/orders/217503754",
        200,
        json!({
            "id": 217503754, "amount_cents": 100_000,
            "paid_amount_cents": 100_000, "payment_status": "PAID"
        }),
    )
    .await;

    let rocket = tracked_rocket(&server).await;
    assert_eq!(
        rocket
            .get("/inquiries/transactions/192036465")
            .dispatch()
            .await
            .status(),
        Status::Ok
    );
    assert_eq!(
        post_json(
            &rocket,
            "/inquiries/by-order",
            &json!({ "order_id": 217503754 })
        )
        .await,
        Status::Ok
    );
    assert_eq!(
        rocket
            .get("/inquiries/orders/217503754")
            .dispatch()
            .await
            .status(),
        Status::Ok
    );
}

#[tokio::test]
async fn e2e_quicklinks_and_splits_return_200_201() {
    let server = PaymobMockServer::start().await;
    server.mount_accept_auth_sequence(&["jwt-ql-1"]).await;
    mount_accept(
        &server,
        "POST",
        "/api/ecommerce/payment-links",
        201,
        json!({
            "id": "ql_u4",
            "url": "https://accept.paymob.com/standalone/?ref=ql_u4",
            "client_url": "https://accept.paymob.com/api/acceptance/post_pay?ref=ql_u4"
        }),
    )
    .await;
    mount_accept(
        &server,
        "POST",
        "/api/ecommerce/payment-links/cancel",
        200,
        json!({ "detail": "cancelled" }),
    )
    .await;

    let rocket = tracked_rocket(&server).await;
    let created = post_json(
        &rocket,
        "/quicklinks",
        &json!({ "amount_cents": 15_000, "currency": "EGP", "integrations": [4097558] }),
    )
    .await;
    assert_eq!(created, Status::Created);

    let cancelled = post_json(&rocket, "/quicklinks/ql_u4/cancel", &json!({})).await;
    assert_eq!(cancelled, Status::Ok);

    let quoted = post_json(
        &rocket,
        "/splits/validate-and-quote",
        &json!({
            "total_amount_cents": 100_000,
            "recipients": [{ "recipient_id": "sub_1", "percentage_bps": 10_000 }],
            "cards": [{ "amount_cents": 100_000 }],
            "fixed_fee_cents": 500
        }),
    )
    .await;
    assert_eq!(quoted, Status::Ok);
}

#[tokio::test]
async fn e2e_saved_cards_and_subscriptions_return_200_201() {
    let server = PaymobMockServer::start().await;
    server.mount_accept_auth_sequence(&["jwt-sub-1"]).await;
    mount_accept(
        &server,
        "POST",
        "/api/acceptance/payments/pay",
        200,
        json!({ "id": 501, "success": true, "pending": false }),
    )
    .await;
    mount_accept(
        &server,
        "POST",
        "/api/acceptance/subscription-plans",
        201,
        json!({ "id": 701, "name": "Pro Plan", "amount_cents": 20_000 }),
    )
    .await;

    let rocket = tracked_rocket(&server).await;
    assert_eq!(
        post_json(
            &rocket,
            "/saved-cards/pay",
            &json!({ "payment_token": "tok_u4", "source_type": "CARD" })
        )
        .await,
        Status::Ok
    );
    assert_eq!(
        post_json(
            &rocket,
            "/subscriptions/plans",
            &json!({ "name": "Pro Plan", "amount_cents": 20_000, "frequency": 30 })
        )
        .await,
        Status::Created
    );
}

#[tokio::test]
async fn e2e_payouts_bulk_budget_and_topup_return_200() {
    let server = PaymobMockServer::start().await;
    mount_payouts(
        &server,
        "POST",
        "/disburse/api/v1/disburse/bulk_transaction",
        200,
        json!({ "status": "ok", "results": [{ "transaction_id": "tx_u4", "amount": 200 }] }),
    )
    .await;
    mount_payouts(
        &server,
        "GET",
        "/api/secure/budget/",
        200,
        json!({ "current_budget": "1000.00" }),
    )
    .await;

    let rocket = tracked_rocket(&server).await;
    assert_eq!(
        post_json(
            &rocket,
            "/payouts/bulk",
            &json!({
                "items": [{ "issuer": "vodafone", "amount": 200, "msisdn": "01023456789" }]
            })
        )
        .await,
        Status::Ok
    );
    assert_eq!(
        rocket.get("/payouts/budget").dispatch().await.status(),
        Status::Ok
    );
}

#[tokio::test]
async fn e2e_onboarding_and_merchant_scoped_return_200_201() {
    let server = PaymobMockServer::start().await;
    mount_accept(
        &server,
        "POST",
        "/api/auth/partners/register",
        201,
        json!({ "merchant_id": "mid_u4", "status": "registered" }),
    )
    .await;
    mount_accept(
        &server,
        "GET",
        "/api/acceptance/transactions/192036465",
        200,
        json!({ "id": 192036465, "success": true, "amount_cents": 100_000 }),
    )
    .await;

    let rocket = tracked_rocket(&server).await;
    assert_eq!(
        post_json(
            &rocket,
            "/onboarding/register",
            &json!({ "email": "partner@example.com", "business_name": "Acme" })
        )
        .await,
        Status::Created
    );
    assert_eq!(
        rocket
            .get("/merchants/mid_u4/inquiries/transactions/192036465")
            .dispatch()
            .await
            .status(),
        Status::Ok
    );
}

#[tokio::test]
async fn e2e_unified_adapter_routes_return_200_201() {
    let server = PaymobMockServer::start().await;
    mount_accept(
        &server,
        "POST",
        "/v1/intention/",
        201,
        json!({
            "id": "pi_unified_u4",
            "client_secret": "egy_csk_unified_u4",
            "status": "intended",
            "intention_order_id": 88001
        }),
    )
    .await;
    mount_accept(
        &server,
        "POST",
        "/api/acceptance/capture",
        200,
        json!({ "id": 9001, "success": true, "is_capture": true, "amount_cents": 5000 }),
    )
    .await;

    let rocket = tracked_rocket(&server).await;
    assert_eq!(
        post_json(
            &rocket,
            "/unified/sessions",
            &json!({ "amount_cents": 15_000, "currency": "EGP", "payment_methods": ["4097558"] })
        )
        .await,
        Status::Created
    );
    assert_eq!(
        post_json(
            &rocket,
            "/unified/capture",
            &json!({ "transaction_id": 9001, "amount_cents": 5000 })
        )
        .await,
        Status::Ok
    );
}

#[tokio::test]
async fn e2e_webhooks_protocols_a_through_e_return_200() {
    let server = PaymobMockServer::start().await;
    let rocket = tracked_rocket(&server).await;

    let tx_vec = transaction_processed_192036465();
    let proto_a = rocket
        .post(format!(
            "/webhooks/transaction?hmac={}",
            tx_vec.expected_hmac_hex
        ))
        .header(ContentType::JSON)
        .body(tx_vec.payload_or_query)
        .dispatch()
        .await
        .status();
    assert_eq!(proto_a, Status::Ok);

    let redir_vec = transaction_response_316004();
    let proto_b = rocket
        .get(format!("/webhooks/redirect?{}", redir_vec.payload_or_query))
        .dispatch()
        .await
        .status();
    assert_eq!(proto_b, Status::Ok);

    let tok_vec = card_token_15978654();
    let proto_c = rocket
        .post(format!(
            "/webhooks/card-token?hmac={}",
            tok_vec.expected_hmac_hex
        ))
        .header(ContentType::JSON)
        .body(tok_vec.payload_or_query)
        .dispatch()
        .await
        .status();
    assert_eq!(proto_c, Status::Ok);

    let sub_vec = subscription_1264();
    let proto_d = rocket
        .post("/webhooks/subscription")
        .header(ContentType::JSON)
        .body(sub_vec.payload_or_query)
        .dispatch()
        .await
        .status();
    assert_eq!(proto_d, Status::Ok);

    let proto_e = post_json(
        &rocket,
        "/webhooks/payouts",
        &json!({ "transaction_id": "tx_e1", "disbursement_status": "successful", "amount": 200 }),
    )
    .await;
    assert_eq!(proto_e, Status::Ok);
}

// ---------------------------------------------------------------------------
// Boundary Condition Tests
// ---------------------------------------------------------------------------

#[test]
fn boundary_amount_zero_one_and_u64_max_overflow() {
    assert_eq!(MinorUnitAmount::new(0).as_u64(), 0);
    assert_eq!(MinorUnitAmount::new(1).as_u64(), 1);
    assert!(matches!(
        RefundParams::try_new(100, 0),
        Err(PaymobError::ValidationError { .. })
    ));
    assert!(RefundParams::try_new(100, 1).is_ok());

    let max = MinorUnitAmount::new(u64::MAX);
    assert!(matches!(
        max.checked_add(MinorUnitAmount::new(1)),
        Err(PaymobError::ValidationError { .. })
    ));
    assert!(matches!(
        max.checked_mul(2),
        Err(PaymobError::ValidationError { .. })
    ));
}

#[tokio::test]
async fn boundary_bulk_disbursements_0_1_1000_1001_items() {
    let server = PaymobMockServer::start().await;
    mount_payouts(
        &server,
        "POST",
        "/disburse/api/v1/disburse/bulk_transaction",
        200,
        json!({ "status": "ok", "results": [] }),
    )
    .await;
    let client = build_test_client(&server);
    let svc = client.payouts().cashin();

    let empty = BulkDisbursementParams::new(vec![]);
    assert!(matches!(
        svc.bulk(empty).await,
        Err(PaymobError::ValidationError { .. })
    ));

    let one = BulkDisbursementParams::new(vec![sample_bulk_item(1)]);
    assert!(svc.bulk(one).await.is_ok());

    let thousand: Vec<_> = (0..1_000).map(sample_bulk_item).collect();
    assert!(
        svc.bulk(BulkDisbursementParams::new(thousand))
            .await
            .is_ok()
    );

    let over: Vec<_> = (0..1_001).map(sample_bulk_item).collect();
    assert!(matches!(
        svc.bulk(BulkDisbursementParams::new(over)).await,
        Err(PaymobError::ValidationError { .. })
    ));
}

#[tokio::test]
async fn boundary_inquiry_ids_0_1_500_501() {
    let server = PaymobMockServer::start().await;
    mount_payouts(
        &server,
        "POST",
        "/api/secure/transaction/inquire/",
        200,
        json!({ "results": [] }),
    )
    .await;
    let client = build_test_client(&server);
    let svc = client.payouts().inquiries();

    assert!(matches!(
        svc.transactions(TransactionInquiryParams::new(vec![]))
            .await,
        Err(PaymobError::ValidationError { .. })
    ));

    for count in [1usize, 500, 501] {
        let ids = (0..count).map(|i| format!("tx_{i}")).collect();
        assert!(
            svc.transactions(TransactionInquiryParams::new(ids))
                .await
                .is_ok()
        );
    }
}

#[tokio::test]
async fn boundary_bank_transfer_proof_sizes_0_max_and_over() {
    let server = PaymobMockServer::start().await;
    mount_payouts(
        &server,
        "POST",
        "/api/secure/topup/request/",
        200,
        json!({ "id": 12, "status": "pending" }),
    )
    .await;
    let client = build_test_client(&server);
    let svc = client.payouts().topups();

    assert!(matches!(
        svc.from_bank_transfer(sample_topup_params(0)).await,
        Err(PaymobError::ValidationError { .. })
    ));
    assert_eq!(MAX_TOPUP_PROOF_BYTES, 2_936_012);
    assert!(
        svc.from_bank_transfer(sample_topup_params(2_936_012))
            .await
            .is_ok()
    );
    assert!(matches!(
        svc.from_bank_transfer(sample_topup_params(2_936_013)).await,
        Err(PaymobError::ValidationError { .. })
    ));
}

#[test]
fn boundary_split_payments_cards_and_bps_not_10000() {
    assert!(matches!(
        SplitPaymentConfig::new(vec![]),
        Err(PaymobError::ValidationError { .. })
    ));
    assert!(SplitPaymentConfig::new(vec![SplitCardPortion::new(1_000)]).is_ok());
    assert!(SplitPaymentConfig::new(vec![SplitCardPortion::new(1_000); 3]).is_ok());
    assert!(matches!(
        SplitPaymentConfig::new(vec![SplitCardPortion::new(1_000); 4]),
        Err(PaymobError::ValidationError { .. })
    ));

    let under_bps = SplitDescription::new(vec![SplitRecipientRule::percentage_bps("s1", 9_999)]);
    assert!(under_bps.is_ok());
    assert_ne!(
        under_bps
            .expect("valid")
            .total_percentage_bps()
            .expect("bps"),
        10_000
    );
    assert!(matches!(
        SplitDescription::new(vec![
            SplitRecipientRule::percentage_bps("s1", 6_000),
            SplitRecipientRule::percentage_bps("s2", 4_001),
        ]),
        Err(PaymobError::ValidationError { .. })
    ));
}

#[test]
fn boundary_sandbox_guard_credential_age_24_25_30_days() {
    let day_24 = SandboxGuard::check_constraints(&SandboxCheckRequest {
        is_sandbox: true,
        credential_age_days: 24,
        channel: SandboxPaymentChannel::Card,
    });
    assert!(day_24.is_ok() && day_24.warnings.is_empty());

    let day_25 = SandboxGuard::check_constraints(&SandboxCheckRequest {
        is_sandbox: true,
        credential_age_days: 25,
        channel: SandboxPaymentChannel::Card,
    });
    assert!(day_25.is_ok());
    assert_eq!(
        day_25.warnings,
        vec![SandboxWarning::CredentialExpiringSoon {
            age_days: 25,
            days_remaining: 5,
        }]
    );

    let day_30 = SandboxGuard::check_constraints(&SandboxCheckRequest {
        is_sandbox: true,
        credential_age_days: 30,
        channel: SandboxPaymentChannel::Card,
    });
    assert!(!day_30.is_ok());
    assert_eq!(
        day_30.errors,
        vec![SandboxConstraintError::CredentialExpired { age_days: 30 }]
    );
}

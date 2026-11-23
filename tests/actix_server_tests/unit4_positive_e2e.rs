#![forbid(unsafe_code)]
//! Unit 4a: Positive E2E Integration Tests across all 14 services and Protocols A–E.

use actix_web::{App, http::StatusCode, test};
use serde_json::{Value, json};
use some_paymob::prelude::*;

use crate::actix_server::configure_app;
use crate::helpers::{build_test_state, mount_accept, mount_intention_ok, mount_payouts};
use crate::init_actix_app;

#[actix_rt::test]
async fn test_health_and_sandbox_check_ok() {
    let mock = PaymobMockServer::start().await;
    let state = build_test_state(&mock);
    let app = init_actix_app!(state);

    let req = test::TestRequest::get().uri("/health").to_request();
    assert_eq!(test::call_service(&app, req).await.status(), StatusCode::OK);

    let sb_req = test::TestRequest::post()
        .uri("/sandbox/check")
        .set_json(json!({ "is_sandbox": true, "credential_age_days": 10, "channel": "card" }))
        .to_request();
    assert_eq!(
        test::call_service(&app, sb_req).await.status(),
        StatusCode::OK
    );
}

#[actix_rt::test]
async fn test_intentions_and_checkout_widgets_ok() {
    let mock = PaymobMockServer::start().await;
    mount_intention_ok(&mock).await;
    let state = build_test_state(&mock);
    let app = init_actix_app!(state);

    let req = test::TestRequest::post()
        .uri("/intentions")
        .set_json(json!({
            "amount_cents": 15000,
            "currency": "EGP",
            "payment_methods": [12345],
            "billing_data": { "phone_number": "+201012345678", "first_name": "Ali" }
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["client_secret"], "[REDACTED]");
}

#[actix_rt::test]
async fn test_pixel_and_affordability_configs_ok() {
    let mock = PaymobMockServer::start().await;
    let state = build_test_state(&mock);
    let app = init_actix_app!(state);

    let px_req = test::TestRequest::post()
        .uri("/checkout/pixel")
        .set_json(json!({
            "public_key": "egy_pk_test_123456",
            "client_secret": "egy_csk_test_secret",
            "show_save_card": true
        }))
        .to_request();
    assert_eq!(
        test::call_service(&app, px_req).await.status(),
        StatusCode::OK
    );

    let af_req = test::TestRequest::post()
        .uri("/checkout/affordability")
        .set_json(json!({
            "public_key": "egy_pk_test_123456",
            "amount_cents": 50000,
            "currency": "EGP",
            "tenure_months": 6
        }))
        .to_request();
    assert_eq!(
        test::call_service(&app, af_req).await.status(),
        StatusCode::OK
    );
}

#[actix_rt::test]
async fn test_legacy_v2_three_step_checkout_ok() {
    let mock = PaymobMockServer::start().await;
    mock.mount_accept_auth_sequence(&["jwt_tok_123"]).await;
    mount_accept(
        &mock,
        ("POST", "/api/ecommerce/orders"),
        201,
        json!({ "id": 9001, "amount_cents": 10000, "currency": "EGP" }),
    )
    .await;
    mount_accept(
        &mock,
        ("POST", "/api/acceptance/payment_keys"),
        201,
        json!({ "token": "pay_key_xyz" }),
    )
    .await;
    let state = build_test_state(&mock);
    let app = init_actix_app!(state);

    let req = test::TestRequest::post()
        .uri("/legacy/checkout")
        .set_json(json!({
            "amount_cents": 10000, "currency": "EGP", "integration_id": 111, "iframe_id": 222,
            "first_name": "Sara", "last_name": "Kamal", "email": "sara@example.com", "phone_number": "+201099998888"
        }))
        .to_request();
    assert_eq!(
        test::call_service(&app, req).await.status(),
        StatusCode::CREATED
    );
}

#[actix_rt::test]
async fn test_manage_refund_void_capture_ok() {
    let mock = PaymobMockServer::start().await;
    let tx_json = json!({
        "id": 7001, "success": true, "pending": false, "amount_cents": 5000,
        "is_refund": true, "is_void": true, "is_capture": true, "is_refunded": true, "is_voided": true
    });
    mount_accept(
        &mock,
        ("POST", "/api/acceptance/void_refund/refund"),
        200,
        tx_json.clone(),
    )
    .await;
    mount_accept(
        &mock,
        ("POST", "/api/acceptance/void_refund/void"),
        200,
        tx_json.clone(),
    )
    .await;
    mount_accept(&mock, ("POST", "/api/acceptance/capture"), 200, tx_json).await;
    let state = build_test_state(&mock);
    let app = init_actix_app!(state);

    for (uri, payload) in [
        (
            "/manage/refund",
            json!({ "transaction_id": 7001, "amount_cents": 5000 }),
        ),
        ("/manage/void", json!({ "transaction_id": 7001 })),
        (
            "/manage/capture",
            json!({ "transaction_id": 7001, "amount_cents": 5000 }),
        ),
    ] {
        let req = test::TestRequest::post()
            .uri(uri)
            .set_json(payload)
            .to_request();
        assert_eq!(test::call_service(&app, req).await.status(), StatusCode::OK);
    }
}

#[actix_rt::test]
async fn test_inquiries_and_quicklinks_splits_ok() {
    let mock = PaymobMockServer::start().await;
    mock.mount_accept_auth_sequence(&["jwt_inq_1"]).await;
    mount_accept(
        &mock,
        ("GET", "/api/acceptance/transactions/7001"),
        200,
        json!({
            "id": 7001, "success": true, "pending": false, "amount_cents": 5000, "currency": "EGP"
        }),
    )
    .await;
    let state = build_test_state(&mock);
    let app = init_actix_app!(state);

    let req = test::TestRequest::get()
        .uri("/inquiries/transactions/7001")
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status(), StatusCode::OK);

    let sp_req = test::TestRequest::post()
        .uri("/splits/validate-and-quote")
        .set_json(json!({
            "total_amount_cents": 10000,
            "recipients": [
                { "recipient_id": "m_1", "percentage_bps": 6000 },
                { "recipient_id": "m_2", "percentage_bps": 4000 }
            ],
            "cards": [{ "amount_cents": 6000 }, { "amount_cents": 4000 }],
            "fixed_fee_cents": 250
        }))
        .to_request();
    assert_eq!(
        test::call_service(&app, sp_req).await.status(),
        StatusCode::OK
    );
}

#[actix_rt::test]
async fn test_saved_cards_subscriptions_and_payouts_ok() {
    let mock = PaymobMockServer::start().await;
    mock.mount_accept_auth_sequence(&["jwt_sub_1"]).await;
    mock.mount_payouts_oauth("acc_tok_1", Some("ref_tok_1"), 3600)
        .await;
    mount_accept(
        &mock,
        ("GET", "/api/acceptance/subscription-plans"),
        200,
        json!({ "count": 1, "results": [{ "id": 10, "name": "Pro", "frequency": 30, "integration": 111, "is_active": true }] }),
    )
    .await;
    mount_payouts(
        &mock,
        ("GET", "/api/secure/budget/inquire/"),
        200,
        json!({ "current_budget": "Your current budget is 500.00 LE" }),
    )
    .await;
    let state = build_test_state(&mock);
    let app = init_actix_app!(state);

    let p_req = test::TestRequest::get()
        .uri("/subscriptions/plans")
        .to_request();
    assert_eq!(
        test::call_service(&app, p_req).await.status(),
        StatusCode::OK
    );

    let b_req = test::TestRequest::get()
        .uri("/payouts/inquiries/budget")
        .to_request();
    assert_eq!(
        test::call_service(&app, b_req).await.status(),
        StatusCode::OK
    );
}

#[actix_rt::test]
async fn test_onboarding_and_unified_adapter_ok() {
    let mock = PaymobMockServer::start().await;
    mount_intention_ok(&mock).await;
    mount_accept(
        &mock,
        ("GET", "/api/onboarding/merchant/987654"),
        200,
        json!({ "paymob_mid": 987654, "status": "approved", "is_live": true }),
    )
    .await;
    let state = build_test_state(&mock);
    let app = init_actix_app!(state);

    let onb_req = test::TestRequest::get()
        .uri("/onboarding/flow/merchants/987654")
        .to_request();
    assert_eq!(
        test::call_service(&app, onb_req).await.status(),
        StatusCode::OK
    );

    let uni_req = test::TestRequest::post()
        .uri("/unified/sessions")
        .set_json(json!({
            "amount_cents": 15000, "currency": "EGP", "payment_methods": ["4097558"],
            "customer_phone": "+201012345678", "customer_email": "ali@example.com"
        }))
        .to_request();
    assert_eq!(
        test::call_service(&app, uni_req).await.status(),
        StatusCode::CREATED
    );
}

#[actix_rt::test]
async fn test_webhooks_all_5_protocols_and_replay_conflict() {
    let mock = PaymobMockServer::start().await;
    let state = build_test_state(&mock);
    let app = init_actix_app!(state);

    let pa = transaction_processed_192036465();
    let pc = card_token_15978654();
    let pd = subscription_1264();
    for (uri, body) in [
        (
            format!("/webhooks/paymob?hmac={}", pa.expected_hmac_hex),
            pa.payload_or_query,
        ),
        (
            format!("/webhooks/paymob?hmac={}", pc.expected_hmac_hex),
            pc.payload_or_query,
        ),
        ("/webhooks/paymob".to_owned(), pd.payload_or_query),
    ] {
        let req = test::TestRequest::post()
            .uri(&uri)
            .set_payload(body)
            .to_request();
        assert_eq!(test::call_service(&app, req).await.status(), StatusCode::OK);
    }

    // WHK-01: Unsigned Protocol E fails closed (500) when no payouts HMAC secret is configured.
    let proto_e_req = test::TestRequest::post()
        .uri("/webhooks/paymob")
        .set_payload(
            r#"{"topup_id":"top_1","amount_cents":1000,"currency":"EGP","status":"Approved"}"#,
        )
        .to_request();
    assert_eq!(
        test::call_service(&app, proto_e_req).await.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );

    let pb = transaction_response_316004();
    let uri = format!("/webhooks/paymob/redirect?{}", pb.payload_or_query);
    let req1 = test::TestRequest::get().uri(&uri).to_request();
    assert_eq!(
        test::call_service(&app, req1).await.status(),
        StatusCode::OK
    );
    let req2 = test::TestRequest::get().uri(&uri).to_request();
    assert_eq!(
        test::call_service(&app, req2).await.status(),
        StatusCode::CONFLICT
    );
}

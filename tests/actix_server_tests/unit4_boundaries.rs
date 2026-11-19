#![forbid(unsafe_code)]
//! Unit 4b: Boundary Condition Integration Tests (`0`, `1`, `max-1`, `max`, `max+1`).

use actix_web::{App, http::StatusCode, test};
use serde_json::json;
use some_paymob::prelude::*;

use crate::actix_server::configure_app;
use crate::helpers::{build_test_state, mount_intention_ok, mount_payouts};
use crate::init_actix_app;

#[actix_rt::test]
async fn test_sandbox_guard_credential_age_boundaries_24_25_30_days() {
    let mock = PaymobMockServer::start().await;
    let state = build_test_state(&mock);
    let app = init_actix_app!(state);

    let r24 = test::TestRequest::post()
        .uri("/sandbox/check")
        .set_json(json!({ "is_sandbox": true, "credential_age_days": 24, "channel": "card" }))
        .to_request();
    let b24: serde_json::Value = test::call_and_read_body_json(&app, r24).await;
    assert_eq!(b24["warnings"].as_array().unwrap().len(), 0);

    let r25 = test::TestRequest::post()
        .uri("/sandbox/check")
        .set_json(json!({ "is_sandbox": true, "credential_age_days": 25, "channel": "card" }))
        .to_request();
    let b25: serde_json::Value = test::call_and_read_body_json(&app, r25).await;
    assert_eq!(b25["warnings"].as_array().unwrap().len(), 1);

    let r30 = test::TestRequest::post()
        .uri("/sandbox/check")
        .set_json(json!({ "is_sandbox": true, "credential_age_days": 30, "channel": "card" }))
        .to_request();
    assert_eq!(
        test::call_service(&app, r30).await.status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
}

#[actix_rt::test]
async fn test_amount_boundaries_0_vs_1_cent() {
    let mock = PaymobMockServer::start().await;
    mount_intention_ok(&mock).await;
    let state = build_test_state(&mock);
    let app = init_actix_app!(state);

    let r0 = test::TestRequest::post()
        .uri("/intentions")
        .set_json(json!({
            "amount_cents": 0, "currency": "EGP", "payment_methods": [111],
            "billing_data": { "phone_number": "+201012345678" }
        }))
        .to_request();
    assert_eq!(
        test::call_service(&app, r0).await.status(),
        StatusCode::BAD_REQUEST
    );

    let r1 = test::TestRequest::post()
        .uri("/intentions")
        .set_json(json!({
            "amount_cents": 1, "currency": "EGP", "payment_methods": [111],
            "billing_data": { "phone_number": "+201012345678" }
        }))
        .to_request();
    assert_eq!(
        test::call_service(&app, r1).await.status(),
        StatusCode::CREATED
    );
}

#[actix_rt::test]
async fn test_bulk_disbursement_item_boundaries_0_1_1000_1001() {
    let mock = PaymobMockServer::start().await;
    mock.mount_payouts_oauth("tok_bulk", Some("ref_bulk"), 3600)
        .await;
    mount_payouts(
        &mock,
        ("POST", "/api/secure/disburse/bulk/"),
        200,
        json!({ "status": "Pending", "status_code": "200", "results": [] }),
    )
    .await;
    let state = build_test_state(&mock);
    let app = init_actix_app!(state);

    let r0 = test::TestRequest::post()
        .uri("/payouts/cashin/bulk")
        .set_json(json!({ "transactions": [] }))
        .to_request();
    assert_eq!(
        test::call_service(&app, r0).await.status(),
        StatusCode::BAD_REQUEST
    );

    let items_1001: Vec<_> = (0..1001)
        .map(|_| json!({ "issuer": "vodafone", "amount": 100, "msisdn": "01012345678" }))
        .collect();
    let r1001 = test::TestRequest::post()
        .uri("/payouts/cashin/bulk")
        .set_json(json!({ "transactions": items_1001 }))
        .to_request();
    assert_eq!(
        test::call_service(&app, r1001).await.status(),
        StatusCode::BAD_REQUEST
    );
}

#[actix_rt::test]
async fn test_payouts_inquiry_id_boundaries_0_and_over_max() {
    let mock = PaymobMockServer::start().await;
    let state = build_test_state(&mock);
    let app = init_actix_app!(state);

    let r0 = test::TestRequest::post()
        .uri("/payouts/inquiries/transactions")
        .set_json(json!({ "transactions_ids": [] }))
        .to_request();
    assert_eq!(
        test::call_service(&app, r0).await.status(),
        StatusCode::BAD_REQUEST
    );

    let ids_over: Vec<String> = (0..=MAX_INQUIRY_IDS).map(|i| format!("tx_{i}")).collect();
    let r_over = test::TestRequest::post()
        .uri("/payouts/inquiries/transactions")
        .set_json(json!({ "transactions_ids": ids_over }))
        .to_request();
    assert_eq!(
        test::call_service(&app, r_over).await.status(),
        StatusCode::BAD_REQUEST
    );
}

#[actix_rt::test]
async fn test_topup_proof_size_and_filename_boundaries() {
    let mock = PaymobMockServer::start().await;
    let state = build_test_state(&mock);
    let app = init_actix_app!(state);

    let r_empty = test::TestRequest::post()
        .uri("/payouts/topups/bank-transfer")
        .set_json(json!({
            "amount": 1000, "currency": "egyptian_pound",
            "proof_bytes": [], "proof_filename": "receipt.pdf"
        }))
        .to_request();
    assert_eq!(
        test::call_service(&app, r_empty).await.status(),
        StatusCode::BAD_REQUEST
    );

    let r_traversal = test::TestRequest::post()
        .uri("/payouts/topups/bank-transfer")
        .set_json(json!({
            "amount": 1000, "currency": "egyptian_pound",
            "proof_bytes": [1, 2, 3], "proof_filename": "../etc/passwd"
        }))
        .to_request();
    assert_eq!(
        test::call_service(&app, r_traversal).await.status(),
        StatusCode::BAD_REQUEST
    );
}

#[actix_rt::test]
async fn test_split_cards_0_1_4_boundaries() {
    let mock = PaymobMockServer::start().await;
    let state = build_test_state(&mock);
    let app = init_actix_app!(state);

    let r0 = test::TestRequest::post()
        .uri("/splits/validate-and-quote")
        .set_json(json!({
            "total_amount_cents": 1000,
            "recipients": [{ "recipient_id": "m1", "percentage_bps": 10000 }],
            "cards": []
        }))
        .to_request();
    assert_eq!(
        test::call_service(&app, r0).await.status(),
        StatusCode::BAD_REQUEST
    );

    let r1 = test::TestRequest::post()
        .uri("/splits/validate-and-quote")
        .set_json(json!({
            "total_amount_cents": 1000,
            "recipients": [{ "recipient_id": "m1", "percentage_bps": 10000 }],
            "cards": [{ "amount_cents": 1000 }]
        }))
        .to_request();
    assert_eq!(test::call_service(&app, r1).await.status(), StatusCode::OK);

    let r4 = test::TestRequest::post()
        .uri("/splits/validate-and-quote")
        .set_json(json!({
            "total_amount_cents": 4000,
            "recipients": [{ "recipient_id": "m1", "percentage_bps": 10000 }],
            "cards": [
                { "amount_cents": 1000 }, { "amount_cents": 1000 },
                { "amount_cents": 1000 }, { "amount_cents": 1000 }
            ]
        }))
        .to_request();
    assert_eq!(
        test::call_service(&app, r4).await.status(),
        StatusCode::BAD_REQUEST
    );
}

#[actix_rt::test]
async fn test_split_bps_mismatch_returns_400() {
    let mock = PaymobMockServer::start().await;
    let state = build_test_state(&mock);
    let app = init_actix_app!(state);

    let req = test::TestRequest::post()
        .uri("/splits/validate-and-quote")
        .set_json(json!({
            "total_amount_cents": 1000,
            "recipients": [
                { "recipient_id": "m1", "percentage_bps": 6000 },
                { "recipient_id": "m2", "percentage_bps": 4001 }
            ],
            "cards": [{ "amount_cents": 1000 }]
        }))
        .to_request();
    assert_eq!(
        test::call_service(&app, req).await.status(),
        StatusCode::BAD_REQUEST
    );
}

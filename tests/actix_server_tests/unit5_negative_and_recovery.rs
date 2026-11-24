#![forbid(unsafe_code)]
//! Unit 5: Negative Validation, Security/Redaction, and Error Recovery Integration Tests.

use actix_web::{App, http::StatusCode, test};
use serde_json::json;
use some_paymob::prelude::*;
use some_paymob::test_utils::{OFFICIAL_TX_192036465_JSON, SAMPLE_TX_192036465_HMAC};

use crate::actix_server::configure_app;
use crate::helpers::{build_test_state, mount_accept};
use crate::init_actix_app;

#[actix_rt::test]
async fn test_negative_moto_cvc_mismatch_and_tampered_webhooks() {
    let mock = PaymobMockServer::start().await;
    let state = build_test_state(&mock);
    let app = init_actix_app!(state);

    let moto_req = test::TestRequest::post()
        .uri("/saved-cards/pay/mit")
        .set_json(json!({
            "payment_token": "pay_tok_1",
            "saved_token": "saved_tok_1",
            "use_cvc_with_moto": true
        }))
        .to_request();
    assert_eq!(
        test::call_service(&app, moto_req).await.status(),
        StatusCode::BAD_REQUEST
    );

    let bad_hex = test::TestRequest::post()
        .uri("/webhooks/paymob?hmac=zzzz_not_hex")
        .set_payload(OFFICIAL_TX_192036465_JSON)
        .to_request();
    assert_eq!(
        test::call_service(&app, bad_hex).await.status(),
        StatusCode::UNAUTHORIZED
    );

    let zeros_hmac = "0".repeat(128);
    let tampered = test::TestRequest::post()
        .uri(&format!("/webhooks/paymob?hmac={zeros_hmac}"))
        .set_payload(OFFICIAL_TX_192036465_JSON)
        .to_request();
    assert_eq!(
        test::call_service(&app, tampered).await.status(),
        StatusCode::UNAUTHORIZED
    );
}

#[actix_rt::test]
async fn test_duplicate_webhook_replay_returns_409_conflict() {
    let mock = PaymobMockServer::start().await;
    let state = build_test_state(&mock);
    let app = init_actix_app!(state);
    let uri = format!("/webhooks/paymob?hmac={SAMPLE_TX_192036465_HMAC}");

    let req1 = test::TestRequest::post()
        .uri(&uri)
        .set_payload(OFFICIAL_TX_192036465_JSON)
        .to_request();
    assert_eq!(
        test::call_service(&app, req1).await.status(),
        StatusCode::OK
    );

    let req2 = test::TestRequest::post()
        .uri(&uri)
        .set_payload(OFFICIAL_TX_192036465_JSON)
        .to_request();
    assert_eq!(
        test::call_service(&app, req2).await.status(),
        StatusCode::CONFLICT
    );
}

#[actix_rt::test]
async fn test_negative_payout_issuer_and_national_id_validation() {
    let mock = PaymobMockServer::start().await;
    let state = build_test_state(&mock);
    let app = init_actix_app!(state);

    let bad_issuer = test::TestRequest::post()
        .uri("/payouts/cashin/wallet/unknown_issuer")
        .set_json(json!({ "amount": "100.00", "msisdn": "01012345678" }))
        .to_request();
    assert_eq!(
        test::call_service(&app, bad_issuer).await.status(),
        StatusCode::BAD_REQUEST
    );

    let bad_nid = test::TestRequest::post()
        .uri("/payouts/cashin/egyptian-post")
        .set_json(json!({
            "amount": "100.00", "msisdn": "01012345678",
            "full_name": "Test User", "national_id": "12345"
        }))
        .to_request();
    assert_eq!(
        test::call_service(&app, bad_nid).await.status(),
        StatusCode::BAD_REQUEST
    );
}

#[actix_rt::test]
async fn test_over_refund_and_environment_mismatch_return_422() {
    let mock = PaymobMockServer::start().await;
    mount_accept(
        &mock,
        ("POST", "/api/acceptance/void_refund/refund"),
        400,
        json!({ "detail": "Amount exceeds the permissible refund amount" }),
    )
    .await;
    let state = build_test_state(&mock);
    let app = init_actix_app!(state);

    let ref_req = test::TestRequest::post()
        .uri("/manage/refund")
        .set_json(json!({ "transaction_id": 7001, "amount_cents": 999999 }))
        .to_request();
    assert_eq!(
        test::call_service(&app, ref_req).await.status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );

    let env_req = test::TestRequest::post()
        .uri("/intentions")
        .set_json(json!({
            "amount_cents": 1000, "currency": "EGP", "payment_methods": [111],
            "integration_mode": "live",
            "billing_data": { "phone_number": "+201012345678" }
        }))
        .to_request();
    assert_eq!(
        test::call_service(&app, env_req).await.status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
}

#[actix_rt::test]
async fn test_regime2_401_jwt_eviction_and_single_flight_retry() {
    let mock = PaymobMockServer::start().await;
    mock.mount_accept_auth_sequence(&["stale_jwt_1", "fresh_jwt_2"])
        .await;
    mock.mount_jwt_expiry_then_ok(JwtExpiryMockConfig {
        http_method: "GET",
        endpoint_path: "/api/acceptance/transactions/8888",
        fail_count: 1,
        ok_body: json!({
            "id": 8888, "success": true, "pending": false, "amount_cents": 3000,
            "currency": "EGP", "is_auth": false, "is_capture": false,
            "is_voided": false, "is_refunded": false, "is_3d_secure": true
        }),
    })
    .await;
    let state = build_test_state(&mock);
    let app = init_actix_app!(state);

    let req = test::TestRequest::get()
        .uri("/inquiries/transactions/8888")
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status(), StatusCode::OK);
}

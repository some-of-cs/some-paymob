#![forbid(unsafe_code)]
//! Boundary condition integration tests for `examples/axum_server.rs` (`US-axum` Unit 4).

use axum::Router;
use axum::http::{Method, StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use serde_json::{Value, json};

use super::common::{
    mount_accept_post, mount_payouts_json, mount_payouts_token, post_status,
    sample_intention_response, send_json, setup_test_app,
};

async fn assert_post_cases<F>(
    router: &Router,
    uri: &str,
    cases: &[(usize, StatusCode)],
    build_body: F,
) where
    F: Fn(usize) -> Value,
{
    for &(count, expected) in cases {
        assert_eq!(
            post_status(router, uri, build_body(count)).await,
            expected,
            "unexpected status for {uri} with count={count}"
        );
    }
}

#[tokio::test]
async fn boundary_amount_zero_one_and_u64_max_overflow() {
    let (server, router, _state) = setup_test_app().await;
    mount_accept_post(&server, "/v1/intention/", 201, sample_intention_response()).await;
    let zero = json!({ "amount": 0, "currency": "EGP", "payment_methods": [4097558] });
    assert_eq!(
        post_status(&router, "/intentions", zero).await,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let one = json!({ "amount": 1, "currency": "EGP", "payment_methods": [4097558] });
    let one_st = post_status(&router, "/intentions", one).await;
    assert!(one_st == StatusCode::CREATED || one_st == StatusCode::OK);
    let max = json!({
        "amount_cents": u64::MAX,
        "convenience_fee": {
            "mode": { "FixedCents": 1 },
            "is_refundable": false,
            "card_rule": "Uniform"
        }
    });
    assert_eq!(
        post_status(&router, "/splits/validate-and-quote", max).await,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn boundary_bulk_disbursements_0_1_1000_1001() {
    let (server, router, _state) = setup_test_app().await;
    mount_payouts_token(&server, "po_bulk_1").await;
    mount_payouts_json(
        &server,
        "POST",
        "/disburse/api/v1/disburse/bulk_transaction",
        200,
        json!({ "status": "ok", "results": [] }),
    )
    .await;
    assert_post_cases(
        &router,
        "/payouts/cashin/bulk",
        &[
            (0, StatusCode::BAD_REQUEST),
            (1, StatusCode::OK),
            (1_000, StatusCode::OK),
            (1_001, StatusCode::BAD_REQUEST),
        ],
        |n| {
            let items: Vec<Value> = (0..n)
                .map(|i| {
                    json!({ "issuer": "vodafone", "amount": 100, "msisdn": format!("010{i:08}") })
                })
                .collect();
            json!({ "transactions": items })
        },
    )
    .await;
}

#[tokio::test]
async fn boundary_payout_inquiry_ids_0_1_500_501() {
    let (server, router, _state) = setup_test_app().await;
    mount_payouts_token(&server, "po_inq_1").await;
    mount_payouts_json(
        &server,
        "POST",
        "/disburse/api/v1/bulk_transaction/inquire",
        200,
        json!({ "results": [] }),
    )
    .await;
    assert_post_cases(
        &router,
        "/payouts/inquiries/transactions",
        &[
            (0, StatusCode::BAD_REQUEST),
            (1, StatusCode::OK),
            (1_000, StatusCode::OK),
            (1_001, StatusCode::BAD_REQUEST),
        ],
        |n| {
            let ids: Vec<String> = (0..n).map(|i| format!("tx_{i}")).collect();
            json!({ "transactions_ids": ids, "is_bulk": true })
        },
    )
    .await;
}

#[tokio::test]
async fn boundary_bank_transfer_proof_size_0_2936012_2936013() {
    let (server, router, _state) = setup_test_app().await;
    mount_payouts_token(&server, "po_top_1").await;
    mount_payouts_json(
        &server,
        "POST",
        "/api/secure/topup/request/",
        200,
        json!({ "status": "pending", "id": 102 }),
    )
    .await;
    assert_post_cases(
        &router,
        "/payouts/topups/bank-transfer",
        &[
            (0, StatusCode::BAD_REQUEST),
            (2_936_012, StatusCode::OK),
            (2_936_013, StatusCode::BAD_REQUEST),
        ],
        |bytes| {
            json!({
                "amount": 1000,
                "currency": "egyptian_pound",
                "to_attach_proof_base64": BASE64_STANDARD.encode(vec![b'a'; bytes]),
                "proof_filename": "receipt.pdf"
            })
        },
    )
    .await;
}

#[tokio::test]
async fn boundary_split_payments_cards_0_1_3_4_and_bps_not_10000() {
    let (_server, router, _state) = setup_test_app().await;
    let build_split = |cards: usize, bps: u16| -> Value {
        let card_list: Vec<Value> = (0..cards).map(|_| json!({ "amount_cents": 1000 })).collect();
        json!({
            "amount_cents": 10000,
            "split_description": { "recipients": [{ "recipient_id": "1", "percentage_bps": bps }] },
            "split_payment": { "cards": card_list }
        })
    };
    assert_post_cases(
        &router,
        "/splits/validate-and-quote",
        &[
            (0, StatusCode::UNPROCESSABLE_ENTITY),
            (1, StatusCode::OK),
            (3, StatusCode::OK),
            (4, StatusCode::UNPROCESSABLE_ENTITY),
        ],
        |cards| build_split(cards, 10_000),
    )
    .await;
    assert_eq!(
        post_status(&router, "/splits/validate-and-quote", build_split(1, 10_001)).await,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn boundary_sandbox_guard_credential_age_24_25_30() {
    let (_server, router, _state) = setup_test_app().await;
    let mk_req =
        |age: u64| json!({ "is_sandbox": true, "credential_age_days": age, "channel": "card" });
    let (st24, b24) = send_json(&router, Method::POST, "/sandbox/check", mk_req(24)).await;
    assert_eq!(st24, StatusCode::OK);
    assert!(b24["warnings"].as_array().is_none_or(Vec::is_empty));
    let (st25, b25) = send_json(&router, Method::POST, "/sandbox/check", mk_req(25)).await;
    assert_eq!(st25, StatusCode::OK);
    assert!(!b25["warnings"].as_array().is_none_or(Vec::is_empty));
    let (st30, _) = send_json(&router, Method::POST, "/sandbox/check", mk_req(30)).await;
    assert_eq!(st30, StatusCode::UNPROCESSABLE_ENTITY);
}

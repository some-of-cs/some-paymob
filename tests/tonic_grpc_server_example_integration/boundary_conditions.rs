#![forbid(unsafe_code)]
//! Boundary condition integration tests for `examples/tonic_grpc_server.rs`.

use serde_json::{Value, json};
use some_paymob::test_utils::{
    PaymobMockServer, SandboxCheckRequest, SandboxConstraintError, SandboxGuard,
    SandboxPaymentChannel, SandboxReport, SandboxWarning,
};
use some_paymob::{
    MAX_TOPUP_PROOF_BYTES, MinorUnitAmount, PaymobError, RefundParams, SplitCardPortion,
    SplitDescription, SplitPaymentConfig, SplitRecipientRule,
};
use tonic::Code;

use super::positive_helpers::{
    assert_rpc_code, assert_rpc_ok, build_grpc_service, bulk_items_json, inquiry_ids_json,
    topup_b64_json, topup_raw_json,
};
use super::positive_mocks_core::setup_manage_mocks;
use super::positive_mocks_recurring::{
    setup_payouts_cashin_mocks, setup_payouts_inquiries_and_topups_mocks,
};

/// Verifies amount boundaries at 0, 1, and `u64::MAX` overflow.
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
    assert_rpc_code(
        &service,
        "RefundTransaction",
        &zero_ref,
        Code::InvalidArgument,
    )
    .await;
    assert_rpc_ok(&service, "RefundTransaction", &one_ref).await;
}

/// Verifies bulk disbursement boundaries at 0, 1, 1,000, and 1,001 items.
#[tokio::test]
async fn boundary_bulk_disbursements_0_1_1000_1001_items() {
    let server = PaymobMockServer::start().await;
    setup_payouts_cashin_mocks(&server).await;
    let service = build_grpc_service(&server);
    assert_rpc_code(
        &service,
        "BulkCashin",
        &bulk_items_json(0),
        Code::InvalidArgument,
    )
    .await;
    assert_rpc_ok(&service, "BulkCashin", &bulk_items_json(1)).await;
    assert_rpc_ok(&service, "BulkCashin", &bulk_items_json(1_000)).await;
    assert_rpc_code(
        &service,
        "BulkCashin",
        &bulk_items_json(1_001),
        Code::InvalidArgument,
    )
    .await;
}

/// Verifies payouts inquiry ID batch boundaries at 0, 1, 500, 501, 1,000, and 1,001.
#[tokio::test]
async fn boundary_inquiry_ids_0_1_500_501() {
    let server = PaymobMockServer::start().await;
    setup_payouts_inquiries_and_topups_mocks(&server).await;
    let service = build_grpc_service(&server);
    let method = "InquirePayoutsTransactions";
    assert_rpc_code(
        &service,
        method,
        &inquiry_ids_json(0),
        Code::InvalidArgument,
    )
    .await;
    for count in [1usize, 500, 501, 1_000] {
        assert_rpc_ok(&service, method, &inquiry_ids_json(count)).await;
    }
    assert_rpc_code(
        &service,
        method,
        &inquiry_ids_json(1_001),
        Code::InvalidArgument,
    )
    .await;
}

/// Verifies bank transfer proof byte-size boundaries at 0, max, and over-limit.
#[tokio::test]
async fn boundary_bank_transfer_proof_sizes_0_max_and_over() {
    let server = PaymobMockServer::start().await;
    setup_payouts_inquiries_and_topups_mocks(&server).await;
    let service = build_grpc_service(&server);
    let method = "RequestBankTransferTopup";
    assert_eq!(MAX_TOPUP_PROOF_BYTES, 2_936_012);
    assert_rpc_code(&service, method, &topup_raw_json(0), Code::InvalidArgument).await;
    assert_rpc_ok(&service, method, &topup_raw_json(2_936_012)).await;
    assert_rpc_code(
        &service,
        method,
        &topup_raw_json(2_936_013),
        Code::InvalidArgument,
    )
    .await;
    let over_b64 = "A".repeat(MAX_TOPUP_PROOF_BYTES.div_ceil(3) * 4 + 4);
    assert_rpc_code(
        &service,
        method,
        &topup_b64_json(&over_b64),
        Code::InvalidArgument,
    )
    .await;
}

/// Verifies split payment card count (0, 1, 3, 4) and recipient bps boundaries.
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

/// Verifies `SandboxGuard` credential age boundaries at 24, 25, and 30 days.
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
    assert_rpc_code(
        &service,
        method,
        &sandbox_card_json(30),
        Code::FailedPrecondition,
    )
    .await;
}

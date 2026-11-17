#![forbid(unsafe_code)]
//! Story-level integration tests for `US-5.2.0` (Bulk Disbursements, Inquiries, Budget & Topups).

use some_paymob::core::auth::CachedToken;
use some_paymob::core::client::PaymobClient;
use some_paymob::core::config::ClientConfig;
use some_paymob::core::region::PaymobRegion;
use some_paymob::resources::payouts::{
    AcceptBalanceTopupParams, BankTransferTopupParams, BulkDisbursementItem,
    BulkDisbursementParams, DisburseIssuer, MAX_TOPUP_PROOF_BYTES, ReferenceInquiryParams,
    TopupInquiryParams, TransactionInquiryParams,
};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn seeded_client(base_url: &str) -> PaymobClient {
    let cfg = ClientConfig::builder()
        .region(PaymobRegion::Custom {
            accept_base_url: base_url.to_owned(),
            payouts_base_url: Some(base_url.to_owned()),
        })
        .build()
        .expect("valid config");
    let client = PaymobClient::new(cfg).expect("valid client");
    client
        .auth()
        .payouts_cache()
        .store(CachedToken::with_default_ttl("story-52-jwt", None));
    client
}

#[tokio::test]
async fn us_5_2_0_bulk_disbursement_and_inquiries() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/disburse/api/v1/disburse/bulk_transaction/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "ok",
            "results": [{"transaction_id": "tx_b1", "amount": 200}]
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/disburse/api/v1/bulk_transaction/inquire/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": [{"transaction_id": "tx_b1", "disbursement_status": "successful"}]
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(
            "/disburse/api/v1/bulk_transaction/inquire_by_reference/",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": [{"transaction_id": "tx_b1", "disbursement_status": "successful"}]
        })))
        .mount(&server)
        .await;

    let client = seeded_client(&server.uri());
    let bulk = client
        .payouts()
        .cashin()
        .bulk(
            BulkDisbursementParams::new(vec![BulkDisbursementItem {
                issuer: DisburseIssuer::Vodafone,
                amount: 200,
                msisdn: Some(String::from("01023456789")),
                full_name: Some(String::from("User")),
                bank_code: None,
                client_reference_id: Some(String::from("ref_b1")),
            }])
            .with_bank_transaction(false),
        )
        .await
        .unwrap();
    assert_eq!(bulk.results[0].transaction_id, "tx_b1");

    let tx_inq = client
        .payouts()
        .inquiries()
        .transactions(
            TransactionInquiryParams::new(vec![String::from("tx_b1")])
                .with_bulk(true)
                .with_bank_transactions(false),
        )
        .await
        .unwrap();
    assert_eq!(tx_inq.results[0].transaction_id, "tx_b1");

    let ref_inq = client
        .payouts()
        .inquiries()
        .by_reference(ReferenceInquiryParams::new(vec![String::from("ref_b1")]))
        .await
        .unwrap();
    assert_eq!(ref_inq.results[0].transaction_id, "tx_b1");
}

#[tokio::test]
async fn us_5_2_0_budget_and_topup_flows() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/secure/budget/inquire/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "current_budget": "Your current budget is 888.25 LE"
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/secure/topup/inquire/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "count": 1,
            "results": [{"id": 10, "amount": 500, "status": "approved"}]
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/secure/topup/request/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": 11,
            "amount": 500,
            "status": "pending",
            "type": "from_accept_balance"
        })))
        .mount(&server)
        .await;

    let client = seeded_client(&server.uri());
    let budget = client.payouts().inquiries().user_budget().await.unwrap();
    assert!(budget.current_budget.contains("888.25"));

    let topup_hist = client
        .payouts()
        .inquiries()
        .topup(TopupInquiryParams {
            page: Some(1),
            id: None,
        })
        .await
        .unwrap();
    assert_eq!(topup_hist.results[0].id, Some(10));

    let bank_topup = client
        .payouts()
        .topups()
        .from_bank_transfer(BankTransferTopupParams {
            amount: 500,
            currency: String::from("egyptian_pound"),
            to_attach_proof: vec![1u8; 64],
            proof_filename: String::from("receipt.pdf"),
            from_bank_name: Some(String::from("CIB")),
            reference_number: Some(String::from("REF-123")),
        })
        .await
        .unwrap();
    assert_eq!(bank_topup.status.as_deref(), Some("pending"));

    let accept_topup = client
        .payouts()
        .topups()
        .from_accept_balance(AcceptBalanceTopupParams::new(
            500,
            "egyptian_pound",
            "treasury_user",
        ))
        .await
        .unwrap();
    assert_eq!(accept_topup.id, Some(11));
    assert_eq!(MAX_TOPUP_PROOF_BYTES, 2_936_012);
}

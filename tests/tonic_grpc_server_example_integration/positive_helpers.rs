#![forbid(unsafe_code)]
//! Shared Tonic gRPC client, mock mounting, and payload helpers for Unit 4 tests.

use std::sync::Arc;

use http::uri::PathAndQuery;
use serde_json::{Value, json};
use some_paymob::core::auth::CachedToken;
use some_paymob::core::credentials::{
    ApiKey, HmacSecret, PartnerCredentials, PayoutsCredentials, PublicKey, SecretKey,
};
use some_paymob::test_utils::{
    JsonEndpointMockConfig, MockHost, PaymobMockServer, SAMPLE_HMAC_SECRET,
};
use some_paymob::webhooks::InMemoryWebhookDeduplicator;
use some_paymob::{ClientConfig, PaymobClient, PaymobWebhookEngine};
use tonic::client::Grpc;
use tonic::codec::ProstCodec;
use tonic::{Code, Request, Status};

use crate::tonic_grpc_server::proto::{JsonRpcRequest, JsonRpcResponse, PAYMOB_GRPC_SERVICE_NAME};
use crate::tonic_grpc_server::{PaymobGrpcService, build_grpc_server};

pub(super) fn build_test_client(server: &PaymobMockServer) -> PaymobClient {
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

pub(super) fn build_grpc_service(server: &PaymobMockServer) -> PaymobGrpcService {
    let client = Arc::new(build_test_client(server));
    let webhook_engine =
        Arc::new(PaymobWebhookEngine::new(SAMPLE_HMAC_SECRET).expect("valid webhook engine"));
    let deduplicator = Arc::new(InMemoryWebhookDeduplicator::new());
    PaymobGrpcService::new(client, webhook_engine, deduplicator)
}

pub(super) async fn call_rpc(
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

pub(super) async fn assert_rpc_ok(
    service: &PaymobGrpcService,
    method: &str,
    payload: &Value,
) -> Value {
    match call_rpc(service, method, payload).await {
        Ok(val) => val,
        Err(status) => panic!("expected Code::Ok for {method}, got {status:?}"),
    }
}

pub(super) async fn assert_rpc_code(
    service: &PaymobGrpcService,
    method: &str,
    payload: &Value,
    expected: Code,
) {
    let err = call_rpc(service, method, payload)
        .await
        .expect_err("expected gRPC error status");
    assert_eq!(
        err.code(),
        expected,
        "unexpected status for {method}: {err:?}"
    );
}

async fn mount_host(server: &PaymobMockServer, host: MockHost, route: (&str, &str, u16, Value)) {
    let (http_method, endpoint_path, status, body) = route;
    server
        .mount_json(JsonEndpointMockConfig {
            host,
            http_method,
            endpoint_path,
            status,
            body,
        })
        .await;
}

pub(super) async fn mount_accept(server: &PaymobMockServer, route: (&str, &str, u16, Value)) {
    mount_host(server, MockHost::Accept, route).await;
}

pub(super) async fn mount_payouts(server: &PaymobMockServer, route: (&str, &str, u16, Value)) {
    mount_host(server, MockHost::Payouts, route).await;
}

pub(super) fn sample_billing_json() -> Value {
    json!({
        "phone_number": "+201001234567",
        "first_name": "Maher",
        "last_name": "Aladdin",
        "email": "buyer@example.com",
        "city": "Cairo",
        "country": "EG"
    })
}

pub(super) fn sample_subscription_json(id: u64, state: &str) -> Value {
    json!({
        "id": id,
        "plan_id": 701,
        "state": state,
        "amount_cents": 20_000,
        "created_at": "2026-11-01T00:00:00Z"
    })
}

pub(super) fn sample_subscription_card_json(id: u64, is_primary: bool) -> Value {
    json!({
        "id": id,
        "token": "tok_sub_card_secret",
        "created_at": "2026-11-01T00:00:00Z",
        "is_primary": is_primary,
        "masked_pan": "xxxx-xxxx-xxxx-1111",
        "failed_attempts": 0
    })
}

pub(super) fn sample_subscription_tx_json(id: u64) -> Value {
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

pub(super) fn bulk_items_json(count: usize) -> Value {
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

pub(super) fn inquiry_ids_json(count: usize) -> Value {
    let ids: Vec<String> = (0..count).map(|i| format!("tx_{i}")).collect();
    json!({ "transactions_ids": ids })
}

pub(super) fn topup_raw_json(len: usize) -> Value {
    json!({
        "amount": 500,
        "currency": "egyptian_pound",
        "to_attach_proof": vec![1u8; len],
        "proof_filename": "receipt.pdf"
    })
}

pub(super) fn topup_b64_json(b64: &str) -> Value {
    json!({
        "amount": 500,
        "currency": "egyptian_pound",
        "proof_base64": b64,
        "proof_filename": "receipt.pdf"
    })
}

pub(super) async fn assert_non_wallet_cashin_rpcs(service: &PaymobGrpcService) {
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

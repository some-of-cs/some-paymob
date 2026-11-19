#![forbid(unsafe_code)]
//! Constant-time Webhooks (Protocols A-E + Replay Deduplication) & Unified Adapter unary RPCs.

use serde::{Deserialize, Serialize};
use some_paymob::{
    PaymentProvider, PayoutProvider, SubscriptionProvider, UnifiedCaptureRequest,
    UnifiedPaymentSessionRequest, UnifiedPayoutRequest, UnifiedRefundRequest,
    UnifiedSavedMethodChargeRequest, UnifiedSubscriptionRefundRequest, UnifiedVoidRequest,
};
use tonic::{Request, Response, Status};

use super::super::PaymobGrpcService;
use super::super::error::{map_error_to_grpc_status, map_webhook_error_to_grpc_status};
use super::super::proto::{JsonRpcRequest, JsonRpcResponse, decode_request, encode_response};
use super::RpcHandler;

const HANDLERS: &[(&str, RpcHandler)] = &[
    ("VerifyWebhookEvent", |s, r| {
        Box::pin(verify_webhook_event(s, r))
    }),
    ("VerifyWebhookRedirect", |s, r| {
        Box::pin(verify_webhook_redirect(s, r))
    }),
    ("UnifiedCreateSession", |s, r| {
        Box::pin(unified_create_session(s, r))
    }),
    ("UnifiedCapture", |s, r| Box::pin(unified_capture(s, r))),
    ("UnifiedRefund", |s, r| Box::pin(unified_refund(s, r))),
    ("UnifiedVoid", |s, r| Box::pin(unified_void(s, r))),
    ("UnifiedChargeSavedMethod", |s, r| {
        Box::pin(unified_charge_saved_method(s, r))
    }),
    ("UnifiedRefundSubscription", |s, r| {
        Box::pin(unified_refund_subscription(s, r))
    }),
    ("UnifiedExecutePayout", |s, r| {
        Box::pin(unified_execute_payout(s, r))
    }),
    ("UnifiedVerifyWebhook", |s, r| {
        Box::pin(unified_verify_webhook(s, r))
    }),
];

pub(super) fn find_handler(method: &str) -> Option<RpcHandler> {
    HANDLERS
        .iter()
        .find(|(name, _)| *name == method)
        .map(|(_, handler)| *handler)
}

#[derive(Debug, Deserialize)]
struct WebhookEventInput {
    #[serde(alias = "body")]
    raw_body: String,
    #[serde(default)]
    hmac: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WebhookRedirectInput {
    #[serde(alias = "query")]
    raw_query: String,
}

#[derive(Debug, Serialize)]
struct WebhookAckDto {
    event_type: String,
    verified: bool,
    deduplicated: bool,
}

#[derive(Debug, Serialize)]
struct RedirectWebhookAckDto {
    id: String,
    order_id: String,
    currency: String,
    amount_cents: String,
    approved: bool,
    pending: bool,
    deduplicated: bool,
}

#[derive(Debug, Hash, Serialize)]
struct UnifiedSessionDto {
    session_id: String,
    order_id: String,
    status: String,
    confirmed: bool,
}

#[derive(Debug, Deserialize)]
struct UnifiedSavedChargeInput {
    payment_token: String,
    saved_method_token: String,
    #[serde(default)]
    cvn: Option<String>,
}

async fn verify_webhook_event(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let input: WebhookEventInput = decode_request(req)?;
    let event = service
        .webhook_engine
        .construct_event(&input.raw_body, input.hmac.as_deref())
        .map_err(map_webhook_error_to_grpc_status)?;
    service
        .deduplicator
        .claim_or_reject(&event)
        .map_err(map_webhook_error_to_grpc_status)?;
    encode_response(&WebhookAckDto {
        event_type: event.event_type().to_string(),
        verified: true,
        deduplicated: true,
    })
}

async fn verify_webhook_redirect(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let input: WebhookRedirectInput = decode_request(req)?;
    let params = service
        .webhook_engine
        .verify_transaction_get_query_str(&input.raw_query)
        .map_err(map_webhook_error_to_grpc_status)?;
    service
        .deduplicator
        .claim_or_reject(&params)
        .map_err(map_webhook_error_to_grpc_status)?;
    encode_response(&RedirectWebhookAckDto {
        id: params.id.clone(),
        order_id: params.order_id.clone(),
        currency: params.currency.clone(),
        amount_cents: params.amount_cents.clone(),
        approved: params.is_approved(),
        pending: params.is_pending(),
        deduplicated: true,
    })
}

async fn unified_create_session(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let input: UnifiedPaymentSessionRequest = decode_request(req)?;
    let session = service
        .client
        .create_payment_session(&input)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&UnifiedSessionDto {
        session_id: session.session_id.clone(),
        order_id: session.order_id.clone(),
        status: session.status.clone(),
        confirmed: session.confirmed,
    })
}

async fn unified_capture(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let input: UnifiedCaptureRequest = decode_request(req)?;
    let receipt = service
        .client
        .capture_payment(&input)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&receipt)
}

async fn unified_refund(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let input: UnifiedRefundRequest = decode_request(req)?;
    let receipt = service
        .client
        .refund_payment(&input)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&receipt)
}

async fn unified_void(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let input: UnifiedVoidRequest = decode_request(req)?;
    let receipt = service
        .client
        .void_payment(&input)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&receipt)
}

async fn unified_charge_saved_method(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let input: UnifiedSavedChargeInput = decode_request(req)?;
    let mut charge_req =
        UnifiedSavedMethodChargeRequest::new(input.payment_token, input.saved_method_token);
    if let Some(cvn) = input.cvn {
        charge_req = charge_req.with_cvn(cvn);
    }
    let receipt = service
        .client
        .charge_saved_method(&charge_req)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&receipt)
}

async fn unified_refund_subscription(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let input: UnifiedSubscriptionRefundRequest = decode_request(req)?;
    let receipt = service
        .client
        .refund_last_transaction(&input)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&receipt)
}

async fn unified_execute_payout(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let input: UnifiedPayoutRequest = decode_request(req)?;
    let receipt = service
        .client
        .execute_payout(&input)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&receipt)
}

async fn unified_verify_webhook(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let input: WebhookEventInput = decode_request(req)?;
    let event = service
        .webhook_engine
        .construct_event(&input.raw_body, input.hmac.as_deref())
        .map_err(map_webhook_error_to_grpc_status)?;
    service
        .deduplicator
        .claim_or_reject(&event)
        .map_err(map_webhook_error_to_grpc_status)?;
    encode_response(&some_paymob::normalize_webhook_event(&event))
}

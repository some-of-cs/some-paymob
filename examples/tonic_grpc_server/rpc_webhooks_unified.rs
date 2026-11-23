#![forbid(unsafe_code)]
//! Constant-time Webhooks (Protocols A-E + Replay Deduplication) & Unified Adapter unary RPCs.

use serde::{Deserialize, Serialize};
use some_paymob::webhooks::WebhookEvent;
use some_paymob::{
    PaymentProvider, PayoutProvider, SubscriptionProvider, UnifiedCaptureRequest,
    UnifiedPaymentSessionRequest, UnifiedPayoutRequest, UnifiedRefundRequest,
    UnifiedSavedMethodChargeRequest, UnifiedSubscriptionRefundRequest, UnifiedVoidRequest,
};
use tonic::{Request, Response, Status};

use super::super::PaymobGrpcService;
use super::super::error::map_webhook_error_to_grpc_status;
use super::super::proto::{JsonRpcRequest, JsonRpcResponse, decode_request, encode_response};
use super::{RpcHandler, run_rpc};

macro_rules! rpc_entry {
    ($name:literal, $func:ident) => {
        ($name, |s, r| Box::pin($func(s, r)))
    };
}

const HANDLERS: &[(&str, RpcHandler)] = &[
    rpc_entry!("VerifyWebhookEvent", verify_webhook_event),
    rpc_entry!("VerifyWebhookRedirect", verify_webhook_redirect),
    rpc_entry!("UnifiedCreateSession", unified_create_session),
    rpc_entry!("UnifiedCapture", unified_capture),
    rpc_entry!("UnifiedRefund", unified_refund),
    rpc_entry!("UnifiedVoid", unified_void),
    rpc_entry!("UnifiedChargeSavedMethod", unified_charge_saved_method),
    rpc_entry!("UnifiedRefundSubscription", unified_refund_subscription),
    rpc_entry!("UnifiedExecutePayout", unified_execute_payout),
    rpc_entry!("UnifiedVerifyWebhook", unified_verify_webhook),
];

pub(super) fn find_handler(method: &str) -> Option<RpcHandler> {
    HANDLERS
        .iter()
        .find(|(name, _)| *name == method)
        .map(|(_, handler)| *handler)
}

#[derive(Deserialize)]
struct WebhookEventInput {
    #[serde(alias = "body")]
    raw_body: String,
    #[serde(default)]
    hmac: Option<String>,
}

impl std::fmt::Debug for WebhookEventInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookEventInput").finish_non_exhaustive()
    }
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

#[derive(Deserialize)]
struct UnifiedSavedChargeInput {
    payment_token: String,
    saved_method_token: String,
    #[serde(default)]
    cvn: Option<String>,
}

impl std::fmt::Debug for UnifiedSavedChargeInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnifiedSavedChargeInput").finish_non_exhaustive()
    }
}

async fn verify_and_claim_event(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<WebhookEvent, Status> {
    let input: WebhookEventInput = decode_request(req)?;
    let event = service
        .webhook_engine
        .construct_event(&input.raw_body, input.hmac.as_deref())
        .map_err(map_webhook_error_to_grpc_status)?;
    service
        .deduplicator
        .claim_or_reject(&event)
        .map_err(map_webhook_error_to_grpc_status)?;
    Ok(event)
}

async fn verify_webhook_event(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let event = verify_and_claim_event(service, req).await?;
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
    run_rpc(req, |input: UnifiedPaymentSessionRequest| async move {
        let session = service.client.create_payment_session(&input).await?;
        Ok(UnifiedSessionDto {
            session_id: session.session_id.clone(),
            order_id: session.order_id.clone(),
            status: session.status.clone(),
            confirmed: session.confirmed,
        })
    })
    .await
}

async fn unified_capture(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    run_rpc(req, |input: UnifiedCaptureRequest| async move {
        service.client.capture_payment(&input).await
    })
    .await
}

async fn unified_refund(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    run_rpc(req, |input: UnifiedRefundRequest| async move {
        service.client.refund_payment(&input).await
    })
    .await
}

async fn unified_void(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    run_rpc(req, |input: UnifiedVoidRequest| async move {
        service.client.void_payment(&input).await
    })
    .await
}

async fn unified_charge_saved_method(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    run_rpc(req, |input: UnifiedSavedChargeInput| async move {
        let mut charge_req =
            UnifiedSavedMethodChargeRequest::new(input.payment_token, input.saved_method_token);
        if let Some(cvn) = input.cvn {
            charge_req = charge_req.with_cvn(cvn);
        }
        service.client.charge_saved_method(&charge_req).await
    })
    .await
}

async fn unified_refund_subscription(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    run_rpc(req, |input: UnifiedSubscriptionRefundRequest| async move {
        service.client.refund_last_transaction(&input).await
    })
    .await
}

async fn unified_execute_payout(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    run_rpc(req, |input: UnifiedPayoutRequest| async move {
        service.client.execute_payout(&input).await
    })
    .await
}

async fn unified_verify_webhook(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let event = verify_and_claim_event(service, req).await?;
    encode_response(&some_paymob::normalize_webhook_event(&event))
}

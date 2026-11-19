#![forbid(unsafe_code)]
//! Unit 1b gRPC RPCs: Services 4-7 (manage, inquiries, quicklinks, splits).

use serde::{Deserialize, Serialize};
use some_paymob::resources::inquiries::TransactionInquiryParams;
use some_paymob::{
    CaptureParams, ConvenienceFeeConfig, CreateQuickLinkParams, OrderInquiryResponse,
    QuickLinkResponse, RefundParams, SplitDescription, SplitRecipientRule, VoidParams,
};
use tonic::{Request, Response, Status};

use super::super::PaymobGrpcService;
use super::super::error::map_error_to_grpc_status;
use super::super::proto::{JsonRpcRequest, JsonRpcResponse, decode_request, encode_response};

macro_rules! manage_client {
    ($service:expr, $bearer:expr) => {
        if $bearer.unwrap_or(false) {
            $service.client.manage().with_legacy_v2_bearer()
        } else {
            $service.client.manage()
        }
    };
}

/// Request payload for `InquireTransactionById`.
#[derive(Debug, Deserialize)]
pub struct InquireTransactionByIdRequest {
    /// Paymob transaction identifier.
    #[serde(alias = "tx_id", alias = "id")]
    pub transaction_id: u64,
}

/// Request payload for `InquireOrder` and `ListOrderCardTokens`.
#[derive(Debug, Deserialize)]
pub struct OrderIdRequest {
    /// Paymob order identifier.
    #[serde(alias = "id")]
    pub order_id: u64,
}

/// Serializable saved card token item returned by `ListOrderCardTokens`.
#[derive(Debug, Serialize)]
pub struct CardTokenRouteItem {
    /// Envelope type discriminator (typically `"TOKEN"`).
    pub token_type: String,
    /// Saved card token record identifier.
    pub id: u64,
    /// Masked card PAN.
    pub masked_pan: String,
    /// Paymob merchant identifier.
    pub merchant_id: u64,
    /// Card network or subtype.
    pub card_subtype: String,
    /// ISO-8601 creation timestamp, if provided.
    pub created_at: Option<String>,
    /// Associated Paymob order identifier.
    pub order_id: String,
    /// Optional next payment intention identifier.
    pub next_payment_intention: Option<String>,
}

/// Request payload for `CreateQuickLink`.
#[derive(Debug, Deserialize)]
pub struct CreateQuickLinkRequest {
    /// Payment link amount in integer minor units.
    pub amount_cents: u64,
    /// ISO-4217 currency code.
    pub currency: String,
    /// Enabled integration IDs.
    pub integrations: Vec<u64>,
    /// Optional link description.
    pub description: Option<String>,
    /// Optional customer full name.
    pub full_name: Option<String>,
    /// Optional customer email.
    pub email: Option<String>,
    /// Optional customer phone number.
    pub phone_number: Option<String>,
    /// Optional redirection URL.
    pub redirection_url: Option<String>,
}

/// Request payload for `CancelQuickLink`.
#[derive(Debug, Deserialize)]
pub struct CancelQuickLinkRequest {
    /// QuickLink identifier to cancel.
    #[serde(alias = "id")]
    pub link_id: String,
}

/// Response returned by `CancelQuickLink`.
#[derive(Debug, Serialize)]
pub struct CancelQuickLinkResponse {
    /// Cancelled QuickLink identifier.
    pub link_id: String,
    /// Always `true` when cancellation succeeded.
    pub cancelled: bool,
}

/// Request payload for `ValidateSplitsAndCalculateFee`.
#[derive(Debug, Deserialize)]
pub struct SplitsValidateAndQuoteRequest {
    /// Marketplace split recipient rules.
    pub recipients: Vec<SplitRecipientRule>,
    /// Gross transaction amount in integer minor units.
    pub amount_cents: u64,
    /// Optional convenience fee configuration to quote alongside the split.
    pub fee_config: Option<ConvenienceFeeConfig>,
}

/// Response returned by `ValidateSplitsAndCalculateFee`.
#[derive(Debug, Serialize)]
pub struct SplitsValidateAndQuoteResponse {
    /// Validated split description.
    pub split: SplitDescription,
    /// Total fixed split amount in minor units.
    pub total_fixed_cents: u64,
    /// Total percentage split in basis points.
    pub total_percentage_bps: u32,
    /// Quoted convenience fee in minor units (if `fee_config` was provided).
    pub fee_cents: Option<u64>,
    /// Total amount including convenience fee in minor units (if `fee_config` was provided).
    pub total_with_fee_cents: Option<u64>,
}

/// Request payload for `VoidTransaction`.
#[derive(Debug, Deserialize)]
pub struct ManageVoidRequest {
    /// Identifier of the unsettled transaction to void.
    pub transaction_id: u64,
    /// Optional flag to authenticate via Legacy Accept v2 Regime 2 (`Bearer <auth_token>`).
    #[serde(default)]
    pub use_legacy_v2_bearer: Option<bool>,
}

/// Request payload for `CaptureTransaction`.
#[derive(Debug, Deserialize)]
pub struct ManageCaptureRequest {
    /// Identifier of the authorized parent transaction to capture.
    pub transaction_id: u64,
    /// Capture amount in integer minor currency units.
    pub amount_cents: u64,
    /// Optional flag to authenticate via Legacy Accept v2 Regime 2 (`Bearer <auth_token>`).
    #[serde(default)]
    pub use_legacy_v2_bearer: Option<bool>,
}

fn apply_quicklink_optionals(
    mut params: CreateQuickLinkParams,
    req: CreateQuickLinkRequest,
) -> CreateQuickLinkParams {
    if let Some(full_name) = req.full_name {
        params = params.with_full_name(full_name);
    }
    if let Some(email) = req.email {
        params = params.with_email(email);
    }
    if let Some(phone_number) = req.phone_number {
        params = params.with_phone_number(phone_number);
    }
    if let Some(description) = req.description {
        params = params.with_description(description);
    }
    if let Some(redirection_url) = req.redirection_url {
        params = params.with_redirection_url(redirection_url);
    }
    params
}

async fn refund_transaction(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let params: RefundParams = decode_request(req)?;
    let tx = service
        .client
        .manage()
        .refund(params)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&tx)
}

async fn void_transaction(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let payload: ManageVoidRequest = decode_request(req)?;
    let params = VoidParams::new(payload.transaction_id);
    let manage = manage_client!(service, payload.use_legacy_v2_bearer);
    let tx = manage
        .void(params)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&tx)
}

async fn capture_transaction(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let payload: ManageCaptureRequest = decode_request(req)?;
    let params = CaptureParams::new(payload.transaction_id, payload.amount_cents);
    let manage = manage_client!(service, payload.use_legacy_v2_bearer);
    let tx = manage
        .capture(params)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&tx)
}

async fn inquire_transaction_by_id(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let payload: InquireTransactionByIdRequest = decode_request(req)?;
    let tx = service
        .client
        .inquiries()
        .by_transaction_id(payload.transaction_id)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&tx)
}

async fn inquire_transaction_by_order(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let params: TransactionInquiryParams = decode_request(req)?;
    let tx = service
        .client
        .inquiries()
        .by_order_or_reference(params)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&tx)
}

async fn inquire_order(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let payload: OrderIdRequest = decode_request(req)?;
    let order: OrderInquiryResponse = service
        .client
        .inquiries()
        .order_inquiry(payload.order_id)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&order)
}

async fn list_order_card_tokens(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let payload: OrderIdRequest = decode_request(req)?;
    let tokens = service
        .client
        .inquiries()
        .card_tokens(payload.order_id)
        .await
        .map_err(map_error_to_grpc_status)?;
    let items: Vec<CardTokenRouteItem> = tokens
        .into_iter()
        .map(|env| CardTokenRouteItem {
            token_type: env.token_type,
            id: env.obj.id,
            masked_pan: env.obj.masked_pan.clone(),
            merchant_id: env.obj.merchant_id,
            card_subtype: env.obj.card_subtype.clone(),
            created_at: env.obj.created_at.clone(),
            order_id: env.obj.order_id.clone(),
            next_payment_intention: env.obj.next_payment_intention.clone(),
        })
        .collect();
    encode_response(&items)
}

async fn create_quick_link(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let payload: CreateQuickLinkRequest = decode_request(req)?;
    let params = CreateQuickLinkParams::new(
        payload.amount_cents,
        payload.currency.clone(),
        payload.integrations.clone(),
    );
    let params = apply_quicklink_optionals(params, payload);
    let resp: QuickLinkResponse = service
        .client
        .quicklinks()
        .create(&params)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&resp)
}

async fn cancel_quick_link(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let payload: CancelQuickLinkRequest = decode_request(req)?;
    service
        .client
        .quicklinks()
        .cancel(&payload.link_id)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&CancelQuickLinkResponse {
        link_id: payload.link_id,
        cancelled: true,
    })
}

fn validate_splits_and_calculate_fee(
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let payload: SplitsValidateAndQuoteRequest = decode_request(req)?;
    let split = SplitDescription::new(payload.recipients).map_err(map_error_to_grpc_status)?;
    let total_fixed_cents = split
        .total_fixed_cents()
        .map_err(map_error_to_grpc_status)?;
    let total_percentage_bps = split
        .total_percentage_bps()
        .map_err(map_error_to_grpc_status)?;
    let (fee_cents, total_with_fee_cents) = match payload.fee_config {
        Some(cfg) => {
            cfg.validate().map_err(map_error_to_grpc_status)?;
            (
                Some(
                    cfg.compute_fee_cents(payload.amount_cents)
                        .map_err(map_error_to_grpc_status)?,
                ),
                Some(
                    cfg.total_with_fee_cents(payload.amount_cents)
                        .map_err(map_error_to_grpc_status)?,
                ),
            )
        }
        None => (None, None),
    };
    encode_response(&SplitsValidateAndQuoteResponse {
        split,
        total_fixed_cents,
        total_percentage_bps,
        fee_cents,
        total_with_fee_cents,
    })
}

pub(super) async fn dispatch_manage_and_inquiries(
    service: &PaymobGrpcService,
    method: &str,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    match method {
        "RefundTransaction" => refund_transaction(service, req).await,
        "VoidTransaction" => void_transaction(service, req).await,
        "CaptureTransaction" => capture_transaction(service, req).await,
        "InquireTransactionById" => inquire_transaction_by_id(service, req).await,
        "InquireTransactionByOrder" => inquire_transaction_by_order(service, req).await,
        _ => Err(Status::unimplemented(format!("unknown method `{method}`"))),
    }
}

pub(super) async fn dispatch_order_quicklinks_splits(
    service: &PaymobGrpcService,
    method: &str,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    match method {
        "InquireOrder" => inquire_order(service, req).await,
        "ListOrderCardTokens" => list_order_card_tokens(service, req).await,
        "CreateQuickLink" => create_quick_link(service, req).await,
        "CancelQuickLink" => cancel_quick_link(service, req).await,
        "ValidateSplitsAndCalculateFee" => validate_splits_and_calculate_fee(req),
        _ => Err(Status::unimplemented(format!("unknown method `{method}`"))),
    }
}

#![forbid(unsafe_code)]
//! Unit 1b gRPC RPCs: Services 4-7 (manage, inquiries, quicklinks, splits).

use serde::{Deserialize, Serialize};
use some_paymob::resources::inquiries::TransactionInquiryParams;
use some_paymob::{
    CaptureParams, ConvenienceFeeConfig, CreateQuickLinkParams, RefundParams, SplitDescription,
    SplitRecipientRule, VoidParams,
};
use tonic::{Request, Response, Status};

use super::super::PaymobGrpcService;
use super::super::proto::{JsonRpcRequest, JsonRpcResponse};

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

macro_rules! unary_rpc {
    ($fn_name:ident, |$service:ident, $p:ident : $ty:ty| $body:expr) => {
        async fn $fn_name(
            $service: &PaymobGrpcService,
            req: Request<JsonRpcRequest>,
        ) -> Result<Response<JsonRpcResponse>, Status> {
            rpc_call!(req, |$p: $ty| $body)
        }
    };
}

unary_rpc!(refund_transaction, |service, params: RefundParams| {
    service.client.manage().refund(params).await
});

unary_rpc!(void_transaction, |service, p: ManageVoidRequest| {
    let manage = manage_client!(service, p.use_legacy_v2_bearer);
    manage.void(VoidParams::new(p.transaction_id)).await
});

unary_rpc!(capture_transaction, |service, p: ManageCaptureRequest| {
    let manage = manage_client!(service, p.use_legacy_v2_bearer);
    manage
        .capture(CaptureParams::new(p.transaction_id, p.amount_cents))
        .await
});

unary_rpc!(
    inquire_transaction_by_id,
    |service, p: InquireTransactionByIdRequest| {
        service
            .client
            .inquiries()
            .by_transaction_id(p.transaction_id)
            .await
    }
);

unary_rpc!(
    inquire_transaction_by_order,
    |service, params: TransactionInquiryParams| {
        service
            .client
            .inquiries()
            .by_order_or_reference(params)
            .await
    }
);

unary_rpc!(inquire_order, |service, p: OrderIdRequest| {
    service.client.inquiries().order_inquiry(p.order_id).await
});

async fn list_order_card_tokens(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    rpc_call!(req, |p: OrderIdRequest| async {
        let tokens = service.client.inquiries().card_tokens(p.order_id).await?;
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
        Ok(items)
    }
    .await)
}

async fn create_quick_link(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    rpc_call!(req, |p: CreateQuickLinkRequest| async {
        let params =
            CreateQuickLinkParams::new(p.amount_cents, p.currency.clone(), p.integrations.clone());
        let params = apply_quicklink_optionals(params, p);
        service.client.quicklinks().create(&params).await
    }
    .await)
}

async fn cancel_quick_link(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    rpc_call!(req, |p: CancelQuickLinkRequest| async {
        service.client.quicklinks().cancel(&p.link_id).await?;
        Ok(CancelQuickLinkResponse {
            link_id: p.link_id,
            cancelled: true,
        })
    }
    .await)
}

async fn validate_splits_and_calculate_fee(
    _service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    rpc_call!(req, |p: SplitsValidateAndQuoteRequest| {
        let split = SplitDescription::new(p.recipients)?;
        let total_fixed_cents = split.total_fixed_cents()?;
        let total_percentage_bps = split.total_percentage_bps()?;
        let (fee_cents, total_with_fee_cents) = match p.fee_config {
            Some(cfg) => {
                cfg.validate()?;
                (
                    Some(cfg.compute_fee_cents(p.amount_cents)?),
                    Some(cfg.total_with_fee_cents(p.amount_cents)?),
                )
            }
            None => (None, None),
        };
        Ok(SplitsValidateAndQuoteResponse {
            split,
            total_fixed_cents,
            total_percentage_bps,
            fee_cents,
            total_with_fee_cents,
        })
    })
}

dispatch_group!(
    dispatch_manage_and_inquiries,
    "RefundTransaction" => refund_transaction,
    "VoidTransaction" => void_transaction,
    "CaptureTransaction" => capture_transaction,
    "InquireTransactionById" => inquire_transaction_by_id,
    "InquireTransactionByOrder" => inquire_transaction_by_order,
);

dispatch_group!(
    dispatch_order_quicklinks_splits,
    "InquireOrder" => inquire_order,
    "ListOrderCardTokens" => list_order_card_tokens,
    "CreateQuickLink" => create_quick_link,
    "CancelQuickLink" => cancel_quick_link,
    "ValidateSplitsAndCalculateFee" => validate_splits_and_calculate_fee,
);

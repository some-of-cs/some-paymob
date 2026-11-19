#![forbid(unsafe_code)]
//! Service 9 RPCs: Saved Cards & Headless Payments.

use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use some_paymob::resources::saved_cards::{
    HeadlessPayResponse, HeadlessTransaction, KioskPayParams, MitPayParams, RawPayParams,
    WalletPayParams, validate_use_cvc_with_moto,
};
use tonic::{Request, Response, Status};

use super::super::PaymobGrpcService;
use super::super::error::map_error_to_grpc_status;
use super::super::proto::{JsonRpcRequest, JsonRpcResponse, decode_request, encode_response};
use super::{RpcFuture, RpcHandler};

define_routes![
    "PayWithTokenMit" => pay_with_token_mit,
    "PayWithWallet" => pay_with_wallet,
    "PayWithKiosk" => pay_with_kiosk,
    "PayRaw" => pay_raw,
];

// ============================================================================
// Service 9: Saved Cards & Headless Payments
// ============================================================================

#[derive(Debug, Deserialize)]
struct MitPayRequest {
    payment_token: String,
    saved_token: String,
    #[serde(default)]
    cvn: Option<String>,
    #[serde(default)]
    use_cvc_with_moto: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct WalletPayRequest {
    payment_token: String,
    wallet_phone: String,
}

#[derive(Debug, Deserialize)]
struct KioskPayRequest {
    payment_token: String,
}

#[derive(Debug, Deserialize)]
struct RawPayRequest {
    payment_token: String,
    source: Value,
}

#[derive(Debug, Serialize)]
struct HeadlessPayResponseDto {
    transaction: HeadlessTransaction,
    redirect_url: Option<String>,
    kiosk_bill_reference: Option<String>,
}

impl From<HeadlessPayResponse> for HeadlessPayResponseDto {
    fn from(resp: HeadlessPayResponse) -> Self {
        Self {
            transaction: resp.transaction,
            redirect_url: resp.redirect_url,
            kiosk_bill_reference: resp.kiosk_bill_reference,
        }
    }
}

async fn pay_with_token_mit(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let body: MitPayRequest = decode_request(req)?;
    let cvn_secret = body.cvn.map(SecretString::from);
    let use_cvc = body.use_cvc_with_moto.unwrap_or(false);
    validate_use_cvc_with_moto(use_cvc, cvn_secret.as_ref()).map_err(map_error_to_grpc_status)?;
    let mut params = MitPayParams::new(body.payment_token, body.saved_token)
        .map_err(map_error_to_grpc_status)?;
    if let Some(cvn) = cvn_secret {
        params = params.with_cvn(cvn).map_err(map_error_to_grpc_status)?;
    }
    let resp = service
        .client
        .saved_cards()
        .pay_with_token_mit(&params)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&HeadlessPayResponseDto::from(resp))
}

async fn pay_with_wallet(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let body: WalletPayRequest = decode_request(req)?;
    let params = WalletPayParams::new(body.payment_token, body.wallet_phone)
        .map_err(map_error_to_grpc_status)?;
    let resp = service
        .client
        .saved_cards()
        .pay_with_wallet(&params)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&HeadlessPayResponseDto::from(resp))
}

async fn pay_with_kiosk(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let body: KioskPayRequest = decode_request(req)?;
    let params = KioskPayParams::new(body.payment_token).map_err(map_error_to_grpc_status)?;
    let resp = service
        .client
        .saved_cards()
        .pay_with_kiosk(&params)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&HeadlessPayResponseDto::from(resp))
}

async fn pay_raw(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let body: RawPayRequest = decode_request(req)?;
    let params =
        RawPayParams::new(body.payment_token, body.source).map_err(map_error_to_grpc_status)?;
    let resp = service
        .client
        .saved_cards()
        .pay_raw(&params)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&HeadlessPayResponseDto::from(resp))
}

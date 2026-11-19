#![forbid(unsafe_code)]
//! Unit 1 gRPC RPCs: Services 1-7 dispatcher over focused submodules.

use tonic::{Request, Response, Status};

use super::PaymobGrpcService;
use super::proto::{JsonRpcRequest, JsonRpcResponse};

macro_rules! rpc_call {
    ($req:expr, |$payload:ident : $ty:ty| $expr:expr) => {{
        let $payload: $ty = super::super::proto::decode_request($req)?;
        let out = ($expr).map_err(super::super::error::map_error_to_grpc_status)?;
        super::super::proto::encode_response(&out)
    }};
}

macro_rules! dispatch_group {
    ($fn_name:ident, $($lit:literal => $handler:expr),+ $(,)?) => {
        pub(super) async fn $fn_name(
            service: &PaymobGrpcService,
            method: &str,
            req: Request<JsonRpcRequest>,
        ) -> Result<Response<JsonRpcResponse>, Status> {
            match method {
                $($lit => $handler(service, req).await,)+
                _ => Err(Status::unimplemented(format!("unknown method `{method}`"))),
            }
        }
    };
}

#[path = "rpc_core_intentions_legacy.rs"]
mod core_legacy;
#[path = "rpc_manage_inquiries_splits.rs"]
mod manage_inq;

/// Dispatches Unit 1 gRPC unary RPCs (Services 1-7) to `PaymobGrpcService`.
pub async fn dispatch(
    service: &PaymobGrpcService,
    method: &str,
    req: Request<JsonRpcRequest>,
) -> Option<Result<Response<JsonRpcResponse>, Status>> {
    match method {
        "GetHealth"
        | "CheckSandboxConstraints"
        | "BuildPixelConfig"
        | "BuildAffordabilityWidget" => {
            Some(core_legacy::dispatch_core_and_checkout(service, method, req).await)
        }
        "CreateIntention"
        | "UpdateIntention"
        | "CreateLegacyOrder"
        | "CreateLegacyPaymentKey"
        | "CreateLegacyCheckout" => {
            Some(core_legacy::dispatch_intentions_and_legacy(service, method, req).await)
        }
        "RefundTransaction"
        | "VoidTransaction"
        | "CaptureTransaction"
        | "InquireTransactionById"
        | "InquireTransactionByOrder" => {
            Some(manage_inq::dispatch_manage_and_inquiries(service, method, req).await)
        }
        "InquireOrder"
        | "ListOrderCardTokens"
        | "CreateQuickLink"
        | "CancelQuickLink"
        | "ValidateSplitsAndCalculateFee" => {
            Some(manage_inq::dispatch_order_quicklinks_splits(service, method, req).await)
        }
        _ => None,
    }
}

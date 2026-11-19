#![forbid(unsafe_code)]
//! Unit 1 gRPC RPCs: Services 1-7 dispatcher over focused submodules.

use tonic::{Request, Response, Status};

use super::PaymobGrpcService;
use super::proto::{JsonRpcRequest, JsonRpcResponse};

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

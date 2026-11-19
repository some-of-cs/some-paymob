#![forbid(unsafe_code)]
//! Unit 3 RPCs: Services 13-14 (onboarding, multi-tenant scoped, webhooks Protocols A-E, unified adapter).

use std::future::Future;
use std::pin::Pin;

use tonic::{Request, Response, Status};

use super::PaymobGrpcService;
use super::proto::{JsonRpcRequest, JsonRpcResponse};

#[path = "rpc_onboarding.rs"]
mod rpc_onboarding;
#[path = "rpc_webhooks_unified.rs"]
mod rpc_webhooks_unified;

pub(crate) type RpcFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Response<JsonRpcResponse>, Status>> + Send + 'a>>;
pub(crate) type RpcHandler =
    for<'a> fn(&'a PaymobGrpcService, Request<JsonRpcRequest>) -> RpcFuture<'a>;

/// Dispatches Unit 3 unary RPC methods (Services 13-14, webhooks Protocols A-E, and unified adapter).
pub async fn dispatch(
    service: &PaymobGrpcService,
    method: &str,
    req: Request<JsonRpcRequest>,
) -> Option<Result<Response<JsonRpcResponse>, Status>> {
    let handler = rpc_onboarding::find_handler(method)
        .or_else(|| rpc_webhooks_unified::find_handler(method))?;
    Some(handler(service, req).await)
}

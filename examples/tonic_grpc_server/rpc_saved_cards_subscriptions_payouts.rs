#![forbid(unsafe_code)]
//! Unit 2 RPCs: Services 9–12 (saved-cards/tokens, subscriptions, payouts).

use std::future::Future;
use std::pin::Pin;

use serde::Serialize;
use tonic::{Request, Response, Status};

use super::PaymobGrpcService;
use super::error::map_error_to_grpc_status;
use super::proto::{JsonRpcRequest, JsonRpcResponse, encode_response};

pub(super) type RpcFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Response<JsonRpcResponse>, Status>> + Send + 'a>>;
pub(super) type RpcHandler = fn(&PaymobGrpcService, Request<JsonRpcRequest>) -> RpcFuture<'_>;

pub(super) fn encode_sdk_result<T, D>(
    res: Result<T, some_paymob::PaymobError>,
) -> Result<Response<JsonRpcResponse>, Status>
where
    D: Serialize + From<T>,
{
    let val = res.map_err(map_error_to_grpc_status)?;
    encode_response(&D::from(val))
}

macro_rules! define_routes {
    ($( $name:literal => $handler:ident ),* $(,)?) => {
        pub(super) const RPC_ROUTES: &[(&str, RpcHandler)] = &[
            $((
                $name,
                {
                    fn wrapper(
                        service: &PaymobGrpcService,
                        req: Request<JsonRpcRequest>,
                    ) -> RpcFuture<'_> {
                        Box::pin($handler(service, req))
                    }
                    wrapper
                }
            ),)*
        ];
    };
}

#[path = "rpc_payouts.rs"]
mod rpc_payouts;
#[path = "rpc_saved_cards.rs"]
mod rpc_saved_cards;
#[path = "rpc_subscriptions.rs"]
mod rpc_subscriptions;

/// Dispatches a Unit 2 unary gRPC method by name.
pub async fn dispatch(
    service: &PaymobGrpcService,
    method: &str,
    req: Request<JsonRpcRequest>,
) -> Option<Result<Response<JsonRpcResponse>, Status>> {
    let handler = rpc_saved_cards::RPC_ROUTES
        .iter()
        .chain(rpc_subscriptions::RPC_ROUTES.iter())
        .chain(rpc_payouts::RPC_ROUTES.iter())
        .find(|(name, _)| *name == method)
        .map(|(_, handler)| *handler)?;
    Some(handler(service, req).await)
}

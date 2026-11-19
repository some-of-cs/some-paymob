#![forbid(unsafe_code)]
//! Prost-encoded protobuf messages for the Tonic gRPC reference server (no external `protoc` required).

use serde::Serialize;
use serde::de::DeserializeOwned;
use tonic::{Request, Response, Status};

/// Canonical gRPC service name for `PaymobGrpcService`.
pub const PAYMOB_GRPC_SERVICE_NAME: &str = "paymob.v1.PaymobService";

/// Generic Prost unary request carrying a JSON-encoded RPC payload.
#[derive(Clone, PartialEq, prost::Message)]
pub struct JsonRpcRequest {
    /// JSON-serialized request payload.
    #[prost(string, tag = "1")]
    pub payload_json: String,
}

/// Generic Prost unary response carrying a JSON-encoded RPC payload.
#[derive(Clone, PartialEq, prost::Message)]
pub struct JsonRpcResponse {
    /// JSON-serialized response payload.
    #[prost(string, tag = "1")]
    pub payload_json: String,
}

/// Deserializes a `JsonRpcRequest` payload into `T`.
pub fn decode_request<T: DeserializeOwned>(req: Request<JsonRpcRequest>) -> Result<T, Status> {
    let raw = req.into_inner().payload_json;
    let body = if raw.trim().is_empty() { "{}" } else { &raw };
    serde_json::from_str::<T>(body)
        .map_err(|err| Status::invalid_argument(format!("invalid_request_json: {err}")))
}

/// Serializes `T` into a `Response<JsonRpcResponse>`.
pub fn encode_response<T: Serialize>(value: &T) -> Result<Response<JsonRpcResponse>, Status> {
    let payload_json = serde_json::to_string(value)
        .map_err(|err| Status::internal(format!("response_serialization_failed: {err}")))?;
    Ok(Response::new(JsonRpcResponse { payload_json }))
}

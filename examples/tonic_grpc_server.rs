#![forbid(unsafe_code)]
#![allow(clippy::result_large_err)]
//! Tonic gRPC reference server for `some-paymob` covering all 14 services and Protocols A-E.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use some_paymob::webhooks::InMemoryWebhookDeduplicator;
use some_paymob::{PaymobClient, PaymobWebhookEngine};
use tonic::{Request, Response, Status};

#[path = "tonic_grpc_server/error.rs"]
pub mod error;
#[path = "tonic_grpc_server/proto.rs"]
pub mod proto;
#[path = "tonic_grpc_server/rpc_core_checkout_legacy_manage.rs"]
pub mod rpc_core_checkout_legacy_manage;
#[path = "tonic_grpc_server/rpc_onboarding_webhooks_unified.rs"]
pub mod rpc_onboarding_webhooks_unified;
#[path = "tonic_grpc_server/rpc_saved_cards_subscriptions_payouts.rs"]
pub mod rpc_saved_cards_subscriptions_payouts;

use proto::{JsonRpcRequest, JsonRpcResponse};

const SERVICE_PATH_PREFIX: &str = "/paymob.v1.PaymobService/";

/// Shared Tonic gRPC service state backed by `PaymobClient` and webhook primitives.
#[derive(Clone)]
pub struct PaymobGrpcService {
    /// Core Paymob SDK client.
    pub client: Arc<PaymobClient>,
    /// Constant-time HMAC webhook verification engine.
    pub webhook_engine: Arc<PaymobWebhookEngine>,
    /// In-memory replay deduplicator for webhook deliveries.
    pub deduplicator: Arc<InMemoryWebhookDeduplicator>,
}

impl PaymobGrpcService {
    /// Creates a new `PaymobGrpcService` from the given client, webhook engine, and deduplicator.
    #[must_use]
    pub fn new(
        client: Arc<PaymobClient>,
        webhook_engine: Arc<PaymobWebhookEngine>,
        deduplicator: Arc<InMemoryWebhookDeduplicator>,
    ) -> Self {
        Self {
            client,
            webhook_engine,
            deduplicator,
        }
    }
}

/// Tonic `NamedService` + `tower::Service` router for `/paymob.v1.PaymobService/<Method>`.
#[derive(Clone)]
pub struct PaymobGrpcServer {
    service: PaymobGrpcService,
}

impl PaymobGrpcServer {
    /// Wraps a [`PaymobGrpcService`] into a routable [`PaymobGrpcServer`].
    #[must_use]
    pub fn new(service: PaymobGrpcService) -> Self {
        Self { service }
    }
}

/// Builds a [`PaymobGrpcServer`] ready to be registered on `tonic::transport::Server`.
#[must_use]
pub fn build_grpc_server(service: PaymobGrpcService) -> PaymobGrpcServer {
    PaymobGrpcServer::new(service)
}

impl tonic::server::NamedService for PaymobGrpcServer {
    const NAME: &'static str = proto::PAYMOB_GRPC_SERVICE_NAME;
}

impl tower::Service<http::Request<tonic::body::BoxBody>> for PaymobGrpcServer {
    type Response = http::Response<tonic::body::BoxBody>;
    type Error = std::convert::Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: http::Request<tonic::body::BoxBody>) -> Self::Future {
        let service = self.service.clone();
        let method = extract_grpc_method(req.uri().path());
        Box::pin(async move {
            let codec = tonic::codec::ProstCodec::<JsonRpcResponse, JsonRpcRequest>::default();
            let mut grpc = tonic::server::Grpc::new(codec)
                .max_decoding_message_size(8 * 1024 * 1024);
            let res = grpc.unary(DynamicUnarySvc { service, method }, req).await;
            Ok(res)
        })
    }
}

struct DynamicUnarySvc {
    service: PaymobGrpcService,
    method: String,
}

impl tonic::server::UnaryService<JsonRpcRequest> for DynamicUnarySvc {
    type Response = JsonRpcResponse;
    type Future = Pin<Box<dyn Future<Output = Result<Response<JsonRpcResponse>, Status>> + Send>>;

    fn call(&mut self, request: Request<JsonRpcRequest>) -> Self::Future {
        let service = self.service.clone();
        let method = self.method.clone();
        Box::pin(async move { dispatch_rpc(&service, &method, request).await })
    }
}

fn extract_grpc_method(path: &str) -> String {
    path.strip_prefix(SERVICE_PATH_PREFIX)
        .filter(|method| !method.is_empty() && !method.contains('/'))
        .unwrap_or_default()
        .to_owned()
}

async fn dispatch_rpc(
    service: &PaymobGrpcService,
    method: &str,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    if method.is_empty() {
        return Err(Status::unimplemented("unimplemented gRPC method"));
    }
    let (metadata, _extensions, payload) = req.into_parts();
    let req1 = Request::from_parts(metadata.clone(), tonic::Extensions::new(), payload.clone());
    if let Some(res) = rpc_core_checkout_legacy_manage::dispatch(service, method, req1).await {
        return res;
    }
    let req2 = Request::from_parts(metadata.clone(), tonic::Extensions::new(), payload.clone());
    if let Some(res) = rpc_saved_cards_subscriptions_payouts::dispatch(service, method, req2).await
    {
        return res;
    }
    let req3 = Request::from_parts(metadata, tonic::Extensions::new(), payload);
    if let Some(res) = rpc_onboarding_webhooks_unified::dispatch(service, method, req3).await {
        return res;
    }
    Err(Status::unimplemented(format!(
        "unknown gRPC method: {method}"
    )))
}

#[cfg(not(test))]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use some_paymob::{ClientConfig, PaymobRegion};

    let config = ClientConfig::builder()
        .region(PaymobRegion::Egypt)
        .try_secret_key("egy_sk_test_placeholder")?
        .try_public_key("egy_pk_test_placeholder")?
        .try_hmac_secret("0123456789abcdef0123456789abcdef")?
        .build()?;
    let client = Arc::new(PaymobClient::new(config)?);
    let webhook_engine = Arc::new(client.webhook_engine()?);
    let deduplicator = Arc::new(InMemoryWebhookDeduplicator::new());
    let service = PaymobGrpcService::new(client, webhook_engine, deduplicator);
    let addr = "127.0.0.1:50051".parse()?;
    tonic::transport::Server::builder()
        .add_service(build_grpc_server(service))
        .serve(addr)
        .await?;
    Ok(())
}

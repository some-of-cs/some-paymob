#![forbid(unsafe_code)]
//! Shared state, error mapping, and route registration for `examples/actix_server.rs`.

pub mod core_checkout;
pub mod legacy_manage_inquiries;
pub mod quicklinks_splits;

use std::fmt;
use std::sync::Arc;

use actix_web::http::StatusCode;
use actix_web::{HttpResponse, ResponseError, web};
use serde_json::json;
use some_paymob::prelude::*;

/// Shared Actix-Web application state wrapping an `Arc`-backed [`PaymobClient`]
/// and an in-memory webhook replay deduplicator.
#[derive(Clone)]
pub struct AppState {
    /// Configured `some-paymob` microkernel client.
    pub client: PaymobClient,
    /// Thread-safe in-memory webhook replay guard.
    pub webhook_dedup: Arc<InMemoryWebhookDeduplicator>,
}

impl AppState {
    /// Creates a new [`AppState`] with a default [`InMemoryWebhookDeduplicator`].
    #[must_use]
    pub fn new(client: PaymobClient) -> Self {
        Self {
            client,
            webhook_dedup: Arc::new(InMemoryWebhookDeduplicator::new()),
        }
    }
}

/// Deterministic HTTP error wrapper mapping `some-paymob` SDK, webhook, and
/// sandbox constraint errors to Actix-Web `ResponseError` status codes.
#[derive(Debug)]
pub enum ApiServerError {
    /// Core or resource SDK error.
    Paymob(PaymobError),
    /// Cryptographic webhook verification or replay error.
    Webhook(WebhookError),
    /// Sandbox constraint error (credential age >= 30 days or unsupported channel).
    Sandbox(SandboxConstraintError),
}

impl fmt::Display for ApiServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Paymob(err) => write!(f, "{err}"),
            Self::Webhook(err) => write!(f, "{err}"),
            Self::Sandbox(err) => write!(f, "{err}"),
        }
    }
}

impl From<PaymobError> for ApiServerError {
    fn from(err: PaymobError) -> Self {
        Self::Paymob(err)
    }
}

impl From<WebhookError> for ApiServerError {
    fn from(err: WebhookError) -> Self {
        Self::Webhook(err)
    }
}

impl From<SandboxConstraintError> for ApiServerError {
    fn from(err: SandboxConstraintError) -> Self {
        Self::Sandbox(err)
    }
}

fn map_paymob_status(err: &PaymobError) -> StatusCode {
    match err {
        PaymobError::ValidationError { .. } | PaymobError::WebhookError(_) => {
            StatusCode::BAD_REQUEST
        }
        PaymobError::AuthenticationError(_) => StatusCode::UNAUTHORIZED,
        PaymobError::EnvironmentMismatch(_)
        | PaymobError::RefundExceedsPermissibleAmount { .. } => StatusCode::UNPROCESSABLE_ENTITY,
        PaymobError::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
        PaymobError::ApiError { status, .. } => {
            StatusCode::from_u16(*status).unwrap_or(StatusCode::BAD_GATEWAY)
        }
        PaymobError::TransportError(_) => StatusCode::BAD_GATEWAY,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn map_webhook_status(err: &WebhookError) -> StatusCode {
    match err {
        WebhookError::SignatureMismatch => StatusCode::UNAUTHORIZED,
        WebhookError::DuplicateWebhookDelivery { .. } => StatusCode::CONFLICT,
        _ => StatusCode::BAD_REQUEST,
    }
}

impl ResponseError for ApiServerError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::Paymob(err) => map_paymob_status(err),
            Self::Webhook(err) => map_webhook_status(err),
            Self::Sandbox(_) => StatusCode::UNPROCESSABLE_ENTITY,
        }
    }

    fn error_response(&self) -> HttpResponse {
        let status = self.status_code();
        let mut builder = HttpResponse::build(status);
        if let Self::Paymob(PaymobError::RateLimited {
            retry_after_secs: Some(secs),
            ..
        }) = self
        {
            builder.insert_header(("Retry-After", secs.to_string()));
        }
        builder.json(json!({
            "error": self.to_string(),
            "status": status.as_u16(),
        }))
    }
}

pub(crate) fn parse_currency(raw: &str) -> Result<Currency, ApiServerError> {
    match raw.trim().to_ascii_uppercase().as_str() {
        "EGP" => Ok(Currency::EGP),
        "SAR" => Ok(Currency::SAR),
        "AED" => Ok(Currency::AED),
        "OMR" => Ok(Currency::OMR),
        "PKR" => Ok(Currency::PKR),
        "USD" => Ok(Currency::USD),
        _ => Err(PaymobError::ValidationError {
            field: "currency".to_owned(),
            reason: "unsupported currency code".to_owned(),
        }
        .into()),
    }
}

/// Configures Unit 1 routes (Services 1–6).
pub fn configure_unit_1(cfg: &mut web::ServiceConfig) {
    core_checkout::configure(cfg);
    legacy_manage_inquiries::configure(cfg);
    quicklinks_splits::configure(cfg);
}

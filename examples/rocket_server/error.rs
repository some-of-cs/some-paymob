#![forbid(unsafe_code)]
//! Deterministic error-to-HTTP status mapping (`rocket::response::Responder`) for `some-paymob`.

use std::io::Cursor;

use rocket::http::{ContentType, Status};
use rocket::request::Request;
use rocket::response::{self, Responder, Response};
use serde::Serialize;
use some_paymob::{PaymobError, SandboxConstraintError, WebhookError};

/// JSON error payload returned by [`ApiServerError`].
#[derive(Debug, Serialize)]
pub struct ErrorBody {
    /// Machine-readable error category code.
    pub error: String,
    /// Human-readable diagnostic message.
    pub message: String,
}

/// Deterministic HTTP error wrapper for `some-paymob` Rocket handlers.
#[derive(Debug)]
pub struct ApiServerError {
    /// HTTP status code returned to the caller.
    pub status: Status,
    /// Machine-readable error category code.
    pub error: String,
    /// Human-readable diagnostic message.
    pub message: String,
    /// Optional `Retry-After` delay in seconds (emitted on `429 Too Many Requests`).
    pub retry_after_secs: Option<u64>,
}

impl ApiServerError {
    /// Constructs an [`ApiServerError`] from explicit HTTP status, code, message, and optional retry delay.
    #[must_use]
    pub fn new(
        status: Status,
        error: impl Into<String>,
        message: impl Into<String>,
        retry_after_secs: Option<u64>,
    ) -> Self {
        Self {
            status,
            error: error.into(),
            message: message.into(),
            retry_after_secs,
        }
    }
}

fn map_client_paymob_error(err: &PaymobError) -> Option<(Status, &'static str)> {
    match err {
        PaymobError::ValidationError { .. } => Some((Status::BadRequest, "validation_error")),
        PaymobError::AuthenticationError(_) => {
            Some((Status::Unauthorized, "authentication_error"))
        }
        PaymobError::EnvironmentMismatch(_) => {
            Some((Status::UnprocessableEntity, "environment_mismatch"))
        }
        PaymobError::RefundExceedsPermissibleAmount { .. } => Some((
            Status::UnprocessableEntity,
            "refund_exceeds_permissible_amount",
        )),
        _ => None,
    }
}

fn map_gateway_paymob_error(err: &PaymobError) -> (Status, &'static str, Option<u64>) {
    match err {
        PaymobError::RateLimited {
            retry_after_secs, ..
        } => (Status::TooManyRequests, "rate_limited", *retry_after_secs),
        PaymobError::ApiError { status, .. } => (
            Status::from_code(*status).unwrap_or(Status::BadGateway),
            "api_error",
            None,
        ),
        PaymobError::TransportError(_) => (Status::BadGateway, "transport_error", None),
        PaymobError::WebhookError(_) => (Status::BadRequest, "webhook_error", None),
        _ => (Status::InternalServerError, "paymob_error", None),
    }
}

impl From<PaymobError> for ApiServerError {
    fn from(err: PaymobError) -> Self {
        let message = err.to_string();
        if let Some((status, code)) = map_client_paymob_error(&err) {
            return Self::new(status, code, message, None);
        }
        let (status, code, retry_after_secs) = map_gateway_paymob_error(&err);
        Self::new(status, code, message, retry_after_secs)
    }
}

impl From<WebhookError> for ApiServerError {
    fn from(err: WebhookError) -> Self {
        let message = err.to_string();
        let (status, code) = match err {
            WebhookError::SignatureMismatch => (Status::Unauthorized, "webhook_signature_mismatch"),
            WebhookError::DuplicateWebhookDelivery { .. } => {
                (Status::Conflict, "duplicate_webhook_delivery")
            }
            _ => (Status::BadRequest, "webhook_error"),
        };
        Self::new(status, code, message, None)
    }
}

impl From<SandboxConstraintError> for ApiServerError {
    fn from(err: SandboxConstraintError) -> Self {
        Self::new(
            Status::UnprocessableEntity,
            "sandbox_constraint_error",
            err.to_string(),
            None,
        )
    }
}

impl<'r> Responder<'r, 'static> for ApiServerError {
    fn respond_to(self, _req: &'r Request<'_>) -> response::Result<'static> {
        let body = serde_json::to_string(&ErrorBody {
            error: self.error,
            message: self.message,
        })
        .unwrap_or_else(|_| {
            r#"{"error":"serialization_error","message":"failed"}"#.to_string()
        });
        let mut builder = Response::build();
        builder
            .status(self.status)
            .header(ContentType::JSON)
            .sized_body(body.len(), Cursor::new(body));
        if let Some(secs) = self.retry_after_secs {
            builder.raw_header("Retry-After", secs.to_string());
        }
        builder.ok()
    }
}

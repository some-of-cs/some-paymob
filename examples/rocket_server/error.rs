#![forbid(unsafe_code)]
//! Deterministic error-to-HTTP status mapping (`rocket::response::Responder`) for `some-paymob`.

use std::io::Cursor;

use rocket::http::{ContentType, Status};
use rocket::request::Request;
use rocket::response::{self, Responder, Response};
use serde::Serialize;
use some_paymob::{PaymobError, SandboxConstraintError, WebhookError};

#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub error: String,
    pub message: String,
}

#[derive(Debug)]
pub struct ApiServerError {
    pub status: Status,
    pub error: String,
    pub message: String,
    pub retry_after_secs: Option<u64>,
}

impl From<PaymobError> for ApiServerError {
    fn from(err: PaymobError) -> Self {
        Self {
            status: Status::InternalServerError,
            error: "paymob_error".to_string(),
            message: err.to_string(),
            retry_after_secs: None,
        }
    }
}

impl From<WebhookError> for ApiServerError {
    fn from(err: WebhookError) -> Self {
        Self {
            status: Status::BadRequest,
            error: "webhook_error".to_string(),
            message: err.to_string(),
            retry_after_secs: None,
        }
    }
}

impl From<SandboxConstraintError> for ApiServerError {
    fn from(err: SandboxConstraintError) -> Self {
        Self {
            status: Status::UnprocessableEntity,
            error: "sandbox_constraint_error".to_string(),
            message: err.to_string(),
            retry_after_secs: None,
        }
    }
}

impl<'r> Responder<'r, 'static> for ApiServerError {
    fn respond_to(self, _req: &'r Request<'_>) -> response::Result<'static> {
        let body = serde_json::to_string(&ErrorBody {
            error: self.error,
            message: self.message,
        })
        .unwrap_or_else(|_| "{\"error\":\"serialization_error\",\"message\":\"failed\"}".to_string());
        Response::build()
            .status(self.status)
            .header(ContentType::JSON)
            .sized_body(body.len(), Cursor::new(body))
            .ok()
    }
}

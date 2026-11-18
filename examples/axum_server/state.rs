#![forbid(unsafe_code)]
//! Shared Axum application state and HTTP error mapping for the `some-paymob` example server.
//!
//! Provides [`AppState`] for sharing a cheaply cloneable [`PaymobClient`], an
//! [`InMemoryWebhookDeduplicator`], and known integration [`EnvironmentMode`] mappings across
//! Axum handlers, alongside [`ApiServerError`] for deterministic HTTP status mapping with
//! `[REDACTED]` secret and PII hygiene.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use axum::Json;
use axum::http::header::RETRY_AFTER;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use some_paymob::core::credentials::EnvironmentMode;
use some_paymob::webhooks::InMemoryWebhookDeduplicator;
use some_paymob::{PaymobClient, PaymobError, SandboxConstraintError, WebhookError};

/// Shared application state injected into Axum route handlers via `State<Arc<AppState>>`.
#[derive(Clone)]
pub struct AppState {
    /// Thread-safe, `Arc`-backed Paymob microkernel client.
    pub paymob: PaymobClient,
    /// Bounded in-memory webhook deduplicator for idempotent callback handling.
    pub deduplicator: Arc<InMemoryWebhookDeduplicator>,
    /// Known integration ID to [`EnvironmentMode`] (`Test` or `Live`) mappings for pre-flight parity checks.
    pub known_integration_modes: HashMap<u64, EnvironmentMode>,
}

impl fmt::Debug for AppState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppState")
            .field("paymob", &self.paymob)
            .field("deduplicator_len", &self.deduplicator.len())
            .field(
                "known_integration_modes_count",
                &self.known_integration_modes.len(),
            )
            .finish()
    }
}

impl AppState {
    /// Creates a new [`AppState`] with a default [`InMemoryWebhookDeduplicator`] and empty integration map.
    #[must_use]
    pub fn new(paymob: PaymobClient) -> Self {
        Self {
            paymob,
            deduplicator: Arc::new(InMemoryWebhookDeduplicator::new()),
            known_integration_modes: HashMap::new(),
        }
    }

    /// Populates `known_integration_modes` from an iterator of `(integration_id, EnvironmentMode)` pairs.
    #[must_use]
    pub fn with_integration_modes(
        mut self,
        modes: impl IntoIterator<Item = (u64, EnvironmentMode)>,
    ) -> Self {
        self.known_integration_modes.extend(modes);
        self
    }
}

/// Unified HTTP error type for the `some-paymob` Axum example server.
///
/// Maps SDK domain errors ([`PaymobError`], [`WebhookError`], and [`SandboxConstraintError`])
/// into structured JSON error responses while preserving `[REDACTED]` hygiene.
#[derive(Debug)]
pub enum ApiServerError {
    /// Core Paymob SDK or upstream API error.
    Paymob(PaymobError),
    /// Cryptographic webhook verification or idempotency conflict error.
    Webhook(WebhookError),
    /// Sandbox constraint violation (expired test credentials or live-only channel in sandbox).
    Sandbox(SandboxConstraintError),
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

impl fmt::Display for ApiServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Paymob(err) => write!(f, "{err}"),
            Self::Webhook(err) => write!(f, "{err}"),
            Self::Sandbox(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for ApiServerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Paymob(err) => Some(err),
            Self::Webhook(err) => Some(err),
            Self::Sandbox(err) => Some(err),
        }
    }
}

#[derive(Serialize)]
struct ErrorEnvelope {
    error: ErrorBody,
}

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    message: String,
}

impl IntoResponse for ApiServerError {
    fn into_response(self) -> Response {
        let (status, retry_after, code, message) = match &self {
            Self::Paymob(err) => map_paymob_error(err),
            Self::Webhook(err) => map_webhook_error(err),
            Self::Sandbox(err) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                None,
                "sandbox_constraint_error",
                err.to_string(),
            ),
        };

        let headers = build_retry_headers(retry_after);
        let body = Json(ErrorEnvelope {
            error: ErrorBody {
                code,
                message: sanitize_error_message(&message),
            },
        });
        (status, headers, body).into_response()
    }
}

fn map_paymob_error(err: &PaymobError) -> (StatusCode, Option<u64>, &'static str, String) {
    if let Some(mapped) = map_paymob_client_error(err) {
        return mapped;
    }
    map_paymob_upstream_error(err)
}

fn map_paymob_client_error(
    err: &PaymobError,
) -> Option<(StatusCode, Option<u64>, &'static str, String)> {
    match err {
        PaymobError::ValidationError { .. } => Some((
            StatusCode::BAD_REQUEST,
            None,
            "validation_error",
            err.to_string(),
        )),
        PaymobError::AuthenticationError(_) => Some((
            StatusCode::UNAUTHORIZED,
            None,
            "authentication_error",
            err.to_string(),
        )),
        PaymobError::EnvironmentMismatch(_) => Some((
            StatusCode::UNPROCESSABLE_ENTITY,
            None,
            "environment_mismatch",
            err.to_string(),
        )),
        PaymobError::RefundExceedsPermissibleAmount { .. } => Some((
            StatusCode::UNPROCESSABLE_ENTITY,
            None,
            "refund_exceeds_permissible_amount",
            err.to_string(),
        )),
        _ => None,
    }
}

fn map_paymob_upstream_error(err: &PaymobError) -> (StatusCode, Option<u64>, &'static str, String) {
    match err {
        PaymobError::RateLimited {
            retry_after_secs, ..
        } => (
            StatusCode::TOO_MANY_REQUESTS,
            *retry_after_secs,
            "rate_limited",
            err.to_string(),
        ),
        PaymobError::ApiError { status, .. } => {
            let http_status = StatusCode::from_u16(*status).unwrap_or(StatusCode::BAD_GATEWAY);
            (http_status, None, "upstream_api_error", err.to_string())
        }
        PaymobError::TransportError(_) => (
            StatusCode::BAD_GATEWAY,
            None,
            "transport_error",
            err.to_string(),
        ),
        PaymobError::WebhookError(_) => (
            StatusCode::BAD_REQUEST,
            None,
            "webhook_error",
            err.to_string(),
        ),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            None,
            "internal_error",
            err.to_string(),
        ),
    }
}

fn map_webhook_error(err: &WebhookError) -> (StatusCode, Option<u64>, &'static str, String) {
    match err {
        WebhookError::SignatureMismatch => (
            StatusCode::UNAUTHORIZED,
            None,
            "webhook_signature_mismatch",
            err.to_string(),
        ),
        WebhookError::DuplicateWebhookDelivery { .. } => (
            StatusCode::CONFLICT,
            None,
            "webhook_duplicate_delivery",
            err.to_string(),
        ),
        _ => (
            StatusCode::BAD_REQUEST,
            None,
            "webhook_verification_error",
            err.to_string(),
        ),
    }
}

fn build_retry_headers(retry_after: Option<u64>) -> HeaderMap {
    let mut headers = HeaderMap::new();
    let Some(secs) = retry_after else {
        return headers;
    };
    if let Ok(val) = HeaderValue::from_str(&secs.to_string()) {
        headers.insert(RETRY_AFTER, val);
    }
    headers
}

fn sanitize_error_message(raw: &str) -> String {
    const SECRET_MARKERS: &[&str] = &[
        "sk_live_", "sk_test_", "pk_live_", "pk_test_", "egy_sk_", "ksa_sk_", "uae_sk_", "omn_sk_",
        "pak_sk_", "eyJ",
    ];
    if SECRET_MARKERS.iter().any(|prefix| raw.contains(prefix)) {
        return String::from("[REDACTED]");
    }
    raw.to_owned()
}

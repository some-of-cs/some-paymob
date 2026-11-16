#![forbid(unsafe_code)]
//! Story-level integration tests for US-1.3.0 (`TC-1.3.1`..`TC-1.3.4`).
//!
//! Covers:
//! - `TC-1.3.1`: `PaymobError` multi-shape response parsing, HTTP status mapping,
//!   retryability classification, and PII/secret redaction in `Display` and `Debug`.
//! - `TC-1.3.2`: `HttpClient` transport pipeline, `X-Request-Id` UUID v4 tracing,
//!   exponential backoff with full jitter, `429`/`502`/`503`/`504` retries,
//!   `Retry-After` handling, bounded response bodies, timeouts, and non-retryable 4xx.
//! - `TC-1.3.3`: `MinorUnitAmount` zero-float checked arithmetic & serde, `Currency`
//!   ISO-4217 lookup & decimal precision, and `validate_prefixed_id`.
//! - `TC-1.3.4`: `PaginatedResponse<T>`, `PageQuery`, and `some_paymob::prelude::*`
//!   re-exports.

mod error_redaction;
mod error_workflow;
mod http_transport;
mod types_pagination;

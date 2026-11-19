#![forbid(unsafe_code)]
//! Deterministic error-to-gRPC `tonic::Status` mapping for `some-paymob`.

use some_paymob::{PaymobError, SandboxConstraintError, WebhookError};
use tonic::metadata::{Ascii, MetadataValue};
use tonic::{Code, Status};

fn map_client_paymob_code(err: &PaymobError) -> Option<Code> {
    match err {
        PaymobError::ValidationError { .. } => Some(Code::InvalidArgument),
        PaymobError::AuthenticationError(_) => Some(Code::Unauthenticated),
        PaymobError::EnvironmentMismatch(_)
        | PaymobError::RefundExceedsPermissibleAmount { .. } => Some(Code::FailedPrecondition),
        _ => None,
    }
}

fn attach_retry_after_metadata(status: &mut Status, retry_after_secs: Option<u64>) {
    let val =
        retry_after_secs.and_then(|secs| secs.to_string().parse::<MetadataValue<Ascii>>().ok());
    if let Some(val) = val {
        status.metadata_mut().insert("retry-after-secs", val);
    }
}

fn map_gateway_paymob_status(err: PaymobError, message: String) -> Status {
    match err {
        PaymobError::RateLimited {
            retry_after_secs, ..
        } => {
            let mut status = Status::new(Code::ResourceExhausted, message);
            attach_retry_after_metadata(&mut status, retry_after_secs);
            status
        }
        PaymobError::ApiError { status: 404, .. } => Status::new(Code::NotFound, message),
        PaymobError::ApiError { .. } | PaymobError::TransportError(_) => {
            Status::new(Code::Unavailable, message)
        }
        PaymobError::WebhookError(inner) => Status::invalid_argument(inner),
        _ => Status::new(Code::Internal, message),
    }
}

/// Maps a [`PaymobError`] into a deterministic [`tonic::Status`].
#[must_use]
pub fn map_error_to_grpc_status(err: PaymobError) -> Status {
    let message = err.to_string();
    if let Some(code) = map_client_paymob_code(&err) {
        return Status::new(code, message);
    }
    map_gateway_paymob_status(err, message)
}

/// Maps a [`WebhookError`] into a deterministic [`tonic::Status`].
#[must_use]
pub fn map_webhook_error_to_grpc_status(err: WebhookError) -> Status {
    let message = err.to_string();
    let code = match err {
        WebhookError::SignatureMismatch => Code::Unauthenticated,
        WebhookError::DuplicateWebhookDelivery { .. } => Code::AlreadyExists,
        _ => Code::InvalidArgument,
    };
    Status::new(code, message)
}

/// Maps a [`SandboxConstraintError`] into [`Code::FailedPrecondition`].
#[must_use]
pub fn map_sandbox_error_to_grpc_status(err: SandboxConstraintError) -> Status {
    Status::new(Code::FailedPrecondition, err.to_string())
}

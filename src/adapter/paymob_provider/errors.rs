use reqwest::{Response, StatusCode};
use serde::Deserialize;
use some_payment_core::{PaymentError, PaymentStatus, ProviderId};

use crate::alignment::callback_dispatcher::CallbackDispatchError;
use crate::alignment::dual_auth::DualAuthError;
use crate::alignment::integration_validation::IntegrationValidationError;
use crate::alignment::region_checkout::RegionCheckoutError;
use crate::alignment::status_synthesizer::SynthesizedPaymentStatus;
use crate::alignment::tx_correlation::TxCorrelationError;

const MAX_API_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

/// Maps a Paymob [`SynthesizedPaymentStatus`] to a canonical [`PaymentStatus`].
///
/// # Example
///
/// ```rust
/// use some_payment_core::PaymentStatus;
/// use some_paymob::adapter::paymob_provider::map_synthesized_status;
/// use some_paymob::alignment::status_synthesizer::SynthesizedPaymentStatus;
///
/// assert_eq!(
///     map_synthesized_status(SynthesizedPaymentStatus::Authorized),
///     PaymentStatus::Authorized
/// );
/// assert_eq!(
///     map_synthesized_status(SynthesizedPaymentStatus::PartiallyRefunded),
///     PaymentStatus::PartiallyRefunded
/// );
/// ```
#[must_use]
pub const fn map_synthesized_status(status: SynthesizedPaymentStatus) -> PaymentStatus {
    match status {
        SynthesizedPaymentStatus::Processing => PaymentStatus::Processing,
        SynthesizedPaymentStatus::Failed => PaymentStatus::Failed,
        SynthesizedPaymentStatus::Voided => PaymentStatus::Voided,
        SynthesizedPaymentStatus::Refunded => PaymentStatus::Refunded,
        SynthesizedPaymentStatus::PartiallyRefunded => PaymentStatus::PartiallyRefunded,
        SynthesizedPaymentStatus::Authorized => PaymentStatus::Authorized,
        SynthesizedPaymentStatus::PartiallyCaptured => PaymentStatus::PartiallyCaptured,
        SynthesizedPaymentStatus::Captured => PaymentStatus::Captured,
        SynthesizedPaymentStatus::Paid => PaymentStatus::Paid,
    }
}

pub(super) async fn parse_api_response<T: for<'de> Deserialize<'de>>(
    provider_id: &ProviderId,
    operation: &'static str,
    response: Response,
) -> Result<T, PaymentError> {
    let status = response.status();
    if !status.is_success() {
        return Err(map_http_status_error(provider_id, operation, status));
    }
    let bytes = read_bounded_body(provider_id, operation, response).await?;
    serde_json::from_slice::<T>(&bytes).map_err(|_| PaymentError::ProviderError {
        provider: provider_id.clone(),
        http_status: Some(status.as_u16()),
        vendor_code: None,
        message: format!("failed to decode paymob {operation} JSON response"),
    })
}

async fn read_bounded_body(
    provider_id: &ProviderId,
    operation: &'static str,
    mut response: Response,
) -> Result<Vec<u8>, PaymentError> {
    let status = response.status();
    if response
        .content_length()
        .is_some_and(|len| len > MAX_API_RESPONSE_BYTES as u64)
    {
        return Err(oversized_response_error(provider_id, operation, status));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|err| map_transport_error(provider_id, operation, err))?
    {
        if body.len().saturating_add(chunk.len()) > MAX_API_RESPONSE_BYTES {
            return Err(oversized_response_error(provider_id, operation, status));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn oversized_response_error(
    provider_id: &ProviderId,
    operation: &'static str,
    status: StatusCode,
) -> PaymentError {
    PaymentError::ProviderError {
        provider: provider_id.clone(),
        http_status: Some(status.as_u16()),
        vendor_code: None,
        message: format!(
            "paymob {operation} response exceeded {MAX_API_RESPONSE_BYTES} byte limit"
        ),
    }
}

pub(super) fn map_http_status_error(
    provider_id: &ProviderId,
    operation: &'static str,
    status: StatusCode,
) -> PaymentError {
    let code = status.as_u16();
    match code {
        401 | 403 => PaymentError::AuthenticationError {
            provider: provider_id.clone(),
            message: format!("paymob rejected credentials for {operation}"),
        },
        429 => PaymentError::RateLimited {
            provider: provider_id.clone(),
            retry_after_secs: None,
        },
        500..=599 => PaymentError::ProviderUnavailable {
            provider: provider_id.clone(),
            http_status: Some(code),
            indeterminate: true,
            message: format!("paymob returned HTTP {code} during {operation}"),
        },
        _ => PaymentError::ProviderError {
            provider: provider_id.clone(),
            http_status: Some(code),
            vendor_code: None,
            message: format!("paymob returned HTTP {code} during {operation}"),
        },
    }
}

pub(super) fn map_transport_error(
    provider_id: &ProviderId,
    operation: &'static str,
    err: reqwest::Error,
) -> PaymentError {
    let kind = if err.is_timeout() {
        "timeout"
    } else if err.is_connect() {
        "connection error"
    } else {
        "transport error"
    };
    PaymentError::ProviderUnavailable {
        provider: provider_id.clone(),
        http_status: None,
        indeterminate: true,
        message: format!("paymob {operation} failed with {kind}"),
    }
}

pub(super) fn map_integration_error(err: IntegrationValidationError) -> PaymentError {
    match err {
        IntegrationValidationError::ConfigurationError(msg) => PaymentError::configuration(msg),
        IntegrationValidationError::ValidationError(msg) => PaymentError::validation(msg),
    }
}

pub(super) fn map_region_error(err: RegionCheckoutError) -> PaymentError {
    PaymentError::configuration(err.to_string())
}

pub(super) fn map_dual_auth_config_error(err: DualAuthError) -> PaymentError {
    PaymentError::configuration(err.to_string())
}

pub(super) fn map_dual_auth_error(provider_id: &ProviderId, err: DualAuthError) -> PaymentError {
    match err {
        DualAuthError::Unauthorized => PaymentError::AuthenticationError {
            provider: provider_id.clone(),
            message: "paymob authentication rejected (HTTP 401)".to_owned(),
        },
        DualAuthError::UnexpectedStatus { status, detail } => PaymentError::ProviderUnavailable {
            provider: provider_id.clone(),
            http_status: Some(status),
            indeterminate: status >= 500,
            message: detail,
        },
        DualAuthError::Transport(detail) => PaymentError::ProviderUnavailable {
            provider: provider_id.clone(),
            http_status: None,
            indeterminate: true,
            message: detail,
        },
        other => PaymentError::configuration(other.to_string()),
    }
}

pub(super) fn map_tx_correlation_error(
    provider_id: &ProviderId,
    err: TxCorrelationError,
) -> PaymentError {
    match err {
        TxCorrelationError::MissingLookupReference
        | TxCorrelationError::InvalidTransactionId(_)
        | TxCorrelationError::ArithmeticUnderflow { .. }
        | TxCorrelationError::NothingRemainingToRefund { .. } => {
            PaymentError::validation(err.to_string())
        }
        TxCorrelationError::HttpStatus { status, endpoint } => {
            let status_code = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
            map_http_status_error(provider_id, endpoint, status_code)
        }
        TxCorrelationError::Transport { endpoint, detail } => PaymentError::ProviderUnavailable {
            provider: provider_id.clone(),
            http_status: None,
            indeterminate: true,
            message: format!("{endpoint}: {detail}"),
        },
        TxCorrelationError::Decode { endpoint, detail } => PaymentError::ProviderError {
            provider: provider_id.clone(),
            http_status: None,
            vendor_code: None,
            message: format!("{endpoint}: {detail}"),
        },
        TxCorrelationError::InvalidBaseUrl | TxCorrelationError::EmptyAuthToken => {
            PaymentError::configuration(err.to_string())
        }
    }
}

pub(super) fn map_callback_error(
    provider_id: &ProviderId,
    err: CallbackDispatchError,
) -> PaymentError {
    PaymentError::WebhookVerificationFailed {
        provider: provider_id.clone(),
        reason: err.to_string(),
    }
}

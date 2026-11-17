#![forbid(unsafe_code)]
//! Opt-in Legacy Accept v2 3-step checkout flow (`auth_token` -> `order` -> `payment_key` -> `iframe`).

pub mod orders;
pub mod payment_keys;
pub mod service;

pub use orders::{
    AuthenticatedLegacyOrderRequest, CreateLegacyOrderParams, LEGACY_ORDERS_PATH, LegacyOrder,
    LegacyOrderItem, create_legacy_order,
};
pub use payment_keys::{
    CreatePaymentKeyParams, DEFAULT_PAYMENT_KEY_EXPIRATION_SECS, LEGACY_PAYMENT_KEYS_PATH,
    LegacyBillingData, PaymentKeyResponse, create_legacy_payment_key,
};
pub use service::{LegacyCheckoutParams, LegacyCheckoutSession, LegacyV2Service};

use crate::core::auth::accept_jwt::AcceptJwtError;
use crate::core::error::PaymobError;

pub(crate) fn map_jwt_err(err: AcceptJwtError) -> PaymobError {
    match err {
        AcceptJwtError::EmptyApiKey | AcceptJwtError::InvalidCredentials => {
            PaymobError::AuthenticationError(err.to_string())
        }
        AcceptJwtError::InvalidBaseUrl(_) | AcceptJwtError::InvalidJsonBody => {
            PaymobError::ValidationError {
                field: "auth_token",
                reason: err.to_string(),
            }
        }
        AcceptJwtError::UnexpectedStatus { status, detail } => PaymobError::ApiError {
            status,
            message: detail,
            code: None,
        },
        _ => PaymobError::TransportError(err.to_string()),
    }
}

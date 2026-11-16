#![forbid(unsafe_code)]
//! 4-Regime authentication state machine and lock-free single-flight token cache.

pub mod accept_jwt;
pub mod cache;
pub mod partner;
pub mod payouts_oauth;
pub mod strategy;

use std::time::Duration;

use reqwest::Client;
use reqwest::header::HeaderValue;
use secrecy::{ExposeSecret, SecretString};
use url::Url;
use zeroize::Zeroizing;

use crate::core::error::PaymobError;

pub use accept_jwt::{
    ACCEPT_AUTH_TOKENS_PATH, ACCEPT_JWT_REFRESH_MARGIN_SECS, ACCEPT_JWT_TTL_SECS, AcceptJwtError,
    AcceptJwtProvider, format_bearer_header, inject_body_auth_token,
    is_incorrect_credentials_401,
};
pub use cache::{
    CachedToken, DEFAULT_TOKEN_TTL_SECS, PROACTIVE_REFRESH_MARGIN_SECS, TokenCache,
};
pub use partner::{
    DEFAULT_MERCHANT_ID_HEADER, DEFAULT_PARTNER_API_KEY_HEADER,
    DEFAULT_PARTNER_API_KEY_QUERY_PARAM, PartnerApiKeyLocation, PartnerAuthContext,
    PartnerAuthError, PartnerAuthMode,
};
pub use payouts_oauth::{
    PAYOUTS_OAUTH_TOKEN_PATH, PAYOUTS_TOKEN_TTL_SECS, PayoutsCredentials, PayoutsOAuthError,
    PayoutsOAuthProvider, format_basic_auth_header,
};
pub use strategy::{
    AuthRegime, AuthStrategy, EndpointAuthSpec, StrategyError, inject_secret_key_token,
};

const DEFAULT_AUTH_HTTP_TIMEOUT_SECS: u64 = 30;

/// Builds a default `reqwest::Client` with a bounded timeout for auth token acquisition.
pub(crate) fn build_default_auth_client() -> Result<Client, reqwest::Error> {
    Client::builder()
        .timeout(Duration::from_secs(DEFAULT_AUTH_HTTP_TIMEOUT_SECS))
        .build()
}

/// Formats `<scheme> <secret>` as a sensitive [`HeaderValue`] with zeroized staging memory.
pub(crate) fn format_sensitive_auth_header(
    scheme: &str,
    secret: &SecretString,
) -> Option<HeaderValue> {
    let raw = secret.expose_secret();
    let mut formatted = Zeroizing::new(String::with_capacity(scheme.len() + 1 + raw.len()));
    formatted.push_str(scheme);
    formatted.push(' ');
    formatted.push_str(raw);

    let mut value = HeaderValue::from_str(&formatted).ok()?;
    value.set_sensitive(true);
    Some(value)
}

/// Parses `base_url` as an HTTP/HTTPS URL with host and joins `path`.
pub(crate) fn join_http_url(base_url: &str, path: &str) -> Result<Url, String> {
    let parsed = Url::parse(base_url).map_err(|err| err.to_string())?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return Err(String::from("expected http(s) URL with host"));
    }
    parsed.join(path).map_err(|err| err.to_string())
}

/// Formats a `reqwest::Error` with any URL query string stripped to prevent secret leakage.
pub(crate) fn format_sanitized_transport_error(err: &reqwest::Error) -> String {
    let raw = err.to_string();
    let Some(url) = err.url() else {
        return raw;
    };
    if url.query().is_none() {
        return raw;
    }
    let mut scrubbed = url.clone();
    scrubbed.set_query(None);
    raw.replace(url.as_str(), scrubbed.as_str())
}

impl From<StrategyError> for PaymobError {
    fn from(err: StrategyError) -> Self {
        match err {
            StrategyError::EmptySecretKey | StrategyError::InvalidHeaderValue => {
                Self::ValidationError {
                    field: "secret_key",
                    reason: err.to_string(),
                }
            }
            StrategyError::EmptyEndpointPath | StrategyError::InvalidEndpointPath { .. } => {
                Self::ValidationError {
                    field: "endpoint_path",
                    reason: err.to_string(),
                }
            }
            StrategyError::StrategyMismatch { .. } => Self::AuthenticationError(err.to_string()),
        }
    }
}

impl From<AcceptJwtError> for PaymobError {
    fn from(err: AcceptJwtError) -> Self {
        match err {
            AcceptJwtError::EmptyApiKey => Self::ValidationError {
                field: "api_key",
                reason: err.to_string(),
            },
            AcceptJwtError::InvalidBaseUrl(_) => Self::ValidationError {
                field: "base_url",
                reason: err.to_string(),
            },
            AcceptJwtError::InvalidHeaderValue => Self::ValidationError {
                field: "auth_token",
                reason: err.to_string(),
            },
            AcceptJwtError::InvalidJsonBody => Self::ValidationError {
                field: "body",
                reason: err.to_string(),
            },
            AcceptJwtError::InvalidCredentials | AcceptJwtError::MissingTokenField => {
                Self::AuthenticationError(err.to_string())
            }
            AcceptJwtError::UnexpectedStatus { status, detail } => Self::ApiError {
                status,
                message: detail,
                code: None,
            },
            AcceptJwtError::Transport(_) => Self::TransportError(err.to_string()),
        }
    }
}

impl From<PayoutsOAuthError> for PaymobError {
    fn from(err: PayoutsOAuthError) -> Self {
        match err {
            PayoutsOAuthError::EmptyCredential(field) => Self::ValidationError {
                field,
                reason: err.to_string(),
            },
            PayoutsOAuthError::InvalidBaseUrl(_) => Self::ValidationError {
                field: "base_url",
                reason: err.to_string(),
            },
            PayoutsOAuthError::InvalidHeaderValue => Self::ValidationError {
                field: "authorization",
                reason: err.to_string(),
            },
            PayoutsOAuthError::InvalidCredentials | PayoutsOAuthError::MissingAccessToken => {
                Self::AuthenticationError(err.to_string())
            }
            PayoutsOAuthError::UnexpectedStatus { status, detail } => Self::ApiError {
                status,
                message: detail,
                code: None,
            },
            PayoutsOAuthError::Transport(_) => Self::TransportError(err.to_string()),
        }
    }
}

impl From<PartnerAuthError> for PaymobError {
    fn from(err: PartnerAuthError) -> Self {
        match err {
            PartnerAuthError::EmptyBearerToken => Self::ValidationError {
                field: "bearer_token",
                reason: err.to_string(),
            },
            PartnerAuthError::EmptyApiKey => Self::ValidationError {
                field: "api_key",
                reason: err.to_string(),
            },
            PartnerAuthError::EmptyMerchantId => Self::ValidationError {
                field: "merchant_id",
                reason: err.to_string(),
            },
            PartnerAuthError::InvalidHeaderName(_) => Self::ValidationError {
                field: "header_name",
                reason: err.to_string(),
            },
            PartnerAuthError::EmptyQueryParamName => Self::ValidationError {
                field: "query_param",
                reason: err.to_string(),
            },
            PartnerAuthError::InvalidHeaderValue => Self::ValidationError {
                field: "header_value",
                reason: err.to_string(),
            },
            PartnerAuthError::MissingCredential => Self::AuthenticationError(err.to_string()),
        }
    }
}

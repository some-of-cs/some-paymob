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

macro_rules! impl_paymob_error_from {
    (
        $err_ty:ty,
        validation: [$( $val_pat:pat => $field:expr ),+ $(,)?],
        auth: $auth_pat:pat,
        $(
            api: $api_pat:pat => ($status:ident, $detail:ident),
            transport: $trans_pat:pat,
        )?
    ) => {
        impl From<$err_ty> for PaymobError {
            fn from(err: $err_ty) -> Self {
                match err {
                    $(
                        $val_pat => Self::ValidationError {
                            field: $field,
                            reason: err.to_string(),
                        },
                    )+
                    $auth_pat => Self::AuthenticationError(err.to_string()),
                    $(
                        $api_pat => Self::ApiError {
                            status: $status,
                            message: $detail,
                            code: None,
                        },
                        $trans_pat => Self::TransportError(err.to_string()),
                    )?
                }
            }
        }
    };
}

impl_paymob_error_from!(
    StrategyError,
    validation: [
        StrategyError::EmptySecretKey | StrategyError::InvalidHeaderValue => "secret_key",
        StrategyError::EmptyEndpointPath | StrategyError::InvalidEndpointPath { .. } => {
            "endpoint_path"
        },
    ],
    auth: StrategyError::StrategyMismatch { .. },
);

impl_paymob_error_from!(
    AcceptJwtError,
    validation: [
        AcceptJwtError::EmptyApiKey => "api_key",
        AcceptJwtError::InvalidBaseUrl(_) => "base_url",
        AcceptJwtError::InvalidHeaderValue => "auth_token",
        AcceptJwtError::InvalidJsonBody => "body",
    ],
    auth: AcceptJwtError::InvalidCredentials | AcceptJwtError::MissingTokenField,
    api: AcceptJwtError::UnexpectedStatus { status, detail } => (status, detail),
    transport: AcceptJwtError::Transport(_),
);

impl_paymob_error_from!(
    PayoutsOAuthError,
    validation: [
        PayoutsOAuthError::EmptyCredential(field) => field,
        PayoutsOAuthError::InvalidBaseUrl(_) => "base_url",
        PayoutsOAuthError::InvalidHeaderValue => "authorization",
    ],
    auth: PayoutsOAuthError::InvalidCredentials | PayoutsOAuthError::MissingAccessToken,
    api: PayoutsOAuthError::UnexpectedStatus { status, detail } => (status, detail),
    transport: PayoutsOAuthError::Transport(_),
);

impl_paymob_error_from!(
    PartnerAuthError,
    validation: [
        PartnerAuthError::EmptyBearerToken => "bearer_token",
        PartnerAuthError::EmptyApiKey => "api_key",
        PartnerAuthError::EmptyMerchantId => "merchant_id",
        PartnerAuthError::InvalidHeaderName(_) => "header_name",
        PartnerAuthError::EmptyQueryParamName => "query_param",
        PartnerAuthError::InvalidHeaderValue => "header_value",
    ],
    auth: PartnerAuthError::MissingCredential,
);

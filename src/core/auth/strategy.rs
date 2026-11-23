#![forbid(unsafe_code)]
//! Authentication strategy taxonomy, endpoint binding, and Regime 1 `Token` header injector.
//!
//! Paymob exposes four distinct authentication regimes across its regional APIs plus public
//! key-only frontend flows. Mixing schemes (for example, sending `Authorization: Bearer` to
//! `/v1/intention/`) results in HTTP `401 Unauthorized`. This module defines [`AuthStrategy`]
//! and [`EndpointAuthSpec`] to bind every endpoint to its exact regime at compile/build time,
//! and provides [`inject_secret_key_token`] for Regime 1 (`Authorization: Token <secret_key>`).

use std::borrow::Cow;
use std::fmt;

use reqwest::Method;
use reqwest::header::{AUTHORIZATION, HeaderMap};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::core::auth::format_sensitive_auth_header;

/// High-level Paymob authentication regime grouping for [`AuthStrategy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum AuthRegime {
    /// Regime 1: Secret key `Authorization: Token <secret_key>` (e.g. Unified Intention API).
    Regime1SecretKey,
    /// Regime 2: 60-minute Accept JWT (`Bearer` header or JSON body `"auth_token"`).
    Regime2AcceptJwt,
    /// Regime 3: Payouts OAuth 2.0 `Bearer` access token (`password` / `refresh_token` grants).
    Regime3PayoutsOAuth2,
    /// Regime 4: Partner delegated authentication (`Bearer` or `api_key`).
    Regime4Partner,
    /// Public-key-only frontend/checkout flow (`pk_*`), no secret header attached.
    Public,
}

/// Exact authentication strategy required by a Paymob HTTP endpoint.
///
/// # Examples
///
/// ```rust
/// use some_paymob::core::auth::strategy::{AuthRegime, AuthStrategy};
///
/// let strategy = AuthStrategy::SecretKeyToken;
/// assert_eq!(strategy.regime(), AuthRegime::Regime1SecretKey);
/// assert!(strategy.requires_secret());
/// assert!(strategy.uses_authorization_header());
/// assert_eq!(strategy.as_str(), "SecretKeyToken");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum AuthStrategy {
    /// Regime 1: `Authorization: Token <secret_key>` (used by `/v1/intention/`).
    SecretKeyToken = 0,
    /// Regime 2: `Authorization: Bearer <auth_token>` using the 60-minute Accept JWT.
    AcceptJwtBearer = 1,
    /// Regime 2: JSON body `"auth_token": "<auth_token>"` using the 60-minute Accept JWT.
    AcceptJwtBody = 2,
    /// Regime 3: `Authorization: Bearer <access_token>` from Payouts OAuth 2.0.
    PayoutsOAuth2 = 3,
    /// Regime 4: `Authorization: Bearer <partner_token>` for delegated partner calls.
    PartnerBearer = 4,
    /// Regime 4: Partner API key header or query parameter authentication.
    PartnerApiKey = 5,
    /// Public-key-only flow (`pk_*`); no secret credential is transmitted.
    PublicKeyOnly = 6,
}

const STRATEGY_NAMES: [&str; 7] = [
    "SecretKeyToken",
    "AcceptJwtBearer",
    "AcceptJwtBody",
    "PayoutsOAuth2",
    "PartnerBearer",
    "PartnerApiKey",
    "PublicKeyOnly",
];

impl AuthStrategy {
    /// Returns the overarching [`AuthRegime`] for this strategy.
    #[must_use]
    pub const fn regime(&self) -> AuthRegime {
        match self {
            Self::SecretKeyToken => AuthRegime::Regime1SecretKey,
            Self::AcceptJwtBearer | Self::AcceptJwtBody => AuthRegime::Regime2AcceptJwt,
            Self::PayoutsOAuth2 => AuthRegime::Regime3PayoutsOAuth2,
            Self::PartnerBearer | Self::PartnerApiKey => AuthRegime::Regime4Partner,
            Self::PublicKeyOnly => AuthRegime::Public,
        }
    }

    /// Returns `true` if this strategy transmits a secret credential or short-lived token.
    #[must_use]
    pub const fn requires_secret(&self) -> bool {
        !matches!(self, Self::PublicKeyOnly)
    }

    /// Returns `true` if this strategy attaches an HTTP `Authorization` header.
    #[must_use]
    pub const fn uses_authorization_header(&self) -> bool {
        matches!(
            self,
            Self::SecretKeyToken
                | Self::AcceptJwtBearer
                | Self::PayoutsOAuth2
                | Self::PartnerBearer
        )
    }

    /// Returns the canonical variant name as a static string slice.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        STRATEGY_NAMES[*self as usize]
    }
}

impl fmt::Display for AuthStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Errors produced when validating [`EndpointAuthSpec`] or injecting Regime 1 auth headers.
///
/// Error messages never include raw secret material.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum StrategyError {
    /// The provided secret key is empty.
    #[error("secret key must not be empty")]
    EmptySecretKey,
    /// The provided secret key contains invalid or unsafe HTTP header bytes.
    #[error("secret key contains invalid HTTP header characters")]
    InvalidHeaderValue,
    /// The endpoint path is empty.
    #[error("endpoint path must not be empty")]
    EmptyEndpointPath,
    /// The endpoint path does not start with `/` or contains invalid characters.
    #[error(
        "invalid endpoint path '{path}': must start with '/' and contain no whitespace or control characters"
    )]
    InvalidEndpointPath {
        /// The rejected endpoint path.
        path: String,
    },
    /// Attempted to apply an auth injector that does not match the endpoint's [`AuthStrategy`].
    #[error("auth strategy mismatch: expected {expected}, found {actual}")]
    StrategyMismatch {
        /// Expected authentication strategy for the operation.
        expected: AuthStrategy,
        /// Actual authentication strategy bound to the endpoint.
        actual: AuthStrategy,
    },
}

/// Binds a Paymob API endpoint path and HTTP method to its required [`AuthStrategy`].
///
/// # Examples
///
/// ```rust
/// use reqwest::Method;
/// use reqwest::header::{AUTHORIZATION, HeaderMap};
/// use secrecy::SecretString;
/// use some_paymob::core::auth::strategy::{AuthStrategy, EndpointAuthSpec};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let spec = EndpointAuthSpec::new("/v1/intention/", Method::POST, AuthStrategy::SecretKeyToken)?;
/// assert_eq!(spec.path(), "/v1/intention/");
/// assert_eq!(spec.method(), &Method::POST);
/// assert_eq!(spec.strategy(), AuthStrategy::SecretKeyToken);
///
/// let mut headers = HeaderMap::new();
/// let secret = SecretString::from("egy_sk_test_0123456789abcdef");
/// spec.apply_secret_key(&mut headers, &secret)?;
/// assert!(headers.contains_key(AUTHORIZATION));
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointAuthSpec {
    path: Cow<'static, str>,
    method: Method,
    strategy: AuthStrategy,
}

/// Ergonomic type alias for [`EndpointAuthSpec`] (`US-1.2.0`).
pub type EndpointSpec = EndpointAuthSpec;

impl EndpointAuthSpec {
    /// Constructs a validated [`EndpointAuthSpec`].
    ///
    /// Returns [`StrategyError::EmptyEndpointPath`] if `path` is empty, or
    /// [`StrategyError::InvalidEndpointPath`] if `path` does not start with `/`
    /// or contains ASCII whitespace or control characters.
    pub fn new(
        path: impl Into<Cow<'static, str>>,
        method: Method,
        strategy: AuthStrategy,
    ) -> Result<Self, StrategyError> {
        let path = path.into();
        if path.is_empty() {
            return Err(StrategyError::EmptyEndpointPath);
        }
        if !path.starts_with('/') || path.bytes().any(is_invalid_path_byte) {
            return Err(StrategyError::InvalidEndpointPath {
                path: path.into_owned(),
            });
        }
        Ok(Self {
            path,
            method,
            strategy,
        })
    }

    /// Returns the bound endpoint path (always starting with `/`).
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the bound HTTP [`Method`].
    #[must_use]
    pub const fn method(&self) -> &Method {
        &self.method
    }

    /// Returns the bound [`AuthStrategy`].
    #[must_use]
    pub const fn strategy(&self) -> AuthStrategy {
        self.strategy
    }

    /// Injects the Regime 1 `Authorization: Token <secret_key>` header if and only if
    /// this endpoint is bound to [`AuthStrategy::SecretKeyToken`].
    ///
    /// Returns [`StrategyError::StrategyMismatch`] for any other [`AuthStrategy`].
    pub fn apply_secret_key(
        &self,
        headers: &mut HeaderMap,
        secret_key: &SecretString,
    ) -> Result<(), StrategyError> {
        if self.strategy != AuthStrategy::SecretKeyToken {
            return Err(StrategyError::StrategyMismatch {
                expected: AuthStrategy::SecretKeyToken,
                actual: self.strategy,
            });
        }
        inject_secret_key_token(headers, secret_key)
    }
}

/// Injects the Regime 1 `Authorization: Token <secret_key>` header into `headers`.
///
/// The resulting `HeaderValue` is marked sensitive (`set_sensitive(true)`) so `HeaderMap`
/// debug output redacts the credential, and intermediate formatting buffers are zeroized
/// on drop.
///
/// # Examples
///
/// ```rust
/// use reqwest::header::{AUTHORIZATION, HeaderMap};
/// use secrecy::SecretString;
/// use some_paymob::core::auth::strategy::inject_secret_key_token;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut headers = HeaderMap::new();
/// let secret = SecretString::from("egy_sk_test_example");
/// inject_secret_key_token(&mut headers, &secret)?;
///
/// let header = headers.get(AUTHORIZATION).expect("authorization header present");
/// assert!(header.is_sensitive());
/// assert_eq!(header.to_str()?, "Token egy_sk_test_example");
/// # Ok(())
/// # }
/// ```
pub fn inject_secret_key_token(
    headers: &mut HeaderMap,
    secret_key: &SecretString,
) -> Result<(), StrategyError> {
    let raw_input = secret_key.expose_secret();
    if raw_input.is_empty() {
        return Err(StrategyError::EmptySecretKey);
    }
    if raw_input.bytes().any(is_invalid_token_byte) {
        return Err(StrategyError::InvalidHeaderValue);
    }
    let resolved = if raw_input.starts_with('$') {
        crate::core::credentials::resolve_secret_or_env_with("secret_key", raw_input, |var| {
            std::env::var(var).ok().filter(|v| !v.trim().is_empty())
        })
        .map_err(|_| StrategyError::EmptySecretKey)?
    } else {
        secret_key.clone()
    };
    let raw = resolved.expose_secret();
    if raw.is_empty() {
        return Err(StrategyError::EmptySecretKey);
    }
    if raw.bytes().any(is_invalid_token_byte) {
        return Err(StrategyError::InvalidHeaderValue);
    }

    let value = format_sensitive_auth_header("Token", &resolved)
        .ok_or(StrategyError::InvalidHeaderValue)?;
    headers.insert(AUTHORIZATION, value);
    Ok(())
}

#[inline]
const fn is_invalid_path_byte(byte: u8) -> bool {
    byte.is_ascii_control() || byte.is_ascii_whitespace()
}

#[inline]
const fn is_invalid_token_byte(byte: u8) -> bool {
    byte.is_ascii_control() || byte.is_ascii_whitespace()
}

#[cfg(test)]
mod tests {
    use reqwest::header::HeaderValue;

    use super::*;

    #[test]
    fn tc_1_2_1_auth_strategy_taxonomy_and_regimes() {
        let cases = [
            (
                AuthStrategy::SecretKeyToken,
                AuthRegime::Regime1SecretKey,
                true,
                true,
                "SecretKeyToken",
            ),
            (
                AuthStrategy::AcceptJwtBearer,
                AuthRegime::Regime2AcceptJwt,
                true,
                true,
                "AcceptJwtBearer",
            ),
            (
                AuthStrategy::AcceptJwtBody,
                AuthRegime::Regime2AcceptJwt,
                true,
                false,
                "AcceptJwtBody",
            ),
            (
                AuthStrategy::PayoutsOAuth2,
                AuthRegime::Regime3PayoutsOAuth2,
                true,
                true,
                "PayoutsOAuth2",
            ),
            (
                AuthStrategy::PartnerBearer,
                AuthRegime::Regime4Partner,
                true,
                true,
                "PartnerBearer",
            ),
            (
                AuthStrategy::PartnerApiKey,
                AuthRegime::Regime4Partner,
                true,
                false,
                "PartnerApiKey",
            ),
            (
                AuthStrategy::PublicKeyOnly,
                AuthRegime::Public,
                false,
                false,
                "PublicKeyOnly",
            ),
        ];

        for (strategy, regime, needs_secret, uses_auth_hdr, name) in cases {
            assert_eq!(strategy.regime(), regime);
            assert_eq!(strategy.requires_secret(), needs_secret);
            assert_eq!(strategy.uses_authorization_header(), uses_auth_hdr);
            assert_eq!(strategy.as_str(), name);
            assert_eq!(strategy.to_string(), name);

            let serialized = serde_json::to_string(&strategy).expect("serialize strategy");
            let deserialized: AuthStrategy =
                serde_json::from_str(&serialized).expect("deserialize strategy");
            assert_eq!(deserialized, strategy);
        }
    }

    #[test]
    fn tc_1_2_1_endpoint_auth_spec_valid_and_invalid_paths() {
        let intention =
            EndpointAuthSpec::new("/v1/intention/", Method::POST, AuthStrategy::SecretKeyToken)
                .expect("valid intention spec");
        assert_eq!(intention.path(), "/v1/intention/");
        assert_eq!(intention.method(), &Method::POST);
        assert_eq!(intention.strategy(), AuthStrategy::SecretKeyToken);

        let inquiry = EndpointAuthSpec::new(
            String::from("/api/ecommerce/orders/transaction_inquiry"),
            Method::POST,
            AuthStrategy::AcceptJwtBody,
        )
        .expect("valid owned path spec");
        assert_eq!(inquiry.strategy(), AuthStrategy::AcceptJwtBody);

        assert_eq!(
            EndpointAuthSpec::new("", Method::GET, AuthStrategy::PublicKeyOnly),
            Err(StrategyError::EmptyEndpointPath)
        );
        assert_eq!(
            EndpointAuthSpec::new("v1/intention/", Method::POST, AuthStrategy::SecretKeyToken),
            Err(StrategyError::InvalidEndpointPath {
                path: String::from("v1/intention/"),
            })
        );
        assert_eq!(
            EndpointAuthSpec::new(
                "/v1/intention/ bad",
                Method::POST,
                AuthStrategy::SecretKeyToken
            ),
            Err(StrategyError::InvalidEndpointPath {
                path: String::from("/v1/intention/ bad"),
            })
        );
        assert_eq!(
            EndpointAuthSpec::new(
                "/v1/intention/\n",
                Method::POST,
                AuthStrategy::SecretKeyToken
            ),
            Err(StrategyError::InvalidEndpointPath {
                path: String::from("/v1/intention/\n"),
            })
        );
    }

    #[test]
    fn tc_1_2_1_inject_secret_key_token_positive_and_overwrite() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer stale"));

        let secret = SecretString::from("egy_sk_test_1234567890");
        inject_secret_key_token(&mut headers, &secret).expect("inject valid secret key");

        let value = headers.get(AUTHORIZATION).expect("header present");
        assert!(value.is_sensitive());
        assert_eq!(
            value.to_str().expect("valid utf8"),
            "Token egy_sk_test_1234567890"
        );
    }

    #[test]
    fn tc_1_2_1_inject_secret_key_token_rejects_malformed_inputs() {
        let mut headers = HeaderMap::new();

        assert_eq!(
            inject_secret_key_token(&mut headers, &SecretString::from("")),
            Err(StrategyError::EmptySecretKey)
        );
        assert_eq!(
            inject_secret_key_token(&mut headers, &SecretString::from("   ")),
            Err(StrategyError::InvalidHeaderValue)
        );
        assert_eq!(
            inject_secret_key_token(&mut headers, &SecretString::from("sk_test with_space")),
            Err(StrategyError::InvalidHeaderValue)
        );
        assert_eq!(
            inject_secret_key_token(&mut headers, &SecretString::from("sk_test\r\nX-Inject: 1")),
            Err(StrategyError::InvalidHeaderValue)
        );
        assert_eq!(
            inject_secret_key_token(&mut headers, &SecretString::from("sk_test\0null")),
            Err(StrategyError::InvalidHeaderValue)
        );
        assert!(!headers.contains_key(AUTHORIZATION));
    }

    #[test]
    fn tc_1_2_1_apply_secret_key_enforces_strategy_segregation() {
        let secret = SecretString::from("egy_sk_test_segregation");
        let intention =
            EndpointAuthSpec::new("/v1/intention/", Method::POST, AuthStrategy::SecretKeyToken)
                .expect("intention spec");
        let mut ok_headers = HeaderMap::new();
        intention
            .apply_secret_key(&mut ok_headers, &secret)
            .expect("regime 1 accepts secret key");
        assert!(ok_headers.contains_key(AUTHORIZATION));

        for wrong_strategy in [
            AuthStrategy::AcceptJwtBearer,
            AuthStrategy::AcceptJwtBody,
            AuthStrategy::PayoutsOAuth2,
            AuthStrategy::PartnerBearer,
            AuthStrategy::PartnerApiKey,
            AuthStrategy::PublicKeyOnly,
        ] {
            let spec = EndpointAuthSpec::new("/api/test", Method::POST, wrong_strategy)
                .expect("valid spec");
            let mut headers = HeaderMap::new();
            let err = spec
                .apply_secret_key(&mut headers, &secret)
                .expect_err("non-regime-1 strategy must reject secret key token");
            assert_eq!(
                err,
                StrategyError::StrategyMismatch {
                    expected: AuthStrategy::SecretKeyToken,
                    actual: wrong_strategy,
                }
            );
            assert!(!headers.contains_key(AUTHORIZATION));
        }
    }

    #[test]
    fn tc_1_2_1_debug_output_redacts_secret_material() {
        let raw_secret = "egy_sk_live_super_secret_do_not_leak";
        let secret = SecretString::from(raw_secret);
        let secret_dbg = format!("{secret:?}");
        assert!(!secret_dbg.contains(raw_secret));
        assert!(secret_dbg.contains("REDACTED"));

        let mut headers = HeaderMap::new();
        inject_secret_key_token(&mut headers, &secret).expect("inject token");
        let headers_dbg = format!("{headers:?}");
        assert!(!headers_dbg.contains(raw_secret));
    }
}

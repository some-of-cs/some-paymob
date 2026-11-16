#![forbid(unsafe_code)]
//! Regime 4 Partner Delegated authentication context (`US-1.2.0` / `unit-5`).
//!
//! Provides [`PartnerAuthContext`] for Paymob Partner & Sub-Merchant Onboarding APIs:
//! - [`PartnerAuthMode::PartnerBearer`]: injects `Authorization: Bearer <token>`.
//! - [`PartnerAuthMode::PartnerApiKey`]: injects a partner API key into an HTTP header
//!   (default: `X-Api-Key`) or URL query parameter (default: `api_key`).
//! - Sub-merchant delegation binding via [`PartnerAuthContext::with_merchant_id`] with
//!   non-empty validation and `X-Merchant-Id` header injection.
//!
//! All secret credentials are stored in [`secrecy::SecretString`], scrubbed on drop via
//! [`zeroize::ZeroizeOnDrop`], and redacted as `"[REDACTED]"` in [`fmt::Debug`].

use std::fmt;

use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderName, HeaderValue};
use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;
use url::Url;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Default HTTP header name used when injecting a partner API key.
pub const DEFAULT_PARTNER_API_KEY_HEADER: &str = "X-Api-Key";

/// Default URL query parameter name used when injecting a partner API key.
pub const DEFAULT_PARTNER_API_KEY_QUERY_PARAM: &str = "api_key";

/// Default HTTP header name used for sub-merchant delegation binding.
pub const DEFAULT_MERCHANT_ID_HEADER: &str = "X-Merchant-Id";

/// Regime 4 partner authentication mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
pub enum PartnerAuthMode {
    /// Injects `Authorization: Bearer <token>` on outgoing partner requests.
    PartnerBearer,
    /// Injects a partner API key into a configured HTTP header or URL query parameter.
    PartnerApiKey,
}

/// Target location for [`PartnerAuthMode::PartnerApiKey`] credential injection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
pub enum PartnerApiKeyLocation {
    /// Inject the partner API key as an HTTP header.
    Header,
    /// Inject the partner API key as a URL query parameter.
    Query,
}

/// Errors returned when constructing or applying [`PartnerAuthContext`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PartnerAuthError {
    /// Returned when a partner bearer token is empty or whitespace-only.
    #[error("partner bearer token must not be empty")]
    EmptyBearerToken,
    /// Returned when a partner API key is empty or whitespace-only.
    #[error("partner API key must not be empty")]
    EmptyApiKey,
    /// Returned when a sub-merchant `merchant_id` is empty or whitespace-only.
    #[error("sub-merchant ID must not be empty")]
    EmptyMerchantId,
    /// Returned when an HTTP header name is empty or contains invalid characters.
    #[error("invalid HTTP header name: {0}")]
    InvalidHeaderName(String),
    /// Returned when a URL query parameter name is empty or whitespace-only.
    #[error("partner API key query parameter name must not be empty")]
    EmptyQueryParamName,
    /// Returned when a credential or merchant ID contains invalid HTTP header bytes.
    #[error("value contains invalid HTTP header characters")]
    InvalidHeaderValue,
    /// Returned when the credential required by the active [`PartnerAuthMode`] is absent.
    #[error("partner credential is missing for the active auth mode")]
    MissingCredential,
}

/// Regime 4 Partner Delegated authentication context with optional sub-merchant binding.
///
/// Secrets are protected by [`SecretString`], zeroized on drop via [`ZeroizeOnDrop`],
/// and never exposed in [`fmt::Debug`] output (`"[REDACTED]"`).
///
/// # Examples
///
/// Bearer token with sub-merchant delegation:
///
/// ```rust
/// use reqwest::header::{AUTHORIZATION, HeaderMap};
/// use some_paymob::core::auth::partner::{DEFAULT_MERCHANT_ID_HEADER, PartnerAuthContext};
///
/// let ctx = PartnerAuthContext::bearer("partner_jwt_token")?
///     .with_merchant_id("merchant_42")?;
///
/// let mut headers = HeaderMap::new();
/// ctx.apply_headers(&mut headers)?;
///
/// assert_eq!(headers.get(AUTHORIZATION).unwrap(), "Bearer partner_jwt_token");
/// assert_eq!(headers.get(DEFAULT_MERCHANT_ID_HEADER).unwrap(), "merchant_42");
/// # Ok::<(), some_paymob::core::auth::partner::PartnerAuthError>(())
/// ```
///
/// Partner API key injected into URL query parameters:
///
/// ```rust
/// use reqwest::header::HeaderMap;
/// use some_paymob::core::auth::partner::PartnerAuthContext;
/// use url::Url;
///
/// let ctx = PartnerAuthContext::api_key_query("pk_partner_123")?;
/// let mut headers = HeaderMap::new();
/// let mut url = Url::parse("https://accept.paymob.com/api/partner/merchants")?;
///
/// ctx.apply_request(&mut headers, &mut url)?;
///
/// assert_eq!(
///     url.as_str(),
///     "https://accept.paymob.com/api/partner/merchants?api_key=pk_partner_123"
/// );
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PartnerAuthContext {
    mode: PartnerAuthMode,
    bearer_token: Option<SecretString>,
    api_key: Option<SecretString>,
    api_key_location: PartnerApiKeyLocation,
    api_key_header_name: String,
    api_key_query_param: String,
    merchant_id: Option<String>,
    merchant_id_header_name: String,
}

impl PartnerAuthContext {
    /// Creates a [`PartnerAuthMode::PartnerBearer`] context using `Authorization: Bearer <token>`.
    ///
    /// Returns [`PartnerAuthError::EmptyBearerToken`] if `token` is empty or whitespace-only.
    pub fn bearer(token: impl Into<String>) -> Result<Self, PartnerAuthError> {
        let validated = validate_non_empty(token.into(), PartnerAuthError::EmptyBearerToken)?;
        Ok(Self {
            mode: PartnerAuthMode::PartnerBearer,
            bearer_token: Some(SecretString::from(validated)),
            api_key: None,
            api_key_location: PartnerApiKeyLocation::Header,
            api_key_header_name: DEFAULT_PARTNER_API_KEY_HEADER.to_owned(),
            api_key_query_param: DEFAULT_PARTNER_API_KEY_QUERY_PARAM.to_owned(),
            merchant_id: None,
            merchant_id_header_name: DEFAULT_MERCHANT_ID_HEADER.to_owned(),
        })
    }

    /// Creates a [`PartnerAuthMode::PartnerApiKey`] context injecting into `X-Api-Key` header.
    ///
    /// Returns [`PartnerAuthError::EmptyApiKey`] if `api_key` is empty or whitespace-only.
    pub fn api_key_header(api_key: impl Into<String>) -> Result<Self, PartnerAuthError> {
        Self::api_key_with_header_name(api_key, DEFAULT_PARTNER_API_KEY_HEADER)
    }

    /// Creates a [`PartnerAuthMode::PartnerApiKey`] context injecting into a custom HTTP header.
    ///
    /// Returns [`PartnerAuthError::EmptyApiKey`] or [`PartnerAuthError::InvalidHeaderName`] on
    /// invalid input.
    pub fn api_key_with_header_name(
        api_key: impl Into<String>,
        header_name: impl Into<String>,
    ) -> Result<Self, PartnerAuthError> {
        let validated_key = validate_non_empty(api_key.into(), PartnerAuthError::EmptyApiKey)?;
        let validated_header = build_header_name(header_name.into())?;
        Ok(Self {
            mode: PartnerAuthMode::PartnerApiKey,
            bearer_token: None,
            api_key: Some(SecretString::from(validated_key)),
            api_key_location: PartnerApiKeyLocation::Header,
            api_key_header_name: validated_header.as_str().to_owned(),
            api_key_query_param: DEFAULT_PARTNER_API_KEY_QUERY_PARAM.to_owned(),
            merchant_id: None,
            merchant_id_header_name: DEFAULT_MERCHANT_ID_HEADER.to_owned(),
        })
    }

    /// Creates a [`PartnerAuthMode::PartnerApiKey`] context injecting into the `api_key` query param.
    ///
    /// Returns [`PartnerAuthError::EmptyApiKey`] if `api_key` is empty or whitespace-only.
    pub fn api_key_query(api_key: impl Into<String>) -> Result<Self, PartnerAuthError> {
        Self::api_key_with_query_param(api_key, DEFAULT_PARTNER_API_KEY_QUERY_PARAM)
    }

    /// Creates a [`PartnerAuthMode::PartnerApiKey`] context injecting into a custom query parameter.
    ///
    /// Returns [`PartnerAuthError::EmptyApiKey`] or [`PartnerAuthError::EmptyQueryParamName`] on
    /// invalid input.
    pub fn api_key_with_query_param(
        api_key: impl Into<String>,
        param_name: impl Into<String>,
    ) -> Result<Self, PartnerAuthError> {
        let validated_key = validate_non_empty(api_key.into(), PartnerAuthError::EmptyApiKey)?;
        let validated_param =
            validate_non_empty(param_name.into(), PartnerAuthError::EmptyQueryParamName)?;
        Ok(Self {
            mode: PartnerAuthMode::PartnerApiKey,
            bearer_token: None,
            api_key: Some(SecretString::from(validated_key)),
            api_key_location: PartnerApiKeyLocation::Query,
            api_key_header_name: DEFAULT_PARTNER_API_KEY_HEADER.to_owned(),
            api_key_query_param: validated_param,
            merchant_id: None,
            merchant_id_header_name: DEFAULT_MERCHANT_ID_HEADER.to_owned(),
        })
    }

    /// Binds a sub-merchant `merchant_id` for delegated partner operations.
    ///
    /// Returns [`PartnerAuthError::EmptyMerchantId`] if `merchant_id` is empty or whitespace-only.
    pub fn with_merchant_id(
        mut self,
        merchant_id: impl Into<String>,
    ) -> Result<Self, PartnerAuthError> {
        let validated = validate_non_empty(merchant_id.into(), PartnerAuthError::EmptyMerchantId)?;
        self.merchant_id = Some(validated);
        Ok(self)
    }

    /// Overrides the HTTP header name used when injecting the delegated `merchant_id`.
    ///
    /// Returns [`PartnerAuthError::InvalidHeaderName`] if `header_name` is not a valid HTTP
    /// header name.
    pub fn with_merchant_id_header(
        mut self,
        header_name: impl Into<String>,
    ) -> Result<Self, PartnerAuthError> {
        let validated_header = build_header_name(header_name.into())?;
        self.merchant_id_header_name = validated_header.as_str().to_owned();
        Ok(self)
    }

    /// Returns the active [`PartnerAuthMode`].
    #[must_use]
    pub const fn mode(&self) -> PartnerAuthMode {
        self.mode
    }

    /// Returns the [`PartnerApiKeyLocation`] when configured in [`PartnerAuthMode::PartnerApiKey`].
    #[must_use]
    pub const fn api_key_location(&self) -> Option<PartnerApiKeyLocation> {
        match self.mode {
            PartnerAuthMode::PartnerApiKey => Some(self.api_key_location),
            PartnerAuthMode::PartnerBearer => None,
        }
    }

    /// Returns the bound sub-merchant `merchant_id`, if any.
    #[must_use]
    pub fn merchant_id(&self) -> Option<&str> {
        self.merchant_id.as_deref()
    }

    /// Returns `true` when a sub-merchant `merchant_id` is bound to this context.
    #[must_use]
    pub const fn is_delegated(&self) -> bool {
        self.merchant_id.is_some()
    }

    /// Injects Regime 4 authentication and optional sub-merchant delegation headers into `headers`.
    pub fn apply_headers(&self, headers: &mut HeaderMap) -> Result<(), PartnerAuthError> {
        self.apply_auth_header(headers)?;
        self.apply_merchant_header(headers)?;
        Ok(())
    }

    /// Injects the partner API key into `url` query parameters when configured for query injection.
    pub fn apply_query(&self, url: &mut Url) -> Result<(), PartnerAuthError> {
        if self.mode != PartnerAuthMode::PartnerApiKey
            || self.api_key_location != PartnerApiKeyLocation::Query
        {
            return Ok(());
        }
        let Some(key) = self.api_key.as_ref() else {
            return Err(PartnerAuthError::MissingCredential);
        };
        url.query_pairs_mut()
            .append_pair(&self.api_key_query_param, key.expose_secret());
        Ok(())
    }

    /// Injects both HTTP headers and URL query parameters for a complete outgoing partner request.
    pub fn apply_request(
        &self,
        headers: &mut HeaderMap,
        url: &mut Url,
    ) -> Result<(), PartnerAuthError> {
        self.apply_headers(headers)?;
        self.apply_query(url)?;
        Ok(())
    }

    fn apply_auth_header(&self, headers: &mut HeaderMap) -> Result<(), PartnerAuthError> {
        match self.mode {
            PartnerAuthMode::PartnerBearer => self.apply_bearer_header(headers),
            PartnerAuthMode::PartnerApiKey => self.apply_api_key_header_if_needed(headers),
        }
    }

    fn apply_bearer_header(&self, headers: &mut HeaderMap) -> Result<(), PartnerAuthError> {
        let token = self
            .bearer_token
            .as_ref()
            .ok_or(PartnerAuthError::MissingCredential)?;
        let formatted = Zeroizing::new(format!("Bearer {}", token.expose_secret()));
        let value = build_header_value(&formatted, true)?;
        headers.insert(AUTHORIZATION, value);
        Ok(())
    }

    fn apply_api_key_header_if_needed(
        &self,
        headers: &mut HeaderMap,
    ) -> Result<(), PartnerAuthError> {
        if self.api_key_location != PartnerApiKeyLocation::Header {
            return Ok(());
        }
        let key = self
            .api_key
            .as_ref()
            .ok_or(PartnerAuthError::MissingCredential)?;
        let name = build_header_name(self.api_key_header_name.clone())?;
        let value = build_header_value(key.expose_secret(), true)?;
        headers.insert(name, value);
        Ok(())
    }

    fn apply_merchant_header(&self, headers: &mut HeaderMap) -> Result<(), PartnerAuthError> {
        let Some(id) = self.merchant_id.as_deref() else {
            return Ok(());
        };
        let name = build_header_name(self.merchant_id_header_name.clone())?;
        let value = build_header_value(id, false)?;
        headers.insert(name, value);
        Ok(())
    }
}

impl fmt::Debug for PartnerAuthContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PartnerAuthContext")
            .field("mode", &self.mode)
            .field(
                "bearer_token",
                &self.bearer_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("api_key", &self.api_key.as_ref().map(|_| "[REDACTED]"))
            .field("api_key_location", &self.api_key_location)
            .field("api_key_header_name", &self.api_key_header_name)
            .field("api_key_query_param", &self.api_key_query_param)
            .field("merchant_id", &self.merchant_id)
            .field("merchant_id_header_name", &self.merchant_id_header_name)
            .finish()
    }
}

fn validate_non_empty(value: String, err: PartnerAuthError) -> Result<String, PartnerAuthError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(err);
    }
    Ok(trimmed.to_owned())
}

fn build_header_name(name: String) -> Result<HeaderName, PartnerAuthError> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(PartnerAuthError::InvalidHeaderName(name));
    }
    HeaderName::from_bytes(trimmed.as_bytes())
        .map_err(|_| PartnerAuthError::InvalidHeaderName(name))
}

fn build_header_value(raw: &str, sensitive: bool) -> Result<HeaderValue, PartnerAuthError> {
    let mut header_value =
        HeaderValue::from_str(raw).map_err(|_| PartnerAuthError::InvalidHeaderValue)?;
    header_value.set_sensitive(sensitive);
    Ok(header_value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tc_1_2_5_partner_bearer_injects_authorization_header() {
        let ctx = PartnerAuthContext::bearer("  secret_partner_jwt  ")
            .expect("valid bearer token should construct context");
        assert_eq!(ctx.mode(), PartnerAuthMode::PartnerBearer);
        assert_eq!(ctx.api_key_location(), None);
        assert!(!ctx.is_delegated());

        let mut headers = HeaderMap::new();
        let mut url = Url::parse("https://accept.paymob.com/api/partner/profile")
            .expect("valid test URL");
        ctx.apply_request(&mut headers, &mut url)
            .expect("header injection should succeed");

        let auth_header = headers.get(AUTHORIZATION).expect("authorization header");
        assert!(auth_header.is_sensitive());
        assert_eq!(auth_header.to_str().ok(), Some("Bearer secret_partner_jwt"));
        assert_eq!(url.query(), None);
        assert!(headers.get(DEFAULT_MERCHANT_ID_HEADER).is_none());
    }

    #[test]
    fn tc_1_2_5_partner_api_key_header_injection() {
        let ctx = PartnerAuthContext::api_key_header("partner_api_key_abc")
            .expect("valid API key should construct header context");
        assert_eq!(ctx.mode(), PartnerAuthMode::PartnerApiKey);
        assert_eq!(ctx.api_key_location(), Some(PartnerApiKeyLocation::Header));

        let mut headers = HeaderMap::new();
        let mut url = Url::parse("https://accept.paymob.com/api/partner/merchants")
            .expect("valid test URL");
        ctx.apply_request(&mut headers, &mut url)
            .expect("API key header injection should succeed");

        let key_header = headers
            .get(DEFAULT_PARTNER_API_KEY_HEADER)
            .expect("api key header");
        assert!(key_header.is_sensitive());
        assert_eq!(key_header.to_str().ok(), Some("partner_api_key_abc"));
        assert!(headers.get(AUTHORIZATION).is_none());
        assert_eq!(url.query(), None);
    }

    #[test]
    fn tc_1_2_5_partner_api_key_custom_header_and_query_injection() {
        let custom_header_ctx =
            PartnerAuthContext::api_key_with_header_name("key_999", "X-Partner-Key")
                .expect("valid custom header should succeed");
        let mut headers = HeaderMap::new();
        custom_header_ctx
            .apply_headers(&mut headers)
            .expect("custom header injection should succeed");
        assert_eq!(
            headers
                .get("x-partner-key")
                .and_then(|v| v.to_str().ok()),
            Some("key_999")
        );

        let query_ctx = PartnerAuthContext::api_key_with_query_param("key_query_1", "partner_key")
            .expect("valid custom query param should succeed");
        let mut query_headers = HeaderMap::new();
        let mut url = Url::parse("https://accept.paymob.com/api/partner/hmac?region=egy")
            .expect("valid test URL");
        query_ctx
            .apply_request(&mut query_headers, &mut url)
            .expect("query injection should succeed");
        assert!(query_headers.is_empty());
        assert_eq!(
            url.as_str(),
            "https://accept.paymob.com/api/partner/hmac?region=egy&partner_key=key_query_1"
        );
    }

    #[test]
    fn tc_1_2_5_sub_merchant_delegation_binding() {
        let ctx = PartnerAuthContext::bearer("partner_tok_1")
            .expect("valid bearer")
            .with_merchant_id("  sub_merch_777  ")
            .expect("valid merchant_id")
            .with_merchant_id_header("X-Sub-Merchant")
            .expect("valid merchant header");
        assert!(ctx.is_delegated());
        assert_eq!(ctx.merchant_id(), Some("sub_merch_777"));

        let mut headers = HeaderMap::new();
        ctx.apply_headers(&mut headers)
            .expect("delegated headers should apply");
        assert_eq!(
            headers
                .get(AUTHORIZATION)
                .and_then(|v| v.to_str().ok()),
            Some("Bearer partner_tok_1")
        );
        assert_eq!(
            headers
                .get("x-sub-merchant")
                .and_then(|v| v.to_str().ok()),
            Some("sub_merch_777")
        );
    }

    #[test]
    fn tc_1_2_5_rejects_empty_and_malformed_inputs() {
        assert_eq!(
            PartnerAuthContext::bearer(""),
            Err(PartnerAuthError::EmptyBearerToken)
        );
        assert_eq!(
            PartnerAuthContext::bearer("   \t\n "),
            Err(PartnerAuthError::EmptyBearerToken)
        );
        assert_eq!(
            PartnerAuthContext::api_key_header("   "),
            Err(PartnerAuthError::EmptyApiKey)
        );
        assert_eq!(
            PartnerAuthContext::api_key_query(""),
            Err(PartnerAuthError::EmptyApiKey)
        );
        assert_eq!(
            PartnerAuthContext::api_key_with_query_param("valid_key", "  "),
            Err(PartnerAuthError::EmptyQueryParamName)
        );
        assert!(matches!(
            PartnerAuthContext::api_key_with_header_name("valid_key", "bad header name"),
            Err(PartnerAuthError::InvalidHeaderName(_))
        ));

        let base = PartnerAuthContext::bearer("valid_tok").expect("valid bearer");
        assert_eq!(
            base.clone().with_merchant_id(""),
            Err(PartnerAuthError::EmptyMerchantId)
        );
        assert_eq!(
            base.with_merchant_id("   "),
            Err(PartnerAuthError::EmptyMerchantId)
        );
    }

    #[test]
    fn tc_1_2_5_rejects_invalid_merchant_id_header_name() {
        let base = PartnerAuthContext::bearer("valid_tok")
            .expect("valid bearer")
            .with_merchant_id("merchant_123")
            .expect("valid merchant_id");

        assert!(matches!(
            base.clone().with_merchant_id_header(""),
            Err(PartnerAuthError::InvalidHeaderName(_))
        ));
        assert!(matches!(
            base.clone().with_merchant_id_header("   "),
            Err(PartnerAuthError::InvalidHeaderName(_))
        ));
        assert!(matches!(
            base.with_merchant_id_header("bad header name"),
            Err(PartnerAuthError::InvalidHeaderName(_))
        ));
    }

    #[test]
    fn tc_1_2_5_rejects_crlf_header_injection() {
        let bad_ctx = PartnerAuthContext::bearer("tok\r\nX-Injected: evil")
            .expect("construction defers header byte check to injection");
        let mut headers = HeaderMap::new();
        assert_eq!(
            bad_ctx.apply_headers(&mut headers),
            Err(PartnerAuthError::InvalidHeaderValue)
        );
        assert!(headers.is_empty());

        let bad_merchant = PartnerAuthContext::bearer("valid_tok")
            .expect("valid bearer")
            .with_merchant_id("m1\nX-Evil: 1")
            .expect("non-empty merchant_id");
        let mut headers2 = HeaderMap::new();
        assert_eq!(
            bad_merchant.apply_headers(&mut headers2),
            Err(PartnerAuthError::InvalidHeaderValue)
        );
    }

    #[test]
    fn tc_1_2_5_debug_redacts_all_secrets() {
        let bearer_ctx = PartnerAuthContext::bearer("super_secret_bearer_xyz")
            .expect("valid bearer")
            .with_merchant_id("merchant_99")
            .expect("valid merchant");
        let bearer_dbg = format!("{bearer_ctx:?}");
        assert!(!bearer_dbg.contains("super_secret_bearer_xyz"));
        assert!(bearer_dbg.contains("[REDACTED]"));
        assert!(bearer_dbg.contains("merchant_99"));

        let api_ctx = PartnerAuthContext::api_key_header("super_secret_api_key_xyz")
            .expect("valid api key");
        let api_dbg = format!("{api_ctx:?}");
        assert!(!api_dbg.contains("super_secret_api_key_xyz"));
        assert!(api_dbg.contains("[REDACTED]"));
    }
}

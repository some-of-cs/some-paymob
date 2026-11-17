#![forbid(unsafe_code)]
//! Partner Authentication & HMAC Secret models (`US-6.1.0` / `unit-1`).
//!
//! Provides strongly-typed request and response models for Paymob Partner Onboarding
//! authentication (`login`), Partner API Key provisioning (`create_api_key`), and
//! Partner HMAC secret retrieval (`GET /api/auth/hmac_secret/get_hmac`), with
//! automatic [`ZeroizeOnDrop`] memory scrubbing and `[REDACTED]` [`fmt::Debug`] formatting.

use std::fmt;

use secrecy::{ExposeSecret, SecretString};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize, Serializer};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::core::error::PaymobError;

const REDACTED: &str = "[REDACTED]";

/// Credentials submitted to Paymob Partner login (`US-6.1.0`).
///
/// The `password` field is stored in a [`SecretString`], automatically scrubbed
/// on drop via [`ZeroizeOnDrop`], and redacted as `"[REDACTED]"` in [`fmt::Debug`].
///
/// # Examples
///
/// ```
/// use some_paymob::resources::onboarding::auth_models::PartnerLoginCredentials;
///
/// let creds = PartnerLoginCredentials::try_new("partner@example.com", "super-secret-pass")?;
/// assert_eq!(creds.username(), "partner@example.com");
/// assert!(format!("{creds:?}").contains("[REDACTED]"));
/// assert!(!format!("{creds:?}").contains("super-secret-pass"));
/// # Ok::<(), some_paymob::core::error::PaymobError>(())
/// ```
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PartnerLoginCredentials {
    username: String,
    password: SecretString,
}

impl PartnerLoginCredentials {
    /// Creates a new [`PartnerLoginCredentials`] without validating field contents.
    #[must_use]
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: SecretString::from(password.into()),
        }
    }

    /// Creates and validates [`PartnerLoginCredentials`].
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `username` or `password` is
    /// empty or whitespace-only.
    pub fn try_new(
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<Self, PaymobError> {
        let creds = Self::new(username, password);
        creds.validate()?;
        Ok(creds)
    }

    /// Validates that `username` and `password` are non-empty.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if either credential is empty or
    /// whitespace-only.
    pub fn validate(&self) -> Result<(), PaymobError> {
        if self.username.trim().is_empty() {
            return Err(PaymobError::ValidationError {
                field: "username",
                reason: String::from("partner username must not be empty"),
            });
        }
        if self.password.expose_secret().trim().is_empty() {
            return Err(PaymobError::ValidationError {
                field: "password",
                reason: String::from("partner password must not be empty"),
            });
        }
        Ok(())
    }

    /// Returns the partner username.
    #[must_use]
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Exposes the partner password secret.
    #[must_use]
    pub fn password(&self) -> &str {
        self.password.expose_secret()
    }
}

impl fmt::Debug for PartnerLoginCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PartnerLoginCredentials")
            .field("username", &self.username)
            .field("password", &REDACTED)
            .finish()
    }
}

impl Serialize for PartnerLoginCredentials {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("PartnerLoginCredentials", 2)?;
        state.serialize_field("username", &self.username)?;
        state.serialize_field("password", self.password.expose_secret())?;
        state.end()
    }
}

/// Response returned by Paymob Partner login containing a Partner Bearer token.
///
/// The `token` is stored in [`SecretString`], zeroized on drop, and redacted
/// as `"[REDACTED]"` in [`fmt::Debug`].
///
/// # Examples
///
/// ```
/// use some_paymob::resources::onboarding::auth_models::PartnerAuthTokenResponse;
///
/// let resp: PartnerAuthTokenResponse = serde_json::from_str(r#"{"token":"jwt-partner-123"}"#)?;
/// assert_eq!(resp.token(), "jwt-partner-123");
/// assert!(format!("{resp:?}").contains("[REDACTED]"));
/// assert!(!format!("{resp:?}").contains("jwt-partner-123"));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Clone, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct PartnerAuthTokenResponse {
    /// Partner Bearer authentication token wrapped in [`SecretString`].
    #[serde(alias = "access_token")]
    pub token: SecretString,
}

impl PartnerAuthTokenResponse {
    /// Exposes the Partner Bearer token string.
    #[must_use]
    pub fn token(&self) -> &str {
        self.token.expose_secret()
    }
}

impl fmt::Debug for PartnerAuthTokenResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PartnerAuthTokenResponse")
            .field("token", &REDACTED)
            .finish()
    }
}

/// Request parameters for provisioning a Partner API Key (`US-6.1.0`).
///
/// # Examples
///
/// ```
/// use some_paymob::resources::onboarding::auth_models::CreatePartnerApiKeyParams;
///
/// let params = CreatePartnerApiKeyParams::new().with_label("primary-onboarding-key");
/// assert_eq!(params.label(), Some("primary-onboarding-key"));
/// assert!(params.validate().is_ok());
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreatePartnerApiKeyParams {
    /// Optional human-readable label for the provisioned Partner API Key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

impl CreatePartnerApiKeyParams {
    /// Creates an empty [`CreatePartnerApiKeyParams`] request.
    #[must_use]
    pub const fn new() -> Self {
        Self { label: None }
    }

    /// Attaches an optional descriptive label for the Partner API Key.
    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Returns the configured label, if any.
    #[must_use]
    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }

    /// Validates that any provided `label` is non-empty.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `label` is `Some` and empty or
    /// whitespace-only.
    pub fn validate(&self) -> Result<(), PaymobError> {
        if let Some(label) = &self.label
            && label.trim().is_empty()
        {
            return Err(PaymobError::ValidationError {
                field: "label",
                reason: String::from("partner API key label must not be empty when provided"),
            });
        }
        Ok(())
    }
}

/// Response returned when provisioning a Partner API Key (`US-6.1.0`).
///
/// The `api_key` is stored in [`SecretString`], zeroized on drop, and redacted
/// as `"[REDACTED]"` in [`fmt::Debug`].
///
/// # Examples
///
/// ```
/// use some_paymob::resources::onboarding::auth_models::PartnerApiKeyResponse;
///
/// let resp: PartnerApiKeyResponse = serde_json::from_str(
///     r#"{"api_key":"pk_partner_secret_999","label":"prod-key"}"#,
/// )?;
/// assert_eq!(resp.api_key(), "pk_partner_secret_999");
/// assert!(format!("{resp:?}").contains("[REDACTED]"));
/// assert!(!format!("{resp:?}").contains("pk_partner_secret_999"));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Clone, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct PartnerApiKeyResponse {
    /// Provisioned Partner API Key wrapped in [`SecretString`].
    #[serde(alias = "key")]
    pub api_key: SecretString,
    /// Optional label associated with the Partner API Key.
    #[serde(default)]
    pub label: Option<String>,
}

impl PartnerApiKeyResponse {
    /// Exposes the provisioned Partner API Key.
    #[must_use]
    pub fn api_key(&self) -> &str {
        self.api_key.expose_secret()
    }
}

impl fmt::Debug for PartnerApiKeyResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PartnerApiKeyResponse")
            .field("api_key", &REDACTED)
            .field("label", &self.label)
            .finish()
    }
}

/// Inner body of [`PartnerHmacEnvelope`] containing the sub-merchant HMAC secret.
///
/// # Examples
///
/// ```
/// use some_paymob::resources::onboarding::auth_models::PartnerHmacBody;
///
/// let body: PartnerHmacBody = serde_json::from_str(r#"{"hmac_secret":"5F4DCC3B"}"#)?;
/// assert_eq!(body.hmac_secret(), "5F4DCC3B");
/// assert!(format!("{body:?}").contains("[REDACTED]"));
/// assert!(!format!("{body:?}").contains("5F4DCC3B"));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Clone, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct PartnerHmacBody {
    /// Sub-merchant HMAC secret wrapped in [`SecretString`].
    pub hmac_secret: SecretString,
}

impl PartnerHmacBody {
    /// Exposes the sub-merchant HMAC secret string.
    #[must_use]
    pub fn hmac_secret(&self) -> &str {
        self.hmac_secret.expose_secret()
    }
}

impl fmt::Debug for PartnerHmacBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PartnerHmacBody")
            .field("hmac_secret", &REDACTED)
            .finish()
    }
}

/// Envelope returned by `GET /api/auth/hmac_secret/get_hmac` (`US-6.1.0`).
///
/// # Examples
///
/// ```
/// use some_paymob::resources::onboarding::auth_models::PartnerHmacEnvelope;
///
/// let json = r#"{"label":null,"status":"Created","code":201,"body":{"hmac_secret":"ABC123HMAC"}}"#;
/// let env: PartnerHmacEnvelope = serde_json::from_str(json)?;
/// assert_eq!(env.status, "Created");
/// assert_eq!(env.code, 201);
/// assert_eq!(env.hmac_secret(), "ABC123HMAC");
/// assert!(!format!("{env:?}").contains("ABC123HMAC"));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Clone, Debug, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct PartnerHmacEnvelope {
    /// Optional label attached to the HMAC secret response.
    pub label: Option<String>,
    /// Status string returned by Paymob (typically `"Created"`).
    pub status: String,
    /// Numeric status code returned in the envelope (typically `201`).
    pub code: u16,
    /// Nested body holding the [`SecretString`] HMAC secret.
    pub body: PartnerHmacBody,
}

impl PartnerHmacEnvelope {
    /// Exposes the sub-merchant HMAC secret from the nested body.
    #[must_use]
    pub fn hmac_secret(&self) -> &str {
        self.body.hmac_secret()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tc_6_1_1_login_credentials_validation_and_redaction() {
        let creds = PartnerLoginCredentials::try_new("partner@acme.io", "s3cr3t_pass_!").unwrap();
        assert_eq!(creds.username(), "partner@acme.io");
        assert_eq!(creds.password(), "s3cr3t_pass_!");

        let dbg = format!("{creds:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("s3cr3t_pass_!"));

        let serialized = serde_json::to_value(&creds).unwrap();
        assert_eq!(serialized["username"], "partner@acme.io");
        assert_eq!(serialized["password"], "s3cr3t_pass_!");

        assert!(PartnerLoginCredentials::try_new("   ", "pass").is_err());
        assert!(PartnerLoginCredentials::try_new("user", "  ").is_err());
    }

    #[test]
    fn tc_6_1_1_auth_token_and_api_key_redaction_and_deserialization() {
        let token_resp: PartnerAuthTokenResponse =
            serde_json::from_str(r#"{"token":"eyJhbGciOiJIUzI1NiJ9.secret"}"#).unwrap();
        assert_eq!(token_resp.token(), "eyJhbGciOiJIUzI1NiJ9.secret");
        let token_dbg = format!("{token_resp:?}");
        assert!(token_dbg.contains("[REDACTED]"));
        assert!(!token_dbg.contains("eyJhbGciOiJIUzI1NiJ9.secret"));

        let alias_resp: PartnerAuthTokenResponse =
            serde_json::from_str(r#"{"access_token":"tok_alias_1"}"#).unwrap();
        assert_eq!(alias_resp.token(), "tok_alias_1");

        let key_resp: PartnerApiKeyResponse =
            serde_json::from_str(r#"{"api_key":"pk_partner_live_xyz","label":"main"}"#).unwrap();
        assert_eq!(key_resp.api_key(), "pk_partner_live_xyz");
        assert_eq!(key_resp.label.as_deref(), Some("main"));
        let key_dbg = format!("{key_resp:?}");
        assert!(key_dbg.contains("[REDACTED]"));
        assert!(!key_dbg.contains("pk_partner_live_xyz"));
    }

    #[test]
    fn tc_6_1_1_create_api_key_params_validation() {
        let default_params = CreatePartnerApiKeyParams::new();
        assert!(default_params.label().is_none());
        assert!(default_params.validate().is_ok());

        let labeled = CreatePartnerApiKeyParams::new().with_label("ci-key");
        assert_eq!(labeled.label(), Some("ci-key"));
        assert!(labeled.validate().is_ok());

        let empty_label = CreatePartnerApiKeyParams::new().with_label("   ");
        assert!(empty_label.validate().is_err());
    }

    #[test]
    fn tc_6_1_1_hmac_envelope_deserialization_and_redaction() {
        let payload = r#"{
            "label": null,
            "status": "Created",
            "code": 201,
            "body": {
                "hmac_secret": "9A8B7C6D5E4F3A2B1C0D"
            }
        }"#;
        let env: PartnerHmacEnvelope = serde_json::from_str(payload).unwrap();
        assert!(env.label.is_none());
        assert_eq!(env.status, "Created");
        assert_eq!(env.code, 201);
        assert_eq!(env.hmac_secret(), "9A8B7C6D5E4F3A2B1C0D");

        let dbg = format!("{env:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("9A8B7C6D5E4F3A2B1C0D"));
    }

    #[test]
    fn tc_6_1_1_malformed_hmac_envelope_rejected() {
        let missing_body = r#"{"label":null,"status":"Created","code":201}"#;
        assert!(serde_json::from_str::<PartnerHmacEnvelope>(missing_body).is_err());
    }
}

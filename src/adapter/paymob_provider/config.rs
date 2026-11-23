use std::fmt;
use std::time::Duration;

use reqwest::Client;
use secrecy::{ExposeSecret, SecretString};
use some_payment_core::{PaymentCapabilities, PaymentError};
use url::Url;

use crate::alignment::dual_auth::{AuthTokenConfig, AuthTokenManager};
use crate::alignment::integration_validation::IntegrationRoutingConfig;
use crate::alignment::region_checkout::PaymobRegion;

use super::errors::{map_dual_auth_config_error, map_region_error};

const REDACTED: &str = "[REDACTED]";
const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Redacted Paymob credential bundle for [`PaymobProviderConfig`].
///
/// All secret material (`secret_key`, `api_key`, `hmac_secret`, `public_key`) is
/// stored in [`SecretString`] wrappers and redacted as `[REDACTED]` in [`fmt::Debug`].
#[derive(Clone)]
pub struct PaymobCredentials {
    secret_key: SecretString,
    api_key: SecretString,
    hmac_secret: SecretString,
    public_key: SecretString,
}

impl fmt::Debug for PaymobCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PaymobCredentials")
            .field("secret_key", &REDACTED)
            .field("api_key", &REDACTED)
            .field("hmac_secret", &REDACTED)
            .field("public_key", &REDACTED)
            .finish()
    }
}

impl PaymobCredentials {
    /// Creates a new [`PaymobCredentials`] bundle from raw secret inputs.
    #[must_use]
    pub fn new(
        secret_key: impl Into<SecretString>,
        api_key: impl Into<SecretString>,
        hmac_secret: impl Into<SecretString>,
        public_key: impl Into<SecretString>,
    ) -> Self {
        Self {
            secret_key: secret_key.into(),
            api_key: api_key.into(),
            hmac_secret: hmac_secret.into(),
            public_key: public_key.into(),
        }
    }

    pub(super) const fn secret_key(&self) -> &SecretString {
        &self.secret_key
    }

    pub(super) const fn api_key(&self) -> &SecretString {
        &self.api_key
    }

    pub(super) const fn hmac_secret(&self) -> &SecretString {
        &self.hmac_secret
    }

    pub(super) const fn public_key(&self) -> &SecretString {
        &self.public_key
    }
}

/// Configuration for [`crate::adapter::paymob_provider::PaymobProvider`].
///
/// Secret material is held inside [`PaymobCredentials`] and redacted as `[REDACTED]`
/// in [`fmt::Debug`].
#[derive(Clone)]
pub struct PaymobProviderConfig {
    region: PaymobRegion,
    integration_routing: IntegrationRoutingConfig,
    credentials: PaymobCredentials,
    auth_base_url_override: Option<String>,
    checkout_base_url_override: Option<String>,
    http_client: Option<Client>,
    livemode: bool,
    notification_url: Option<String>,
    redirection_url: Option<String>,
}

impl fmt::Debug for PaymobProviderConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PaymobProviderConfig")
            .field("region", &self.region)
            .field("integration_routing", &self.integration_routing)
            .field("credentials", &self.credentials)
            .field("auth_base_url_override", &self.auth_base_url_override)
            .field(
                "checkout_base_url_override",
                &self.checkout_base_url_override,
            )
            .field("custom_http_client", &self.http_client.is_some())
            .field("livemode", &self.livemode)
            .field("notification_url", &self.notification_url)
            .field("redirection_url", &self.redirection_url)
            .finish()
    }
}

impl PaymobProviderConfig {
    /// Creates a new [`PaymobProviderConfig`] with the required Paymob routing and credentials.
    ///
    /// By default, `livemode` is inferred from whether `credentials` contains a `_live_` secret key.
    /// Override it explicitly with [`Self::with_livemode`] when needed.
    #[must_use]
    pub fn new(
        region: PaymobRegion,
        integration_routing: IntegrationRoutingConfig,
        credentials: PaymobCredentials,
    ) -> Self {
        let livemode = credentials.secret_key().expose_secret().contains("_live_");
        Self {
            region,
            integration_routing,
            credentials,
            auth_base_url_override: None,
            checkout_base_url_override: None,
            http_client: None,
            livemode,
            notification_url: None,
            redirection_url: None,
        }
    }

    /// Overrides the API and `/api/auth/tokens` base URL (permits `http://` only for loopback hosts).
    #[must_use]
    pub fn with_auth_base_url_override(mut self, base_url: impl Into<String>) -> Self {
        self.auth_base_url_override = Some(base_url.into());
        self
    }

    /// Overrides the HTTPS base URL used when generating Unified Checkout redirect links.
    #[must_use]
    pub fn with_checkout_base_url_override(mut self, checkout_base_url: impl Into<String>) -> Self {
        self.checkout_base_url_override = Some(checkout_base_url.into());
        self
    }

    /// Injects a custom [`reqwest::Client`] (for custom TLS, timeouts, or offline tests).
    #[must_use]
    pub fn with_http_client(mut self, client: Client) -> Self {
        self.http_client = Some(client);
        self
    }

    /// Explicitly sets whether this provider instance operates in live mode.
    #[must_use]
    pub const fn with_livemode(mut self, livemode: bool) -> Self {
        self.livemode = livemode;
        self
    }

    /// Configures a default webhook `notification_url` sent on Intention creation requests.
    #[must_use]
    pub fn with_notification_url(mut self, url: impl Into<String>) -> Self {
        self.notification_url = Some(url.into());
        self
    }

    /// Configures a default customer `redirection_url` sent on Intention creation requests.
    #[must_use]
    pub fn with_redirection_url(mut self, url: impl Into<String>) -> Self {
        self.redirection_url = Some(url.into());
        self
    }

    /// Returns the configured [`PaymobRegion`].
    #[must_use]
    pub const fn region(&self) -> &PaymobRegion {
        &self.region
    }

    /// Returns the configured [`IntegrationRoutingConfig`].
    #[must_use]
    pub const fn integration_routing(&self) -> &IntegrationRoutingConfig {
        &self.integration_routing
    }

    /// Returns the optional API/auth base URL override.
    #[must_use]
    pub fn auth_base_url_override(&self) -> Option<&str> {
        self.auth_base_url_override.as_deref()
    }

    /// Returns the optional checkout base URL override.
    #[must_use]
    pub fn checkout_base_url_override(&self) -> Option<&str> {
        self.checkout_base_url_override.as_deref()
    }

    /// Returns whether this configuration is marked as live mode.
    #[must_use]
    pub const fn livemode(&self) -> bool {
        self.livemode
    }

    pub(super) const fn credentials(&self) -> &PaymobCredentials {
        &self.credentials
    }

    pub(super) fn notification_url(&self) -> Option<&str> {
        self.notification_url.as_deref()
    }

    pub(super) fn redirection_url(&self) -> Option<&str> {
        self.redirection_url.as_deref()
    }
}

pub(super) fn validate_required_secrets(config: &PaymobProviderConfig) -> Result<(), PaymentError> {
    let creds = config.credentials();
    ensure_non_empty_secret(creds.secret_key(), "secret_key")?;
    ensure_non_empty_secret(creds.api_key(), "api_key")?;
    ensure_non_empty_secret(creds.hmac_secret(), "hmac_secret")?;
    ensure_non_empty_secret(creds.public_key(), "public_key")
}

fn ensure_non_empty_secret(secret: &SecretString, field: &str) -> Result<(), PaymentError> {
    if secret.expose_secret().trim().is_empty() {
        return Err(PaymentError::configuration(format!(
            "paymob {field} must not be empty"
        )));
    }
    Ok(())
}

pub(super) fn resolve_api_base_url(config: &PaymobProviderConfig) -> Result<String, PaymentError> {
    let raw = match &config.auth_base_url_override {
        Some(override_url) => override_url.trim().to_owned(),
        None => config.region.api_base_url().map_err(map_region_error)?,
    };
    let parsed = Url::parse(&raw)
        .map_err(|err| PaymentError::configuration(format!("invalid paymob base URL: {err}")))?;
    validate_base_url_security(&parsed)?;
    Ok(raw.trim_end_matches('/').to_owned())
}

fn validate_base_url_security(parsed: &Url) -> Result<(), PaymentError> {
    let Some(host) = parsed.host_str() else {
        return Err(PaymentError::configuration(
            "paymob base URL must include a valid host",
        ));
    };
    if has_disallowed_url_components(parsed) {
        return Err(PaymentError::configuration(
            "paymob base URL must not contain userinfo, query parameters, or fragments",
        ));
    }
    match parsed.scheme() {
        "https" => Ok(()),
        "http" if is_loopback_host(host) => Ok(()),
        _ => Err(PaymentError::configuration(
            "paymob base URL must use https (http is allowed only for loopback hosts)",
        )),
    }
}

fn has_disallowed_url_components(parsed: &Url) -> bool {
    !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
}

fn is_loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]")
}

pub(super) fn resolve_http_client(config: &PaymobProviderConfig) -> Result<Client, PaymentError> {
    if let Some(client) = &config.http_client {
        return Ok(client.clone());
    }
    Client::builder()
        .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| PaymentError::configuration("failed to initialize reqwest HTTP client"))
}

pub(super) fn build_auth_manager(
    api_base_url: &str,
    config: &PaymobProviderConfig,
    http: &Client,
) -> Result<AuthTokenManager, PaymentError> {
    let creds = config.credentials();
    let auth_config = AuthTokenConfig::new(
        api_base_url,
        creds.api_key().clone(),
        creds.secret_key().clone(),
    )
    .map_err(map_dual_auth_config_error)?
    .with_http_client(http.clone());
    AuthTokenManager::new(auth_config).map_err(map_dual_auth_config_error)
}

pub(super) fn resolve_capabilities(config: &PaymobProviderConfig) -> PaymentCapabilities {
    let mut caps = PaymentCapabilities::HOSTED_CHECKOUT
        | PaymentCapabilities::EMBEDDED_INTENT
        | PaymentCapabilities::VOID_AUTHORIZED
        | PaymentCapabilities::VOID_SETTLED_WINDOW
        | PaymentCapabilities::REFUND
        | PaymentCapabilities::PARTIAL_REFUND
        | PaymentCapabilities::SAVED_CARDS
        | PaymentCapabilities::SPLITS;
    if config.integration_routing().auth_integration_id.is_some() {
        caps |= PaymentCapabilities::AUTH_CAPTURE | PaymentCapabilities::PARTIAL_CAPTURE;
    }
    caps
}

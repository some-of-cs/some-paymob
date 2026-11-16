//! Client configuration and builder for `some-paymob` (`US-1.1.0/unit-3`).
//!
//! Provides [`ClientConfig`] and [`ClientConfigBuilder`] with deterministic
//! key-prefix region and environment parity validation (`Test` vs `Live`),
//! strict rejection of publishable keys (`pk_*`) in the secret key slot,
//! configurable timeouts and retry limits, Payouts staging and legacy-v2 capture
//! `Bearer` toggles, environment-variable loading via [`ClientConfig::from_env`],
//! and `[REDACTED]` [`fmt::Debug`] formatting.

#![forbid(unsafe_code)]

use std::fmt;
use std::time::Duration;

use crate::core::credentials::{
    ApiKey, EnvironmentMode, HmacSecret, PartnerCredentials, PayoutsCredentials, PublicKey,
    SecretKey,
};
use crate::core::error::PaymobError;
use crate::core::region::PaymobRegion;

/// Default HTTP request timeout in seconds (30 seconds).
pub const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Default maximum retry attempts for transient HTTP failures.
pub const DEFAULT_MAX_RETRIES: u32 = 3;

/// Full-name aliases accepted by `PAYMOB_REGION` in addition to 3-letter codes.
const ENV_REGION_ALIASES: &[(&str, PaymobRegion)] = &[
    ("egypt", PaymobRegion::Egypt),
    ("saudi", PaymobRegion::SaudiArabia),
    ("saudi_arabia", PaymobRegion::SaudiArabia),
    ("saudi-arabia", PaymobRegion::SaudiArabia),
    ("oman", PaymobRegion::Oman),
    ("pakistan", PaymobRegion::Pakistan),
];

/// Immutable configuration for [`crate::core::client::PaymobClient`].
///
/// Construct instances via [`ClientConfig::builder()`] or [`ClientConfig::from_env()`].
/// All credential fields are redacted (`"[REDACTED]"`) in [`fmt::Debug`] output
/// to prevent secret leakage in logs or panic traces.
///
/// # Examples
///
/// ```rust
/// use std::time::Duration;
/// use some_paymob::core::config::ClientConfig;
/// use some_paymob::core::credentials::{EnvironmentMode, PublicKey, SecretKey};
/// use some_paymob::core::region::PaymobRegion;
///
/// let config = ClientConfig::builder()
///     .region(PaymobRegion::Egypt)
///     .secret_key(SecretKey::new("egy_sk_test_example")?)
///     .public_key(PublicKey::new("egy_pk_test_example")?)
///     .timeout(Duration::from_secs(15))
///     .max_retries(2)
///     .build()?;
///
/// assert_eq!(config.environment(), EnvironmentMode::Test);
/// assert_eq!(config.timeout(), Duration::from_secs(15));
/// assert_eq!(config.max_retries(), 2);
/// assert!(!config.use_payouts_staging());
/// assert!(!config.use_legacy_v2_bearer_for_capture());
/// # Ok::<(), some_paymob::core::error::PaymobError>(())
/// ```
#[derive(Clone)]
pub struct ClientConfig {
    region: PaymobRegion,
    environment: EnvironmentMode,
    secret_key: Option<SecretKey>,
    public_key: Option<PublicKey>,
    api_key: Option<ApiKey>,
    hmac_secret: Option<HmacSecret>,
    payouts_credentials: Option<PayoutsCredentials>,
    partner_credentials: Option<PartnerCredentials>,
    timeout: Duration,
    max_retries: u32,
    use_payouts_staging: bool,
    use_legacy_v2_bearer_for_capture: bool,
}

impl ClientConfig {
    /// Creates a new [`ClientConfigBuilder`] with default timeout (30s) and
    /// retry count (3).
    #[must_use]
    pub fn builder() -> ClientConfigBuilder {
        ClientConfigBuilder::new()
    }

    /// Loads and validates [`ClientConfig`] from `PAYMOB_*` environment variables.
    ///
    /// Reads `PAYMOB_REGION` (required) plus optional `PAYMOB_ENVIRONMENT`,
    /// `PAYMOB_SECRET_KEY`, `PAYMOB_PUBLIC_KEY`, `PAYMOB_API_KEY`,
    /// `PAYMOB_HMAC_SECRET`, `PAYMOB_TIMEOUT_SECS`, `PAYMOB_MAX_RETRIES`,
    /// `PAYMOB_USE_PAYOUTS_STAGING`, and `PAYMOB_USE_LEGACY_V2_BEARER`.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `PAYMOB_REGION` is missing or
    /// any configured variable is empty or malformed, or
    /// [`PaymobError::EnvironmentMismatch`] if key prefixes conflict with
    /// `PAYMOB_ENVIRONMENT`.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use some_paymob::core::config::ClientConfig;
    ///
    /// let config = ClientConfig::from_env()?;
    /// println!("configured region: {}", config.region().country_code());
    /// # Ok::<(), some_paymob::core::error::PaymobError>(())
    /// ```
    pub fn from_env() -> Result<Self, PaymobError> {
        ClientConfigBuilder::from_env()?.build()
    }

    /// Returns the configured [`PaymobRegion`] for dual-host routing.
    #[must_use]
    pub fn region(&self) -> &PaymobRegion {
        &self.region
    }

    /// Returns the validated [`EnvironmentMode`] (`Test` or `Live`).
    #[must_use]
    pub fn environment(&self) -> EnvironmentMode {
        self.environment
    }

    /// Returns the optional server-side [`SecretKey`] (`sk_*`).
    #[must_use]
    pub fn secret_key(&self) -> Option<&SecretKey> {
        self.secret_key.as_ref()
    }

    /// Returns the optional client-side [`PublicKey`] (`pk_*`).
    #[must_use]
    pub fn public_key(&self) -> Option<&PublicKey> {
        self.public_key.as_ref()
    }

    /// Returns the optional Accept [`ApiKey`] used for Regime 2 JWT auth.
    #[must_use]
    pub fn api_key(&self) -> Option<&ApiKey> {
        self.api_key.as_ref()
    }

    /// Returns the optional [`HmacSecret`] used for webhook verification.
    #[must_use]
    pub fn hmac_secret(&self) -> Option<&HmacSecret> {
        self.hmac_secret.as_ref()
    }

    /// Returns the optional [`PayoutsCredentials`] used for Regime 3 OAuth2.
    #[must_use]
    pub fn payouts_credentials(&self) -> Option<&PayoutsCredentials> {
        self.payouts_credentials.as_ref()
    }

    /// Returns the optional [`PartnerCredentials`] used for Regime 4 auth.
    #[must_use]
    pub fn partner_credentials(&self) -> Option<&PartnerCredentials> {
        self.partner_credentials.as_ref()
    }

    /// Returns the configured HTTP request [`Duration`] timeout.
    #[must_use]
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Returns the configured maximum retry count for transient failures.
    #[must_use]
    pub fn max_retries(&self) -> u32 {
        self.max_retries
    }

    /// Returns `true` if Payouts requests should route to the staging host.
    #[must_use]
    pub fn use_payouts_staging(&self) -> bool {
        self.use_payouts_staging
    }

    /// Returns `true` if legacy-v2 `Bearer <auth_token>` auth is enabled
    /// for refund, void, and capture endpoints instead of `Token <secret_key>`.
    #[must_use]
    pub fn use_legacy_v2_bearer_for_capture(&self) -> bool {
        self.use_legacy_v2_bearer_for_capture
    }
}

impl fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_config_fields(
            f,
            &ConfigDebugView {
                type_name: "ClientConfig",
                region: &self.region,
                environment: &self.environment,
                secret_key: &self.secret_key,
                public_key: &self.public_key,
                api_key: &self.api_key,
                hmac_secret: &self.hmac_secret,
                payouts_credentials: &self.payouts_credentials,
                partner_credentials: &self.partner_credentials,
                timeout: self.timeout,
                max_retries: self.max_retries,
                use_payouts_staging: self.use_payouts_staging,
                use_legacy_v2_bearer_for_capture: self.use_legacy_v2_bearer_for_capture,
            },
        )
    }
}

/// Ergonomic builder for constructing a validated [`ClientConfig`].
///
/// Validates credential prefix isolation (`pk_*` rejected in `secret_key`),
/// `PaymobRegion` parity across keys, `Test` vs `Live` environment parity, and
/// non-zero request timeouts before returning [`ClientConfig`].
///
/// # Examples
///
/// ```rust
/// use some_paymob::core::config::ClientConfigBuilder;
/// use some_paymob::core::credentials::SecretKey;
/// use some_paymob::core::region::PaymobRegion;
///
/// let config = ClientConfigBuilder::new()
///     .region(PaymobRegion::SaudiArabia)
///     .secret_key(SecretKey::new("ksa_sk_live_example")?)
///     .use_payouts_staging(false)
///     .use_legacy_v2_bearer_for_capture(true)
///     .build()?;
///
/// assert!(config.use_legacy_v2_bearer_for_capture());
/// # Ok::<(), some_paymob::core::error::PaymobError>(())
/// ```
#[derive(Clone)]
pub struct ClientConfigBuilder {
    region: Option<PaymobRegion>,
    environment: Option<EnvironmentMode>,
    secret_key: Option<SecretKey>,
    public_key: Option<PublicKey>,
    api_key: Option<ApiKey>,
    hmac_secret: Option<HmacSecret>,
    payouts_credentials: Option<PayoutsCredentials>,
    partner_credentials: Option<PartnerCredentials>,
    timeout: Duration,
    max_retries: u32,
    use_payouts_staging: bool,
    use_legacy_v2_bearer_for_capture: bool,
}

impl Default for ClientConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientConfigBuilder {
    /// Creates a new [`ClientConfigBuilder`] with default settings
    /// (`timeout = 30s`, `max_retries = 3`, toggles `false`).
    #[must_use]
    pub fn new() -> Self {
        Self {
            region: None,
            environment: None,
            secret_key: None,
            public_key: None,
            api_key: None,
            hmac_secret: None,
            payouts_credentials: None,
            partner_credentials: None,
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            max_retries: DEFAULT_MAX_RETRIES,
            use_payouts_staging: false,
            use_legacy_v2_bearer_for_capture: false,
        }
    }

    /// Populates a [`ClientConfigBuilder`] from `PAYMOB_*` environment variables.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `PAYMOB_REGION` is missing or
    /// any set variable is empty or cannot be parsed.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use some_paymob::core::config::ClientConfigBuilder;
    ///
    /// let builder = ClientConfigBuilder::from_env()?;
    /// let config = builder.build()?;
    /// assert!(config.timeout().as_secs() > 0);
    /// # Ok::<(), some_paymob::core::error::PaymobError>(())
    /// ```
    pub fn from_env() -> Result<Self, PaymobError> {
        Self::from_env_with(|key| std::env::var(key).ok())
    }

    /// Populates a [`ClientConfigBuilder`] using a custom environment lookup closure.
    fn from_env_with<F>(lookup: F) -> Result<Self, PaymobError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let region_raw = lookup("PAYMOB_REGION").ok_or_else(|| PaymobError::ValidationError {
            field: "region",
            reason: "PAYMOB_REGION environment variable is not set".to_owned(),
        })?;
        let mut builder = Self::new().region(parse_region_env(&region_raw)?);
        if let Some(env_raw) = lookup("PAYMOB_ENVIRONMENT") {
            builder = builder.environment(parse_mode_env(&env_raw)?);
        }
        builder.apply_env_credentials(&lookup)?;
        builder.apply_env_transport(&lookup)?;
        Ok(builder)
    }

    /// Applies optional credential variables from `lookup`.
    fn apply_env_credentials<F>(&mut self, lookup: &F) -> Result<(), PaymobError>
    where
        F: Fn(&str) -> Option<String>,
    {
        if let Some(val) = lookup("PAYMOB_SECRET_KEY") {
            self.secret_key = Some(SecretKey::new(val)?);
        }
        if let Some(val) = lookup("PAYMOB_PUBLIC_KEY") {
            self.public_key = Some(PublicKey::new(val)?);
        }
        if let Some(val) = lookup("PAYMOB_API_KEY") {
            self.api_key = Some(ApiKey::new(val)?);
        }
        if let Some(val) = lookup("PAYMOB_HMAC_SECRET") {
            self.hmac_secret = Some(HmacSecret::new(val)?);
        }
        Ok(())
    }

    /// Applies optional timeout, retry, and feature-toggle variables from `lookup`.
    fn apply_env_transport<F>(&mut self, lookup: &F) -> Result<(), PaymobError>
    where
        F: Fn(&str) -> Option<String>,
    {
        if let Some(val) = lookup("PAYMOB_TIMEOUT_SECS") {
            self.timeout = parse_timeout_env(&val)?;
        }
        if let Some(val) = lookup("PAYMOB_MAX_RETRIES") {
            self.max_retries = parse_retries_env(&val)?;
        }
        if let Some(val) = lookup("PAYMOB_USE_PAYOUTS_STAGING") {
            self.use_payouts_staging = parse_bool_env("use_payouts_staging", &val)?;
        }
        if let Some(val) = lookup("PAYMOB_USE_LEGACY_V2_BEARER") {
            self.use_legacy_v2_bearer_for_capture =
                parse_bool_env("use_legacy_v2_bearer_for_capture", &val)?;
        }
        Ok(())
    }

    /// Sets the target [`PaymobRegion`] for Accept and Payouts routing.
    #[must_use]
    pub fn region(mut self, region: PaymobRegion) -> Self {
        self.region = Some(region);
        self
    }

    /// Explicitly sets the [`EnvironmentMode`] (`Test` or `Live`).
    ///
    /// If key prefixes are also provided, [`Self::build`] verifies that they
    /// match this mode and returns [`PaymobError::EnvironmentMismatch`] on
    /// conflict.
    #[must_use]
    pub fn environment(mut self, environment: EnvironmentMode) -> Self {
        self.environment = Some(environment);
        self
    }

    /// Sets the server-side [`SecretKey`] (`sk_*`).
    #[must_use]
    pub fn secret_key(mut self, secret_key: SecretKey) -> Self {
        self.secret_key = Some(secret_key);
        self
    }

    /// Sets the client-side [`PublicKey`] (`pk_*`).
    #[must_use]
    pub fn public_key(mut self, public_key: PublicKey) -> Self {
        self.public_key = Some(public_key);
        self
    }

    /// Sets the Accept [`ApiKey`] for Regime 2 JWT authentication.
    #[must_use]
    pub fn api_key(mut self, api_key: ApiKey) -> Self {
        self.api_key = Some(api_key);
        self
    }

    /// Sets the [`HmacSecret`] for constant-time webhook verification.
    #[must_use]
    pub fn hmac_secret(mut self, hmac_secret: HmacSecret) -> Self {
        self.hmac_secret = Some(hmac_secret);
        self
    }

    /// Sets the [`PayoutsCredentials`] for Regime 3 OAuth2 authentication.
    #[must_use]
    pub fn payouts_credentials(mut self, credentials: PayoutsCredentials) -> Self {
        self.payouts_credentials = Some(credentials);
        self
    }

    /// Sets the [`PartnerCredentials`] for Regime 4 delegated authentication.
    #[must_use]
    pub fn partner_credentials(mut self, credentials: PartnerCredentials) -> Self {
        self.partner_credentials = Some(credentials);
        self
    }

    /// Sets the HTTP request [`Duration`] timeout (defaults to 30 seconds).
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Sets the maximum retry attempts for transient HTTP errors (defaults to 3).
    #[must_use]
    pub fn max_retries(mut self, max_retries: u32) -> Self {
        self.max_retries = max_retries;
        self
    }

    /// Enables or disables routing Payouts requests to the staging host.
    #[must_use]
    pub fn use_payouts_staging(mut self, enabled: bool) -> Self {
        self.use_payouts_staging = enabled;
        self
    }

    /// Enables or disables legacy-v2 `Bearer <auth_token>` authentication
    /// for refund, void, and capture endpoints.
    #[must_use]
    pub fn use_legacy_v2_bearer_for_capture(mut self, enabled: bool) -> Self {
        self.use_legacy_v2_bearer_for_capture = enabled;
        self
    }

    /// Validates builder invariants before constructing [`ClientConfig`].
    fn validate_builder_invariants(&self) -> Result<(PaymobRegion, EnvironmentMode), PaymobError> {
        let region = self
            .region
            .as_ref()
            .ok_or_else(|| PaymobError::ValidationError {
                field: "region",
                reason: "region must be specified".to_owned(),
            })?;
        if self.timeout.is_zero() {
            return Err(PaymobError::ValidationError {
                field: "timeout",
                reason: "timeout must be greater than zero".to_owned(),
            });
        }
        let sk_region = self.secret_key.as_ref().and_then(SecretKey::region);
        let pk_region = self.public_key.as_ref().and_then(PublicKey::region);
        resolve_region_parity(region, sk_region, pk_region)?;
        let sk_mode = self.secret_key.as_ref().map(SecretKey::mode);
        let pk_mode = self.public_key.as_ref().map(PublicKey::mode);
        let environment = resolve_environment(self.environment, sk_mode, pk_mode)?;
        Ok((region.clone(), environment))
    }

    /// Validates all builder invariants and constructs a [`ClientConfig`].
    ///
    /// # Errors
    ///
    /// - [`PaymobError::ValidationError`] if `region` is unset, `timeout` is
    ///   zero, or key region prefixes conflict with the configured `region`.
    /// - [`PaymobError::EnvironmentMismatch`] if `Test` and `Live` credentials
    ///   (or explicit `environment`) are mixed.
    pub fn build(self) -> Result<ClientConfig, PaymobError> {
        let (region, environment) = self.validate_builder_invariants()?;
        Ok(ClientConfig {
            region,
            environment,
            secret_key: self.secret_key,
            public_key: self.public_key,
            api_key: self.api_key,
            hmac_secret: self.hmac_secret,
            payouts_credentials: self.payouts_credentials,
            partner_credentials: self.partner_credentials,
            timeout: self.timeout,
            max_retries: self.max_retries,
            use_payouts_staging: self.use_payouts_staging,
            use_legacy_v2_bearer_for_capture: self.use_legacy_v2_bearer_for_capture,
        })
    }
}

impl fmt::Debug for ClientConfigBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_config_fields(
            f,
            &ConfigDebugView {
                type_name: "ClientConfigBuilder",
                region: &self.region,
                environment: &self.environment,
                secret_key: &self.secret_key,
                public_key: &self.public_key,
                api_key: &self.api_key,
                hmac_secret: &self.hmac_secret,
                payouts_credentials: &self.payouts_credentials,
                partner_credentials: &self.partner_credentials,
                timeout: self.timeout,
                max_retries: self.max_retries,
                use_payouts_staging: self.use_payouts_staging,
                use_legacy_v2_bearer_for_capture: self.use_legacy_v2_bearer_for_capture,
            },
        )
    }
}

/// Borrowed view of config fields shared by [`ClientConfig`] and [`ClientConfigBuilder`] `Debug`.
struct ConfigDebugView<'a, R, E> {
    type_name: &'static str,
    region: &'a R,
    environment: &'a E,
    secret_key: &'a Option<SecretKey>,
    public_key: &'a Option<PublicKey>,
    api_key: &'a Option<ApiKey>,
    hmac_secret: &'a Option<HmacSecret>,
    payouts_credentials: &'a Option<PayoutsCredentials>,
    partner_credentials: &'a Option<PartnerCredentials>,
    timeout: Duration,
    max_retries: u32,
    use_payouts_staging: bool,
    use_legacy_v2_bearer_for_capture: bool,
}

/// Shared [`fmt::Debug`] formatter redacting all optional credential fields.
fn fmt_config_fields<R: fmt::Debug, E: fmt::Debug>(
    f: &mut fmt::Formatter<'_>,
    view: &ConfigDebugView<'_, R, E>,
) -> fmt::Result {
    f.debug_struct(view.type_name)
        .field("region", view.region)
        .field("environment", view.environment)
        .field("secret_key", &redact_option(view.secret_key))
        .field("public_key", &redact_option(view.public_key))
        .field("api_key", &redact_option(view.api_key))
        .field("hmac_secret", &redact_option(view.hmac_secret))
        .field(
            "payouts_credentials",
            &redact_option(view.payouts_credentials),
        )
        .field(
            "partner_credentials",
            &redact_option(view.partner_credentials),
        )
        .field("timeout", &view.timeout)
        .field("max_retries", &view.max_retries)
        .field("use_payouts_staging", &view.use_payouts_staging)
        .field(
            "use_legacy_v2_bearer_for_capture",
            &view.use_legacy_v2_bearer_for_capture,
        )
        .finish()
}

fn redact_option<T>(opt: &Option<T>) -> &'static str {
    if opt.is_some() { "[REDACTED]" } else { "None" }
}

fn parse_region_env(raw: &str) -> Result<PaymobRegion, PaymobError> {
    let normalized = raw.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Err(PaymobError::ValidationError {
            field: "region",
            reason: "PAYMOB_REGION must not be empty".to_owned(),
        });
    }
    PaymobRegion::from_key_prefix(&normalized)
        .or_else(|| {
            ENV_REGION_ALIASES
                .iter()
                .find(|(alias, _)| *alias == normalized)
                .map(|(_, region)| region.clone())
        })
        .ok_or_else(|| PaymobError::ValidationError {
            field: "region",
            reason: format!("unrecognized PAYMOB_REGION value: {raw}"),
        })
}

fn parse_mode_env(raw: &str) -> Result<EnvironmentMode, PaymobError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "test" => Ok(EnvironmentMode::Test),
        "live" => Ok(EnvironmentMode::Live),
        _ => Err(PaymobError::ValidationError {
            field: "environment",
            reason: format!("invalid PAYMOB_ENVIRONMENT value: {raw}"),
        }),
    }
}

fn parse_timeout_env(raw: &str) -> Result<Duration, PaymobError> {
    let secs = raw
        .trim()
        .parse::<u64>()
        .map_err(|_| PaymobError::ValidationError {
            field: "timeout",
            reason: format!("invalid PAYMOB_TIMEOUT_SECS value: {raw}"),
        })?;
    if secs == 0 {
        return Err(PaymobError::ValidationError {
            field: "timeout",
            reason: "PAYMOB_TIMEOUT_SECS must be greater than zero".to_owned(),
        });
    }
    Ok(Duration::from_secs(secs))
}

fn parse_retries_env(raw: &str) -> Result<u32, PaymobError> {
    raw.trim()
        .parse::<u32>()
        .map_err(|_| PaymobError::ValidationError {
            field: "max_retries",
            reason: format!("invalid PAYMOB_MAX_RETRIES value: {raw}"),
        })
}

fn parse_bool_env(field: &'static str, raw: &str) -> Result<bool, PaymobError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        _ => Err(PaymobError::ValidationError {
            field,
            reason: format!("invalid boolean environment value for {field}: {raw}"),
        }),
    }
}

fn check_region_pair(
    left: Option<&PaymobRegion>,
    right: Option<&PaymobRegion>,
    context: &str,
) -> Result<(), PaymobError> {
    if let (Some(lhs), Some(rhs)) = (left, right) {
        if lhs != rhs {
            return Err(PaymobError::ValidationError {
                field: "region",
                reason: format!(
                    "{context}: {} vs {}",
                    lhs.country_code(),
                    rhs.country_code()
                ),
            });
        }
    }
    Ok(())
}

fn resolve_region_parity(
    configured: &PaymobRegion,
    sk_region: Option<&PaymobRegion>,
    pk_region: Option<&PaymobRegion>,
) -> Result<(), PaymobError> {
    check_region_pair(
        sk_region,
        pk_region,
        "secret_key and public_key region mismatch",
    )?;
    if matches!(configured, PaymobRegion::Custom { .. }) {
        return Ok(());
    }
    let key_region = sk_region.or(pk_region);
    check_region_pair(
        Some(configured),
        key_region,
        "configured region and key prefix region mismatch",
    )
}

fn check_mode_pair(
    left: Option<EnvironmentMode>,
    right: Option<EnvironmentMode>,
    context: &str,
) -> Result<(), PaymobError> {
    if let (Some(lhs), Some(rhs)) = (left, right) {
        if lhs != rhs {
            return Err(PaymobError::EnvironmentMismatch(format!(
                "{context}: {lhs:?} vs {rhs:?}"
            )));
        }
    }
    Ok(())
}

fn resolve_environment(
    explicit: Option<EnvironmentMode>,
    sk_mode: Option<EnvironmentMode>,
    pk_mode: Option<EnvironmentMode>,
) -> Result<EnvironmentMode, PaymobError> {
    check_mode_pair(
        sk_mode,
        pk_mode,
        "secret_key and public_key environment mismatch",
    )?;
    let inferred = sk_mode.or(pk_mode);
    check_mode_pair(
        explicit,
        inferred,
        "explicit environment and key prefix mismatch",
    )?;
    Ok(explicit.or(inferred).unwrap_or(EnvironmentMode::Test))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn tc_1_1_3_builds_valid_test_config_with_defaults() {
        let config = ClientConfig::builder()
            .region(PaymobRegion::Egypt)
            .secret_key(SecretKey::new("egy_sk_test_626secret").expect("valid secret key"))
            .public_key(PublicKey::new("egy_pk_test_999public").expect("valid public key"))
            .api_key(ApiKey::new("test_api_key").expect("valid api key"))
            .hmac_secret(HmacSecret::new("test_hmac_secret").expect("valid hmac secret"))
            .build()
            .expect("valid test config should build");

        assert_eq!(
            (
                config.region(),
                config.environment(),
                config.timeout(),
                config.max_retries()
            ),
            (
                &PaymobRegion::Egypt,
                EnvironmentMode::Test,
                Duration::from_secs(30),
                3
            )
        );
        assert!(!config.use_payouts_staging() && !config.use_legacy_v2_bearer_for_capture());
    }

    #[test]
    fn tc_1_1_3_builds_valid_live_config_with_custom_options() {
        let config = ClientConfig::builder()
            .region(PaymobRegion::SaudiArabia)
            .secret_key(SecretKey::new("ksa_sk_live_abc").expect("valid secret key"))
            .public_key(PublicKey::new("ksa_pk_live_xyz").expect("valid public key"))
            .timeout(Duration::from_secs(60))
            .max_retries(5)
            .use_payouts_staging(true)
            .use_legacy_v2_bearer_for_capture(true)
            .build()
            .expect("valid live config should build");

        assert_eq!(
            (config.environment(), config.timeout(), config.max_retries()),
            (EnvironmentMode::Live, Duration::from_secs(60), 5)
        );
        assert!(config.use_payouts_staging() && config.use_legacy_v2_bearer_for_capture());
    }

    #[test]
    fn tc_1_1_3_rejects_region_parity_mismatch() {
        let err = ClientConfig::builder()
            .region(PaymobRegion::Egypt)
            .secret_key(SecretKey::new("ksa_sk_test_123").expect("valid secret key"))
            .build()
            .expect_err("Egypt region with KSA key must fail");
        assert!(matches!(
            err,
            PaymobError::ValidationError {
                field: "region",
                ..
            }
        ));

        let pair_err = ClientConfig::builder()
            .region(PaymobRegion::Custom {
                accept_base_url: "https://accept.example.com".to_owned(),
                checkout_base_url: "https://checkout.example.com".to_owned(),
                payouts_base_url: "https://payouts.example.com".to_owned(),
                payouts_staging_base_url: "https://staging.example.com".to_owned(),
            })
            .secret_key(SecretKey::new("egy_sk_test_1").expect("valid sk"))
            .public_key(PublicKey::new("uae_pk_test_1").expect("valid pk"))
            .build()
            .expect_err("EGY secret + UAE public must fail");
        assert!(matches!(
            pair_err,
            PaymobError::ValidationError {
                field: "region",
                ..
            }
        ));
    }

    #[test]
    fn tc_1_1_3_rejects_test_and_live_environment_mismatch() {
        let err = ClientConfig::builder()
            .region(PaymobRegion::Egypt)
            .secret_key(SecretKey::new("egy_sk_test_626xxx").expect("valid secret key"))
            .public_key(PublicKey::new("egy_pk_live_999xxx").expect("valid public key"))
            .build()
            .expect_err("Test secret key + Live public key must fail");
        assert!(matches!(err, PaymobError::EnvironmentMismatch(_)));

        let err_explicit = ClientConfig::builder()
            .region(PaymobRegion::Uae)
            .environment(EnvironmentMode::Live)
            .secret_key(SecretKey::new("uae_sk_test_111").expect("valid secret key"))
            .build()
            .expect_err("Explicit Live + Test secret key must fail");
        assert!(matches!(err_explicit, PaymobError::EnvironmentMismatch(_)));
    }

    #[test]
    fn tc_1_1_3_rejects_missing_region_and_zero_timeout() {
        let err_region = ClientConfig::builder()
            .build()
            .expect_err("missing region must fail");
        assert!(matches!(
            err_region,
            PaymobError::ValidationError {
                field: "region",
                ..
            }
        ));

        let err_timeout = ClientConfig::builder()
            .region(PaymobRegion::Oman)
            .timeout(Duration::ZERO)
            .build()
            .expect_err("zero timeout must fail");
        assert!(matches!(
            err_timeout,
            PaymobError::ValidationError {
                field: "timeout",
                ..
            }
        ));
    }

    #[test]
    fn tc_1_1_3_debug_redacts_all_credentials_including_payouts_and_partner() {
        let builder = ClientConfig::builder()
            .region(PaymobRegion::Egypt)
            .secret_key(SecretKey::new("egy_sk_test_super_secret_value").expect("valid secret key"))
            .public_key(PublicKey::new("egy_pk_test_super_public_value").expect("valid public key"))
            .api_key(ApiKey::new("super_api_key_value").expect("valid api key"))
            .hmac_secret(HmacSecret::new("super_hmac_secret_value").expect("valid hmac secret"))
            .payouts_credentials(
                PayoutsCredentials::new(
                    "cid_leak_check",
                    "csec_leak_check",
                    "usr_leak",
                    "pwd_leak",
                )
                .expect("valid payouts"),
            )
            .partner_credentials(
                PartnerCredentials::with_bearer_token("partner_api_leak", "partner_tok_leak")
                    .expect("valid partner"),
            );

        let builder_dbg = format!("{builder:?}");
        let config = builder.build().expect("valid config should build");
        let config_dbg = format!("{config:?}");

        for leaked in [
            "super_secret_value",
            "super_public_value",
            "super_api_key_value",
            "super_hmac_secret_value",
            "csec_leak_check",
            "partner_tok_leak",
        ] {
            assert!(!builder_dbg.contains(leaked) && !config_dbg.contains(leaked));
        }
        assert!(builder_dbg.contains("[REDACTED]") && config_dbg.contains("[REDACTED]"));
    }

    #[test]
    fn tc_1_1_3_from_env_loads_valid_configuration() {
        let map: HashMap<&str, &str> = HashMap::from([
            ("PAYMOB_REGION", "ksa"),
            ("PAYMOB_ENVIRONMENT", "live"),
            ("PAYMOB_SECRET_KEY", "ksa_sk_live_env_secret"),
            ("PAYMOB_TIMEOUT_SECS", "45"),
            ("PAYMOB_MAX_RETRIES", "4"),
            ("PAYMOB_USE_PAYOUTS_STAGING", "true"),
        ]);
        let cfg = ClientConfigBuilder::from_env_with(|k| map.get(k).map(|v| (*v).to_owned()))
            .expect("valid env builder")
            .build()
            .expect("valid env config");
        assert_eq!(
            (
                cfg.region(),
                cfg.environment(),
                cfg.timeout(),
                cfg.max_retries()
            ),
            (
                &PaymobRegion::SaudiArabia,
                EnvironmentMode::Live,
                Duration::from_secs(45),
                4
            )
        );
        assert!(cfg.use_payouts_staging());
    }

    #[test]
    fn tc_1_1_3_from_env_rejects_missing_or_empty_region() {
        let missing = ClientConfigBuilder::from_env_with(|_| None);
        assert!(matches!(
            missing,
            Err(PaymobError::ValidationError {
                field: "region",
                ..
            })
        ));

        let empty = ClientConfigBuilder::from_env_with(|k| {
            (k == "PAYMOB_REGION").then(|| "   ".to_owned())
        });
        assert!(matches!(
            empty,
            Err(PaymobError::ValidationError {
                field: "region",
                ..
            })
        ));
    }

    #[test]
    fn tc_1_1_3_from_env_rejects_invalid_env_values() {
        let cases: &[(&str, &str, &str)] = &[
            ("PAYMOB_REGION", "mars", "region"),
            ("PAYMOB_ENVIRONMENT", "staging", "environment"),
            ("PAYMOB_TIMEOUT_SECS", "0", "timeout"),
            ("PAYMOB_TIMEOUT_SECS", "abc", "timeout"),
            ("PAYMOB_MAX_RETRIES", "nope", "max_retries"),
            ("PAYMOB_USE_PAYOUTS_STAGING", "maybe", "use_payouts_staging"),
            ("PAYMOB_SECRET_KEY", "pk_test_wrong", "secret_key"),
        ];
        for (var, val, expected_field) in cases {
            let err = ClientConfigBuilder::from_env_with(|k| {
                if k == "PAYMOB_REGION" && *var != "PAYMOB_REGION" {
                    Some("egy".to_owned())
                } else if k == *var {
                    Some((*val).to_owned())
                } else {
                    None
                }
            })
            .expect_err("invalid env var must fail");
            assert!(
                matches!(err, PaymobError::ValidationError { field, .. } if field == *expected_field)
            );
        }
    }
}

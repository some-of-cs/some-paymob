//! Client configuration and builder for `some-paymob` (`US-1.1.0/unit-3`).
//!
//! Provides [`ClientConfig`] and [`ClientConfigBuilder`] with deterministic
//! key-prefix environment parity validation (`Test` vs `Live`), strict
//! rejection of publishable keys (`pk_*`) in the secret key slot, configurable
//! timeouts and retry limits, Payouts staging and legacy-v2 capture `Bearer`
//! toggles, and `[REDACTED]` [`fmt::Debug`] formatting.

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

const REGION_PREFIXES: &[&str] = &["egy_", "ksa_", "uae_", "omn_", "pak_"];

const MODE_PREFIXES: &[(&str, EnvironmentMode)] = &[
    ("sk_test_", EnvironmentMode::Test),
    ("pk_test_", EnvironmentMode::Test),
    ("sk_live_", EnvironmentMode::Live),
    ("pk_live_", EnvironmentMode::Live),
];

/// Immutable configuration for [`crate::core::client::PaymobClient`].
///
/// Construct instances via [`ClientConfig::builder()`]. All credential fields
/// are redacted (`"[REDACTED]"`) in [`fmt::Debug`] output to prevent secret
/// leakage in logs or panic traces.
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
        f.debug_struct("ClientConfig")
            .field("region", &self.region)
            .field("environment", &self.environment)
            .field("secret_key", &redact_option(&self.secret_key))
            .field("public_key", &redact_option(&self.public_key))
            .field("api_key", &redact_option(&self.api_key))
            .field("hmac_secret", &redact_option(&self.hmac_secret))
            .field(
                "payouts_credentials",
                &redact_option(&self.payouts_credentials),
            )
            .field(
                "partner_credentials",
                &redact_option(&self.partner_credentials),
            )
            .field("timeout", &self.timeout)
            .field("max_retries", &self.max_retries)
            .field("use_payouts_staging", &self.use_payouts_staging)
            .field(
                "use_legacy_v2_bearer_for_capture",
                &self.use_legacy_v2_bearer_for_capture,
            )
            .finish()
    }
}

/// Ergonomic builder for constructing a validated [`ClientConfig`].
///
/// Validates credential prefix isolation (`pk_*` rejected in `secret_key`),
/// `Test` vs `Live` environment parity across keys, and non-zero request
/// timeouts before returning [`ClientConfig`].
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

    /// Validates all builder invariants and constructs a [`ClientConfig`].
    ///
    /// # Errors
    ///
    /// - [`PaymobError::ValidationError`] if `region` is unset, `timeout` is
    ///   zero, `secret_key` or `public_key` is empty, or a `pk_*` publishable
    ///   key was passed into `secret_key`.
    /// - [`PaymobError::EnvironmentMismatch`] if `Test` and `Live` credentials
    ///   (or explicit `environment`) are mixed.
    pub fn build(self) -> Result<ClientConfig, PaymobError> {
        let region = self.region.ok_or_else(|| PaymobError::ValidationError {
            field: "region",
            reason: "region must be specified".to_owned(),
        })?;
        if self.timeout.is_zero() {
            return Err(PaymobError::ValidationError {
                field: "timeout",
                reason: "timeout must be greater than zero".to_owned(),
            });
        }
        let sk_mode = validate_secret_key(self.secret_key.as_ref())?;
        let pk_mode = validate_public_key(self.public_key.as_ref())?;
        let environment = resolve_environment(self.environment, sk_mode, pk_mode)?;
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
        f.debug_struct("ClientConfigBuilder")
            .field("region", &self.region)
            .field("environment", &self.environment)
            .field("secret_key", &redact_option(&self.secret_key))
            .field("public_key", &redact_option(&self.public_key))
            .field("api_key", &redact_option(&self.api_key))
            .field("hmac_secret", &redact_option(&self.hmac_secret))
            .field(
                "payouts_credentials",
                &redact_option(&self.payouts_credentials),
            )
            .field(
                "partner_credentials",
                &redact_option(&self.partner_credentials),
            )
            .field("timeout", &self.timeout)
            .field("max_retries", &self.max_retries)
            .field("use_payouts_staging", &self.use_payouts_staging)
            .field(
                "use_legacy_v2_bearer_for_capture",
                &self.use_legacy_v2_bearer_for_capture,
            )
            .finish()
    }
}

fn redact_option<T>(opt: &Option<T>) -> &'static str {
    if opt.is_some() {
        "[REDACTED]"
    } else {
        "None"
    }
}

fn strip_region_prefix(raw: &str) -> &str {
    for prefix in REGION_PREFIXES {
        if let Some(rest) = raw.strip_prefix(prefix) {
            return rest;
        }
    }
    raw
}

fn is_public_key_raw(raw: &str) -> bool {
    strip_region_prefix(raw).starts_with("pk_")
}

fn infer_key_environment(raw: &str) -> Option<EnvironmentMode> {
    let normalized = strip_region_prefix(raw);
    for (prefix, mode) in MODE_PREFIXES {
        if normalized.starts_with(prefix) {
            return Some(*mode);
        }
    }
    None
}

fn validate_secret_key(
    secret_key: Option<&SecretKey>,
) -> Result<Option<EnvironmentMode>, PaymobError> {
    let Some(key) = secret_key else {
        return Ok(None);
    };
    let raw = key.expose_secret();
    if raw.trim().is_empty() {
        return Err(PaymobError::ValidationError {
            field: "secret_key",
            reason: "secret_key must not be empty".to_owned(),
        });
    }
    if is_public_key_raw(raw) {
        return Err(PaymobError::ValidationError {
            field: "secret_key",
            reason: "public key (pk_*) cannot be used in secret_key slot".to_owned(),
        });
    }
    Ok(infer_key_environment(raw))
}

fn validate_public_key(
    public_key: Option<&PublicKey>,
) -> Result<Option<EnvironmentMode>, PaymobError> {
    let Some(key) = public_key else {
        return Ok(None);
    };
    let raw = key.expose_secret();
    if raw.trim().is_empty() {
        return Err(PaymobError::ValidationError {
            field: "public_key",
            reason: "public_key must not be empty".to_owned(),
        });
    }
    Ok(infer_key_environment(raw))
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

        assert_eq!(config.region(), &PaymobRegion::Egypt);
        assert_eq!(config.environment(), EnvironmentMode::Test);
        assert_eq!(config.timeout(), Duration::from_secs(30));
        assert_eq!(config.max_retries(), 3);
        assert!(!config.use_payouts_staging());
        assert!(!config.use_legacy_v2_bearer_for_capture());
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

        assert_eq!(config.environment(), EnvironmentMode::Live);
        assert_eq!(config.timeout(), Duration::from_secs(60));
        assert_eq!(config.max_retries(), 5);
        assert!(config.use_payouts_staging());
        assert!(config.use_legacy_v2_bearer_for_capture());
    }

    #[test]
    fn tc_1_1_3_rejects_public_key_in_secret_key_slot() {
        for pk in ["pk_test_12345", "egy_pk_test_12345", "ksa_pk_live_99999"] {
            let err = SecretKey::new(pk)
                .expect_err("pk_* in secret_key must be rejected");

            assert!(
                matches!(
                    err,
                    PaymobError::ValidationError {
                        field: "secret_key",
                        ..
                    }
                ),
                "unexpected error for {pk}: {err:?}"
            );
        }
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
    fn tc_1_1_3_rejects_missing_region_and_zero_timeout_and_empty_keys() {
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

        let err_empty_sk = SecretKey::new("   ")
            .expect_err("blank secret_key must fail");
        assert!(matches!(
            err_empty_sk,
            PaymobError::ValidationError {
                field: "secret_key",
                ..
            }
        ));
    }

    #[test]
    fn tc_1_1_3_debug_redacts_all_credentials_on_config_and_builder() {
        let builder = ClientConfig::builder()
            .region(PaymobRegion::Egypt)
            .secret_key(SecretKey::new("egy_sk_test_super_secret_value").expect("valid secret key"))
            .public_key(PublicKey::new("egy_pk_test_super_public_value").expect("valid public key"))
            .api_key(ApiKey::new("super_api_key_value").expect("valid api key"))
            .hmac_secret(HmacSecret::new("super_hmac_secret_value").expect("valid hmac secret"));

        let builder_dbg = format!("{builder:?}");
        assert!(builder_dbg.contains("[REDACTED]"));
        assert!(!builder_dbg.contains("super_secret_value"));
        assert!(!builder_dbg.contains("super_public_value"));
        assert!(!builder_dbg.contains("super_api_key_value"));
        assert!(!builder_dbg.contains("super_hmac_secret_value"));

        let config = builder.build().expect("valid config should build");
        let config_dbg = format!("{config:?}");
        assert!(config_dbg.contains("[REDACTED]"));
        assert!(!config_dbg.contains("super_secret_value"));
        assert!(!config_dbg.contains("super_public_value"));
        assert!(!config_dbg.contains("super_api_key_value"));
        assert!(!config_dbg.contains("super_hmac_secret_value"));
    }
}

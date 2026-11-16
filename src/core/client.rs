#![forbid(unsafe_code)]
//! Arc-backed Paymob microkernel client and regional URL builders.
//!
//! [`PaymobClient`] is the primary entry point for `some-paymob`. It wraps a
//! shared [`PaymobCore`] inside an [`Arc`] so cloning the client across async
//! tasks or HTTP handlers is an atomic reference-count increment (`O(1)`),
//! with compile-time `Send + Sync` guarantees and `[REDACTED]` debug output.

use std::fmt;
use std::sync::Arc;

use url::Url;

use crate::core::config::ClientConfig;
use crate::core::error::PaymobError;
use crate::core::http::{HttpClient, HttpClientConfig, RetryPolicy};
use crate::core::region::RegionalEndpoints;

/// Shared microkernel state backing [`PaymobClient`].
///
/// Holds the validated [`ClientConfig`], resolved [`RegionalEndpoints`], and
/// the underlying resilient TLS 1.3 [`HttpClient`] transport pipeline.
pub struct PaymobCore {
    config: ClientConfig,
    endpoints: RegionalEndpoints,
    http: HttpClient,
}

impl fmt::Debug for PaymobCore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PaymobCore")
            .field("region", self.config.region())
            .field("endpoints", &self.endpoints)
            .field("credentials", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Thread-safe, cheaply cloneable Paymob microkernel client.
///
/// Wraps `Arc<PaymobCore>` so it can be shared freely across Tokio tasks,
/// Axum/Actix state extractors, and Tonic gRPC services without duplicating
/// connection pools or credential buffers.
///
/// # Examples
///
/// ```rust,no_run
/// use some_paymob::core::client::PaymobClient;
/// use some_paymob::core::config::ClientConfig;
/// use some_paymob::core::credentials::{PublicKey, SecretKey};
/// use some_paymob::core::region::PaymobRegion;
///
/// # fn example() -> Result<(), some_paymob::core::error::PaymobError> {
/// let config = ClientConfig::builder()
///     .region(PaymobRegion::Egypt)
///     .secret_key(SecretKey::new("egy_sk_test_example")?)
///     .public_key(PublicKey::new("egy_pk_test_example")?)
///     .build()?;
///
/// let client = PaymobClient::new(config)?;
/// let cloned = client.clone();
/// let intention_url = cloned.accept_url("/v1/intention/")?;
/// assert_eq!(intention_url.as_str(), "https://accept.paymob.com/v1/intention/");
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct PaymobClient {
    inner: Arc<PaymobCore>,
}

#[allow(dead_code)]
const _: () = {
    fn assert_send_sync<T: Send + Sync>() {}
    fn check() {
        assert_send_sync::<PaymobClient>();
        assert_send_sync::<PaymobCore>();
    }
};

impl fmt::Debug for PaymobClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PaymobClient")
            .field("core", &self.inner)
            .finish()
    }
}

impl PaymobClient {
    /// Constructs a new [`PaymobClient`] from a validated [`ClientConfig`].
    ///
    /// Resolves [`RegionalEndpoints`] for the configured region and initializes
    /// the underlying [`HttpClient`] with `connect_timeout`, `request_timeout`,
    /// TLS 1.3 (when `rustls-tls` is enabled), and `max_retries` mapped from
    /// `config`.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if regional endpoint resolution
    /// fails, or [`PaymobError::TransportError`] if the HTTP client fails to
    /// initialize.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use some_paymob::core::client::PaymobClient;
    /// use some_paymob::core::config::ClientConfig;
    /// use some_paymob::core::credentials::SecretKey;
    /// use some_paymob::core::region::PaymobRegion;
    ///
    /// # fn example() -> Result<(), some_paymob::core::error::PaymobError> {
    /// let config = ClientConfig::builder()
    ///     .region(PaymobRegion::Egypt)
    ///     .secret_key(SecretKey::new("egy_sk_test_example")?)
    ///     .build()?;
    /// let client = PaymobClient::new(config)?;
    /// assert!(format!("{client:?}").contains("[REDACTED]"));
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(config: ClientConfig) -> Result<Self, PaymobError> {
        let endpoints = config.region().endpoints()?;
        let default_http = HttpClientConfig::default();
        let http_config = HttpClientConfig {
            connect_timeout: config.timeout().min(default_http.connect_timeout),
            request_timeout: config.timeout(),
            max_response_bytes: default_http.max_response_bytes,
            allow_insecure_http: default_http.allow_insecure_http,
            retry: RetryPolicy {
                max_retries: config.max_retries(),
                ..default_http.retry
            },
        };
        let http = HttpClient::new(http_config)
            .map_err(|err| PaymobError::TransportError(err.to_string()))?;
        let core = PaymobCore {
            config,
            endpoints,
            http,
        };
        Ok(Self {
            inner: Arc::new(core),
        })
    }

    /// Returns a reference to the validated [`ClientConfig`].
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use some_paymob::core::client::PaymobClient;
    /// use some_paymob::core::config::ClientConfig;
    /// use some_paymob::core::credentials::SecretKey;
    /// use some_paymob::core::region::PaymobRegion;
    ///
    /// # fn example() -> Result<(), some_paymob::core::error::PaymobError> {
    /// let config = ClientConfig::builder()
    ///     .region(PaymobRegion::SaudiArabia)
    ///     .secret_key(SecretKey::new("ksa_sk_test_example")?)
    ///     .build()?;
    /// let client = PaymobClient::new(config)?;
    /// assert_eq!(client.config().region(), &PaymobRegion::SaudiArabia);
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn config(&self) -> &ClientConfig {
        &self.inner.config
    }

    /// Returns a reference to the resolved [`RegionalEndpoints`].
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use some_paymob::core::client::PaymobClient;
    /// use some_paymob::core::config::ClientConfig;
    /// use some_paymob::core::credentials::SecretKey;
    /// use some_paymob::core::region::PaymobRegion;
    ///
    /// # fn example() -> Result<(), some_paymob::core::error::PaymobError> {
    /// let config = ClientConfig::builder()
    ///     .region(PaymobRegion::Egypt)
    ///     .secret_key(SecretKey::new("egy_sk_test_example")?)
    ///     .build()?;
    /// let client = PaymobClient::new(config)?;
    /// let _endpoints = client.endpoints();
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn endpoints(&self) -> &RegionalEndpoints {
        &self.inner.endpoints
    }

    /// Returns a reference to the underlying resilient [`HttpClient`] transport.
    #[must_use]
    pub fn http(&self) -> &HttpClient {
        &self.inner.http
    }

    /// Builds a full Accept Acquiring URL by joining `path` onto the regional Accept base URL.
    ///
    /// Preserves trailing slashes on `path` (for example, `/v1/intention/`).
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `path` is empty, contains control
    /// characters, backslashes, `.`/`..` traversal segments, an explicit URL
    /// scheme/authority, or produces an invalid URL.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use some_paymob::core::client::PaymobClient;
    /// use some_paymob::core::config::ClientConfig;
    /// use some_paymob::core::credentials::SecretKey;
    /// use some_paymob::core::region::PaymobRegion;
    ///
    /// # fn example() -> Result<(), some_paymob::core::error::PaymobError> {
    /// let config = ClientConfig::builder()
    ///     .region(PaymobRegion::Egypt)
    ///     .secret_key(SecretKey::new("egy_sk_test_example")?)
    ///     .build()?;
    /// let client = PaymobClient::new(config)?;
    /// let url = client.accept_url("/v1/intention/")?;
    /// assert_eq!(url.as_str(), "https://accept.paymob.com/v1/intention/");
    /// # Ok(())
    /// # }
    /// ```
    pub fn accept_url(&self, path: &str) -> Result<Url, PaymobError> {
        let clean_path = ensure_relative_path(path)?;
        let resolved = self.inner.endpoints.accept_url(clean_path)?;
        parse_regional_url(&resolved, "accept_url")
    }

    /// Builds a full Unified Checkout URL by joining `path` onto the regional Checkout base URL.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `path` is empty, contains control
    /// characters, backslashes, `.`/`..` traversal segments, an explicit URL
    /// scheme/authority, or produces an invalid URL.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use some_paymob::core::client::PaymobClient;
    /// use some_paymob::core::config::ClientConfig;
    /// use some_paymob::core::credentials::SecretKey;
    /// use some_paymob::core::region::PaymobRegion;
    ///
    /// # fn example() -> Result<(), some_paymob::core::error::PaymobError> {
    /// let config = ClientConfig::builder()
    ///     .region(PaymobRegion::Egypt)
    ///     .secret_key(SecretKey::new("egy_sk_test_example")?)
    ///     .build()?;
    /// let client = PaymobClient::new(config)?;
    /// let url = client.checkout_url("/?publicKey=egy_pk_test_1&clientSecret=cs_1")?;
    /// assert!(url.as_str().starts_with("https://accept.paymob.com/unifiedcheckout/"));
    /// # Ok(())
    /// # }
    /// ```
    pub fn checkout_url(&self, path: &str) -> Result<Url, PaymobError> {
        let clean_path = ensure_relative_path(path)?;
        let resolved = self.inner.endpoints.checkout_url(clean_path)?;
        parse_regional_url(&resolved, "checkout_url")
    }

    /// Builds a full Payouts URL by joining `path` onto the regional Payouts base URL.
    ///
    /// Routes to the Payouts staging host when [`ClientConfig::use_payouts_staging`]
    /// is enabled, and preserves trailing slashes required by Payouts endpoints
    /// (for example, `/api/secure/disburse/`).
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if Payouts is unavailable for the
    /// configured region (such as [`crate::core::region::PaymobRegion::Pakistan`]),
    /// or if `path` is empty, contains control characters, backslashes, `.`/`..`
    /// traversal segments, an explicit URL scheme/authority, or produces an invalid URL.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use some_paymob::core::client::PaymobClient;
    /// use some_paymob::core::config::ClientConfig;
    /// use some_paymob::core::credentials::SecretKey;
    /// use some_paymob::core::region::PaymobRegion;
    ///
    /// # fn example() -> Result<(), some_paymob::core::error::PaymobError> {
    /// let config = ClientConfig::builder()
    ///     .region(PaymobRegion::Egypt)
    ///     .secret_key(SecretKey::new("egy_sk_test_example")?)
    ///     .build()?;
    /// let client = PaymobClient::new(config)?;
    /// let url = client.payouts_url("/api/secure/disburse/")?;
    /// assert_eq!(
    ///     url.as_str(),
    ///     "https://payouts.paymobsolutions.com/api/secure/disburse/"
    /// );
    /// # Ok(())
    /// # }
    /// ```
    pub fn payouts_url(&self, path: &str) -> Result<Url, PaymobError> {
        let clean_path = ensure_relative_path(path)?;
        let resolved = self
            .inner
            .endpoints
            .payouts_url(clean_path, self.inner.config.use_payouts_staging())?;
        parse_regional_url(&resolved, "payouts_url")
    }

    /// Returns `true` when two [`PaymobClient`] handles share the same underlying [`PaymobCore`].
    #[must_use]
    pub fn ptr_eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }
}

fn has_forbidden_chars_or_authority(path: &str, trimmed: &str) -> bool {
    trimmed.is_empty()
        || path.bytes().any(|b| b.is_ascii_control())
        || trimmed.contains('\\')
        || trimmed.contains("://")
        || trimmed.starts_with("//")
}

fn has_scheme_prefix(trimmed: &str) -> bool {
    let before_query = trimmed.split(['?', '#']).next().unwrap_or(trimmed);
    let first_segment = before_query.split('/').next().unwrap_or(before_query);
    first_segment.contains(':')
}

fn has_dot_segment(trimmed: &str) -> bool {
    let before_query = trimmed.split(['?', '#']).next().unwrap_or(trimmed);
    before_query
        .split('/')
        .any(|segment| segment == "." || segment == "..")
}

fn ensure_relative_path(path: &str) -> Result<&str, PaymobError> {
    let trimmed = path.trim();
    if has_forbidden_chars_or_authority(path, trimmed)
        || has_scheme_prefix(trimmed)
        || has_dot_segment(trimmed)
    {
        return Err(PaymobError::ValidationError {
            field: "path",
            reason: "relative endpoint path must be non-empty, relative, and free of control chars or traversal segments".to_owned(),
        });
    }
    Ok(trimmed)
}

fn parse_regional_url(resolved: &str, field: &'static str) -> Result<Url, PaymobError> {
    Url::parse(resolved).map_err(|err| PaymobError::ValidationError {
        field,
        reason: format!("invalid regional URL: {err}"),
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::core::credentials::{PublicKey, SecretKey};
    use crate::core::region::PaymobRegion;

    fn sample_client(region: PaymobRegion) -> PaymobClient {
        let prefix = match region {
            PaymobRegion::Egypt | PaymobRegion::Custom { .. } => "egy",
            PaymobRegion::SaudiArabia => "ksa",
            PaymobRegion::Uae => "uae",
            PaymobRegion::Oman => "omn",
            PaymobRegion::Pakistan => "pak",
        };
        let secret = format!("{prefix}_sk_test_626supersecretvalue");
        let public = format!("{prefix}_pk_test_999publicvalue");
        let config = ClientConfig::builder()
            .region(region)
            .secret_key(SecretKey::new(&secret).expect("valid test secret key"))
            .public_key(PublicKey::new(&public).expect("valid test public key"))
            .build()
            .expect("valid test client config");
        PaymobClient::new(config).expect("valid PaymobClient")
    }

    #[test]
    fn tc_1_1_4_cheap_clone_shares_arc_core() {
        let client = sample_client(PaymobRegion::Egypt);
        let cloned = client.clone();
        assert!(client.ptr_eq(&cloned));
    }

    #[test]
    fn tc_1_1_4_send_sync_runtime_check() {
        fn requires_send_sync<T: Send + Sync>(_val: &T) {}
        let client = sample_client(PaymobRegion::Egypt);
        requires_send_sync(&client);
    }

    #[test]
    fn tc_1_1_4_http_client_wires_timeout_and_retries() {
        let config = ClientConfig::builder()
            .region(PaymobRegion::Egypt)
            .timeout(Duration::from_secs(5))
            .max_retries(7)
            .build()
            .expect("valid config");
        let client = PaymobClient::new(config).expect("valid PaymobClient");
        let http_cfg = client.http().config();
        assert_eq!(
            (
                http_cfg.connect_timeout,
                http_cfg.request_timeout,
                http_cfg.retry.max_retries
            ),
            (Duration::from_secs(5), Duration::from_secs(5), 7)
        );
    }

    #[test]
    fn tc_1_1_4_regional_url_builders_preserve_trailing_slashes() {
        let client = sample_client(PaymobRegion::Egypt);
        let accept = client
            .accept_url("/v1/intention/")
            .expect("accept URL should parse");
        let checkout = client
            .checkout_url("?publicKey=pk_1&clientSecret=cs_1")
            .expect("checkout URL should parse");
        let payouts = client
            .payouts_url("/api/secure/disburse/")
            .expect("payouts URL should parse");
        assert_eq!(
            (accept.as_str(), checkout.as_str(), payouts.as_str()),
            (
                "https://accept.paymob.com/v1/intention/",
                "https://accept.paymob.com/unifiedcheckout/?publicKey=pk_1&clientSecret=cs_1",
                "https://payouts.paymobsolutions.com/api/secure/disburse/",
            )
        );
    }

    #[test]
    fn tc_1_1_4_regional_url_builders_reject_unsafe_paths() {
        let client = sample_client(PaymobRegion::Egypt);
        let unsafe_paths = [
            "https://evil.example.com/steal",
            "//evil.example.com/steal",
            "http:evil.example.com",
            "/v1/../admin",
            "./v1/intention",
            "/v1\\intention",
            "/v1/intention\r\nX-Injected: 1",
            "/v1/intention\0",
            "/v1/\tintention",
        ];
        for bad in unsafe_paths {
            assert!(matches!(
                client.accept_url(bad),
                Err(PaymobError::ValidationError { field: "path", .. })
            ));
        }
    }

    #[test]
    fn tc_1_1_4_config_and_endpoints_accessors_match_region() {
        let client = sample_client(PaymobRegion::SaudiArabia);
        assert_eq!(
            (
                client.config().region(),
                client.endpoints().accept_base_url.as_str()
            ),
            (&PaymobRegion::SaudiArabia, "https://ksa.paymob.com")
        );
    }

    #[test]
    fn tc_1_1_4_debug_output_redacts_secrets() {
        let client = sample_client(PaymobRegion::Egypt);
        let debug_str = format!("{client:?}");
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains("626supersecretvalue") && !debug_str.contains("egy_sk_test_"));
    }

    #[test]
    fn tc_1_1_4_empty_path_and_unsupported_payouts_are_rejected() {
        let client = sample_client(PaymobRegion::Pakistan);
        assert!(matches!(
            client.accept_url(""),
            Err(PaymobError::ValidationError { field: "path", .. })
        ));
        assert!(matches!(
            client.payouts_url("/api/secure/disburse/"),
            Err(PaymobError::ValidationError {
                field: "region",
                ..
            })
        ));
    }

    #[test]
    fn tc_1_1_4_payouts_url_respects_staging_toggle() {
        let config = ClientConfig::builder()
            .region(PaymobRegion::Egypt)
            .secret_key(
                SecretKey::new("egy_sk_test_626supersecretvalue").expect("valid test secret key"),
            )
            .use_payouts_staging(true)
            .build()
            .expect("valid test client config");
        let client = PaymobClient::new(config).expect("valid PaymobClient");
        let url = client
            .payouts_url("/api/secure/disburse/")
            .expect("staging payouts URL should parse");
        assert_eq!(
            url.as_str(),
            "https://stagingpayouts.paymobsolutions.com/api/secure/disburse/"
        );
    }
}

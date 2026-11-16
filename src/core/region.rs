#![forbid(unsafe_code)]
//! Multi-region dual-host URL routing and endpoint trailing-slash normalization.
//!
//! Paymob partitions its infrastructure by **country** (`EGY`, `KSA`, `UAE`, `OMN`,
//! `PAK`) and by **product line** (Accept Acquiring, Unified Checkout, and Payouts
//! Disbursement). In addition, Paymob's API v0.6.3 changelog mandates strict
//! trailing-slash preservation on `/v1/intention/` and Payouts `/api/secure/`
//! endpoints.
//!
//! This module provides [`PaymobRegion`], [`RegionalEndpoints`], and
//! [`normalize_endpoint_path`] to deterministically resolve and validate regional
//! URLs before any network request leaves the process.

use serde::{Deserialize, Serialize};
use url::Url;

use crate::core::error::PaymobError;

/// Static lookup table mapping country key prefixes to [`PaymobRegion`].
const PREFIX_REGION_TABLE: &[(&str, PaymobRegion)] = &[
    ("egy", PaymobRegion::Egypt),
    ("ksa", PaymobRegion::SaudiArabia),
    ("sau", PaymobRegion::SaudiArabia),
    ("uae", PaymobRegion::Uae),
    ("are", PaymobRegion::Uae),
    ("omn", PaymobRegion::Oman),
    ("pak", PaymobRegion::Pakistan),
];

/// Supported Paymob regional deployments and custom gateway overrides.
///
/// Each built-in variant resolves deterministic base URLs for Accept Acquiring,
/// Unified Checkout, Payouts Production, and Payouts Staging per the official
/// Paymob Developer Portal.
///
/// # Examples
///
/// ```
/// use some_paymob::core::region::PaymobRegion;
///
/// let region = PaymobRegion::Egypt;
/// let endpoints = region.endpoints().expect("built-in region is valid");
/// assert_eq!(endpoints.accept_base_url, "https://accept.paymob.com");
/// assert_eq!(
///     endpoints.checkout_base_url,
///     "https://accept.paymob.com/unifiedcheckout/"
/// );
/// assert_eq!(
///     endpoints.payouts_base_url.as_deref(),
///     Some("https://payouts.paymobsolutions.com")
/// );
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PaymobRegion {
    /// Arab Republic of Egypt (`EGY`).
    Egypt,
    /// Kingdom of Saudi Arabia (`KSA`).
    SaudiArabia,
    /// United Arab Emirates (`UAE`).
    Uae,
    /// Sultanate of Oman (`OMN`).
    Oman,
    /// Islamic Republic of Pakistan (`PAK`).
    Pakistan,
    /// Custom regional endpoint overrides for dedicated environments or mock servers.
    Custom {
        /// Base URL for the Accept Acquiring API (e.g., `https://accept.paymob.com`).
        accept_base_url: String,
        /// Base URL for Unified Checkout (e.g., `https://accept.paymob.com/unifiedcheckout/`).
        checkout_base_url: String,
        /// Base URL for the Payouts Production API.
        payouts_base_url: String,
        /// Base URL for the Payouts Staging API.
        payouts_staging_base_url: String,
    },
}

/// Resolved dual-host base URLs for a [`PaymobRegion`].
///
/// # Examples
///
/// ```
/// use some_paymob::core::region::PaymobRegion;
///
/// let endpoints = PaymobRegion::SaudiArabia.endpoints().unwrap();
/// let intention_url = endpoints.accept_url("v1/intention").unwrap();
/// assert_eq!(intention_url, "https://ksa.paymob.com/v1/intention/");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RegionalEndpoints {
    /// Accept Acquiring API base URL without a trailing slash.
    pub accept_base_url: String,
    /// Unified Checkout base URL (preserving `/unifiedcheckout/`).
    pub checkout_base_url: String,
    /// Payouts Production API base URL, or `None` when unsupported in the region.
    pub payouts_base_url: Option<String>,
    /// Payouts Staging API base URL, or `None` when unsupported in the region.
    pub payouts_staging_base_url: Option<String>,
}

/// Borrowed base URL inputs for [`PaymobRegion::Custom`].
struct CustomUrlInputs<'a> {
    accept_base_url: &'a str,
    checkout_base_url: &'a str,
    payouts_base_url: &'a str,
    payouts_staging_base_url: &'a str,
}

/// Identifies a [`PaymobRegion::Custom`] URL field for validation errors.
#[derive(Clone, Copy)]
enum CustomUrlField {
    AcceptBaseUrl,
    CheckoutBaseUrl,
    PayoutsBaseUrl,
    PayoutsStagingBaseUrl,
}

impl CustomUrlField {
    /// Returns the static field name used in [`PaymobError::ValidationError`].
    const fn as_str(self) -> &'static str {
        match self {
            Self::AcceptBaseUrl => "accept_base_url",
            Self::CheckoutBaseUrl => "checkout_base_url",
            Self::PayoutsBaseUrl => "payouts_base_url",
            Self::PayoutsStagingBaseUrl => "payouts_staging_base_url",
        }
    }
}

/// Borrowed base URL and endpoint path pair for [`join_base_and_path`].
struct JoinPathRequest<'a> {
    base: &'a str,
    path: &'a str,
}

impl PaymobRegion {
    /// Resolves and validates the [`RegionalEndpoints`] for this region.
    ///
    /// Built-in regions always succeed. [`PaymobRegion::Custom`] validates that
    /// every configured URL is non-empty, parses cleanly, uses `https` (or `http`
    /// only for loopback/local test hosts), includes a host, and omits embedded
    /// credentials, queries, and fragments.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if any URL in [`PaymobRegion::Custom`]
    /// is empty, malformed, lacks a host, uses an unsupported scheme, or contains
    /// embedded credentials, query parameters, or fragments.
    ///
    /// # Examples
    ///
    /// ```
    /// use some_paymob::core::region::PaymobRegion;
    ///
    /// let eps = PaymobRegion::Uae.endpoints().unwrap();
    /// assert_eq!(eps.accept_base_url, "https://uae.paymob.com");
    /// assert_eq!(
    ///     eps.payouts_staging_base_url.as_deref(),
    ///     Some("https://stagingpayouts-uae.paymobsolutions.com")
    /// );
    /// ```
    pub fn endpoints(&self) -> Result<RegionalEndpoints, PaymobError> {
        match self {
            Self::Egypt => Ok(RegionalEndpoints {
                accept_base_url: "https://accept.paymob.com".to_string(),
                checkout_base_url: "https://accept.paymob.com/unifiedcheckout/".to_string(),
                payouts_base_url: Some("https://payouts.paymobsolutions.com".to_string()),
                payouts_staging_base_url: Some(
                    "https://stagingpayouts.paymobsolutions.com".to_string(),
                ),
            }),
            Self::SaudiArabia => Ok(RegionalEndpoints {
                accept_base_url: "https://ksa.paymob.com".to_string(),
                checkout_base_url: "https://ksa.paymob.com/unifiedcheckout/".to_string(),
                payouts_base_url: Some("https://payouts.paymob.sa".to_string()),
                payouts_staging_base_url: Some("https://stagingpayouts.paymob.sa".to_string()),
            }),
            Self::Uae => Ok(RegionalEndpoints {
                accept_base_url: "https://uae.paymob.com".to_string(),
                checkout_base_url: "https://uae.paymob.com/unifiedcheckout/".to_string(),
                payouts_base_url: Some("https://payouts-uae.paymobsolutions.com".to_string()),
                payouts_staging_base_url: Some(
                    "https://stagingpayouts-uae.paymobsolutions.com".to_string(),
                ),
            }),
            Self::Oman => Ok(RegionalEndpoints {
                accept_base_url: "https://oman.paymob.com".to_string(),
                checkout_base_url: "https://oman.paymob.com/unifiedcheckout/".to_string(),
                payouts_base_url: Some("https://oman.paymob.com".to_string()),
                payouts_staging_base_url: Some("https://oman.paymob.com".to_string()),
            }),
            Self::Pakistan => Ok(RegionalEndpoints {
                accept_base_url: "https://pakistan.paymob.com".to_string(),
                checkout_base_url: "https://pakistan.paymob.com/unifiedcheckout/".to_string(),
                payouts_base_url: None,
                payouts_staging_base_url: None,
            }),
            Self::Custom {
                accept_base_url,
                checkout_base_url,
                payouts_base_url,
                payouts_staging_base_url,
            } => resolve_custom_endpoints(CustomUrlInputs {
                accept_base_url,
                checkout_base_url,
                payouts_base_url,
                payouts_staging_base_url,
            }),
        }
    }

    /// Resolves a full Accept Acquiring URL by normalizing `path` and joining it
    /// with the region's Accept base URL.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `self` is an invalid custom
    /// region or if `path` is empty.
    pub fn resolve_accept_url(&self, path: &str) -> Result<String, PaymobError> {
        self.endpoints()?.accept_url(path)
    }

    /// Resolves a full Unified Checkout URL by normalizing `path` and joining it
    /// with the region's Unified Checkout base URL.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `self` is an invalid custom
    /// region or if `path` is empty.
    pub fn resolve_checkout_url(&self, path: &str) -> Result<String, PaymobError> {
        self.endpoints()?.checkout_url(path)
    }

    /// Resolves a full Payouts URL (production or staging) by normalizing `path`
    /// and joining it with the region's Payouts base URL.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if Payouts is unsupported for
    /// this region (such as [`PaymobRegion::Pakistan`]), if `self` is an invalid
    /// custom region, or if `path` is empty.
    pub fn resolve_payouts_url(&self, path: &str, staging: bool) -> Result<String, PaymobError> {
        self.endpoints()?.payouts_url(path, staging)
    }

    /// Infers a built-in [`PaymobRegion`] from a lowercase or uppercase 3-letter
    /// credential prefix (e.g., `"egy"`, `"ksa"`, `"uae"`, `"omn"`, `"pak"`).
    ///
    /// Returns `None` if the prefix does not match a known region.
    ///
    /// # Examples
    ///
    /// ```
    /// use some_paymob::core::region::PaymobRegion;
    ///
    /// assert_eq!(PaymobRegion::from_key_prefix("egy"), Some(PaymobRegion::Egypt));
    /// assert_eq!(PaymobRegion::from_key_prefix("KSA"), Some(PaymobRegion::SaudiArabia));
    /// assert_eq!(PaymobRegion::from_key_prefix("unknown"), None);
    /// ```
    pub fn from_key_prefix(prefix: &str) -> Option<Self> {
        let normalized = prefix.trim().to_ascii_lowercase();
        PREFIX_REGION_TABLE
            .iter()
            .find(|(code, _)| *code == normalized)
            .map(|(_, region)| region.clone())
    }

    /// Returns the canonical uppercase region code (`"EGY"`, `"KSA"`, `"UAE"`,
    /// `"OMN"`, `"PAK"`, or `"CUSTOM"`).
    pub fn country_code(&self) -> &'static str {
        match self {
            Self::Egypt => "EGY",
            Self::SaudiArabia => "KSA",
            Self::Uae => "UAE",
            Self::Oman => "OMN",
            Self::Pakistan => "PAK",
            Self::Custom { .. } => "CUSTOM",
        }
    }
}

impl RegionalEndpoints {
    /// Builds a full Accept Acquiring URL for `path` using [`normalize_endpoint_path`].
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `path` is empty or whitespace.
    pub fn accept_url(&self, path: &str) -> Result<String, PaymobError> {
        join_base_and_path(JoinPathRequest {
            base: &self.accept_base_url,
            path,
        })
    }

    /// Builds a full Unified Checkout URL for `path` using [`normalize_endpoint_path`].
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `path` is empty or whitespace.
    pub fn checkout_url(&self, path: &str) -> Result<String, PaymobError> {
        join_base_and_path(JoinPathRequest {
            base: &self.checkout_base_url,
            path,
        })
    }

    /// Builds a full Payouts URL (production when `staging == false`, staging when
    /// `staging == true`) using [`normalize_endpoint_path`].
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if Payouts is unavailable for this
    /// region or if `path` is empty or whitespace.
    pub fn payouts_url(&self, path: &str, staging: bool) -> Result<String, PaymobError> {
        let base = if staging {
            self.payouts_staging_base_url.as_deref()
        } else {
            self.payouts_base_url.as_deref()
        };
        let Some(base_url) = base else {
            return Err(PaymobError::ValidationError {
                field: "region",
                reason: "Payouts API is not available for this Paymob region".to_string(),
            });
        };
        join_base_and_path(JoinPathRequest {
            base: base_url,
            path,
        })
    }
}

/// Normalizes an API endpoint path according to Paymob's trailing-slash contract.
///
/// - Collapses repeated slashes (`//` -> `/`) and ensures a leading `/`.
/// - Preserves (or enforces) a single trailing `/` on `/v1/intention/` and
///   Payouts `/api/secure/.../` paths (including `/api/secure/disburse/`).
/// - Strips trailing slashes on all other non-root paths.
/// - Preserves any `?query` suffix verbatim.
///
/// # Examples
///
/// ```
/// use some_paymob::core::region::normalize_endpoint_path;
///
/// assert_eq!(normalize_endpoint_path("v1/intention"), "/v1/intention/");
/// assert_eq!(normalize_endpoint_path("/v1/intention/"), "/v1/intention/");
/// assert_eq!(
///     normalize_endpoint_path("/api/secure/disburse"),
///     "/api/secure/disburse/"
/// );
/// assert_eq!(normalize_endpoint_path("/api/auth/tokens/"), "/api/auth/tokens");
/// ```
pub fn normalize_endpoint_path(path: &str) -> String {
    let trimmed = path.trim();
    let (raw_path, query) = match trimmed.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (trimmed, None),
    };
    let mut clean = collapse_slashes(raw_path);
    if requires_trailing_slash(&clean) {
        clean.push('/');
    }
    if let Some(q) = query {
        clean.push('?');
        clean.push_str(q);
    }
    clean
}

/// Validates and resolves all four base URLs for [`PaymobRegion::Custom`].
fn resolve_custom_endpoints(inputs: CustomUrlInputs<'_>) -> Result<RegionalEndpoints, PaymobError> {
    let accept = validate_custom_url(CustomUrlField::AcceptBaseUrl, inputs.accept_base_url)?;
    let checkout = validate_custom_url(CustomUrlField::CheckoutBaseUrl, inputs.checkout_base_url)?;
    let payouts = validate_custom_url(CustomUrlField::PayoutsBaseUrl, inputs.payouts_base_url)?;
    let payouts_staging = validate_custom_url(
        CustomUrlField::PayoutsStagingBaseUrl,
        inputs.payouts_staging_base_url,
    )?;

    Ok(RegionalEndpoints {
        accept_base_url: accept,
        checkout_base_url: format!("{checkout}/"),
        payouts_base_url: Some(payouts),
        payouts_staging_base_url: Some(payouts_staging),
    })
}

/// Validates a single custom URL field for non-emptiness, valid syntax, host
/// presence, scheme policy, and absence of credentials, queries, or fragments.
fn validate_custom_url(field: CustomUrlField, raw: &str) -> Result<String, PaymobError> {
    let field_name = field.as_str();
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(PaymobError::ValidationError {
            field: field_name,
            reason: format!("{field_name} must not be empty"),
        });
    }
    let parsed = Url::parse(trimmed).map_err(|err| PaymobError::ValidationError {
        field: field_name,
        reason: format!("invalid URL for {field_name}: {err}"),
    })?;
    validate_custom_url_scheme(field, &parsed)?;
    validate_custom_url_parts(field, &parsed)?;
    Ok(trimmed.trim_end_matches('/').to_string())
}

/// Enforces host presence, `https` for remote hosts, and `http` only on loopback/local test hosts.
fn validate_custom_url_scheme(field: CustomUrlField, parsed: &Url) -> Result<(), PaymobError> {
    let field_name = field.as_str();
    let Some(host) = parsed.host_str() else {
        return Err(PaymobError::ValidationError {
            field: field_name,
            reason: format!("{field_name} must include a host"),
        });
    };
    if parsed.scheme() == "https" {
        return Ok(());
    }
    if parsed.scheme() == "http" && is_loopback_or_local_host(host) {
        return Ok(());
    }
    Err(PaymobError::ValidationError {
        field: field_name,
        reason: format!("{field_name} must use https unless targeting a local/loopback host"),
    })
}

/// Rejects embedded credentials (`username`/`password`) and `query`/`fragment` parts.
fn validate_custom_url_parts(field: CustomUrlField, parsed: &Url) -> Result<(), PaymobError> {
    let field_name = field.as_str();
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(PaymobError::ValidationError {
            field: field_name,
            reason: format!("{field_name} must not contain embedded credentials"),
        });
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(PaymobError::ValidationError {
            field: field_name,
            reason: format!("{field_name} must not contain query or fragment components"),
        });
    }
    Ok(())
}

/// Returns `true` when `host` is a loopback or `.local` test host permitted for `http://`.
fn is_loopback_or_local_host(host: &str) -> bool {
    let lower = host.to_ascii_lowercase();
    lower == "localhost"
        || lower == "127.0.0.1"
        || lower == "[::1]"
        || lower.ends_with(".local")
}

/// Joins a base URL with a normalized endpoint path.
fn join_base_and_path(req: JoinPathRequest<'_>) -> Result<String, PaymobError> {
    let trimmed_path = req.path.trim();
    if trimmed_path.is_empty() {
        return Err(PaymobError::ValidationError {
            field: "path",
            reason: "endpoint path must not be empty".to_string(),
        });
    }
    let normalized = normalize_endpoint_path(trimmed_path);
    let base_clean = req.base.trim_end_matches('/');
    Ok(format!("{base_clean}{normalized}"))
}

/// Collapses duplicate slashes and guarantees a leading `/` without trailing `/`.
fn collapse_slashes(raw: &str) -> String {
    let joined = raw
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>()
        .join("/");
    format!("/{joined}")
}

/// Returns `true` when `clean_path` (no trailing slash) requires a trailing `/`
/// under Paymob's API contract.
fn requires_trailing_slash(clean_path: &str) -> bool {
    clean_path == "/v1/intention"
        || clean_path == "/api/secure"
        || clean_path.starts_with("/api/secure/")
}

#[cfg(test)]
mod tests {
    use super::*;

    struct BuiltinCase {
        region: PaymobRegion,
        accept: &'static str,
        checkout: &'static str,
        payouts: Option<&'static str>,
        staging: Option<&'static str>,
    }

    struct CustomRejectCase {
        accept: &'static str,
        checkout: &'static str,
        payouts: &'static str,
        staging: &'static str,
        expected_field: &'static str,
    }

    fn assert_endpoints(case: &BuiltinCase) {
        let eps = case.region.endpoints().expect("builtin region endpoints");
        assert_eq!(eps.accept_base_url, case.accept);
        assert_eq!(eps.checkout_base_url, case.checkout);
        assert_eq!(eps.payouts_base_url.as_deref(), case.payouts);
        assert_eq!(eps.payouts_staging_base_url.as_deref(), case.staging);
    }

    fn assert_custom_rejected(case: &CustomRejectCase) {
        let region = PaymobRegion::Custom {
            accept_base_url: case.accept.to_string(),
            checkout_base_url: case.checkout.to_string(),
            payouts_base_url: case.payouts.to_string(),
            payouts_staging_base_url: case.staging.to_string(),
        };
        let err = region.endpoints().expect_err("expected validation error");
        assert!(
            matches!(err, PaymobError::ValidationError { field, .. } if field == case.expected_field),
            "unexpected error for {}: {err:?}",
            case.expected_field
        );
    }

    #[test]
    fn tc_1_1_1_builtin_regions_resolve_expected_hosts() {
        let cases = [
            BuiltinCase {
                region: PaymobRegion::Egypt,
                accept: "https://accept.paymob.com",
                checkout: "https://accept.paymob.com/unifiedcheckout/",
                payouts: Some("https://payouts.paymobsolutions.com"),
                staging: Some("https://stagingpayouts.paymobsolutions.com"),
            },
            BuiltinCase {
                region: PaymobRegion::SaudiArabia,
                accept: "https://ksa.paymob.com",
                checkout: "https://ksa.paymob.com/unifiedcheckout/",
                payouts: Some("https://payouts.paymob.sa"),
                staging: Some("https://stagingpayouts.paymob.sa"),
            },
            BuiltinCase {
                region: PaymobRegion::Uae,
                accept: "https://uae.paymob.com",
                checkout: "https://uae.paymob.com/unifiedcheckout/",
                payouts: Some("https://payouts-uae.paymobsolutions.com"),
                staging: Some("https://stagingpayouts-uae.paymobsolutions.com"),
            },
            BuiltinCase {
                region: PaymobRegion::Oman,
                accept: "https://oman.paymob.com",
                checkout: "https://oman.paymob.com/unifiedcheckout/",
                payouts: Some("https://oman.paymob.com"),
                staging: Some("https://oman.paymob.com"),
            },
            BuiltinCase {
                region: PaymobRegion::Pakistan,
                accept: "https://pakistan.paymob.com",
                checkout: "https://pakistan.paymob.com/unifiedcheckout/",
                payouts: None,
                staging: None,
            },
        ];
        for case in &cases {
            assert_endpoints(case);
        }
    }

    #[test]
    fn tc_1_1_1_trailing_slash_policy_normalizer() {
        let cases = [
            ("/v1/intention/", "/v1/intention/"),
            ("v1/intention", "/v1/intention/"),
            ("//v1//intention//", "/v1/intention/"),
            ("/v1/intention?foo=bar", "/v1/intention/?foo=bar"),
            ("/api/secure/disburse/", "/api/secure/disburse/"),
            ("api/secure/disburse", "/api/secure/disburse/"),
            ("/api/secure/budget/inquire", "/api/secure/budget/inquire/"),
            ("/api/auth/tokens/", "/api/auth/tokens"),
            ("/", "/"),
        ];
        for (input, expected) in cases {
            assert_eq!(normalize_endpoint_path(input), expected);
        }
    }

    #[test]
    fn tc_1_1_1_custom_region_accepts_local_http_and_https() {
        let valid = PaymobRegion::Custom {
            accept_base_url: "http://localhost:8080/".to_string(),
            checkout_base_url: "http://[::1]:8080/unifiedcheckout/".to_string(),
            payouts_base_url: "http://127.0.0.1:8080/".to_string(),
            payouts_staging_base_url: "http://mock-payouts.local".to_string(),
        };
        let eps = valid.endpoints().expect("valid local custom endpoints");
        assert_eq!(eps.accept_base_url, "http://localhost:8080");
        assert_eq!(eps.checkout_base_url, "http://[::1]:8080/unifiedcheckout/");
        assert_eq!(eps.payouts_base_url.as_deref(), Some("http://127.0.0.1:8080"));
        assert_eq!(
            eps.payouts_staging_base_url.as_deref(),
            Some("http://mock-payouts.local")
        );
    }

    #[test]
    fn tc_1_1_1_custom_region_rejects_invalid_urls() {
        let cases = [
            CustomRejectCase {
                accept: "   ",
                checkout: "https://example.com/checkout",
                payouts: "https://example.com/payouts",
                staging: "https://example.com/staging",
                expected_field: "accept_base_url",
            },
            CustomRejectCase {
                accept: "https://example.com",
                checkout: "https://example.com/checkout",
                payouts: "not-a-url",
                staging: "https://example.com/staging",
                expected_field: "payouts_base_url",
            },
            CustomRejectCase {
                accept: "https://example.com",
                checkout: "https://example.com/checkout",
                payouts: "https://example.com/payouts",
                staging: "",
                expected_field: "payouts_staging_base_url",
            },
            CustomRejectCase {
                accept: "https://example.com",
                checkout: "ftp://example.com/checkout",
                payouts: "https://example.com/payouts",
                staging: "https://example.com/staging",
                expected_field: "checkout_base_url",
            },
            CustomRejectCase {
                accept: "http://api.example.com",
                checkout: "https://example.com/checkout",
                payouts: "https://example.com/payouts",
                staging: "https://example.com/staging",
                expected_field: "accept_base_url",
            },
            CustomRejectCase {
                accept: "https://user:secret@example.com",
                checkout: "https://example.com/checkout",
                payouts: "https://example.com/payouts",
                staging: "https://example.com/staging",
                expected_field: "accept_base_url",
            },
            CustomRejectCase {
                accept: "https://example.com",
                checkout: "https://example.com/checkout?token=1",
                payouts: "https://example.com/payouts",
                staging: "https://example.com/staging",
                expected_field: "checkout_base_url",
            },
            CustomRejectCase {
                accept: "https://example.com",
                checkout: "https://example.com/checkout",
                payouts: "https://example.com/payouts#section",
                staging: "https://example.com/staging",
                expected_field: "payouts_base_url",
            },
        ];
        for case in &cases {
            assert_custom_rejected(case);
        }
    }

    #[test]
    fn tc_1_1_1_url_resolution_and_pakistan_payouts_rejection() {
        assert_eq!(
            PaymobRegion::Egypt.resolve_accept_url("v1/intention").unwrap(),
            "https://accept.paymob.com/v1/intention/"
        );
        assert_eq!(
            PaymobRegion::Egypt
                .resolve_checkout_url("?publicKey=pk_test&clientSecret=cs_test")
                .unwrap(),
            "https://accept.paymob.com/unifiedcheckout/?publicKey=pk_test&clientSecret=cs_test"
        );
        assert_eq!(
            PaymobRegion::Egypt
                .resolve_payouts_url("/api/secure/disburse", false)
                .unwrap(),
            "https://payouts.paymobsolutions.com/api/secure/disburse/"
        );
        assert!(matches!(
            PaymobRegion::Pakistan.resolve_payouts_url("/api/secure/disburse/", false),
            Err(PaymobError::ValidationError { field: "region", .. })
        ));
        assert!(matches!(
            PaymobRegion::Egypt.resolve_accept_url("   "),
            Err(PaymobError::ValidationError { field: "path", .. })
        ));
    }

    #[test]
    fn tc_1_1_1_prefix_lookup_and_country_codes() {
        let prefixes = [
            ("egy", Some(PaymobRegion::Egypt)),
            (" KSA ", Some(PaymobRegion::SaudiArabia)),
            ("are", Some(PaymobRegion::Uae)),
            ("omn", Some(PaymobRegion::Oman)),
            ("pak", Some(PaymobRegion::Pakistan)),
            ("us", None),
        ];
        for (prefix, expected) in prefixes {
            assert_eq!(PaymobRegion::from_key_prefix(prefix), expected);
        }
        assert_eq!(PaymobRegion::Egypt.country_code(), "EGY");
        assert_eq!(PaymobRegion::SaudiArabia.country_code(), "KSA");
        assert_eq!(PaymobRegion::Uae.country_code(), "UAE");
        assert_eq!(PaymobRegion::Oman.country_code(), "OMN");
        assert_eq!(PaymobRegion::Pakistan.country_code(), "PAK");
    }
}

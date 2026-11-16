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
use url::{Host, Url};

use crate::core::error::PaymobError;

/// Static specification for a built-in [`PaymobRegion`].
struct BuiltinRegionSpec {
    region: PaymobRegion,
    country_code: &'static str,
    accept_base_url: &'static str,
    checkout_base_url: &'static str,
    payouts_base_url: Option<&'static str>,
    payouts_staging_base_url: Option<&'static str>,
}

/// Static lookup table mapping built-in regions to canonical codes and endpoints.
const BUILTIN_REGION_SPECS: &[BuiltinRegionSpec] = &[
    BuiltinRegionSpec {
        region: PaymobRegion::Egypt,
        country_code: "EGY",
        accept_base_url: "https://accept.paymob.com",
        checkout_base_url: "https://accept.paymob.com/unifiedcheckout/",
        payouts_base_url: Some("https://payouts.paymobsolutions.com"),
        payouts_staging_base_url: Some("https://stagingpayouts.paymobsolutions.com"),
    },
    BuiltinRegionSpec {
        region: PaymobRegion::SaudiArabia,
        country_code: "KSA",
        accept_base_url: "https://ksa.paymob.com",
        checkout_base_url: "https://ksa.paymob.com/unifiedcheckout/",
        payouts_base_url: Some("https://payouts.paymob.sa"),
        payouts_staging_base_url: Some("https://stagingpayouts.paymob.sa"),
    },
    BuiltinRegionSpec {
        region: PaymobRegion::Uae,
        country_code: "UAE",
        accept_base_url: "https://uae.paymob.com",
        checkout_base_url: "https://uae.paymob.com/unifiedcheckout/",
        payouts_base_url: Some("https://payouts-uae.paymobsolutions.com"),
        payouts_staging_base_url: Some("https://stagingpayouts-uae.paymobsolutions.com"),
    },
    BuiltinRegionSpec {
        region: PaymobRegion::Oman,
        country_code: "OMN",
        accept_base_url: "https://oman.paymob.com",
        checkout_base_url: "https://oman.paymob.com/unifiedcheckout/",
        payouts_base_url: Some("https://oman.paymob.com"),
        payouts_staging_base_url: Some("https://oman.paymob.com"),
    },
    BuiltinRegionSpec {
        region: PaymobRegion::Pakistan,
        country_code: "PAK",
        accept_base_url: "https://pakistan.paymob.com",
        checkout_base_url: "https://pakistan.paymob.com/unifiedcheckout/",
        payouts_base_url: None,
        payouts_staging_base_url: None,
    },
];

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
    Accept,
    Checkout,
    Payouts,
    PayoutsStaging,
}

impl CustomUrlField {
    /// Returns the static field name used in [`PaymobError::ValidationError`].
    const fn as_str(self) -> &'static str {
        match self {
            Self::Accept => "accept_base_url",
            Self::Checkout => "checkout_base_url",
            Self::Payouts => "payouts_base_url",
            Self::PayoutsStaging => "payouts_staging_base_url",
        }
    }
}

/// Borrowed base URL and endpoint path pair for [`join_base_and_path`].
struct JoinPathRequest<'a> {
    base: &'a str,
    path: &'a str,
}

/// Internal newtype wrapping a candidate custom base URL for validation.
struct CustomUrlCandidate<'a>(&'a str);

/// Internal newtype wrapping a raw endpoint path for slash normalization.
struct RawEndpointPath<'a>(&'a str);

impl PaymobRegion {
    /// Looks up the static specification for built-in regions.
    fn builtin_spec(&self) -> Option<&'static BuiltinRegionSpec> {
        BUILTIN_REGION_SPECS
            .iter()
            .find(|spec| &spec.region == self)
    }

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
        if let Self::Custom {
            accept_base_url,
            checkout_base_url,
            payouts_base_url,
            payouts_staging_base_url,
        } = self
        {
            return resolve_custom_endpoints(CustomUrlInputs {
                accept_base_url,
                checkout_base_url,
                payouts_base_url,
                payouts_staging_base_url,
            });
        }
        let spec = self
            .builtin_spec()
            .ok_or_else(|| PaymobError::ValidationError {
                field: "region",
                reason: "unknown built-in Paymob region".to_string(),
            })?;
        Ok(RegionalEndpoints {
            accept_base_url: spec.accept_base_url.to_string(),
            checkout_base_url: spec.checkout_base_url.to_string(),
            payouts_base_url: spec.payouts_base_url.map(str::to_string),
            payouts_staging_base_url: spec.payouts_staging_base_url.map(str::to_string),
        })
    }

    /// Resolves a full Accept Acquiring URL by normalizing `path` and joining it
    /// with the region's Accept base URL.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `self` is an invalid custom
    /// region or if `path` is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// use some_paymob::core::region::PaymobRegion;
    ///
    /// let url = PaymobRegion::Egypt
    ///     .resolve_accept_url("v1/intention")
    ///     .expect("valid accept url");
    /// assert_eq!(url, "https://accept.paymob.com/v1/intention/");
    /// ```
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
    ///
    /// # Examples
    ///
    /// ```
    /// use some_paymob::core::region::PaymobRegion;
    ///
    /// let url = PaymobRegion::Egypt
    ///     .resolve_checkout_url("?publicKey=pk_test&clientSecret=cs_test")
    ///     .expect("valid checkout url");
    /// assert_eq!(
    ///     url,
    ///     "https://accept.paymob.com/unifiedcheckout/?publicKey=pk_test&clientSecret=cs_test"
    /// );
    /// ```
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
    ///
    /// # Examples
    ///
    /// ```
    /// use some_paymob::core::region::PaymobRegion;
    ///
    /// let url = PaymobRegion::Egypt
    ///     .resolve_payouts_url("/api/secure/disburse", false)
    ///     .expect("valid payouts url");
    /// assert_eq!(url, "https://payouts.paymobsolutions.com/api/secure/disburse/");
    /// ```
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
    ///
    /// # Examples
    ///
    /// ```
    /// use some_paymob::core::region::PaymobRegion;
    ///
    /// assert_eq!(PaymobRegion::Egypt.country_code(), "EGY");
    /// assert_eq!(PaymobRegion::Pakistan.country_code(), "PAK");
    /// ```
    pub fn country_code(&self) -> &'static str {
        self.builtin_spec()
            .map_or("CUSTOM", |spec| spec.country_code)
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
    RawEndpointPath(path).normalize()
}

impl CustomUrlCandidate<'_> {
    /// Validates a single custom URL field for non-emptiness, valid syntax, host
    /// presence, scheme policy, and absence of credentials, queries, or fragments.
    fn validate(&self, field: CustomUrlField) -> Result<String, PaymobError> {
        let field_name = field.as_str();
        let trimmed = self.0.trim();
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
        Self::validate_scheme(field, &parsed)?;
        Self::validate_parts(field, &parsed)?;
        Ok(trimmed.trim_end_matches('/').to_string())
    }

    /// Enforces host presence, `https` for remote hosts, and `http` only on loopback/local test hosts.
    fn validate_scheme(field: CustomUrlField, parsed: &Url) -> Result<(), PaymobError> {
        let field_name = field.as_str();
        if parsed.host().is_none() {
            return Err(PaymobError::ValidationError {
                field: field_name,
                reason: format!("{field_name} must include a host"),
            });
        }
        if parsed.scheme() == "https" {
            return Ok(());
        }
        if parsed.scheme() == "http" && Self::is_loopback_or_local(parsed) {
            return Ok(());
        }
        Err(PaymobError::ValidationError {
            field: field_name,
            reason: format!("{field_name} must use https unless targeting a local/loopback host"),
        })
    }

    /// Rejects embedded credentials (`username`/`password`) and `query`/`fragment` parts.
    fn validate_parts(field: CustomUrlField, parsed: &Url) -> Result<(), PaymobError> {
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

    /// Returns `true` when `parsed` targets a loopback IP (`127.0.0.0/8`, `::1`),
    /// `localhost`, or a `.local` test host permitted for `http://`.
    fn is_loopback_or_local(parsed: &Url) -> bool {
        match parsed.host() {
            Some(Host::Ipv4(ip)) => ip.is_loopback(),
            Some(Host::Ipv6(ip)) => ip.is_loopback(),
            Some(Host::Domain(domain)) => {
                let lower = domain.to_ascii_lowercase();
                lower == "localhost" || lower.ends_with(".local")
            }
            None => false,
        }
    }
}

impl RawEndpointPath<'_> {
    /// Normalizes the wrapped endpoint path and preserves any `?query` suffix.
    fn normalize(&self) -> String {
        let trimmed = self.0.trim();
        let (raw_path, query) = match trimmed.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (trimmed, None),
        };
        let mut clean = RawEndpointPath(raw_path).collapse_slashes();
        if RawEndpointPath(&clean).requires_trailing_slash() {
            clean.push('/');
        }
        if let Some(q) = query {
            clean.push('?');
            clean.push_str(q);
        }
        clean
    }

    /// Collapses duplicate slashes and guarantees a leading `/` without trailing `/`.
    fn collapse_slashes(&self) -> String {
        let joined = self
            .0
            .split('/')
            .filter(|segment| !segment.is_empty())
            .collect::<Vec<_>>()
            .join("/");
        format!("/{joined}")
    }

    /// Returns `true` when `self.0` (no trailing slash) requires a trailing `/`
    /// under Paymob's API contract.
    fn requires_trailing_slash(&self) -> bool {
        self.0 == "/v1/intention" || self.0 == "/api/secure" || self.0.starts_with("/api/secure/")
    }
}

/// Validates and resolves all four base URLs for [`PaymobRegion::Custom`].
fn resolve_custom_endpoints(inputs: CustomUrlInputs<'_>) -> Result<RegionalEndpoints, PaymobError> {
    let accept = CustomUrlCandidate(inputs.accept_base_url).validate(CustomUrlField::Accept)?;
    let checkout =
        CustomUrlCandidate(inputs.checkout_base_url).validate(CustomUrlField::Checkout)?;
    let payouts = CustomUrlCandidate(inputs.payouts_base_url).validate(CustomUrlField::Payouts)?;
    let payouts_staging = CustomUrlCandidate(inputs.payouts_staging_base_url)
        .validate(CustomUrlField::PayoutsStaging)?;

    Ok(RegionalEndpoints {
        accept_base_url: accept,
        checkout_base_url: format!("{checkout}/"),
        payouts_base_url: Some(payouts),
        payouts_staging_base_url: Some(payouts_staging),
    })
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
    let normalized = RawEndpointPath(trimmed_path).normalize();
    let base_clean = req.base.trim_end_matches('/');
    Ok(format!("{base_clean}{normalized}"))
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

    struct SlashCase {
        input: &'static str,
        expected: &'static str,
    }

    fn assert_endpoints(case: &BuiltinCase) {
        let eps = case.region.endpoints().expect("builtin region endpoints");
        assert_eq!(
            (
                eps.accept_base_url.as_str(),
                eps.checkout_base_url.as_str(),
                eps.payouts_base_url.as_deref(),
                eps.payouts_staging_base_url.as_deref(),
            ),
            (case.accept, case.checkout, case.payouts, case.staging)
        );
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
    fn tc_1_1_1_trailing_slash_preserved_paths() {
        let cases = [
            SlashCase {
                input: "/v1/intention/",
                expected: "/v1/intention/",
            },
            SlashCase {
                input: "v1/intention",
                expected: "/v1/intention/",
            },
            SlashCase {
                input: "/v1/intention?foo=bar",
                expected: "/v1/intention/?foo=bar",
            },
            SlashCase {
                input: "api/secure/disburse",
                expected: "/api/secure/disburse/",
            },
            SlashCase {
                input: "/api/secure/budget/inquire",
                expected: "/api/secure/budget/inquire/",
            },
        ];
        for case in &cases {
            assert_eq!(normalize_endpoint_path(case.input), case.expected);
        }
    }

    #[test]
    fn tc_1_1_1_trailing_slash_stripped_paths() {
        let cases = [
            SlashCase {
                input: "/api/auth/tokens/",
                expected: "/api/auth/tokens",
            },
            SlashCase {
                input: "//api//acceptance//orders//",
                expected: "/api/acceptance/orders",
            },
            SlashCase {
                input: "/",
                expected: "/",
            },
        ];
        for case in &cases {
            assert_eq!(normalize_endpoint_path(case.input), case.expected);
        }
    }

    #[test]
    fn tc_1_1_1_custom_region_accepts_local_http_and_loopback_cidr() {
        let valid = PaymobRegion::Custom {
            accept_base_url: "http://localhost:8080/".to_string(),
            checkout_base_url: "http://[::1]:8080/unifiedcheckout/".to_string(),
            payouts_base_url: "http://127.0.0.2:8080/".to_string(),
            payouts_staging_base_url: "http://mock-payouts.local".to_string(),
        };
        let eps = valid.endpoints().expect("valid local custom endpoints");
        assert_eq!(
            (
                eps.accept_base_url.as_str(),
                eps.checkout_base_url.as_str(),
                eps.payouts_base_url.as_deref(),
                eps.payouts_staging_base_url.as_deref(),
            ),
            (
                "http://localhost:8080",
                "http://[::1]:8080/unifiedcheckout/",
                Some("http://127.0.0.2:8080"),
                Some("http://mock-payouts.local"),
            )
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
    fn tc_1_1_1_url_resolution_succeeds_for_egypt() {
        assert_eq!(
            (
                PaymobRegion::Egypt
                    .resolve_accept_url("v1/intention")
                    .unwrap(),
                PaymobRegion::Egypt
                    .resolve_checkout_url("?publicKey=pk_test&clientSecret=cs_test")
                    .unwrap(),
                PaymobRegion::Egypt
                    .resolve_payouts_url("/api/secure/disburse", false)
                    .unwrap(),
            ),
            (
                "https://accept.paymob.com/v1/intention/".to_string(),
                "https://accept.paymob.com/unifiedcheckout/?publicKey=pk_test&clientSecret=cs_test"
                    .to_string(),
                "https://payouts.paymobsolutions.com/api/secure/disburse/".to_string(),
            )
        );
    }

    #[test]
    fn tc_1_1_1_pakistan_payouts_and_empty_path_rejected() {
        assert!(matches!(
            PaymobRegion::Pakistan.resolve_payouts_url("/api/secure/disburse/", false),
            Err(PaymobError::ValidationError {
                field: "region",
                ..
            })
        ));
        assert!(matches!(
            PaymobRegion::Egypt.resolve_accept_url("   "),
            Err(PaymobError::ValidationError { field: "path", .. })
        ));
    }

    #[test]
    fn tc_1_1_1_pakistan_staging_payouts_rejected() {
        assert!(matches!(
            PaymobRegion::Pakistan.resolve_payouts_url("/api/secure/disburse/", true),
            Err(PaymobError::ValidationError {
                field: "region",
                ..
            })
        ));
    }

    #[test]
    fn tc_1_1_1_prefix_lookup_resolves_all_supported_codes() {
        let prefixes = [
            ("egy", Some(PaymobRegion::Egypt)),
            (" KSA ", Some(PaymobRegion::SaudiArabia)),
            ("sau", Some(PaymobRegion::SaudiArabia)),
            ("are", Some(PaymobRegion::Uae)),
            ("omn", Some(PaymobRegion::Oman)),
            ("pak", Some(PaymobRegion::Pakistan)),
            ("us", None),
        ];
        for (prefix, expected) in prefixes {
            assert_eq!(PaymobRegion::from_key_prefix(prefix), expected);
        }
    }

    #[test]
    fn tc_1_1_1_country_codes_cover_builtin_and_custom() {
        let custom = PaymobRegion::Custom {
            accept_base_url: "https://accept.example.com".to_string(),
            checkout_base_url: "https://checkout.example.com".to_string(),
            payouts_base_url: "https://payouts.example.com".to_string(),
            payouts_staging_base_url: "https://staging.example.com".to_string(),
        };
        let codes = [
            (PaymobRegion::Egypt, "EGY"),
            (PaymobRegion::SaudiArabia, "KSA"),
            (PaymobRegion::Uae, "UAE"),
            (PaymobRegion::Oman, "OMN"),
            (PaymobRegion::Pakistan, "PAK"),
            (custom, "CUSTOM"),
        ];
        for (region, code) in codes {
            assert_eq!(region.country_code(), code);
        }
    }
}

#![forbid(unsafe_code)]
//! QuickLinks payment links service (`US-3.3.0/unit-1`).
//!
//! Provides [`CreateQuickLinkParams`], [`QuickLinkResponse`], and
//! [`QuickLinksService`] for creating (`POST /api/ecommerce/payment-links`)
//! and cancelling (`POST /api/ecommerce/payment-links/cancel`) hosted Paymob
//! payment links under Regime 2 (`Authorization: Bearer <auth_token>`).

use std::fmt;

use reqwest::Method;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::core::client::{PaymobClient, build_bearer_json_request};
use crate::core::error::PaymobError;
use crate::core::http::HttpResponse;
use crate::core::types::deserialize_string_or_u64;

const CREATE_PAYMENT_LINK_PATH: &str = "/api/ecommerce/payment-links";
const CANCEL_PAYMENT_LINK_PATH: &str = "/api/ecommerce/payment-links/cancel";
const REDACTED_MARKER: &str = "[REDACTED]";

/// Parameters for creating a Paymob QuickLink hosted payment link.
///
/// Customer PII fields (`full_name`, `email`, `phone_number`) are automatically
/// redacted as `"[REDACTED]"` in [`fmt::Debug`] output.
///
/// # Examples
///
/// ```rust
/// use some_paymob::resources::quicklinks::CreateQuickLinkParams;
///
/// let params = CreateQuickLinkParams::new(150_000, "EGP", vec![4097558])
///     .with_description("Invoice #1042")
///     .with_email("buyer@example.com");
///
/// assert!(params.validate().is_ok());
/// assert!(format!("{params:?}").contains("[REDACTED]"));
/// ```
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct CreateQuickLinkParams {
    /// Payment amount in integer minor units (for example, piasters or halalas).
    pub amount_cents: u64,
    /// Three-letter ISO-4217 currency code (for example, `"EGP"` or `"SAR"`).
    pub currency: String,
    /// Paymob integration IDs enabled for this payment link.
    pub integrations: Vec<u64>,
    /// Optional human-readable order or invoice description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Optional customer full name (redacted in `Debug` output).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_name: Option<String>,
    /// Optional customer email address (redacted in `Debug` output).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Optional customer phone number (redacted in `Debug` output).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<String>,
    /// Optional post-payment customer redirection URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirection_url: Option<String>,
}

impl fmt::Debug for CreateQuickLinkParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CreateQuickLinkParams")
            .field("amount_cents", &self.amount_cents)
            .field("currency", &self.currency)
            .field("integrations", &self.integrations)
            .field("description", &self.description)
            .field("full_name", &redact_opt(&self.full_name))
            .field("email", &redact_opt(&self.email))
            .field("phone_number", &redact_opt(&self.phone_number))
            .field("redirection_url", &self.redirection_url)
            .finish()
    }
}

impl CreateQuickLinkParams {
    /// Creates a new [`CreateQuickLinkParams`] with required amount, currency, and integrations.
    #[must_use]
    pub fn new(amount_cents: u64, currency: impl Into<String>, integrations: Vec<u64>) -> Self {
        Self {
            amount_cents,
            currency: currency.into(),
            integrations,
            description: None,
            full_name: None,
            email: None,
            phone_number: None,
            redirection_url: None,
        }
    }

    /// Sets the optional payment link description.
    #[must_use]
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Sets the optional customer full name.
    #[must_use]
    pub fn with_full_name(mut self, full_name: impl Into<String>) -> Self {
        self.full_name = Some(full_name.into());
        self
    }

    /// Sets the optional customer email address.
    #[must_use]
    pub fn with_email(mut self, email: impl Into<String>) -> Self {
        self.email = Some(email.into());
        self
    }

    /// Sets the optional customer phone number.
    #[must_use]
    pub fn with_phone_number(mut self, phone_number: impl Into<String>) -> Self {
        self.phone_number = Some(phone_number.into());
        self
    }

    /// Sets the optional post-payment redirection URL.
    #[must_use]
    pub fn with_redirection_url(mut self, redirection_url: impl Into<String>) -> Self {
        self.redirection_url = Some(redirection_url.into());
        self
    }

    /// Validates all QuickLink parameters before network dispatch.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `amount_cents == 0`,
    /// `currency` is not a 3-letter ASCII alphabetic ISO-4217 code,
    /// `integrations` is empty or contains `0`, any optional text field contains
    /// control characters, or `redirection_url` is malformed.
    pub fn validate(&self) -> Result<(), PaymobError> {
        if self.amount_cents == 0 {
            return Err(validation_err(
                "amount_cents",
                "amount_cents must be greater than zero",
            ));
        }
        validate_currency_code(&self.currency)?;
        validate_integrations(&self.integrations)?;
        self.validate_optional_fields()
    }

    fn validate_optional_fields(&self) -> Result<(), PaymobError> {
        for (field, opt_val) in [
            ("description", &self.description),
            ("full_name", &self.full_name),
            ("email", &self.email),
            ("phone_number", &self.phone_number),
        ] {
            if let Some(val) = opt_val {
                validate_no_control_chars(field, val)?;
            }
        }
        if let Some(raw_url) = &self.redirection_url {
            validate_redirection_url(raw_url)?;
        }
        Ok(())
    }
}

/// Response returned by `POST /api/ecommerce/payment-links`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuickLinkResponse {
    /// Unique Paymob payment link identifier.
    #[serde(deserialize_with = "deserialize_string_or_u64")]
    pub id: String,
    /// Hosted QuickLink payment URL for the merchant or short-link sharing.
    pub url: String,
    /// Client-facing hosted checkout URL.
    pub client_url: String,
}

#[derive(Serialize)]
struct CancelQuickLinkRequest<'a> {
    payment_link_id: &'a str,
}

/// Service handle for Paymob QuickLinks payment link creation and cancellation.
#[derive(Debug, Clone, Copy)]
pub struct QuickLinksService<'a> {
    client: &'a PaymobClient,
}

impl<'a> QuickLinksService<'a> {
    /// Creates a new [`QuickLinksService`] bound to `client`.
    #[must_use]
    pub(crate) const fn new(client: &'a PaymobClient) -> Self {
        Self { client }
    }

    /// Returns the underlying [`PaymobClient`].
    #[must_use]
    pub const fn client(&self) -> &'a PaymobClient {
        self.client
    }

    /// Creates a hosted QuickLink payment link via `POST /api/ecommerce/payment-links`.
    ///
    /// Authenticates using Regime 2 (`Authorization: Bearer <auth_token>`) and
    /// automatically retries once on a stale-token `401` response.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] on invalid parameters or missing
    /// `api_key`, [`PaymobError::AuthenticationError`] on credential failure, or
    /// [`PaymobError::ApiError`] / [`PaymobError::RateLimited`] on gateway errors.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use some_paymob::core::client::PaymobClient;
    /// use some_paymob::core::config::ClientConfig;
    /// use some_paymob::core::credentials::ApiKey;
    /// use some_paymob::core::region::PaymobRegion;
    /// use some_paymob::resources::quicklinks::CreateQuickLinkParams;
    ///
    /// # async fn example() -> Result<(), some_paymob::PaymobError> {
    /// let config = ClientConfig::builder()
    ///     .region(PaymobRegion::Egypt)
    ///     .api_key(ApiKey::new("egy_api_key_example")?)
    ///     .build()?;
    /// let client = PaymobClient::new(config)?;
    /// let params = CreateQuickLinkParams::new(150_000, "EGP", vec![4097558]);
    /// let link = client.quicklinks().create(&params).await?;
    /// assert!(!link.client_url.is_empty());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn create(
        &self,
        params: &CreateQuickLinkParams,
    ) -> Result<QuickLinkResponse, PaymobError> {
        params.validate()?;
        let target_url = self.client.accept_url(CREATE_PAYMENT_LINK_PATH)?;
        let response = self.post_bearer_json(&target_url, params).await?;
        if !response.status.is_success() {
            return Err(PaymobError::from_http_response(&response));
        }
        response
            .json::<QuickLinkResponse>()
            .map_err(PaymobError::from)
    }

    /// Cancels an active QuickLink payment link via `POST /api/ecommerce/payment-links/cancel`.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `link_id` is empty/whitespace,
    /// contains control characters, or `api_key` is missing, or [`PaymobError`] on
    /// authentication or API errors.
    pub async fn cancel(&self, link_id: &str) -> Result<(), PaymobError> {
        let trimmed = link_id.trim();
        if trimmed.is_empty() || link_id.chars().any(char::is_control) {
            return Err(validation_err(
                "link_id",
                "payment link identifier must be non-empty and free of control characters",
            ));
        }
        let target_url = self.client.accept_url(CANCEL_PAYMENT_LINK_PATH)?;
        let payload = CancelQuickLinkRequest {
            payment_link_id: trimmed,
        };
        let response = self.post_bearer_json(&target_url, &payload).await?;
        if !response.status.is_success() {
            return Err(PaymobError::from_http_response(&response));
        }
        Ok(())
    }

    async fn post_bearer_json<T: Serialize>(
        &self,
        url: &Url,
        payload: &T,
    ) -> Result<HttpResponse, PaymobError> {
        self.client
            .execute_regime2_with_retry(
                || {
                    validation_err(
                        "api_key",
                        "api_key must be configured on ClientConfig for QuickLinks",
                    )
                },
                |token| build_bearer_json_request(Method::POST, url.as_str(), token, Some(payload)),
            )
            .await
    }
}

impl PaymobClient {
    /// Returns the QuickLinks payment links service (`create`, `cancel`).
    #[must_use]
    pub const fn quicklinks(&self) -> QuickLinksService<'_> {
        QuickLinksService::new(self)
    }
}

fn redact_opt(value: &Option<String>) -> &'static str {
    if value.is_some() {
        REDACTED_MARKER
    } else {
        "None"
    }
}

fn validation_err(field: &'static str, reason: impl Into<String>) -> PaymobError {
    PaymobError::ValidationError {
        field,
        reason: reason.into(),
    }
}

fn validate_no_control_chars(field: &'static str, value: &str) -> Result<(), PaymobError> {
    if value.chars().any(char::is_control) {
        return Err(validation_err(
            field,
            format!("{field} must not contain control characters"),
        ));
    }
    Ok(())
}

fn validate_integrations(integrations: &[u64]) -> Result<(), PaymobError> {
    if integrations.is_empty() {
        return Err(validation_err(
            "integrations",
            "at least one integration ID is required",
        ));
    }
    if integrations.contains(&0) {
        return Err(validation_err(
            "integrations",
            "integration IDs must be non-zero",
        ));
    }
    Ok(())
}

fn validate_currency_code(currency: &str) -> Result<(), PaymobError> {
    let trimmed = currency.trim();
    if trimmed.len() == 3 && trimmed.chars().all(|c| c.is_ascii_alphabetic()) {
        return Ok(());
    }
    Err(validation_err(
        "currency",
        "currency must be a 3-letter ISO-4217 alphabetic code",
    ))
}

fn validate_redirection_url(raw_url: &str) -> Result<(), PaymobError> {
    validate_no_control_chars("redirection_url", raw_url)?;
    let parsed = Url::parse(raw_url.trim())
        .map_err(|err| validation_err("redirection_url", format!("invalid URL: {err}")))?;
    if !matches!(parsed.scheme(), "https" | "http") || parsed.host_str().is_none() {
        return Err(validation_err(
            "redirection_url",
            "redirection_url must use http or https with a valid host",
        ));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(validation_err(
            "redirection_url",
            "redirection_url must not contain embedded credentials",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::core::config::ClientConfig;
    use crate::core::credentials::ApiKey;
    use crate::core::region::PaymobRegion;

    fn mock_client(server: &MockServer) -> PaymobClient {
        let uri = server.uri();
        let config = ClientConfig::builder()
            .region(PaymobRegion::Custom {
                accept_base_url: uri.clone(),
                checkout_base_url: format!("{uri}/unifiedcheckout/"),
                payouts_base_url: uri.clone(),
                payouts_staging_base_url: uri.clone(),
            })
            .api_key(ApiKey::new("test_api_key_secret_123").expect("valid api key"))
            .max_retries(0)
            .build()
            .expect("valid config");
        PaymobClient::new(config).expect("valid client")
    }

    #[tokio::test]
    async fn tc_3_3_1_create_and_cancel_quicklink_success() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/auth/tokens"))
            .respond_with(
                ResponseTemplate::new(201).set_body_json(serde_json::json!({ "token": "jwt_ql" })),
            )
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/api/ecommerce/payment-links"))
            .and(header("Authorization", "Bearer jwt_ql"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "id": "ql_98765",
                "url": "https://accept.paymob.com/standalone/?ref=ql_98765",
                "client_url": "https://accept.paymob.com/api/acceptance/post_pay?ref=ql_98765"
            })))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/api/ecommerce/payment-links/cancel"))
            .and(header("Authorization", "Bearer jwt_ql"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "detail": "cancelled"
            })))
            .mount(&server)
            .await;

        let client = mock_client(&server);
        let params = CreateQuickLinkParams::new(150_000, "EGP", vec![4097558])
            .with_description("Order #42")
            .with_full_name("Maher Alaa")
            .with_email("maher@example.com")
            .with_phone_number("+201000000000")
            .with_redirection_url("https://merchant.example.com/return");

        let resp = client
            .quicklinks()
            .create(&params)
            .await
            .expect("create ok");
        assert_eq!(resp.id, "ql_98765");
        assert!(resp.client_url.contains("ql_98765"));

        client
            .quicklinks()
            .cancel(&resp.id)
            .await
            .expect("cancel ok");
    }

    #[test]
    fn tc_3_3_1_validation_rejects_invalid_inputs() {
        let zero_amt = CreateQuickLinkParams::new(0, "EGP", vec![1]);
        assert!(matches!(
            zero_amt.validate(),
            Err(PaymobError::ValidationError {
                field: "amount_cents",
                ..
            })
        ));

        let bad_curr = CreateQuickLinkParams::new(100, "EG", vec![1]);
        assert!(matches!(
            bad_curr.validate(),
            Err(PaymobError::ValidationError {
                field: "currency",
                ..
            })
        ));

        let empty_int = CreateQuickLinkParams::new(100, "EGP", vec![]);
        assert!(matches!(
            empty_int.validate(),
            Err(PaymobError::ValidationError {
                field: "integrations",
                ..
            })
        ));

        let zero_int = CreateQuickLinkParams::new(100, "EGP", vec![4097558, 0]);
        assert!(matches!(
            zero_int.validate(),
            Err(PaymobError::ValidationError {
                field: "integrations",
                ..
            })
        ));

        let bad_url =
            CreateQuickLinkParams::new(100, "EGP", vec![1]).with_redirection_url("not-a-url");
        assert!(matches!(
            bad_url.validate(),
            Err(PaymobError::ValidationError {
                field: "redirection_url",
                ..
            })
        ));

        let cred_url = CreateQuickLinkParams::new(100, "EGP", vec![1])
            .with_redirection_url("https://user:pass@example.com/return");
        assert!(matches!(
            cred_url.validate(),
            Err(PaymobError::ValidationError {
                field: "redirection_url",
                ..
            })
        ));

        let ctrl_desc =
            CreateQuickLinkParams::new(100, "EGP", vec![1]).with_description("bad\0desc");
        assert!(matches!(
            ctrl_desc.validate(),
            Err(PaymobError::ValidationError {
                field: "description",
                ..
            })
        ));
    }

    #[tokio::test]
    async fn tc_3_3_1_cancel_rejects_empty_link_id_and_missing_api_key() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        assert!(matches!(
            client.quicklinks().cancel("   ").await,
            Err(PaymobError::ValidationError {
                field: "link_id",
                ..
            })
        ));
        assert!(matches!(
            client.quicklinks().cancel("ql_1\r\n").await,
            Err(PaymobError::ValidationError {
                field: "link_id",
                ..
            })
        ));

        let no_key_cfg = ClientConfig::builder()
            .region(PaymobRegion::Egypt)
            .build()
            .expect("valid config");
        let no_key_client = PaymobClient::new(no_key_cfg).expect("valid client");
        let params = CreateQuickLinkParams::new(10_000, "EGP", vec![4097558]);
        assert!(matches!(
            no_key_client.quicklinks().create(&params).await,
            Err(PaymobError::ValidationError {
                field: "api_key",
                ..
            })
        ));
    }

    #[tokio::test]
    async fn tc_3_3_1_evicts_and_retries_once_on_401_incorrect_credentials() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/auth/tokens"))
            .respond_with(
                ResponseTemplate::new(201)
                    .set_body_json(serde_json::json!({ "token": "jwt_stale" })),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/auth/tokens"))
            .respond_with(
                ResponseTemplate::new(201)
                    .set_body_json(serde_json::json!({ "token": "jwt_fresh" })),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/api/ecommerce/payment-links"))
            .and(header("Authorization", "Bearer jwt_stale"))
            .respond_with(
                ResponseTemplate::new(401)
                    .set_body_json(serde_json::json!({ "detail": "incorrect credentials" })),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/ecommerce/payment-links"))
            .and(header("Authorization", "Bearer jwt_fresh"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "id": 777,
                "url": "https://accept.paymob.com/standalone/?ref=777",
                "client_url": "https://accept.paymob.com/api/acceptance/post_pay?ref=777"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = mock_client(&server);
        let params = CreateQuickLinkParams::new(50_000, "EGP", vec![4097558]);
        let resp = client
            .quicklinks()
            .create(&params)
            .await
            .expect("retries with fresh JWT");
        assert_eq!(resp.id, "777");
    }

    #[tokio::test]
    async fn tc_3_3_1_gateway_error_maps_to_paymob_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/auth/tokens"))
            .respond_with(
                ResponseTemplate::new(201).set_body_json(serde_json::json!({ "token": "jwt_ql" })),
            )
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/api/ecommerce/payment-links"))
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("Retry-After", "12")
                    .set_body_json(serde_json::json!({ "detail": "rate limit exceeded" })),
            )
            .mount(&server)
            .await;

        let client = mock_client(&server);
        let params = CreateQuickLinkParams::new(150_000, "EGP", vec![4097558]);
        let err = client
            .quicklinks()
            .create(&params)
            .await
            .expect_err("429 should fail");
        assert!(err.is_rate_limited());
        assert_eq!(err.retry_after_secs(), Some(12));
    }

    #[test]
    fn tc_3_3_4_debug_redacts_pii_fields() {
        let params = CreateQuickLinkParams::new(50_000, "EGP", vec![4097558])
            .with_full_name("Sensitive Name")
            .with_email("secret@example.com")
            .with_phone_number("+201234567890");
        let dbg = format!("{params:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("Sensitive Name"));
        assert!(!dbg.contains("secret@example.com"));
        assert!(!dbg.contains("+201234567890"));
    }
}

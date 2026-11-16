#![forbid(unsafe_code)]
//! Legacy Accept v2 order registration (`POST /api/ecommerce/orders`, `US-2.3.0` Unit 1).
//!
//! Implements Regime 2 body-injected `"auth_token"` serialization, strict integer
//! minor-unit validation, `[REDACTED]` debug formatting for token wrappers, and
//! [`LegacyOrder`] response deserialization.

use std::fmt;

use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use crate::core::auth::accept_jwt::{AcceptJwtError, inject_body_auth_token};
use crate::core::error::PaymobError;
use crate::core::http::{HttpClient, HttpRequest};
use crate::core::types::Currency;

/// Relative endpoint path for Paymob Accept v2 order registration.
pub const LEGACY_ORDERS_PATH: &str = "/api/ecommerce/orders";

/// Line item included in a [`CreateLegacyOrderParams`] payload.
///
/// All monetary values are represented strictly in integer minor units (`u64`)
/// with zero floating-point arithmetic.
///
/// # Examples
///
/// ```
/// use some_paymob::resources::legacy::orders::LegacyOrderItem;
///
/// let item = LegacyOrderItem::new("Coffee Beans", 25_000, 2)
///     .with_description("Single-origin roast");
/// assert_eq!(item.amount_cents, 25_000);
/// assert_eq!(item.quantity, 2);
/// assert!(item.validate().is_ok());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacyOrderItem {
    /// Human-readable item name.
    pub name: String,
    /// Unit price in integer minor units (for example, piasters or halalas).
    pub amount_cents: u64,
    /// Optional item description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Positive item quantity.
    pub quantity: u32,
}

impl LegacyOrderItem {
    /// Constructs a new [`LegacyOrderItem`] with no description.
    #[must_use]
    pub fn new(name: impl Into<String>, amount_cents: u64, quantity: u32) -> Self {
        Self {
            name: name.into(),
            amount_cents,
            description: None,
            quantity,
        }
    }

    /// Attaches an optional description to this line item.
    #[must_use]
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Validates that `name` is non-empty and `quantity` is at least `1`.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `name` is blank or `quantity == 0`.
    pub fn validate(&self) -> Result<(), PaymobError> {
        if self.name.trim().is_empty() {
            return Err(PaymobError::ValidationError {
                field: "items.name",
                reason: "order item name must not be empty".to_owned(),
            });
        }
        if self.quantity == 0 {
            return Err(PaymobError::ValidationError {
                field: "items.quantity",
                reason: "order item quantity must be greater than zero".to_owned(),
            });
        }
        Ok(())
    }
}

/// Request parameters for `POST /api/ecommerce/orders`.
///
/// # Examples
///
/// ```
/// use some_paymob::core::types::Currency;
/// use some_paymob::resources::legacy::orders::{CreateLegacyOrderParams, LegacyOrderItem};
///
/// let params = CreateLegacyOrderParams::new(50_000, Currency::EGP)
///     .delivery_needed(false)
///     .merchant_order_id("ord-2026-001")
///     .add_item(LegacyOrderItem::new("Subscription", 50_000, 1));
///
/// assert!(params.validate().is_ok());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateLegacyOrderParams {
    /// Order total in integer minor units (must be greater than zero).
    pub amount_cents: u64,
    /// ISO-4217 currency code.
    pub currency: Currency,
    /// Whether physical delivery is required for this order.
    pub delivery_needed: bool,
    /// Optional merchant-assigned unique order reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merchant_order_id: Option<String>,
    /// Optional line items associated with the order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub items: Vec<LegacyOrderItem>,
}

impl CreateLegacyOrderParams {
    /// Creates a new [`CreateLegacyOrderParams`] with `delivery_needed = false`.
    #[must_use]
    pub fn new(amount_cents: u64, currency: Currency) -> Self {
        Self {
            amount_cents,
            currency,
            delivery_needed: false,
            merchant_order_id: None,
            items: Vec::new(),
        }
    }

    /// Sets whether physical delivery is needed.
    #[must_use]
    pub const fn delivery_needed(mut self, delivery_needed: bool) -> Self {
        self.delivery_needed = delivery_needed;
        self
    }

    /// Sets the optional merchant order reference ID.
    #[must_use]
    pub fn merchant_order_id(mut self, merchant_order_id: impl Into<String>) -> Self {
        self.merchant_order_id = Some(merchant_order_id.into());
        self
    }

    /// Replaces the order line items list.
    #[must_use]
    pub fn items(mut self, items: Vec<LegacyOrderItem>) -> Self {
        self.items = items;
        self
    }

    /// Appends a single [`LegacyOrderItem`] to the order.
    #[must_use]
    pub fn add_item(mut self, item: LegacyOrderItem) -> Self {
        self.items.push(item);
        self
    }

    /// Validates all order parameters prior to serialization.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `amount_cents == 0`, `currency`
    /// is empty, `merchant_order_id` is blank, or any item fails validation.
    pub fn validate(&self) -> Result<(), PaymobError> {
        if self.amount_cents == 0 {
            return Err(PaymobError::ValidationError {
                field: "amount_cents",
                reason: "amount_cents must be greater than zero".to_owned(),
            });
        }
        if self.currency.as_str().trim().is_empty() {
            return Err(PaymobError::ValidationError {
                field: "currency",
                reason: "currency must not be empty".to_owned(),
            });
        }
        validate_optional_merchant_id(self.merchant_order_id.as_deref())?;
        for item in &self.items {
            item.validate()?;
        }
        Ok(())
    }

    /// Serializes this order payload and injects Regime 2 `"auth_token"` into the JSON object.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if validation or serialization fails, or
    /// [`PaymobError::AuthenticationError`] if `auth_token` is empty.
    pub fn to_authenticated_body(&self, auth_token: &SecretString) -> Result<Value, PaymobError> {
        self.validate()?;
        let mut body = serde_json::to_value(self).map_err(|err| PaymobError::ValidationError {
            field: "order",
            reason: err.to_string(),
        })?;
        inject_body_auth_token(&mut body, auth_token).map_err(map_jwt_err)?;
        Ok(body)
    }
}

/// Authenticated wrapper pairing [`CreateLegacyOrderParams`] with a Regime 2 `auth_token`.
///
/// Implements a custom [`fmt::Debug`] that emits `"[REDACTED]"` for `auth_token`.
#[derive(Clone)]
pub struct AuthenticatedLegacyOrderRequest {
    auth_token: SecretString,
    params: CreateLegacyOrderParams,
}

impl fmt::Debug for AuthenticatedLegacyOrderRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthenticatedLegacyOrderRequest")
            .field("auth_token", &"[REDACTED]")
            .field("params", &self.params)
            .finish()
    }
}

impl AuthenticatedLegacyOrderRequest {
    /// Creates a new [`AuthenticatedLegacyOrderRequest`].
    #[must_use]
    pub fn new(auth_token: SecretString, params: CreateLegacyOrderParams) -> Self {
        Self { auth_token, params }
    }

    /// Returns a reference to the underlying [`CreateLegacyOrderParams`].
    #[must_use]
    pub const fn params(&self) -> &CreateLegacyOrderParams {
        &self.params
    }

    /// Serializes the request to a JSON [`Value`] containing `"auth_token"`.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError`] if parameter validation or token injection fails.
    pub fn to_json_value(&self) -> Result<Value, PaymobError> {
        self.params.to_authenticated_body(&self.auth_token)
    }
}

/// Registered order returned by `POST /api/ecommerce/orders`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacyOrder {
    /// Paymob-assigned numeric order identifier.
    pub id: u64,
    /// Order amount in integer minor units.
    pub amount_cents: u64,
    /// Order ISO-4217 currency code.
    pub currency: Currency,
    /// Optional merchant-supplied order reference.
    #[serde(default)]
    pub merchant_order_id: Option<String>,
    /// Optional ISO-8601 creation timestamp.
    #[serde(default)]
    pub created_at: Option<String>,
    /// Optional delivery flag echoed by Paymob.
    #[serde(default)]
    pub delivery_needed: Option<bool>,
    /// Optional paid amount in minor units.
    #[serde(default)]
    pub paid_amount_cents: Option<u64>,
    /// Optional payment status string.
    #[serde(default)]
    pub payment_status: Option<String>,
}

/// Executes `POST /api/ecommerce/orders` with Regime 2 `"auth_token"` body injection.
///
/// # Errors
///
/// Returns [`PaymobError::ValidationError`] for invalid parameters,
/// [`PaymobError::TransportError`] on network failure, or a normalized
/// [`PaymobError`] for non-2xx gateway responses.
///
/// # Examples
///
/// ```rust,no_run
/// use secrecy::SecretString;
/// use some_paymob::core::http::{HttpClient, HttpClientConfig};
/// use some_paymob::core::types::Currency;
/// use some_paymob::resources::legacy::orders::{create_legacy_order, CreateLegacyOrderParams};
/// use url::Url;
///
/// # async fn example() -> Result<(), some_paymob::core::error::PaymobError> {
/// let http = HttpClient::new(HttpClientConfig::default())?;
/// let url = Url::parse("https://accept.paymob.com/api/ecommerce/orders").unwrap();
/// let token = SecretString::from("jwt-token");
/// let params = CreateLegacyOrderParams::new(50_000, Currency::EGP);
/// let _order = create_legacy_order(&http, url, &token, &params).await?;
/// # Ok(())
/// # }
/// ```
pub async fn create_legacy_order(
    http: &HttpClient,
    url: Url,
    auth_token: &SecretString,
    params: &CreateLegacyOrderParams,
) -> Result<LegacyOrder, PaymobError> {
    let body = params.to_authenticated_body(auth_token)?;
    let request = HttpRequest::post(url.as_str())?.with_json(&body)?;
    let response = http.execute(&request).await?;
    if !response.status.is_success() {
        return Err(PaymobError::from_http_response(&response));
    }
    response.json::<LegacyOrder>().map_err(PaymobError::from)
}

fn validate_optional_merchant_id(id: Option<&str>) -> Result<(), PaymobError> {
    if let Some(raw) = id {
        if raw.trim().is_empty() {
            return Err(PaymobError::ValidationError {
                field: "merchant_order_id",
                reason: "merchant_order_id must not be blank when provided".to_owned(),
            });
        }
    }
    Ok(())
}

fn map_jwt_err(err: AcceptJwtError) -> PaymobError {
    match err {
        AcceptJwtError::EmptyApiKey | AcceptJwtError::InvalidCredentials => {
            PaymobError::AuthenticationError(err.to_string())
        }
        _ => PaymobError::ValidationError {
            field: "auth_token",
            reason: err.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::http::HttpClientConfig;
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn tc_2_3_1_order_params_validates_and_injects_auth_token() {
        let params = CreateLegacyOrderParams::new(50_000, Currency::EGP)
            .delivery_needed(true)
            .merchant_order_id("merch-101")
            .add_item(LegacyOrderItem::new("Widget", 25_000, 2).with_description("Pro"));

        let token = SecretString::from("super-secret-jwt-token");
        let body = params
            .to_authenticated_body(&token)
            .expect("valid order body");

        assert_eq!(body["amount_cents"], 50_000);
        assert_eq!(body["currency"], "EGP");
        assert_eq!(body["delivery_needed"], true);
        assert_eq!(body["merchant_order_id"], "merch-101");
        assert_eq!(body["auth_token"], "super-secret-jwt-token");
        assert_eq!(body["items"][0]["name"], "Widget");
        assert_eq!(body["items"][0]["quantity"], 2);
    }

    #[test]
    fn tc_2_3_1_rejects_zero_amount_blank_currency_and_bad_items() {
        let zero_amt = CreateLegacyOrderParams::new(0, Currency::EGP);
        assert!(matches!(
            zero_amt.validate(),
            Err(PaymobError::ValidationError {
                field: "amount_cents",
                ..
            })
        ));

        let blank_curr = CreateLegacyOrderParams::new(100, Currency::from_code("  "));
        assert!(matches!(
            blank_curr.validate(),
            Err(PaymobError::ValidationError {
                field: "currency",
                ..
            })
        ));

        let blank_merch = CreateLegacyOrderParams::new(100, Currency::EGP).merchant_order_id("   ");
        assert!(matches!(
            blank_merch.validate(),
            Err(PaymobError::ValidationError {
                field: "merchant_order_id",
                ..
            })
        ));

        let bad_item_name =
            CreateLegacyOrderParams::new(100, Currency::EGP).add_item(LegacyOrderItem::new("", 100, 1));
        assert!(matches!(
            bad_item_name.validate(),
            Err(PaymobError::ValidationError {
                field: "items.name",
                ..
            })
        ));

        let bad_item_qty = CreateLegacyOrderParams::new(100, Currency::EGP)
            .add_item(LegacyOrderItem::new("Item", 100, 0));
        assert!(matches!(
            bad_item_qty.validate(),
            Err(PaymobError::ValidationError {
                field: "items.quantity",
                ..
            })
        ));
    }

    #[test]
    fn tc_2_3_4_redacts_auth_token_in_debug_output() {
        let params = CreateLegacyOrderParams::new(50_000, Currency::EGP);
        let req = AuthenticatedLegacyOrderRequest::new(
            SecretString::from("jwt-secret-should-never-leak"),
            params,
        );
        let debug_str = format!("{req:?}");
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains("jwt-secret-should-never-leak"));
    }

    #[tokio::test]
    async fn tc_2_3_1_create_legacy_order_wiremock_positive_and_401() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(LEGACY_ORDERS_PATH))
            .and(body_partial_json(serde_json::json!({
                "auth_token": "jwt-123",
                "amount_cents": 50_000,
                "currency": "EGP"
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "id": 998877,
                "amount_cents": 50_000,
                "currency": "EGP",
                "merchant_order_id": "ord-1",
                "delivery_needed": false
            })))
            .expect(1)
            .mount(&server)
            .await;

        let http = HttpClient::new(HttpClientConfig::default().with_allow_insecure_http(true))
            .expect("http client");
        let url = Url::parse(&format!("{}{}", server.uri(), LEGACY_ORDERS_PATH)).expect("url");
        let params =
            CreateLegacyOrderParams::new(50_000, Currency::EGP).merchant_order_id("ord-1");
        let order = create_legacy_order(&http, url, &SecretString::from("jwt-123"), &params)
            .await
            .expect("order created");

        assert_eq!(order.id, 998_877);
        assert_eq!(order.amount_cents, 50_000);
        assert_eq!(order.currency, Currency::EGP);
        assert_eq!(order.merchant_order_id.as_deref(), Some("ord-1"));
    }

    #[tokio::test]
    async fn tc_2_3_1_create_legacy_order_maps_gateway_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(LEGACY_ORDERS_PATH))
            .respond_with(
                ResponseTemplate::new(401)
                    .set_body_json(serde_json::json!({"detail": "incorrect credentials"})),
            )
            .expect(1)
            .mount(&server)
            .await;

        let http = HttpClient::new(HttpClientConfig::default().with_allow_insecure_http(true))
            .expect("http client");
        let url = Url::parse(&format!("{}{}", server.uri(), LEGACY_ORDERS_PATH)).expect("url");
        let params = CreateLegacyOrderParams::new(50_000, Currency::EGP);
        let err = create_legacy_order(&http, url, &SecretString::from("bad-jwt"), &params)
            .await
            .expect_err("must fail with 401");

        assert!(err.is_auth_error());
    }
}

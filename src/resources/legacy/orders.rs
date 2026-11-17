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
use zeroize::ZeroizeOnDrop;

use super::map_jwt_err;
use crate::core::auth::accept_jwt::inject_body_auth_token;
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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

    /// Validates that `name` is non-empty and both `amount_cents` and `quantity` are at least `1`.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `name` is blank, `amount_cents == 0`,
    /// or `quantity == 0`.
    pub fn validate(&self) -> Result<(), PaymobError> {
        if self.name.trim().is_empty() {
            return Err(PaymobError::ValidationError {
                field: "items.name",
                reason: "order item name must not be empty".to_owned(),
            });
        }
        if self.amount_cents == 0 {
            return Err(PaymobError::ValidationError {
                field: "items.amount_cents",
                reason: "order item amount_cents must be greater than zero".to_owned(),
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

#[derive(Deserialize)]
struct RawLegacyOrderItem {
    name: String,
    amount_cents: u64,
    #[serde(default)]
    description: Option<String>,
    quantity: u32,
}

impl<'de> Deserialize<'de> for LegacyOrderItem {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = RawLegacyOrderItem::deserialize(deserializer)?;
        let item = Self {
            name: raw.name,
            amount_cents: raw.amount_cents,
            description: raw.description,
            quantity: raw.quantity,
        };
        item.validate().map_err(serde::de::Error::custom)?;
        Ok(item)
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
        validate_order_items(&self.items)
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

#[derive(Deserialize)]
struct RawCreateLegacyOrderParams {
    amount_cents: u64,
    currency: Currency,
    delivery_needed: bool,
    #[serde(default)]
    merchant_order_id: Option<String>,
    #[serde(default)]
    items: Vec<LegacyOrderItem>,
}

impl<'de> Deserialize<'de> for CreateLegacyOrderParams {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = RawCreateLegacyOrderParams::deserialize(deserializer)?;
        let params = Self {
            amount_cents: raw.amount_cents,
            currency: raw.currency,
            delivery_needed: raw.delivery_needed,
            merchant_order_id: raw.merchant_order_id,
            items: raw.items,
        };
        params.validate().map_err(serde::de::Error::custom)?;
        Ok(params)
    }
}

/// Authenticated wrapper pairing [`CreateLegacyOrderParams`] with a Regime 2 `auth_token`.
///
/// Implements a custom [`fmt::Debug`] that emits `"[REDACTED]"` for `auth_token`.
/// The `auth_token` field is private and cannot be accessed directly by callers:
///
/// ```compile_fail
/// use secrecy::SecretString;
/// use some_paymob::core::types::Currency;
/// use some_paymob::resources::legacy::orders::{
///     AuthenticatedLegacyOrderRequest, CreateLegacyOrderParams,
/// };
///
/// let params = CreateLegacyOrderParams::new(50_000, Currency::EGP);
/// let req = AuthenticatedLegacyOrderRequest::new(SecretString::from("jwt"), params);
/// let _leaked = &req.auth_token;
/// ```
#[derive(Clone, ZeroizeOnDrop)]
pub struct AuthenticatedLegacyOrderRequest {
    auth_token: SecretString,
    #[zeroize(skip)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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

impl LegacyOrder {
    /// Validates that `id > 0`, `amount_cents > 0`, and `currency` is non-empty.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `id == 0`, `amount_cents == 0`,
    /// or `currency` is blank.
    pub fn validate(&self) -> Result<(), PaymobError> {
        if self.id == 0 {
            return Err(PaymobError::ValidationError {
                field: "id",
                reason: "legacy order id must be greater than zero".to_owned(),
            });
        }
        if self.amount_cents == 0 {
            return Err(PaymobError::ValidationError {
                field: "amount_cents",
                reason: "legacy order amount_cents must be greater than zero".to_owned(),
            });
        }
        if self.currency.as_str().trim().is_empty() {
            return Err(PaymobError::ValidationError {
                field: "currency",
                reason: "legacy order currency must not be empty".to_owned(),
            });
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct RawLegacyOrder {
    id: u64,
    amount_cents: u64,
    currency: Currency,
    #[serde(default)]
    merchant_order_id: Option<String>,
    #[serde(default)]
    created_at: Option<String>,
    #[serde(default)]
    delivery_needed: Option<bool>,
    #[serde(default)]
    paid_amount_cents: Option<u64>,
    #[serde(default)]
    payment_status: Option<String>,
}

impl<'de> Deserialize<'de> for LegacyOrder {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = RawLegacyOrder::deserialize(deserializer)?;
        let order = Self {
            id: raw.id,
            amount_cents: raw.amount_cents,
            currency: raw.currency,
            merchant_order_id: raw.merchant_order_id,
            created_at: raw.created_at,
            delivery_needed: raw.delivery_needed,
            paid_amount_cents: raw.paid_amount_cents,
            payment_status: raw.payment_status,
        };
        order.validate().map_err(serde::de::Error::custom)?;
        Ok(order)
    }
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
    if id.is_some_and(|raw| raw.trim().is_empty()) {
        return Err(PaymobError::ValidationError {
            field: "merchant_order_id",
            reason: "merchant_order_id must not be blank when provided".to_owned(),
        });
    }
    Ok(())
}

fn validate_order_items(items: &[LegacyOrderItem]) -> Result<(), PaymobError> {
    for item in items {
        item.validate()?;
    }
    Ok(())
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

        let bad_item_name = CreateLegacyOrderParams::new(100, Currency::EGP)
            .add_item(LegacyOrderItem::new("", 100, 1));
        assert!(matches!(
            bad_item_name.validate(),
            Err(PaymobError::ValidationError {
                field: "items.name",
                ..
            })
        ));

        let bad_item_amount = CreateLegacyOrderParams::new(100, Currency::EGP)
            .add_item(LegacyOrderItem::new("Item", 0, 1));
        assert!(matches!(
            bad_item_amount.validate(),
            Err(PaymobError::ValidationError {
                field: "items.amount_cents",
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
    fn tc_2_3_cycle2_deserialize_enforces_validation_on_order_types() {
        let item_json = serde_json::json!({"name": "Widget", "amount_cents": 0, "quantity": 1});
        assert!(serde_json::from_value::<LegacyOrderItem>(item_json).is_err());

        let params_json = serde_json::json!({
            "amount_cents": 0,
            "currency": "EGP",
            "delivery_needed": false
        });
        assert!(serde_json::from_value::<CreateLegacyOrderParams>(params_json).is_err());

        let zero_id_order = serde_json::json!({
            "id": 0,
            "amount_cents": 50_000,
            "currency": "EGP"
        });
        assert!(serde_json::from_value::<LegacyOrder>(zero_id_order).is_err());

        let zero_amt_order = serde_json::json!({
            "id": 998_877,
            "amount_cents": 0,
            "currency": "EGP"
        });
        assert!(serde_json::from_value::<LegacyOrder>(zero_amt_order).is_err());
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
        let params = CreateLegacyOrderParams::new(50_000, Currency::EGP).merchant_order_id("ord-1");
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

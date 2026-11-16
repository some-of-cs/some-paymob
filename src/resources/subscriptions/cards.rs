#![forbid(unsafe_code)]
//! Unit 4.3.3 — Subscription card vault management ([`SubscriptionCardsService`]).
//!
//! Provides Regime 2 (`Authorization: Bearer <auth_token>`) operations for
//! listing cards bound to a Paymob subscription, adding secondary backup
//! cards, promoting a card to primary, and deleting secondary cards.

use std::fmt;

use reqwest::Method;
use reqwest::header::{AUTHORIZATION, HeaderValue};
use secrecy::{ExposeSecret, SecretString};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize, Serializer};
use zeroize::ZeroizeOnDrop;

use super::SubscriptionsService;
use crate::core::auth::{
    AcceptJwtProvider, CachedToken, format_bearer_header, is_incorrect_credentials_401,
};
use crate::core::client::PaymobClient;
use crate::core::error::PaymobError;
#[cfg(test)]
use crate::core::http::HttpClientConfig;
use crate::core::http::{HttpClient, HttpRequest, HttpResponse};

const SUBSCRIPTIONS_BASE_PATH: &str = "/api/acceptance/subscriptions";

/// Saved card record associated with a Paymob subscription (`US-4.3.0`).
///
/// The underlying card `token` is wrapped in [`SecretString`] and redacted
/// as `"[REDACTED]"` in [`fmt::Debug`] output to prevent credential leakage.
///
/// # Examples
///
/// ```rust
/// use some_paymob::resources::subscriptions::cards::SubscriptionCard;
///
/// let payload = serde_json::json!({
///     "id": 374,
///     "card_data": "Visa",
///     "token": "tok_live_secret_card_value",
///     "created_at": "2026-11-16T10:00:00Z",
///     "is_primary": true,
///     "masked_pan": "xxxx-xxxx-xxxx-2346",
///     "failed_attempts": 0
/// });
/// let card: SubscriptionCard = serde_json::from_value(payload).unwrap();
/// assert_eq!(card.id, 374);
/// assert!(card.is_primary);
/// assert!(format!("{card:?}").contains("[REDACTED]"));
/// assert!(!format!("{card:?}").contains("tok_live_secret_card_value"));
/// ```
#[derive(Clone, Deserialize, ZeroizeOnDrop)]
pub struct SubscriptionCard {
    /// Unique identifier of the card record on the subscription.
    #[zeroize(skip)]
    pub id: u64,
    /// Optional card scheme or metadata descriptor returned by Paymob.
    #[serde(default)]
    pub card_data: Option<String>,
    /// Sensitive saved-card token (automatically zeroized and redacted).
    pub token: SecretString,
    /// ISO-8601 creation timestamp of the subscription card record.
    pub created_at: String,
    /// Whether this card is currently the primary recurring billing card.
    #[zeroize(skip)]
    pub is_primary: bool,
    /// Masked Primary Account Number (e.g., `xxxx-xxxx-xxxx-2346`).
    pub masked_pan: String,
    /// Number of consecutive failed recurring deduction attempts on this card.
    #[serde(default)]
    #[zeroize(skip)]
    pub failed_attempts: u32,
}

impl fmt::Debug for SubscriptionCard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SubscriptionCard")
            .field("id", &self.id)
            .field("card_data", &self.card_data)
            .field("token", &"[REDACTED]")
            .field("created_at", &self.created_at)
            .field("is_primary", &self.is_primary)
            .field("masked_pan", &self.masked_pan)
            .field("failed_attempts", &self.failed_attempts)
            .finish()
    }
}

/// Request payload for `POST /api/acceptance/subscriptions/{id}/change-primary-card`.
///
/// # Examples
///
/// ```rust
/// use some_paymob::resources::subscriptions::cards::ChangePrimaryCardParams;
///
/// let params = ChangePrimaryCardParams::new(374);
/// assert_eq!(params.card, 374);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ChangePrimaryCardParams {
    /// Card identifier to promote as the subscription's primary card.
    pub card: u64,
}

impl ChangePrimaryCardParams {
    /// Creates a new [`ChangePrimaryCardParams`] targeting `card`.
    #[must_use]
    pub const fn new(card: u64) -> Self {
        Self { card }
    }
}

/// Request payload for `POST /api/acceptance/subscriptions/{id}/delete-card`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
struct DeleteSecondaryCardParams {
    card: u64,
}

/// Request payload for adding a secondary card to an existing subscription.
///
/// The card token is stored in [`SecretString`] and redacted as `"[REDACTED]"`
/// in [`fmt::Debug`] output.
///
/// # Examples
///
/// ```rust
/// use some_paymob::resources::subscriptions::cards::AddSecondaryCardParams;
///
/// let params = AddSecondaryCardParams::new("tok_secondary_card_123")
///     .unwrap()
///     .with_integration_id(42001);
/// assert_eq!(params.integration_id(), Some(42001));
/// assert!(format!("{params:?}").contains("[REDACTED]"));
/// ```
#[derive(Clone, Serialize, ZeroizeOnDrop)]
pub struct AddSecondaryCardParams {
    #[serde(serialize_with = "serialize_secret_string")]
    token: SecretString,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[zeroize(skip)]
    integration_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    redirect_url: Option<String>,
}

impl AddSecondaryCardParams {
    /// Constructs a validated [`AddSecondaryCardParams`] from a saved-card token.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `card_token` is empty or whitespace.
    pub fn new(card_token: impl Into<String>) -> Result<Self, PaymobError> {
        let raw = card_token.into();
        if raw.trim().is_empty() {
            return Err(PaymobError::ValidationError {
                field: "card_token",
                reason: "secondary card token must not be empty".to_owned(),
            });
        }
        Ok(Self {
            token: SecretString::from(raw),
            integration_id: None,
            redirect_url: None,
        })
    }

    /// Attaches an optional Paymob card integration ID for the secondary card.
    #[must_use]
    pub const fn with_integration_id(mut self, integration_id: u64) -> Self {
        self.integration_id = Some(integration_id);
        self
    }

    /// Attaches an optional redirection URL for 3DS verification if required.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `redirect_url` is empty or whitespace.
    pub fn with_redirect_url(
        mut self,
        redirect_url: impl Into<String>,
    ) -> Result<Self, PaymobError> {
        let trimmed = redirect_url.into().trim().to_owned();
        if trimmed.is_empty() {
            return Err(PaymobError::ValidationError {
                field: "redirect_url",
                reason: "redirect URL must not be empty".to_owned(),
            });
        }
        self.redirect_url = Some(trimmed);
        Ok(self)
    }

    /// Returns the configured Paymob integration ID, if any.
    #[must_use]
    pub const fn integration_id(&self) -> Option<u64> {
        self.integration_id
    }

    /// Returns the configured redirection URL, if any.
    #[must_use]
    pub fn redirect_url(&self) -> Option<&str> {
        self.redirect_url.as_deref()
    }
}

impl fmt::Debug for AddSecondaryCardParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AddSecondaryCardParams")
            .field("token", &"[REDACTED]")
            .field("integration_id", &self.integration_id)
            .field("redirect_url", &self.redirect_url)
            .finish()
    }
}

/// Response returned when deleting a secondary card from a subscription.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct DeleteSecondaryCardResponse {
    /// Optional status detail message returned by Paymob.
    #[serde(default)]
    pub detail: Option<String>,
    /// Optional status message returned by Paymob.
    #[serde(default)]
    pub message: Option<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum CardListEnvelope {
    Array(Vec<SubscriptionCard>),
    Results { results: Vec<SubscriptionCard> },
    Cards { cards: Vec<SubscriptionCard> },
}

impl CardListEnvelope {
    fn into_vec(self) -> Vec<SubscriptionCard> {
        match self {
            Self::Array(items) => items,
            Self::Results { results } => results,
            Self::Cards { cards } => cards,
        }
    }
}

/// Service handle for subscription card vault operations (`US-4.3.0` Unit 3).
///
/// Accessed via `paymob.subscriptions().cards()` and executes all endpoints
/// under Regime 2 (`Authorization: Bearer <auth_token>`).
///
/// # Examples
///
/// ```rust,no_run
/// use some_paymob::core::client::PaymobClient;
/// use some_paymob::core::config::ClientConfig;
/// use some_paymob::core::credentials::ApiKey;
/// use some_paymob::core::region::PaymobRegion;
///
/// # async fn example() -> Result<(), some_paymob::core::error::PaymobError> {
/// let config = ClientConfig::builder()
///     .region(PaymobRegion::Egypt)
///     .api_key(ApiKey::new("egy_api_key_example")?)
///     .build()?;
/// let client = PaymobClient::new(config)?;
///
/// let cards = client.subscriptions().cards().list(1264).await?;
/// if let Some(first) = cards.first() {
///     let updated = client
///         .subscriptions()
///         .cards()
///         .change_primary(1264, first.id)
///         .await?;
///     assert!(updated.is_primary);
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct SubscriptionCardsService {
    client: PaymobClient,
    http: HttpClient,
}

impl SubscriptionsService {
    /// Returns a [`SubscriptionCardsService`] bound to this subscription client.
    #[must_use]
    pub fn cards(&self) -> SubscriptionCardsService {
        SubscriptionCardsService::new(self.client().clone())
    }
}

impl SubscriptionCardsService {
    /// Creates a new [`SubscriptionCardsService`] bound to `client`.
    #[must_use]
    pub fn new(client: PaymobClient) -> Self {
        let http = client.http().clone();
        Self { client, http }
    }

    #[cfg(test)]
    fn with_test_http(client: PaymobClient) -> Self {
        let http_cfg = HttpClientConfig::default().with_allow_insecure_http(true);
        let http = HttpClient::new(http_cfg).expect("test HTTP client should initialize");
        Self { client, http }
    }

    /// Returns a reference to the underlying [`PaymobClient`].
    #[must_use]
    pub fn client(&self) -> &PaymobClient {
        &self.client
    }

    /// Lists all saved cards registered on subscription `sub_id`.
    ///
    /// Executes `GET /api/acceptance/subscriptions/{sub_id}/cards` under Regime 2
    /// (`Authorization: Bearer <auth_token>`).
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `sub_id == 0` or `api_key` is missing,
    /// [`PaymobError::AuthenticationError`] on invalid credentials, or
    /// [`PaymobError::ApiError`] / [`PaymobError::TransportError`] on gateway failure.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use some_paymob::core::client::PaymobClient;
    /// use some_paymob::core::config::ClientConfig;
    /// use some_paymob::core::credentials::ApiKey;
    /// use some_paymob::core::region::PaymobRegion;
    ///
    /// # async fn example() -> Result<(), some_paymob::core::error::PaymobError> {
    /// let config = ClientConfig::builder()
    ///     .region(PaymobRegion::Egypt)
    ///     .api_key(ApiKey::new("egy_api_key_example")?)
    ///     .build()?;
    /// let client = PaymobClient::new(config)?;
    /// let cards = client.subscriptions().cards().list(1264).await?;
    /// println!("found {} cards", cards.len());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn list(&self, sub_id: u64) -> Result<Vec<SubscriptionCard>, PaymobError> {
        validate_positive_id("sub_id", sub_id)?;
        let path = format!("{SUBSCRIPTIONS_BASE_PATH}/{sub_id}/cards");
        let envelope: CardListEnvelope = self
            .execute_bearer_json::<(), CardListEnvelope>(Method::GET, &path, None)
            .await?;
        Ok(envelope.into_vec())
    }

    /// Adds a secondary card to subscription `sub_id`.
    ///
    /// Executes `POST /api/acceptance/subscriptions/{sub_id}/add-secondary-card`
    /// under Regime 2 (`Authorization: Bearer <auth_token>`).
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `sub_id == 0` or `api_key` is missing,
    /// [`PaymobError::AuthenticationError`] on invalid credentials, or
    /// [`PaymobError::ApiError`] / [`PaymobError::TransportError`] on gateway failure.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use some_paymob::core::client::PaymobClient;
    /// use some_paymob::core::config::ClientConfig;
    /// use some_paymob::core::credentials::ApiKey;
    /// use some_paymob::core::region::PaymobRegion;
    /// use some_paymob::resources::subscriptions::cards::AddSecondaryCardParams;
    ///
    /// # async fn example() -> Result<(), some_paymob::core::error::PaymobError> {
    /// let config = ClientConfig::builder()
    ///     .region(PaymobRegion::Egypt)
    ///     .api_key(ApiKey::new("egy_api_key_example")?)
    ///     .build()?;
    /// let client = PaymobClient::new(config)?;
    /// let params = AddSecondaryCardParams::new("tok_secondary_card_123")?;
    /// let added = client.subscriptions().cards().add_secondary(1264, params).await?;
    /// assert!(!added.is_primary);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn add_secondary(
        &self,
        sub_id: u64,
        params: AddSecondaryCardParams,
    ) -> Result<SubscriptionCard, PaymobError> {
        validate_positive_id("sub_id", sub_id)?;
        let path = format!("{SUBSCRIPTIONS_BASE_PATH}/{sub_id}/add-secondary-card");
        self.execute_bearer_json(Method::POST, &path, Some(&params))
            .await
    }

    /// Promotes `card_id` to be the primary card for subscription `sub_id`.
    ///
    /// Executes `POST /api/acceptance/subscriptions/{sub_id}/change-primary-card`
    /// with JSON body `{"card": card_id}` under Regime 2 (`Bearer <auth_token>`).
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `sub_id == 0`, `card_id == 0`, or
    /// `api_key` is missing; returns [`PaymobError::ApiError`] (e.g. `404`
    /// `{"message": "Card not found."}`) if the card does not belong to `sub_id`.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use some_paymob::core::client::PaymobClient;
    /// use some_paymob::core::config::ClientConfig;
    /// use some_paymob::core::credentials::ApiKey;
    /// use some_paymob::core::region::PaymobRegion;
    ///
    /// # async fn example() -> Result<(), some_paymob::core::error::PaymobError> {
    /// let config = ClientConfig::builder()
    ///     .region(PaymobRegion::Egypt)
    ///     .api_key(ApiKey::new("egy_api_key_example")?)
    ///     .build()?;
    /// let client = PaymobClient::new(config)?;
    /// let card = client.subscriptions().cards().change_primary(1264, 374).await?;
    /// assert!(card.is_primary);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn change_primary(
        &self,
        sub_id: u64,
        card_id: u64,
    ) -> Result<SubscriptionCard, PaymobError> {
        validate_positive_id("sub_id", sub_id)?;
        validate_positive_id("card_id", card_id)?;
        let path = format!("{SUBSCRIPTIONS_BASE_PATH}/{sub_id}/change-primary-card");
        let payload = ChangePrimaryCardParams::new(card_id);
        self.execute_bearer_json(Method::POST, &path, Some(&payload))
            .await
    }

    /// Deletes secondary card `card_id` from subscription `sub_id`.
    ///
    /// Executes `POST /api/acceptance/subscriptions/{sub_id}/delete-card`
    /// with JSON body `{"card": card_id}` under Regime 2 (`Bearer <auth_token>`).
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `sub_id == 0`, `card_id == 0`, or
    /// `api_key` is missing; returns [`PaymobError::ApiError`] on gateway errors.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use some_paymob::core::client::PaymobClient;
    /// use some_paymob::core::config::ClientConfig;
    /// use some_paymob::core::credentials::ApiKey;
    /// use some_paymob::core::region::PaymobRegion;
    ///
    /// # async fn example() -> Result<(), some_paymob::core::error::PaymobError> {
    /// let config = ClientConfig::builder()
    ///     .region(PaymobRegion::Egypt)
    ///     .api_key(ApiKey::new("egy_api_key_example")?)
    ///     .build()?;
    /// let client = PaymobClient::new(config)?;
    /// let _res = client
    ///     .subscriptions()
    ///     .cards()
    ///     .delete_secondary(1264, 375)
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn delete_secondary(
        &self,
        sub_id: u64,
        card_id: u64,
    ) -> Result<DeleteSecondaryCardResponse, PaymobError> {
        validate_positive_id("sub_id", sub_id)?;
        validate_positive_id("card_id", card_id)?;
        let path = format!("{SUBSCRIPTIONS_BASE_PATH}/{sub_id}/delete-card");
        let payload = DeleteSecondaryCardParams { card: card_id };
        self.execute_bearer_json(Method::POST, &path, Some(&payload))
            .await
    }

    async fn execute_bearer_json<Req, Resp>(
        &self,
        method: Method,
        path: &str,
        body: Option<&Req>,
    ) -> Result<Resp, PaymobError>
    where
        Req: Serialize + ?Sized,
        Resp: DeserializeOwned,
    {
        let token = self.acquire_accept_token().await?;
        let response = self.send_once(&method, path, body, &token).await?;
        if is_incorrect_credentials_401(response.status, &response.body) {
            return self
                .retry_with_fresh_token(&method, path, body, &token)
                .await;
        }
        decode_response(response)
    }

    async fn retry_with_fresh_token<Req, Resp>(
        &self,
        method: &Method,
        path: &str,
        body: Option<&Req>,
        stale_token: &SecretString,
    ) -> Result<Resp, PaymobError>
    where
        Req: Serialize + ?Sized,
        Resp: DeserializeOwned,
    {
        self.client
            .auth()
            .accept_cache()
            .evict_if_matches(stale_token)
            .await;
        let fresh_token = self.acquire_accept_token().await?;
        let response = self.send_once(method, path, body, &fresh_token).await?;
        decode_response(response)
    }

    async fn send_once<Req>(
        &self,
        method: &Method,
        path: &str,
        body: Option<&Req>,
        token: &SecretString,
    ) -> Result<HttpResponse, PaymobError>
    where
        Req: Serialize + ?Sized,
    {
        let url = self.client.accept_url(path)?;
        let bearer: HeaderValue = format_bearer_header(token)?;
        let mut request = HttpRequest::new(method.clone(), url.as_str())?;
        request = request.with_header(AUTHORIZATION, bearer);
        if let Some(payload) = body {
            request = request.with_json(&payload)?;
        }
        Ok(self.http.execute(&request).await?)
    }

    async fn acquire_accept_token(&self) -> Result<SecretString, PaymobError> {
        let api_key =
            self.client
                .config()
                .api_key()
                .ok_or_else(|| PaymobError::ValidationError {
                    field: "api_key",
                    reason: "Paymob API key is required for Regime 2 authentication".to_owned(),
                })?;
        let base_url = self.client.endpoints().accept_base_url.clone();
        let raw_key = SecretString::from(api_key.expose_secret().to_owned());

        let cached = self
            .client
            .auth()
            .accept_cache()
            .get_or_refresh(|| async {
                let provider = AcceptJwtProvider::new(&base_url, raw_key)?;
                let jwt = provider.token().await?;
                Ok::<CachedToken, PaymobError>(CachedToken::with_default_ttl(jwt, None))
            })
            .await?;

        Ok(cached.access_token.clone())
    }
}

fn decode_response<Resp: DeserializeOwned>(response: HttpResponse) -> Result<Resp, PaymobError> {
    if !response.status.is_success() {
        return Err(PaymobError::from_http_response(&response));
    }
    Ok(response.json::<Resp>()?)
}

fn validate_positive_id(field: &'static str, id: u64) -> Result<(), PaymobError> {
    if id == 0 {
        return Err(PaymobError::ValidationError {
            field,
            reason: format!("{field} must be greater than zero"),
        });
    }
    Ok(())
}

fn serialize_secret_string<S>(secret: &SecretString, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(secret.expose_secret())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use serde_json::json;
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    use super::*;
    use crate::core::config::ClientConfig;
    use crate::core::credentials::{ApiKey, SecretKey};
    use crate::core::region::PaymobRegion;

    const TEST_API_KEY: &str = "test-paymob-api-key-value";
    const TEST_JWT: &str = "eyJ.test.jwt.token";

    fn mock_client(base_uri: &str) -> PaymobClient {
        let region = PaymobRegion::Custom {
            accept_base_url: base_uri.to_owned(),
            checkout_base_url: format!("{base_uri}/unifiedcheckout/"),
            payouts_base_url: base_uri.to_owned(),
            payouts_staging_base_url: base_uri.to_owned(),
        };
        let config = ClientConfig::builder()
            .region(region)
            .secret_key(SecretKey::new("egy_sk_test_secretvalue").expect("valid secret key"))
            .api_key(ApiKey::new(TEST_API_KEY).expect("valid api key"))
            .build()
            .expect("valid mock client config");
        PaymobClient::new(config).expect("client should build")
    }

    async fn mount_auth_mock(server: &MockServer, token: &str) {
        let token_owned = token.to_owned();
        Mock::given(method("POST"))
            .and(path("/api/auth/tokens"))
            .and(body_json(json!({ "api_key": TEST_API_KEY })))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({ "token": token_owned })))
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn tc_4_3_3_list_subscription_cards_returns_cards() {
        let server = MockServer::start().await;
        mount_auth_mock(&server, TEST_JWT).await;
        Mock::given(method("GET"))
            .and(path("/api/acceptance/subscriptions/1264/cards"))
            .and(header("authorization", &format!("Bearer {TEST_JWT}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                {
                    "id": 374,
                    "card_data": "Visa",
                    "token": "tok_primary_secret_374",
                    "created_at": "2026-11-16T09:00:00Z",
                    "is_primary": true,
                    "masked_pan": "xxxx-xxxx-xxxx-2346",
                    "failed_attempts": 0
                },
                {
                    "id": 375,
                    "card_data": "Mastercard",
                    "token": "tok_secondary_secret_375",
                    "created_at": "2026-11-16T09:05:00Z",
                    "is_primary": false,
                    "masked_pan": "xxxx-xxxx-xxxx-8812",
                    "failed_attempts": 1
                }
            ])))
            .expect(1)
            .mount(&server)
            .await;

        let service = SubscriptionCardsService::with_test_http(mock_client(&server.uri()));
        let cards = service.list(1264).await.expect("list cards should succeed");

        assert_eq!(cards.len(), 2);
        assert_eq!(cards[0].id, 374);
        assert!(cards[0].is_primary);
        assert_eq!(cards[1].id, 375);
        assert!(!cards[1].is_primary);
        assert_eq!(cards[1].failed_attempts, 1);
    }

    #[tokio::test]
    async fn tc_4_3_3_list_subscription_cards_supports_wrapped_results() {
        let server = MockServer::start().await;
        mount_auth_mock(&server, TEST_JWT).await;
        Mock::given(method("GET"))
            .and(path("/api/acceptance/subscriptions/1264/cards"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [{
                    "id": 374,
                    "token": "tok_wrapped_374",
                    "created_at": "2026-11-16T09:00:00Z",
                    "is_primary": true,
                    "masked_pan": "xxxx-xxxx-xxxx-2346",
                    "failed_attempts": 0
                }]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let service = SubscriptionCardsService::with_test_http(mock_client(&server.uri()));
        let cards = service.list(1264).await.expect("wrapped list should parse");
        assert_eq!(cards.len(), 1);
        assert_eq!(cards[0].id, 374);
    }

    #[tokio::test]
    async fn tc_4_3_3_add_secondary_card_posts_token_and_redacts_debug() {
        let server = MockServer::start().await;
        mount_auth_mock(&server, TEST_JWT).await;
        Mock::given(method("POST"))
            .and(path("/api/acceptance/subscriptions/1264/add-secondary-card"))
            .and(header("authorization", &format!("Bearer {TEST_JWT}")))
            .and(body_json(json!({
                "token": "tok_new_secondary_999",
                "integration_id": 42001
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "id": 376,
                "card_data": "Visa",
                "token": "tok_new_secondary_999",
                "created_at": "2026-11-16T10:00:00Z",
                "is_primary": false,
                "masked_pan": "xxxx-xxxx-xxxx-1111",
                "failed_attempts": 0
            })))
            .expect(1)
            .mount(&server)
            .await;

        let params = AddSecondaryCardParams::new("tok_new_secondary_999")
            .expect("valid params")
            .with_integration_id(42001);
        let params_debug = format!("{params:?}");
        assert!(params_debug.contains("[REDACTED]"));
        assert!(!params_debug.contains("tok_new_secondary_999"));

        let service = SubscriptionCardsService::with_test_http(mock_client(&server.uri()));
        let card = service
            .add_secondary(1264, params)
            .await
            .expect("add_secondary should succeed");
        assert_eq!(card.id, 376);
        assert!(!card.is_primary);
    }

    #[tokio::test]
    async fn tc_4_3_3_change_primary_card_sends_card_id_and_returns_primary() {
        let server = MockServer::start().await;
        mount_auth_mock(&server, TEST_JWT).await;
        Mock::given(method("POST"))
            .and(path("/api/acceptance/subscriptions/1264/change-primary-card"))
            .and(header("authorization", &format!("Bearer {TEST_JWT}")))
            .and(body_json(json!({ "card": 374 })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": 374,
                "card_data": "Visa",
                "token": "tok_secret_primary_374",
                "created_at": "2026-11-16T10:15:00Z",
                "is_primary": true,
                "masked_pan": "xxxx-xxxx-xxxx-2346",
                "failed_attempts": 0
            })))
            .expect(1)
            .mount(&server)
            .await;

        let service = SubscriptionCardsService::with_test_http(mock_client(&server.uri()));
        let updated = service
            .change_primary(1264, 374)
            .await
            .expect("change_primary should succeed");

        assert_eq!(updated.id, 374);
        assert!(updated.is_primary);
        assert_eq!(updated.masked_pan, "xxxx-xxxx-xxxx-2346");
        let debug_out = format!("{updated:?}");
        assert!(debug_out.contains("[REDACTED]"));
        assert!(!debug_out.contains("tok_secret_primary_374"));
    }

    #[tokio::test]
    async fn tc_4_3_3_change_primary_maps_404_card_not_found_to_api_error() {
        let server = MockServer::start().await;
        mount_auth_mock(&server, TEST_JWT).await;
        Mock::given(method("POST"))
            .and(path(
                "/api/acceptance/subscriptions/1264/change-primary-card",
            ))
            .and(body_json(json!({ "card": 999 })))
            .respond_with(
                ResponseTemplate::new(404).set_body_json(json!({ "message": "Card not found." })),
            )
            .expect(1)
            .mount(&server)
            .await;

        let service = SubscriptionCardsService::with_test_http(mock_client(&server.uri()));
        let err = service
            .change_primary(1264, 999)
            .await
            .expect_err("unknown card should return ApiError");

        assert!(matches!(
            err,
            PaymobError::ApiError { status: 404, ref message, .. } if message == "Card not found."
        ));
    }

    #[tokio::test]
    async fn tc_4_3_3_delete_secondary_card_posts_delete_card_endpoint() {
        let server = MockServer::start().await;
        mount_auth_mock(&server, TEST_JWT).await;
        Mock::given(method("POST"))
            .and(path("/api/acceptance/subscriptions/1264/delete-card"))
            .and(header("authorization", &format!("Bearer {TEST_JWT}")))
            .and(body_json(json!({ "card": 375 })))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "detail": "Card deleted successfully." })),
            )
            .expect(1)
            .mount(&server)
            .await;

        let service = SubscriptionCardsService::with_test_http(mock_client(&server.uri()));
        let res = service
            .delete_secondary(1264, 375)
            .await
            .expect("delete_secondary should succeed");
        assert_eq!(res.detail.as_deref(), Some("Card deleted successfully."));
    }

    #[tokio::test]
    async fn tc_4_3_3_401_incorrect_credentials_evicts_and_retries_once() {
        let server = MockServer::start().await;
        let auth_calls = Arc::new(AtomicUsize::new(0));
        let auth_calls_ref = Arc::clone(&auth_calls);
        Mock::given(method("POST"))
            .and(path("/api/auth/tokens"))
            .respond_with(move |_req: &Request| {
                let idx = auth_calls_ref.fetch_add(1, Ordering::SeqCst);
                let tok = if idx == 0 { "stale-jwt" } else { "fresh-jwt" };
                ResponseTemplate::new(201).set_body_json(json!({ "token": tok }))
            })
            .expect(2)
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/acceptance/subscriptions/1264/cards"))
            .and(header("authorization", "Bearer stale-jwt"))
            .respond_with(
                ResponseTemplate::new(401)
                    .set_body_json(json!({ "detail": "incorrect credentials" })),
            )
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/acceptance/subscriptions/1264/cards"))
            .and(header("authorization", "Bearer fresh-jwt"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
            .expect(1)
            .mount(&server)
            .await;

        let service = SubscriptionCardsService::with_test_http(mock_client(&server.uri()));
        let cards = service.list(1264).await.expect("retry should succeed");
        assert!(cards.is_empty());
        assert_eq!(auth_calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn tc_4_3_3_rejects_zero_ids_empty_tokens_and_missing_api_key() {
        let config = ClientConfig::builder()
            .region(PaymobRegion::Egypt)
            .secret_key(SecretKey::new("egy_sk_test_secretvalue").expect("valid secret"))
            .build()
            .expect("valid config without api_key");
        let client = PaymobClient::new(config).expect("client builds");
        let service = client.subscriptions().cards();

        assert!(matches!(
            service.list(0).await,
            Err(PaymobError::ValidationError {
                field: "sub_id",
                ..
            })
        ));
        assert!(matches!(
            service.change_primary(1264, 0).await,
            Err(PaymobError::ValidationError {
                field: "card_id",
                ..
            })
        ));
        assert!(matches!(
            service.delete_secondary(0, 375).await,
            Err(PaymobError::ValidationError {
                field: "sub_id",
                ..
            })
        ));
        assert!(matches!(
            AddSecondaryCardParams::new("   "),
            Err(PaymobError::ValidationError {
                field: "card_token",
                ..
            })
        ));
        assert!(matches!(
            service.list(1264).await,
            Err(PaymobError::ValidationError {
                field: "api_key",
                ..
            })
        ));
    }
}

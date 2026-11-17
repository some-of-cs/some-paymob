#![forbid(unsafe_code)]
//! Subscriptions & Recurring Billing engine (`US-4.2.0` & `US-4.3.0`).
//!
//! Pre-scaffolded module index for `feat/module-4-saved-cards-subscriptions`.

use reqwest::Method;
use reqwest::header::{AUTHORIZATION, HeaderValue};
use secrecy::SecretString;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::core::auth::{
    AcceptJwtProvider, CachedToken, format_bearer_header, is_incorrect_credentials_401,
};
use crate::core::client::PaymobClient;
use crate::core::error::PaymobError;
use crate::core::http::{HttpClient, HttpRequest, HttpResponse};

/// Unit 4.3.3: Subscription card vault management (`list`, `add_secondary`, `change_primary`, `delete_secondary`).
pub mod cards;
/// Unit 4.3.4: Subscription webhook registration and transaction history endpoints.
pub mod history;
/// Unit 4.3.2: [`SubscriptionsService`] lifecycle operations.
pub mod lifecycle;
/// Unit 4.3.1: Subscription record, state, list filter, and card vault models.
pub mod models;
/// Unit 4.2.1: Subscription plan frequency, plan type, and plan record models.
pub mod plan_models;
/// Unit 4.2.2: Subscription plan creation and update parameter builders.
pub mod plan_params;
/// Unit 4.2.3: Subscription plans CRUD and suspend/resume service.
pub mod plans_service;
/// Unit 4.3.5: Composite `refund_last_transaction` helper.
pub mod refund;

pub use lifecycle::SubscriptionsService;
pub use plans_service::SubscriptionPlansService;

pub(crate) async fn execute_subscription_bearer_json<Req, Resp>(
    client: &PaymobClient,
    http: &HttpClient,
    method: Method,
    path: &str,
    body: Option<&Req>,
) -> Result<Resp, PaymobError>
where
    Req: Serialize + ?Sized,
    Resp: DeserializeOwned,
{
    let token = acquire_subscription_accept_token(client).await?;
    let response = send_subscription_once(client, http, &method, path, body, &token).await?;
    if is_incorrect_credentials_401(response.status, &response.body) {
        return retry_subscription_with_fresh_token(client, http, &method, path, body, &token)
            .await;
    }
    decode_subscription_response(response)
}

async fn retry_subscription_with_fresh_token<Req, Resp>(
    client: &PaymobClient,
    http: &HttpClient,
    method: &Method,
    path: &str,
    body: Option<&Req>,
    stale_token: &SecretString,
) -> Result<Resp, PaymobError>
where
    Req: Serialize + ?Sized,
    Resp: DeserializeOwned,
{
    client
        .auth()
        .accept_cache()
        .evict_if_matches(stale_token)
        .await;
    let fresh_token = acquire_subscription_accept_token(client).await?;
    let response = send_subscription_once(client, http, method, path, body, &fresh_token).await?;
    decode_subscription_response(response)
}

async fn send_subscription_once<Req>(
    client: &PaymobClient,
    http: &HttpClient,
    method: &Method,
    path: &str,
    body: Option<&Req>,
    token: &SecretString,
) -> Result<HttpResponse, PaymobError>
where
    Req: Serialize + ?Sized,
{
    let url = client.accept_url(path)?;
    let bearer: HeaderValue = format_bearer_header(token)?;
    let mut request = HttpRequest::new(method.clone(), url.as_str())?;
    request = request.with_header(AUTHORIZATION, bearer);
    if let Some(payload) = body {
        request = request.with_json(&payload)?;
    }
    Ok(http.execute(&request).await?)
}

pub(crate) async fn acquire_subscription_accept_token(
    client: &PaymobClient,
) -> Result<SecretString, PaymobError> {
    let api_key = client
        .config()
        .api_key()
        .ok_or_else(|| PaymobError::ValidationError {
            field: "api_key",
            reason: "Paymob API key is required for Regime 2 authentication".to_owned(),
        })?;
    let base_url = client.endpoints().accept_base_url.clone();
    let raw_key = SecretString::from(api_key.expose_secret().to_owned());

    let cached = client
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

pub(crate) fn decode_subscription_response<Resp: DeserializeOwned>(
    response: HttpResponse,
) -> Result<Resp, PaymobError> {
    if !response.status.is_success() {
        return Err(PaymobError::from_http_response(&response));
    }
    Ok(response.json::<Resp>()?)
}

pub(crate) fn validate_positive_id(field: &'static str, id: u64) -> Result<(), PaymobError> {
    if id == 0 {
        return Err(PaymobError::ValidationError {
            field,
            reason: format!("{field} must be greater than zero"),
        });
    }
    Ok(())
}

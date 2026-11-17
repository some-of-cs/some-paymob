#![forbid(unsafe_code)]
//! Payouts user budget and topup inquiries (`US-5.2.0/unit-3`).

use std::fmt;

use reqwest::StatusCode;
use reqwest::header::AUTHORIZATION;
use serde::{Deserialize, Serialize};

use crate::core::error::PaymobError;
use crate::core::http::{HttpRequest, parse_retry_after};
use crate::resources::payouts::{
    PayoutsInquiriesService, execute_payouts_request, parse_payouts_response,
    resolve_payouts_bearer_header,
};

/// Relative endpoint path for Paymob Send user budget inquiry.
pub const PAYOUTS_BUDGET_INQUIRE_PATH: &str = "/api/secure/budget/inquire/";
/// Relative endpoint path for Paymob Send topup inquiry.
pub const PAYOUTS_TOPUP_INQUIRE_PATH: &str = "/api/secure/topup/inquire/";

/// Response returned by `GET /api/secure/budget/inquire/`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct UserBudgetResponse {
    /// Human-readable budget string (e.g. `"Your current budget is 888.25 LE"`).
    pub current_budget: String,
}

/// Topup record returned by `GET /api/secure/topup/inquire/` and `POST /api/secure/topup/request/`.
///
/// Redacts `from_account_number` and `to_account_number` (`[REDACTED]`) in [`fmt::Debug`].
#[derive(Clone, PartialEq, Eq, Deserialize)]
pub struct TopupRecord {
    /// Topup request identifier.
    #[serde(default)]
    pub id: Option<u64>,
    /// Topup amount (`u64`, zero floats).
    #[serde(default)]
    pub amount: Option<u64>,
    /// Topup status (e.g. `"pending"`, `"approved"`).
    #[serde(default)]
    pub status: Option<String>,
    /// Topup type (e.g. `"from_accept_balance"`, `"from_bank_transfer"`).
    #[serde(rename = "type", default)]
    pub transfer_type: Option<String>,
    /// Currency string.
    #[serde(default)]
    pub currency: Option<String>,
    /// Source bank account number (redacted in `Debug`).
    #[serde(default)]
    pub from_account_number: Option<String>,
    /// Destination bank account number (redacted in `Debug`).
    #[serde(default)]
    pub to_account_number: Option<String>,
    /// Optional status description.
    #[serde(default)]
    pub status_description: Option<String>,
}

impl fmt::Debug for TopupRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TopupRecord")
            .field("id", &self.id)
            .field("amount", &self.amount)
            .field("status", &self.status)
            .field("transfer_type", &self.transfer_type)
            .field("currency", &self.currency)
            .field(
                "from_account_number",
                &self.from_account_number.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "to_account_number",
                &self.to_account_number.as_ref().map(|_| "[REDACTED]"),
            )
            .field("status_description", &self.status_description)
            .finish()
    }
}

/// Query parameters for `GET /api/secure/topup/inquire/`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct TopupInquiryParams {
    /// Optional page number for paginated topup history.
    pub page: Option<u32>,
    /// Optional topup ID filter.
    pub id: Option<u64>,
}

/// Response returned by `GET /api/secure/topup/inquire/`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct TopupInquiryResponse {
    /// Returned topup records.
    #[serde(default)]
    pub results: Vec<TopupRecord>,
    /// Total count if provided by gateway.
    #[serde(default)]
    pub count: Option<u64>,
}

#[derive(Deserialize)]
struct RateLimitBody {
    status_description: Option<String>,
    status_code: Option<String>,
}

impl<'a> PayoutsInquiriesService<'a> {
    /// Retrieves the authenticated Payouts user budget (`GET /api/secure/budget/inquire/`).
    ///
    /// Maps HTTP `429` (`{ status_description, status_code }`) to [`PaymobError::RateLimited`].
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::RateLimited`] on HTTP 429 or [`PaymobError::AuthenticationError`] on 401.
    pub async fn user_budget(&self) -> Result<UserBudgetResponse, PaymobError> {
        let bearer = resolve_payouts_bearer_header(self.client()).await?;
        let url = self.client().payouts_url(PAYOUTS_BUDGET_INQUIRE_PATH)?;
        let request = HttpRequest::get(url.as_str())
            .map_err(PaymobError::from)?
            .with_header(AUTHORIZATION, bearer);
        let response = execute_payouts_request(self.client(), &request).await?;
        if response.status == StatusCode::TOO_MANY_REQUESTS {
            return Err(map_budget_rate_limit(&response));
        }
        parse_payouts_response(&response)
    }

    /// Queries topup request history (`GET /api/secure/topup/inquire/`).
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError`] on transport, auth, or HTTP error responses.
    pub async fn topup(
        &self,
        params: TopupInquiryParams,
    ) -> Result<TopupInquiryResponse, PaymobError> {
        let bearer = resolve_payouts_bearer_header(self.client()).await?;
        let mut url = self.client().payouts_url(PAYOUTS_TOPUP_INQUIRE_PATH)?;
        append_topup_query(&mut url, &params);
        let request = HttpRequest::get(url.as_str())
            .map_err(PaymobError::from)?
            .with_header(AUTHORIZATION, bearer);
        let response = execute_payouts_request(self.client(), &request).await?;
        parse_payouts_response(&response)
    }
}

fn append_topup_query(url: &mut url::Url, params: &TopupInquiryParams) {
    let mut pairs = url.query_pairs_mut();
    if let Some(page) = params.page {
        pairs.append_pair("page", &page.to_string());
    }
    if let Some(id) = params.id {
        pairs.append_pair("id", &id.to_string());
    }
}

fn map_budget_rate_limit(response: &crate::core::http::HttpResponse) -> PaymobError {
    let retry_after_secs = parse_retry_after(&response.headers).map(|d| d.as_secs());
    let parsed = response
        .text()
        .ok()
        .and_then(|t| serde_json::from_str::<RateLimitBody>(t).ok());
    let message = parsed
        .and_then(|b| b.status_description.or(b.status_code))
        .unwrap_or_else(|| String::from("Payouts user budget rate limit exceeded"));
    PaymobError::RateLimited {
        message,
        retry_after_secs,
    }
}

#[cfg(test)]
mod tests {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::core::auth::CachedToken;
    use crate::core::client::PaymobClient;
    use crate::core::config::ClientConfig;
    use crate::core::region::PaymobRegion;

    fn seeded_client(base_url: &str) -> PaymobClient {
        let cfg = ClientConfig::builder()
            .region(PaymobRegion::Custom {
                accept_base_url: base_url.to_owned(),
                payouts_base_url: Some(base_url.to_owned()),
            })
            .build()
            .expect("valid config");
        let client = PaymobClient::new(cfg).expect("valid client");
        client
            .auth()
            .payouts_cache()
            .store(CachedToken::with_default_ttl("budget-jwt", None));
        client
    }

    #[tokio::test]
    async fn tc_5_2_3_user_budget_and_429_rate_limit_and_topup_inquiry() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/secure/budget/inquire/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "current_budget": "Your current budget is 888.25 LE"
            })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/secure/topup/inquire/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "count": 1,
                "results": [{
                    "id": 42,
                    "amount": 500,
                    "status": "pending",
                    "from_account_number": "1234567890",
                    "to_account_number": "0987654321"
                }]
            })))
            .mount(&server)
            .await;

        let client = seeded_client(&server.uri());
        let budget = client
            .payouts()
            .inquiries()
            .user_budget()
            .await
            .expect("user_budget should succeed");
        assert_eq!(budget.current_budget, "Your current budget is 888.25 LE");

        let topup = client
            .payouts()
            .inquiries()
            .topup(TopupInquiryParams::default())
            .await
            .expect("topup inquiry should succeed");
        let dbg = format!("{:?}", topup.results[0]);
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("1234567890"));
    }

    #[tokio::test]
    async fn tc_5_2_3_user_budget_429_maps_to_rate_limited() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/secure/budget/inquire/"))
            .respond_with(ResponseTemplate::new(429).set_body_json(serde_json::json!({
                "status_description": "Too many budget requests",
                "status_code": "429"
            })))
            .mount(&server)
            .await;

        let client = seeded_client(&server.uri());
        let err = client
            .payouts()
            .inquiries()
            .user_budget()
            .await
            .expect_err("429 must map to RateLimited");
        assert!(matches!(err, PaymobError::RateLimited { .. }));
    }
}

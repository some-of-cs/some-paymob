#![forbid(unsafe_code)]
//! Paymob Send Payouts & Disbursement service (`US-5.1.0` & `US-5.2.0`).
//!
//! Covers Regime 3 OAuth 2.0 (`auth()`), Instant & Bulk Cashin (`cashin()`),
//! Transaction/Reference/Budget/Topup Inquiries (`inquiries()`), and Topup
//! Requests (`topups()`).

/// Regime 3 OAuth 2.0 token acquisition and refresh (`POST /api/secure/o/token/`).
pub mod auth;
/// Bank card, instant bank, Egypt Post cashin, and Aman cancellation operations.
pub mod bank_cashin;
/// User budget and topup history inquiry operations.
pub mod budget;
/// Bulk disbursement batch submission (`POST /disburse/api/v1/disburse/bulk_transaction/`).
pub mod bulk;
/// Single transaction, bulk transaction, and client reference inquiry operations.
pub mod inquiries;
/// Shared Payouts disbursement domain models, issuers, and input validators.
pub mod models;
/// Payouts balance topup requests (Bank Transfer and Accept Balance).
pub mod topups;
/// Instant mobile wallet cashin disbursements (Vodafone, Etisalat, Orange, Bank Wallet).
pub mod wallet_cashin;

pub use auth::{PayoutsAuthService, PayoutsTokenResponse};
pub use bank_cashin::{
    BankCardCashinParams, CancelAmanParams, EgyptianPostCashinParams, InstantBankCashinParams,
    PAYOUTS_AMAN_CANCEL_PATH,
};
pub use budget::{
    PAYOUTS_BUDGET_INQUIRE_PATH, PAYOUTS_TOPUP_INQUIRE_PATH, TopupInquiryParams,
    TopupInquiryResponse, TopupRecord, UserBudgetResponse,
};
pub use bulk::{
    BulkDisbursementItem, BulkDisbursementParams, BulkDisbursementResponse,
    MAX_BULK_DISBURSEMENT_ITEMS, PAYOUTS_BULK_DISBURSE_PATH,
};
pub use inquiries::{
    MAX_INQUIRY_IDS, PAYOUTS_BULK_INQUIRE_BY_REF_PATH, PAYOUTS_BULK_INQUIRE_PATH,
    PAYOUTS_TX_INQUIRE_PATH, ReferenceInquiryParams, TransactionInquiryParams,
    TransactionInquiryResponse,
};
pub use models::{AmanCashingDetails, BankTransactionType, DisburseIssuer, DisbursementResponse};
pub use topups::{
    AcceptBalanceTopupParams, BankTransferTopupParams, MAX_TOPUP_PROOF_BYTES,
    PAYOUTS_TOPUP_REQUEST_PATH, PayoutsTopupsService,
};
pub use wallet_cashin::{MobileWalletCashinParams, PAYOUTS_DISBURSE_PATH};

use reqwest::header::{AUTHORIZATION, HeaderValue};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::core::auth::accept_jwt::format_bearer_header;
use crate::core::client::PaymobClient;
use crate::core::error::PaymobError;
use crate::core::http::{HttpError, HttpRequest, HttpResponse};

/// Top-level Paymob Send Payouts service handle (`paymob.payouts()`).
#[derive(Debug, Clone, Copy)]
pub struct PayoutsService<'a> {
    client: &'a PaymobClient,
}

impl<'a> PayoutsService<'a> {
    /// Creates a new [`PayoutsService`] bound to `client`.
    #[must_use]
    pub const fn new(client: &'a PaymobClient) -> Self {
        Self { client }
    }

    /// Returns the underlying [`PaymobClient`].
    #[must_use]
    pub const fn client(&self) -> &'a PaymobClient {
        self.client
    }

    /// Returns the Payouts OAuth 2.0 token service (`POST /api/secure/o/token/`).
    #[must_use]
    pub const fn auth(&self) -> auth::PayoutsAuthService<'a> {
        auth::PayoutsAuthService::new(self.client)
    }

    /// Returns the Instant & Bulk Cashin disbursement service.
    #[must_use]
    pub const fn cashin(&self) -> PayoutsCashinService<'a> {
        PayoutsCashinService::new(self.client)
    }

    /// Returns the Payouts transaction, reference, budget, and topup inquiry service.
    #[must_use]
    pub const fn inquiries(&self) -> PayoutsInquiriesService<'a> {
        PayoutsInquiriesService::new(self.client)
    }

    /// Returns the Payouts topup request service (Bank Transfer & Accept Balance).
    #[must_use]
    pub const fn topups(&self) -> topups::PayoutsTopupsService<'a> {
        topups::PayoutsTopupsService::new(self.client)
    }
}

/// Instant & Bulk Cashin disbursement service (`paymob.payouts().cashin()`).
#[derive(Debug, Clone, Copy)]
pub struct PayoutsCashinService<'a> {
    client: &'a PaymobClient,
}

impl<'a> PayoutsCashinService<'a> {
    /// Creates a new [`PayoutsCashinService`] bound to `client`.
    #[must_use]
    pub const fn new(client: &'a PaymobClient) -> Self {
        Self { client }
    }

    /// Returns the underlying [`PaymobClient`].
    #[must_use]
    pub const fn client(&self) -> &'a PaymobClient {
        self.client
    }
}

/// Payouts inquiry service (`paymob.payouts().inquiries()`).
#[derive(Debug, Clone, Copy)]
pub struct PayoutsInquiriesService<'a> {
    client: &'a PaymobClient,
}

impl<'a> PayoutsInquiriesService<'a> {
    /// Creates a new [`PayoutsInquiriesService`] bound to `client`.
    #[must_use]
    pub const fn new(client: &'a PaymobClient) -> Self {
        Self { client }
    }

    /// Returns the underlying [`PaymobClient`].
    #[must_use]
    pub const fn client(&self) -> &'a PaymobClient {
        self.client
    }
}

/// Resolves a Regime 3 `Authorization: Bearer <access_token>` header using the
/// client's Payouts cache or single-flight renewal/password acquisition via [`PayoutsAuthService`].
///
/// Uses [`crate::core::auth::TokenCache::get_or_refresh`] so expired or approaching-expiry
/// tokens are renewed via `grant_type=refresh_token` (or `grant_type=password` fallback)
/// without spawning an unconfigured `reqwest::Client`.
pub(crate) async fn resolve_payouts_bearer_header(
    client: &PaymobClient,
) -> Result<HeaderValue, PaymobError> {
    let cached = client
        .auth()
        .payouts_cache()
        .get_or_refresh(|| auth::acquire_or_refresh_cached_token(client))
        .await?;
    format_bearer_header(&cached.access_token)
        .map_err(|err| PaymobError::AuthenticationError(err.to_string()))
}

#[derive(Serialize)]
struct TaggedDisburseWire<'a, T: Serialize> {
    issuer: &'static str,
    #[serde(flatten)]
    inner: &'a T,
}

async fn execute_payouts_with_retry<F>(
    client: &PaymobClient,
    build_request: F,
) -> Result<HttpResponse, PaymobError>
where
    F: Fn(HeaderValue) -> Result<HttpRequest, PaymobError>,
{
    let cached = client
        .auth()
        .payouts_cache()
        .get_or_refresh(|| auth::acquire_or_refresh_cached_token(client))
        .await?;
    let bearer = format_bearer_header(&cached.access_token)
        .map_err(|err| PaymobError::AuthenticationError(err.to_string()))?;
    let request = build_request(bearer)?;
    let response = execute_payouts_request(client, &request).await?;
    if response.status != reqwest::StatusCode::UNAUTHORIZED {
        return Ok(response);
    }
    client
        .auth()
        .payouts_cache()
        .evict_if_matches(&cached.access_token)
        .await;
    let fresh_bearer = resolve_payouts_bearer_header(client).await?;
    let retry_request = build_request(fresh_bearer)?;
    execute_payouts_request(client, &retry_request).await
}

/// Shared Regime 3 authenticated JSON `POST` transport helper across all Payouts endpoints.
pub(crate) async fn post_payouts_json<P, R>(
    client: &PaymobClient,
    endpoint_path: &str,
    payload: &P,
) -> Result<R, PaymobError>
where
    P: Serialize,
    R: DeserializeOwned,
{
    let url = client.payouts_url(endpoint_path)?;
    let response = execute_payouts_with_retry(client, |bearer| {
        HttpRequest::post(url.as_str())
            .map_err(map_http_error)?
            .with_header(AUTHORIZATION, bearer)
            .with_json(payload)
            .map_err(map_http_error)
    })
    .await?;
    parse_payouts_response(&response)
}

/// Shared Regime 3 authenticated `POST /api/secure/disburse/` helper tagging `issuer`.
pub(crate) async fn post_tagged_disburse<P: Serialize>(
    client: &PaymobClient,
    issuer: models::DisburseIssuer,
    params: &P,
) -> Result<models::DisbursementResponse, PaymobError> {
    let payload = TaggedDisburseWire {
        issuer: issuer.as_str(),
        inner: params,
    };
    post_payouts_json(client, wallet_cashin::PAYOUTS_DISBURSE_PATH, &payload).await
}

/// Shared Regime 3 authenticated `GET` transport helper returning raw [`HttpResponse`].
pub(crate) async fn get_payouts_raw(
    client: &PaymobClient,
    url: &url::Url,
) -> Result<HttpResponse, PaymobError> {
    execute_payouts_with_retry(client, |bearer| {
        Ok(HttpRequest::get(url.as_str())
            .map_err(map_http_error)?
            .with_header(AUTHORIZATION, bearer))
    })
    .await
}

pub(crate) async fn execute_payouts_request(
    client: &PaymobClient,
    request: &HttpRequest,
) -> Result<HttpResponse, PaymobError> {
    client.execute_request(request).await
}

pub(crate) fn map_http_error(err: HttpError) -> PaymobError {
    PaymobError::from(err)
}

pub(crate) fn parse_payouts_response<T: DeserializeOwned>(
    response: &HttpResponse,
) -> Result<T, PaymobError> {
    if !response.status.is_success() {
        return Err(PaymobError::from_http_response(response));
    }
    response.json::<T>().map_err(map_http_error)
}

#[cfg(test)]
pub(crate) mod test_support {
    use crate::core::auth::CachedToken;
    use crate::core::client::PaymobClient;
    use crate::core::config::ClientConfig;
    use crate::core::credentials::PayoutsCredentials;
    use crate::core::region::PaymobRegion;

    pub(crate) fn seeded_payouts_client(base_url: &str, token: &str) -> PaymobClient {
        let cfg = ClientConfig::builder()
            .region(PaymobRegion::Custom {
                accept_base_url: base_url.to_owned(),
                checkout_base_url: base_url.to_owned(),
                payouts_base_url: base_url.to_owned(),
                payouts_staging_base_url: base_url.to_owned(),
            })
            .build()
            .expect("valid test config");
        let client = PaymobClient::new(cfg).expect("valid test client");
        client
            .auth()
            .payouts_cache()
            .store(CachedToken::with_default_ttl(token, None));
        client
    }

    pub(crate) fn credentials_payouts_client(base_url: &str) -> PaymobClient {
        let creds = PayoutsCredentials::new("cid_1", "csec_1", "user_1", "pass_1")
            .expect("valid payouts creds");
        let cfg = ClientConfig::builder()
            .region(PaymobRegion::Custom {
                accept_base_url: base_url.to_owned(),
                checkout_base_url: base_url.to_owned(),
                payouts_base_url: base_url.to_owned(),
                payouts_staging_base_url: base_url.to_owned(),
            })
            .payouts_credentials(creds)
            .build()
            .expect("valid test config");
        PaymobClient::new(cfg).expect("valid test client")
    }
}

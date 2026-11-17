#![forbid(unsafe_code)]
//! Payouts topup requests (`US-5.2.0/unit-4`).
//!
//! Covers `POST /api/secure/topup/request/` for Bank Transfers (enforcing `<= 2.8 MB`
//! proof size guard) and Accept Balance transfers.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use reqwest::header::AUTHORIZATION;
use serde::Serialize;

use crate::core::client::PaymobClient;
use crate::core::error::PaymobError;
use crate::core::http::HttpRequest;
use crate::resources::payouts::budget::TopupRecord;
use crate::resources::payouts::models::{validate_non_empty, validate_positive_amount};
use crate::resources::payouts::{
    execute_payouts_request, parse_payouts_response, resolve_payouts_bearer_header,
};

/// Relative endpoint path for Paymob Send topup requests.
pub const PAYOUTS_TOPUP_REQUEST_PATH: &str = "/api/secure/topup/request/";

/// Maximum allowed size in bytes for bank-transfer proof attachments (`2.8 MB`).
pub const MAX_TOPUP_PROOF_BYTES: usize = 2_936_012;

/// Request parameters for Bank Transfer topup (`POST /api/secure/topup/request/`).
#[derive(Clone, PartialEq, Eq)]
pub struct BankTransferTopupParams {
    /// Topup amount (`u64`, zero floats).
    pub amount: u64,
    /// Currency name (e.g. `"egyptian_pound"`).
    pub currency: String,
    /// Raw proof file bytes (enforced `<= 2_936_012` bytes / 2.8 MB).
    pub to_attach_proof: Vec<u8>,
    /// Proof filename (e.g. `"receipt.pdf"`).
    pub proof_filename: String,
    /// Optional source bank name.
    pub from_bank_name: Option<String>,
    /// Optional bank transfer reference number.
    pub reference_number: Option<String>,
}

impl fmt::Debug for BankTransferTopupParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BankTransferTopupParams")
            .field("amount", &self.amount)
            .field("currency", &self.currency)
            .field("proof_bytes", &self.to_attach_proof.len())
            .field("proof_filename", &self.proof_filename)
            .field("from_bank_name", &self.from_bank_name)
            .field("reference_number", &self.reference_number)
            .finish()
    }
}

/// Request parameters for Accept Balance topup (`POST /api/secure/topup/request/`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AcceptBalanceTopupParams {
    /// Topup amount (`u64`, zero floats).
    pub amount: u64,
    /// Fixed transfer type (`"from_accept_balance"`).
    #[serde(rename = "type")]
    pub transfer_type: &'static str,
    /// Currency string (e.g. `"egyptian_pound"`).
    pub currency: String,
    /// Paymob Payouts username.
    pub username: String,
}

impl AcceptBalanceTopupParams {
    /// Creates a new [`AcceptBalanceTopupParams`] with `transfer_type = "from_accept_balance"`.
    #[must_use]
    pub fn new(
        amount: u64,
        currency: impl Into<String>,
        username: impl Into<String>,
    ) -> Self {
        Self {
            amount,
            transfer_type: "from_accept_balance",
            currency: currency.into(),
            username: username.into(),
        }
    }
}

#[derive(Serialize)]
struct BankTransferWire<'a> {
    amount: u64,
    #[serde(rename = "type")]
    transfer_type: &'static str,
    currency: &'a str,
    to_attach_proof: String,
    proof_filename: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    from_bank_name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reference_number: Option<&'a str>,
}

/// Payouts topup request service (`paymob.payouts().topups()`).
#[derive(Debug, Clone, Copy)]
pub struct PayoutsTopupsService<'a> {
    client: &'a PaymobClient,
}

impl<'a> PayoutsTopupsService<'a> {
    /// Creates a new [`PayoutsTopupsService`] bound to `client`.
    #[must_use]
    pub const fn new(client: &'a PaymobClient) -> Self {
        Self { client }
    }

    /// Returns the underlying [`PaymobClient`].
    #[must_use]
    pub const fn client(&self) -> &'a PaymobClient {
        self.client
    }

    /// Submits a Bank Transfer topup request (`POST /api/secure/topup/request/`).
    ///
    /// Rejects attachments exceeding [`MAX_TOPUP_PROOF_BYTES`] (`2.8 MB`) locally before upload.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `amount == 0`, `to_attach_proof` is empty or
    /// exceeds `2,936,012` bytes, or `currency`/`proof_filename` is empty.
    pub async fn from_bank_transfer(
        &self,
        params: BankTransferTopupParams,
    ) -> Result<TopupRecord, PaymobError> {
        validate_positive_amount(params.amount)?;
        validate_non_empty("currency", &params.currency)?;
        validate_non_empty("proof_filename", &params.proof_filename)?;
        validate_proof_size(&params.to_attach_proof)?;

        let wire = BankTransferWire {
            amount: params.amount,
            transfer_type: "from_bank_transfer",
            currency: params.currency.trim(),
            to_attach_proof: BASE64_STANDARD.encode(&params.to_attach_proof),
            proof_filename: params.proof_filename.trim(),
            from_bank_name: params.from_bank_name.as_deref().map(str::trim),
            reference_number: params.reference_number.as_deref().map(str::trim),
        };
        self.post_topup(&wire).await
    }

    /// Submits an Accept Balance topup request (`POST /api/secure/topup/request/`).
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `amount == 0` or `currency`/`username` is empty.
    pub async fn from_accept_balance(
        &self,
        params: AcceptBalanceTopupParams,
    ) -> Result<TopupRecord, PaymobError> {
        validate_positive_amount(params.amount)?;
        validate_non_empty("currency", &params.currency)?;
        validate_non_empty("username", &params.username)?;
        self.post_topup(&params).await
    }

    async fn post_topup<T: Serialize>(&self, payload: &T) -> Result<TopupRecord, PaymobError> {
        let bearer = resolve_payouts_bearer_header(self.client).await?;
        let url = self.client.payouts_url(PAYOUTS_TOPUP_REQUEST_PATH)?;
        let request = HttpRequest::post(url.as_str())
            .map_err(PaymobError::from)?
            .with_header(AUTHORIZATION, bearer)
            .with_json(payload)
            .map_err(PaymobError::from)?;
        let response = execute_payouts_request(self.client, &request).await?;
        parse_payouts_response(&response)
    }
}

fn validate_proof_size(bytes: &[u8]) -> Result<(), PaymobError> {
    if bytes.is_empty() {
        return Err(PaymobError::ValidationError {
            field: "to_attach_proof",
            reason: String::from("to_attach_proof must not be empty"),
        });
    }
    if bytes.len() > MAX_TOPUP_PROOF_BYTES {
        return Err(PaymobError::ValidationError {
            field: "to_attach_proof",
            reason: format!(
                "to_attach_proof exceeds maximum 2.8 MB ({MAX_TOPUP_PROOF_BYTES} bytes)"
            ),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::core::auth::CachedToken;
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
            .store(CachedToken::with_default_ttl("topup-jwt", None));
        client
    }

    #[tokio::test]
    async fn tc_5_2_4_rejects_oversized_proof_locally_before_network() {
        let server = MockServer::start().await;
        let client = seeded_client(&server.uri());
        let oversized = vec![0u8; MAX_TOPUP_PROOF_BYTES + 1];
        let err = client
            .payouts()
            .topups()
            .from_bank_transfer(BankTransferTopupParams {
                amount: 500,
                currency: String::from("egyptian_pound"),
                to_attach_proof: oversized,
                proof_filename: String::from("proof.pdf"),
                from_bank_name: None,
                reference_number: None,
            })
            .await
            .expect_err("oversized proof must fail locally");
        assert!(matches!(
            err,
            PaymobError::ValidationError {
                field: "to_attach_proof",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn tc_5_2_4_from_accept_balance_succeeds_and_redacts_accounts() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/secure/topup/request/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 99,
                "amount": 500,
                "status": "pending",
                "type": "from_accept_balance",
                "currency": "egyptian_pound",
                "from_account_number": "111122223333",
                "to_account_number": "444455556666"
            })))
            .mount(&server)
            .await;

        let client = seeded_client(&server.uri());
        let record = client
            .payouts()
            .topups()
            .from_accept_balance(AcceptBalanceTopupParams::new(
                500,
                "egyptian_pound",
                "treasury_user",
            ))
            .await
            .expect("from_accept_balance should succeed");
        assert_eq!(record.status.as_deref(), Some("pending"));
        let dbg = format!("{record:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("111122223333"));
    }
}

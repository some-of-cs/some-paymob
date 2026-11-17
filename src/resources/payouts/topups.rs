#![forbid(unsafe_code)]
//! Payouts topup requests (`US-5.2.0/unit-4`).
//!
//! Covers `POST /api/secure/topup/request/` for Bank Transfers (enforcing `<= 2.8 MB`
//! proof size guard and path-traversal-free filenames) and Accept Balance transfers.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use serde::Serialize;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::core::client::PaymobClient;
use crate::core::error::PaymobError;
use crate::resources::payouts::budget::TopupRecord;
use crate::resources::payouts::models::{
    validate_clean_field, validate_optional_clean_field, validate_positive_amount,
};
use crate::resources::payouts::post_payouts_json;

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
    /// Raw proof file bytes (enforced `1..=2_936_012` bytes / 2.8 MB).
    pub to_attach_proof: Vec<u8>,
    /// Proof filename (e.g. `"receipt.pdf"`, free of path separators).
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
///
/// Redacts `username` in [`fmt::Debug`].
///
/// # Memory Hygiene & Field Moves (`ZeroizeOnDrop`)
///
/// Implements [`ZeroizeOnDrop`] (`Drop`) to scrub `username` on drop; borrow (`&params.username`)
/// or clone (`params.username.clone()`) fields rather than moving fields out of an owned value (`E0509`).
#[derive(Clone, PartialEq, Eq, Serialize, Zeroize, ZeroizeOnDrop)]
pub struct AcceptBalanceTopupParams {
    /// Topup amount (`u64`, zero floats).
    #[zeroize(skip)]
    pub amount: u64,
    /// Fixed transfer type (`"from_accept_balance"`).
    #[serde(rename = "type")]
    #[zeroize(skip)]
    pub transfer_type: &'static str,
    /// Currency string (e.g. `"egyptian_pound"`).
    pub currency: String,
    /// Paymob Payouts username (redacted in `Debug`).
    pub username: String,
}

impl fmt::Debug for AcceptBalanceTopupParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AcceptBalanceTopupParams")
            .field("amount", &self.amount)
            .field("transfer_type", &self.transfer_type)
            .field("currency", &self.currency)
            .field("username", &"[REDACTED]")
            .finish()
    }
}

impl AcceptBalanceTopupParams {
    /// Creates a new [`AcceptBalanceTopupParams`] with `transfer_type = "from_accept_balance"`.
    #[must_use]
    pub fn new(amount: u64, currency: impl Into<String>, username: impl Into<String>) -> Self {
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
    /// Rejects attachments exceeding [`MAX_TOPUP_PROOF_BYTES`] (`2.8 MB`) or filenames
    /// containing path separators (`/`, `\`, `..`) locally before upload.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `amount == 0`, `to_attach_proof` is empty or
    /// exceeds `2,936,012` bytes, or `currency`/`proof_filename` is invalid.
    pub async fn from_bank_transfer(
        &self,
        params: BankTransferTopupParams,
    ) -> Result<TopupRecord, PaymobError> {
        validate_positive_amount(params.amount)?;
        let currency = validate_clean_field("currency", &params.currency)?;
        let filename = validate_proof_filename(&params.proof_filename)?;
        let from_bank_name =
            validate_optional_clean_field("from_bank_name", params.from_bank_name.as_deref())?;
        let reference_number =
            validate_optional_clean_field("reference_number", params.reference_number.as_deref())?;
        validate_proof_size(&params.to_attach_proof)?;

        let wire = BankTransferWire {
            amount: params.amount,
            transfer_type: "from_bank_transfer",
            currency,
            to_attach_proof: BASE64_STANDARD.encode(&params.to_attach_proof),
            proof_filename: filename,
            from_bank_name,
            reference_number,
        };
        post_payouts_json(self.client, PAYOUTS_TOPUP_REQUEST_PATH, &wire).await
    }

    /// Submits an Accept Balance topup request (`POST /api/secure/topup/request/`).
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `amount == 0` or `currency`/`username` is invalid.
    pub async fn from_accept_balance(
        &self,
        params: AcceptBalanceTopupParams,
    ) -> Result<TopupRecord, PaymobError> {
        validate_positive_amount(params.amount)?;
        let currency = validate_clean_field("currency", &params.currency)?;
        let username = validate_clean_field("username", &params.username)?;
        let normalized = AcceptBalanceTopupParams::new(params.amount, currency, username);
        post_payouts_json(self.client, PAYOUTS_TOPUP_REQUEST_PATH, &normalized).await
    }
}

fn validate_proof_filename(raw: &str) -> Result<&str, PaymobError> {
    let trimmed = validate_clean_field("proof_filename", raw)?;
    if trimmed.contains('/') || trimmed.contains('\\') || trimmed.contains("..") {
        return Err(PaymobError::ValidationError {
            field: "proof_filename",
            reason: String::from("proof_filename must not contain path separators or '..'"),
        });
    }
    Ok(trimmed)
}

fn validate_proof_size(bytes: &[u8]) -> Result<(), PaymobError> {
    if bytes.is_empty() || bytes.len() > MAX_TOPUP_PROOF_BYTES {
        return Err(PaymobError::ValidationError {
            field: "to_attach_proof",
            reason: format!(
                "to_attach_proof must be 1 to {MAX_TOPUP_PROOF_BYTES} bytes (<= 2.8 MB)"
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
    use crate::resources::payouts::test_support::seeded_payouts_client;

    #[tokio::test]
    async fn tc_5_2_4_rejects_oversized_empty_and_path_traversal_proof_locally() {
        let server = MockServer::start().await;
        let client = seeded_payouts_client(&server.uri(), "topup-jwt");

        for bad_proof in [vec![], vec![0u8; MAX_TOPUP_PROOF_BYTES + 1]] {
            let err = client
                .payouts()
                .topups()
                .from_bank_transfer(BankTransferTopupParams {
                    amount: 500,
                    currency: String::from("egyptian_pound"),
                    to_attach_proof: bad_proof,
                    proof_filename: String::from("proof.pdf"),
                    from_bank_name: None,
                    reference_number: None,
                })
                .await
                .expect_err("invalid proof size must fail locally");
            assert!(matches!(
                err,
                PaymobError::ValidationError {
                    field: "to_attach_proof",
                    ..
                }
            ));
        }

        let bad_name_err = client
            .payouts()
            .topups()
            .from_bank_transfer(BankTransferTopupParams {
                amount: 500,
                currency: String::from("egyptian_pound"),
                to_attach_proof: vec![1, 2, 3],
                proof_filename: String::from("../etc/passwd"),
                from_bank_name: None,
                reference_number: None,
            })
            .await
            .expect_err("traversal proof_filename must fail");
        assert!(matches!(
            bad_name_err,
            PaymobError::ValidationError {
                field: "proof_filename",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn tc_5_2_4_from_accept_balance_succeeds_and_redacts_accounts_and_username() {
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

        let params = AcceptBalanceTopupParams::new(500, "egyptian_pound", "secret_treasury_user");
        assert!(!format!("{params:?}").contains("secret_treasury_user"));

        let client = seeded_payouts_client(&server.uri(), "topup-jwt");
        let record = client
            .payouts()
            .topups()
            .from_accept_balance(params)
            .await
            .expect("from_accept_balance should succeed");
        assert_eq!(record.status.as_deref(), Some("pending"));
        let dbg = format!("{record:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("111122223333"));
    }
}

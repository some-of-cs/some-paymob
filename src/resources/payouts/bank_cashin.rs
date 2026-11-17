#![forbid(unsafe_code)]
//! Payouts bank card, instant bank, Egypt Post cashin & Aman cancellation (`US-5.1.0/unit-4`).

use std::fmt;

use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use zeroize::ZeroizeOnDrop;

use crate::core::error::PaymobError;
use crate::resources::payouts::models::{
    BankTransactionType, DisburseIssuer, DisbursementResponse, serialize_secret_string,
    validate_clean_field, validate_msisdn, validate_optional_clean_field, validate_positive_amount,
};
use crate::resources::payouts::{PayoutsCashinService, post_payouts_json, post_tagged_disburse};

/// Relative endpoint path for Paymob Send Aman transaction cancellation.
pub const PAYOUTS_AMAN_CANCEL_PATH: &str = "/api/secure/transaction/aman/cancel/";

/// Request parameters for Bank Card cashin (`issuer: "bank_card"`).
///
/// Redacts `bank_card_number` and `full_name` (`[REDACTED]`) in [`fmt::Debug`] and
/// zeroizes card credentials on drop.
#[derive(Clone, Serialize, ZeroizeOnDrop)]
pub struct BankCardCashinParams {
    /// Disbursement amount (`u64`).
    pub amount: u64,
    /// Recipient bank card number (12–19 ASCII digits, redacted in `Debug`).
    #[serde(serialize_with = "serialize_secret_string")]
    pub bank_card_number: SecretString,
    /// Bank routing code (e.g. `"CIB"`, `"NBE"`).
    pub bank_code: String,
    /// Bank transaction classification.
    pub bank_transaction_type: BankTransactionType,
    /// Recipient full name (redacted in `Debug`).
    pub full_name: String,
    /// Optional client reference ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_reference_id: Option<String>,
    /// Whether customer bears fees.
    #[zeroize(skip)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customer_bears_fees: Option<bool>,
}

impl fmt::Debug for BankCardCashinParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BankCardCashinParams")
            .field("amount", &self.amount)
            .field("bank_card_number", &"[REDACTED]")
            .field("bank_code", &self.bank_code)
            .field("bank_transaction_type", &self.bank_transaction_type)
            .field("full_name", &"[REDACTED]")
            .field("client_reference_id", &self.client_reference_id)
            .field("customer_bears_fees", &self.customer_bears_fees)
            .finish()
    }
}

/// Request parameters for Instant Bank transfer (`issuer: "instant_bank"`).
#[derive(Clone, Serialize, ZeroizeOnDrop)]
pub struct InstantBankCashinParams {
    /// Disbursement amount (`u64`).
    pub amount: u64,
    /// Bank routing code.
    pub bank_code: String,
    /// Recipient bank account number / IBAN (redacted in `Debug`).
    #[serde(serialize_with = "serialize_secret_string")]
    pub bank_account_number: SecretString,
    /// Recipient full name (redacted in `Debug`).
    pub full_name: String,
    /// Optional client reference ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_reference_id: Option<String>,
    /// Whether customer bears fees.
    #[zeroize(skip)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customer_bears_fees: Option<bool>,
}

impl fmt::Debug for InstantBankCashinParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InstantBankCashinParams")
            .field("amount", &self.amount)
            .field("bank_code", &self.bank_code)
            .field("bank_account_number", &"[REDACTED]")
            .field("full_name", &"[REDACTED]")
            .field("client_reference_id", &self.client_reference_id)
            .field("customer_bears_fees", &self.customer_bears_fees)
            .finish()
    }
}

/// Request parameters for Egyptian Post cash disbursement (`issuer: "egyptian_post"`).
#[derive(Clone, Serialize, ZeroizeOnDrop)]
pub struct EgyptianPostCashinParams {
    /// Disbursement amount (`u64`).
    pub amount: u64,
    /// Recipient mobile number (10–15 digits, redacted in `Debug`).
    pub msisdn: String,
    /// Recipient full name (redacted in `Debug`).
    pub full_name: String,
    /// Recipient 14-digit Egyptian national ID (redacted in `Debug`).
    #[serde(serialize_with = "serialize_secret_string")]
    pub national_id: SecretString,
    /// Optional client reference ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_reference_id: Option<String>,
    /// Whether customer bears fees.
    #[zeroize(skip)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customer_bears_fees: Option<bool>,
}

impl fmt::Debug for EgyptianPostCashinParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EgyptianPostCashinParams")
            .field("amount", &self.amount)
            .field("msisdn", &"[REDACTED]")
            .field("full_name", &"[REDACTED]")
            .field("national_id", &"[REDACTED]")
            .field("client_reference_id", &self.client_reference_id)
            .field("customer_bears_fees", &self.customer_bears_fees)
            .finish()
    }
}

/// Request parameters for cancelling an Aman disbursement (`POST /api/secure/transaction/aman/cancel/`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CancelAmanParams {
    /// Payouts transaction ID to cancel.
    pub transaction_id: String,
}

impl CancelAmanParams {
    /// Creates a new [`CancelAmanParams`].
    #[must_use]
    pub fn new(transaction_id: impl Into<String>) -> Self {
        Self {
            transaction_id: transaction_id.into(),
        }
    }
}

fn validate_pan(raw: &str) -> Result<(), PaymobError> {
    let trimmed = validate_clean_field("bank_card_number", raw)?;
    if !(12..=19).contains(&trimmed.len()) || !trimmed.bytes().all(|b| b.is_ascii_digit()) {
        return Err(PaymobError::ValidationError {
            field: "bank_card_number",
            reason: String::from("bank_card_number must be 12 to 19 ASCII digits"),
        });
    }
    Ok(())
}

fn validate_national_id(raw: &str) -> Result<(), PaymobError> {
    let trimmed = validate_clean_field("national_id", raw)?;
    if trimmed.len() != 14 || !trimmed.bytes().all(|b| b.is_ascii_digit()) {
        return Err(PaymobError::ValidationError {
            field: "national_id",
            reason: String::from("national_id must be exactly 14 ASCII digits"),
        });
    }
    Ok(())
}

impl<'a> PayoutsCashinService<'a> {
    /// Executes a Bank Card cashin disbursement (`issuer: "bank_card"`).
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if card number (12–19 digits), bank code,
    /// full name, client reference ID, or amount is invalid.
    pub async fn bank_card(
        &self,
        params: BankCardCashinParams,
    ) -> Result<DisbursementResponse, PaymobError> {
        validate_positive_amount(params.amount)?;
        validate_pan(params.bank_card_number.expose_secret())?;
        validate_clean_field("bank_code", &params.bank_code)?;
        validate_clean_field("full_name", &params.full_name)?;
        validate_optional_clean_field(
            "client_reference_id",
            params.client_reference_id.as_deref(),
        )?;
        post_tagged_disburse(self.client(), DisburseIssuer::BankCard, &params).await
    }

    /// Executes an Instant Bank transfer disbursement (`issuer: "instant_bank"`).
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if account number, bank code, full name,
    /// client reference ID, or amount is invalid.
    pub async fn bank_instant(
        &self,
        params: InstantBankCashinParams,
    ) -> Result<DisbursementResponse, PaymobError> {
        validate_positive_amount(params.amount)?;
        validate_clean_field(
            "bank_account_number",
            params.bank_account_number.expose_secret(),
        )?;
        validate_clean_field("bank_code", &params.bank_code)?;
        validate_clean_field("full_name", &params.full_name)?;
        validate_optional_clean_field(
            "client_reference_id",
            params.client_reference_id.as_deref(),
        )?;
        post_tagged_disburse(self.client(), DisburseIssuer::InstantBank, &params).await
    }

    /// Executes an Egyptian Post cash disbursement (`issuer: "egyptian_post"`).
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if msisdn, 14-digit national ID, full name,
    /// client reference ID, or amount is invalid.
    pub async fn egyptian_post(
        &self,
        params: EgyptianPostCashinParams,
    ) -> Result<DisbursementResponse, PaymobError> {
        validate_positive_amount(params.amount)?;
        validate_msisdn(&params.msisdn)?;
        validate_national_id(params.national_id.expose_secret())?;
        validate_clean_field("full_name", &params.full_name)?;
        validate_optional_clean_field(
            "client_reference_id",
            params.client_reference_id.as_deref(),
        )?;
        post_tagged_disburse(self.client(), DisburseIssuer::EgyptianPost, &params).await
    }

    /// Cancels an Aman cash disbursement via `POST /api/secure/transaction/aman/cancel/`.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `transaction_id` is empty or contains control chars.
    pub async fn cancel_aman(
        &self,
        params: CancelAmanParams,
    ) -> Result<DisbursementResponse, PaymobError> {
        let tx_id = validate_clean_field("transaction_id", &params.transaction_id)?;
        let normalized = CancelAmanParams::new(tx_id);
        post_payouts_json(self.client(), PAYOUTS_AMAN_CANCEL_PATH, &normalized).await
    }
}

#[cfg(test)]
mod tests {
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::resources::payouts::test_support::seeded_payouts_client;

    #[tokio::test]
    async fn tc_5_1_4_bank_card_and_cancel_aman_and_redaction() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/secure/disburse/"))
            .and(body_partial_json(serde_json::json!({
                "issuer": "bank_card",
                "bank_transaction_type": "salary"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "transaction_id": "tx_bc_1",
                "issuer": "bank_card",
                "amount": 2500,
                "disbursement_status": "successful"
            })))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/api/secure/transaction/aman/cancel/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "transaction_id": "tx_aman_1",
                "disbursement_status": "cancelled"
            })))
            .mount(&server)
            .await;

        let params = BankCardCashinParams {
            amount: 2500,
            bank_card_number: SecretString::from("4111111111111234"),
            bank_code: String::from("CIB"),
            bank_transaction_type: BankTransactionType::Salary,
            full_name: String::from("Maher Mansour"),
            client_reference_id: None,
            customer_bears_fees: Some(false),
        };
        let dbg = format!("{params:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("4111111111111234"));
        assert!(!dbg.contains("Maher Mansour"));

        let client = seeded_payouts_client(&server.uri(), "test-payouts-jwt");
        let bc_resp = client
            .payouts()
            .cashin()
            .bank_card(params)
            .await
            .expect("bank_card should succeed");
        assert_eq!(bc_resp.transaction_id, "tx_bc_1");

        let aman_resp = client
            .payouts()
            .cashin()
            .cancel_aman(CancelAmanParams::new("tx_aman_1"))
            .await
            .expect("cancel_aman should succeed");
        assert_eq!(aman_resp.disbursement_status.as_deref(), Some("cancelled"));
    }

    #[tokio::test]
    async fn tc_5_1_4_rejects_malformed_pan_national_id_and_empty_tx_id() {
        let server = MockServer::start().await;
        let client = seeded_payouts_client(&server.uri(), "test-payouts-jwt");

        let bad_pan = BankCardCashinParams {
            amount: 500,
            bank_card_number: SecretString::from("4111ABCD"),
            bank_code: String::from("CIB"),
            bank_transaction_type: BankTransactionType::Salary,
            full_name: String::from("User"),
            client_reference_id: None,
            customer_bears_fees: None,
        };
        assert!(matches!(
            client.payouts().cashin().bank_card(bad_pan).await,
            Err(PaymobError::ValidationError {
                field: "bank_card_number",
                ..
            })
        ));

        let bad_nid = EgyptianPostCashinParams {
            amount: 500,
            msisdn: String::from("01023456789"),
            full_name: String::from("User"),
            national_id: SecretString::from("12345"),
            client_reference_id: None,
            customer_bears_fees: None,
        };
        assert!(matches!(
            client.payouts().cashin().egyptian_post(bad_nid).await,
            Err(PaymobError::ValidationError {
                field: "national_id",
                ..
            })
        ));

        assert!(matches!(
            client
                .payouts()
                .cashin()
                .cancel_aman(CancelAmanParams::new(" \n "))
                .await,
            Err(PaymobError::ValidationError {
                field: "transaction_id",
                ..
            })
        ));
    }
}

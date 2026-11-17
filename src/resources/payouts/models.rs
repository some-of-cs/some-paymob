#![forbid(unsafe_code)]
//! Payouts disbursement domain models (`US-5.1.0/unit-2`).
//!
//! Defines [`DisburseIssuer`], [`BankTransactionType`], [`AmanCashingDetails`],
//! [`DisbursementResponse`], and static lookup tables (`CC <= 3`) plus PII redaction.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::core::error::PaymobError;

/// Supported Paymob Send disbursement issuers.
///
/// Uses a static lookup table for string conversion (`CC <= 3`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisburseIssuer {
    /// Vodafone Cash mobile wallet (`"vodafone"`).
    Vodafone,
    /// Etisalat Cash mobile wallet (`"etisalat"`).
    Etisalat,
    /// Orange Cash mobile wallet (`"orange"`).
    Orange,
    /// Meeza / Bank mobile wallet (`"bank_wallet"`).
    BankWallet,
    /// Bank card cashin (`"bank_card"`).
    BankCard,
    /// Instant bank account transfer (`"instant_bank"`).
    InstantBank,
    /// Egyptian Post cash disbursement (`"egyptian_post"`).
    EgyptianPost,
}

const KNOWN_ISSUERS: &[(&str, DisburseIssuer)] = &[
    ("vodafone", DisburseIssuer::Vodafone),
    ("etisalat", DisburseIssuer::Etisalat),
    ("orange", DisburseIssuer::Orange),
    ("bank_wallet", DisburseIssuer::BankWallet),
    ("bank_card", DisburseIssuer::BankCard),
    ("instant_bank", DisburseIssuer::InstantBank),
    ("egyptian_post", DisburseIssuer::EgyptianPost),
];

impl DisburseIssuer {
    /// Returns the wire string representation for this issuer.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        KNOWN_ISSUERS
            .iter()
            .find(|(_, variant)| variant == self)
            .map_or("vodafone", |(name, _)| *name)
    }

    /// Parses a wire string into [`DisburseIssuer`] using a static lookup table (`CC <= 3`).
    #[must_use]
    pub fn from_wire(raw: &str) -> Option<Self> {
        let normalized = raw.trim().to_ascii_lowercase();
        KNOWN_ISSUERS
            .iter()
            .find(|(name, _)| *name == normalized)
            .map(|(_, variant)| *variant)
    }
}

/// Bank card / account disbursement transaction classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BankTransactionType {
    /// Payroll / salary disbursement (`"salary"`).
    Salary,
    /// Credit card payment (`"credit_card"`).
    CreditCard,
    /// Prepaid card topup (`"prepaid_card"`).
    PrepaidCard,
    /// Cash transfer (`"cash_transfer"`).
    CashTransfer,
}

const KNOWN_BANK_TX_TYPES: &[(&str, BankTransactionType)] = &[
    ("salary", BankTransactionType::Salary),
    ("credit_card", BankTransactionType::CreditCard),
    ("prepaid_card", BankTransactionType::PrepaidCard),
    ("cash_transfer", BankTransactionType::CashTransfer),
];

impl BankTransactionType {
    /// Returns the wire string representation for this bank transaction type.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        KNOWN_BANK_TX_TYPES
            .iter()
            .find(|(_, variant)| variant == self)
            .map_or("salary", |(name, _)| *name)
    }

    /// Parses a wire string into [`BankTransactionType`] using a static lookup table (`CC <= 3`).
    #[must_use]
    pub fn from_wire(raw: &str) -> Option<Self> {
        let normalized = raw.trim().to_ascii_lowercase();
        KNOWN_BANK_TX_TYPES
            .iter()
            .find(|(name, _)| *name == normalized)
            .map(|(_, variant)| *variant)
    }
}

/// Aman kiosk cashing metadata returned on Aman-enabled disbursements.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AmanCashingDetails {
    /// Aman bill reference code.
    #[serde(default)]
    pub bill_reference: Option<String>,
    /// Whether the Aman cashout has been collected.
    #[serde(default)]
    pub is_paid: Option<bool>,
    /// Aman lifecycle status string.
    #[serde(default)]
    pub aman_status: Option<String>,
}

/// Response returned by `POST /api/secure/disburse/` and `POST /api/secure/transaction/aman/cancel/`.
///
/// Redacts `msisdn` in [`fmt::Debug`] to prevent PII leakage in diagnostic logs.
///
/// # Examples
///
/// ```
/// use some_paymob::resources::payouts::{DisburseIssuer, DisbursementResponse};
///
/// let json = r#"{
///     "transaction_id": "tx_9001",
///     "msisdn": "01023456789",
///     "issuer": "vodafone",
///     "amount": 112,
///     "full_name": "Maher Mansour",
///     "disbursement_status": "successful",
///     "status_code": "200",
///     "status_description": "Disbursed successfully"
/// }"#;
/// let resp: DisbursementResponse = serde_json::from_str(json).expect("valid response");
/// assert_eq!(resp.issuer, Some(DisburseIssuer::Vodafone));
/// assert!(!format!("{resp:?}").contains("01023456789"));
/// ```
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisbursementResponse {
    /// Paymob Payouts transaction identifier.
    pub transaction_id: String,
    /// Recipient mobile number (redacted in `Debug` output).
    #[serde(default)]
    pub msisdn: Option<String>,
    /// Disbursement issuer.
    #[serde(default)]
    pub issuer: Option<DisburseIssuer>,
    /// Disbursed amount in integer minor/API units (`u64`, zero floats).
    #[serde(default)]
    pub amount: Option<u64>,
    /// Recipient full name.
    #[serde(default)]
    pub full_name: Option<String>,
    /// Disbursement status string (e.g. `"successful"`, `"pending"`, `"failed"`).
    #[serde(default)]
    pub disbursement_status: Option<String>,
    /// Gateway status code.
    #[serde(default)]
    pub status_code: Option<String>,
    /// Human-readable status description.
    #[serde(default)]
    pub status_description: Option<String>,
    /// Optional Aman cashing details.
    #[serde(default)]
    pub aman_cashing_details: Option<AmanCashingDetails>,
    /// ISO-8601 creation timestamp.
    #[serde(default)]
    pub created_at: Option<String>,
    /// ISO-8601 last update timestamp.
    #[serde(default)]
    pub updated_at: Option<String>,
}

impl fmt::Debug for DisbursementResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DisbursementResponse")
            .field("transaction_id", &self.transaction_id)
            .field("msisdn", &self.msisdn.as_ref().map(|_| "[REDACTED]"))
            .field("issuer", &self.issuer)
            .field("amount", &self.amount)
            .field("full_name", &self.full_name)
            .field("disbursement_status", &self.disbursement_status)
            .field("status_code", &self.status_code)
            .field("status_description", &self.status_description)
            .field("aman_cashing_details", &self.aman_cashing_details)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

/// Validates that a required string field is non-empty after trimming.
///
/// # Errors
///
/// Returns [`PaymobError::ValidationError`] when `value` is empty or whitespace-only.
pub(crate) fn validate_non_empty<'a>(
    field: &'static str,
    value: &'a str,
) -> Result<&'a str, PaymobError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(PaymobError::ValidationError {
            field,
            reason: format!("{field} must not be empty"),
        });
    }
    Ok(trimmed)
}

/// Validates that a disbursement integer amount is strictly positive (`> 0`).
///
/// # Errors
///
/// Returns [`PaymobError::ValidationError`] when `amount == 0`.
pub(crate) fn validate_positive_amount(amount: u64) -> Result<u64, PaymobError> {
    if amount == 0 {
        return Err(PaymobError::ValidationError {
            field: "amount",
            reason: String::from("amount must be greater than zero"),
        });
    }
    Ok(amount)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tc_5_1_2_issuer_and_bank_tx_type_roundtrip_via_lookup() {
        for (wire, expected) in KNOWN_ISSUERS {
            assert_eq!(DisburseIssuer::from_wire(wire), Some(*expected));
            assert_eq!(expected.as_str(), *wire);
        }
        assert_eq!(DisburseIssuer::from_wire("unknown"), None);

        for (wire, expected) in KNOWN_BANK_TX_TYPES {
            assert_eq!(BankTransactionType::from_wire(wire), Some(*expected));
            assert_eq!(expected.as_str(), *wire);
        }
        assert_eq!(BankTransactionType::from_wire("other"), None);
    }

    #[test]
    fn tc_5_1_2_disbursement_response_redacts_msisdn() {
        let resp = DisbursementResponse {
            transaction_id: String::from("tx_1"),
            msisdn: Some(String::from("01023456789")),
            issuer: Some(DisburseIssuer::Vodafone),
            amount: Some(500),
            full_name: Some(String::from("Test User")),
            disbursement_status: Some(String::from("successful")),
            status_code: Some(String::from("200")),
            status_description: None,
            aman_cashing_details: None,
            created_at: None,
            updated_at: None,
        };
        let dbg = format!("{resp:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("01023456789"));
    }
}

#![forbid(unsafe_code)]
//! Expanded 7-issuer Paymob Send payouts, bulk disbursement, and status inquiry adapter
//! (`US-9.2.0` Unit 2).
//!
//! Complements [`crate::adapter::traits::PayoutProvider`] with full Paymob Send rail coverage:
//! - All 7 issuers (`Vodafone`, `Etisalat`, `Orange`, `BankWallet`, `BankCard`, `InstantBank`,
//!   `EgyptianPost`) via [`ExpandedPayoutDestination`] and [`dispatch_expanded_payout`].
//! - Batch disbursements via [`dispatch_bulk_payout`].
//! - Transaction status inquiries (instant & bulk) via [`inquire_payout_status`].

use crate::adapter::traits::UnifiedPayoutReceipt;
use crate::core::client::PaymobClient;
use crate::core::error::PaymobError;
use crate::core::types::MinorUnitAmount;
use crate::resources::payouts::{
    BankCardCashinParams, BulkDisbursementParams, BulkDisbursementResponse, DisburseIssuer,
    DisbursementResponse, EgyptianPostCashinParams, InstantBankCashinParams,
    MobileWalletCashinParams, TransactionInquiryParams, TransactionInquiryResponse,
};

/// Typed destination covering all 7 Paymob Send disbursement issuers.
///
/// Wraps the underlying Paymob Send parameter structs whose [`std::fmt::Debug`]
/// implementations redact sensitive recipient identifiers (`msisdn`, `bank_card_number`,
/// `bank_account_number`, `national_id`, `full_name`) as `"[REDACTED]"`.
///
/// # Examples
///
/// ```rust
/// use some_paymob::adapter::payout_adapter::ExpandedPayoutDestination;
/// use some_paymob::core::types::MinorUnitAmount;
/// use some_paymob::resources::payouts::{DisburseIssuer, MobileWalletCashinParams};
///
/// let dest = ExpandedPayoutDestination::Vodafone(
///     MobileWalletCashinParams::new("01023456789", 5_000).with_client_reference_id("ref_1"),
/// );
/// assert_eq!(dest.issuer(), DisburseIssuer::Vodafone);
/// assert_eq!(dest.amount(), MinorUnitAmount::new(5_000));
/// let dbg = format!("{dest:?}");
/// assert!(dbg.contains("[REDACTED]"));
/// assert!(!dbg.contains("01023456789"));
/// ```
#[derive(Debug, Clone)]
pub enum ExpandedPayoutDestination {
    /// Vodafone Cash mobile wallet disbursement (`issuer: "vodafone"`).
    Vodafone(MobileWalletCashinParams),
    /// Etisalat Cash mobile wallet disbursement (`issuer: "etisalat"`).
    Etisalat(MobileWalletCashinParams),
    /// Orange Cash mobile wallet disbursement (`issuer: "orange"`).
    Orange(MobileWalletCashinParams),
    /// Meeza / bank mobile wallet disbursement (`issuer: "bank_wallet"`).
    BankWallet(MobileWalletCashinParams),
    /// Bank card cashin disbursement (`issuer: "bank_card"`).
    BankCard(BankCardCashinParams),
    /// Instant bank account transfer (`issuer: "instant_bank"`).
    InstantBank(InstantBankCashinParams),
    /// Egyptian Post cash disbursement (`issuer: "egyptian_post"`).
    EgyptianPost(EgyptianPostCashinParams),
}

impl ExpandedPayoutDestination {
    /// Returns the corresponding Paymob [`DisburseIssuer`] for this destination.
    #[must_use]
    pub const fn issuer(&self) -> DisburseIssuer {
        if let Some(wallet) = self.wallet_issuer() {
            return wallet;
        }
        self.bank_or_post_issuer()
    }

    /// Returns the disbursement amount wrapped in [`MinorUnitAmount`].
    #[must_use]
    pub const fn amount(&self) -> MinorUnitAmount {
        if let Some(amount) = self.wallet_amount() {
            return MinorUnitAmount::new(amount);
        }
        MinorUnitAmount::new(self.bank_or_post_amount())
    }

    const fn wallet_issuer(&self) -> Option<DisburseIssuer> {
        match self {
            Self::Vodafone(_) => Some(DisburseIssuer::Vodafone),
            Self::Etisalat(_) => Some(DisburseIssuer::Etisalat),
            Self::Orange(_) => Some(DisburseIssuer::Orange),
            Self::BankWallet(_) => Some(DisburseIssuer::BankWallet),
            _ => None,
        }
    }

    const fn bank_or_post_issuer(&self) -> DisburseIssuer {
        match self {
            Self::BankCard(_) => DisburseIssuer::BankCard,
            Self::InstantBank(_) => DisburseIssuer::InstantBank,
            _ => DisburseIssuer::EgyptianPost,
        }
    }

    const fn wallet_amount(&self) -> Option<u64> {
        match self {
            Self::Vodafone(p) | Self::Etisalat(p) | Self::Orange(p) | Self::BankWallet(p) => {
                Some(p.amount)
            }
            _ => None,
        }
    }

    const fn bank_or_post_amount(&self) -> u64 {
        match self {
            Self::BankCard(p) => p.amount,
            Self::InstantBank(p) => p.amount,
            Self::EgyptianPost(p) => p.amount,
            _ => 0,
        }
    }
}

/// Dispatches a single Paymob Send payout across any of the 7 supported issuers and
/// returns a normalized [`UnifiedPayoutReceipt`].
///
/// # Errors
///
/// Returns [`PaymobError::ValidationError`] if destination parameters fail local validation,
/// or a transport/API [`PaymobError`] if Paymob rejects the disbursement request.
///
/// # Examples
///
/// ```rust,no_run
/// use some_paymob::adapter::payout_adapter::{
///     ExpandedPayoutDestination, dispatch_expanded_payout,
/// };
/// use some_paymob::core::client::PaymobClient;
/// use some_paymob::core::config::ClientConfig;
/// use some_paymob::core::region::PaymobRegion;
/// use some_paymob::resources::payouts::MobileWalletCashinParams;
///
/// # async fn example() -> Result<(), some_paymob::core::error::PaymobError> {
/// let client = PaymobClient::new(
///     ClientConfig::builder().region(PaymobRegion::Egypt).build()?,
/// )?;
/// let dest = ExpandedPayoutDestination::Vodafone(MobileWalletCashinParams::new(
///     "01023456789",
///     1_500,
/// ));
/// let receipt = dispatch_expanded_payout(&client, dest).await?;
/// println!("disbursed {} via {}", receipt.payout_id, receipt.issuer);
/// # Ok(())
/// # }
/// ```
pub async fn dispatch_expanded_payout(
    client: &PaymobClient,
    dest: ExpandedPayoutDestination,
) -> Result<UnifiedPayoutReceipt, PaymobError> {
    match split_wallet_destination(dest) {
        Ok((issuer, params)) => dispatch_wallet_payout(client, issuer, params).await,
        Err(non_wallet) => dispatch_bank_or_post_payout(client, non_wallet).await,
    }
}

/// Dispatches a Paymob Send bulk disbursement batch
/// (`POST /disburse/api/v1/disburse/bulk_transaction/`).
///
/// # Errors
///
/// Returns [`PaymobError::ValidationError`] if `params.transactions` is empty, exceeds
/// [`crate::resources::payouts::MAX_BULK_DISBURSEMENT_ITEMS`], or contains invalid items,
/// or a transport/API [`PaymobError`] if the request fails.
///
/// # Examples
///
/// ```rust,no_run
/// use some_paymob::adapter::payout_adapter::dispatch_bulk_payout;
/// use some_paymob::core::client::PaymobClient;
/// use some_paymob::core::config::ClientConfig;
/// use some_paymob::core::region::PaymobRegion;
/// use some_paymob::resources::payouts::{
///     BulkDisbursementItem, BulkDisbursementParams, DisburseIssuer,
/// };
///
/// # async fn example() -> Result<(), some_paymob::core::error::PaymobError> {
/// let client = PaymobClient::new(
///     ClientConfig::builder().region(PaymobRegion::Egypt).build()?,
/// )?;
/// let params = BulkDisbursementParams::new(vec![BulkDisbursementItem {
///     issuer: DisburseIssuer::Vodafone,
///     amount: 300,
///     msisdn: Some("01023456789".to_owned()),
///     full_name: None,
///     bank_code: None,
///     client_reference_id: Some("batch_1".to_owned()),
/// }]);
/// let resp = dispatch_bulk_payout(&client, params).await?;
/// println!("bulk results: {}", resp.results.len());
/// # Ok(())
/// # }
/// ```
pub async fn dispatch_bulk_payout(
    client: &PaymobClient,
    params: BulkDisbursementParams,
) -> Result<BulkDisbursementResponse, PaymobError> {
    client.payouts().cashin().bulk(params).await
}

/// Queries the status of one or more instant or bulk Paymob Send payout transactions.
///
/// # Errors
///
/// Returns [`PaymobError::ValidationError`] if `params.transactions_ids` is empty, exceeds
/// [`crate::resources::payouts::MAX_INQUIRY_IDS`], or contains invalid IDs, or a
/// transport/API [`PaymobError`] if the inquiry request fails.
///
/// # Examples
///
/// ```rust,no_run
/// use some_paymob::adapter::payout_adapter::inquire_payout_status;
/// use some_paymob::core::client::PaymobClient;
/// use some_paymob::core::config::ClientConfig;
/// use some_paymob::core::region::PaymobRegion;
/// use some_paymob::resources::payouts::TransactionInquiryParams;
///
/// # async fn example() -> Result<(), some_paymob::core::error::PaymobError> {
/// let client = PaymobClient::new(
///     ClientConfig::builder().region(PaymobRegion::Egypt).build()?,
/// )?;
/// let params = TransactionInquiryParams::new(vec!["tx_vf_1".to_owned()]);
/// let resp = inquire_payout_status(&client, params).await?;
/// println!("matched records: {}", resp.results.len());
/// # Ok(())
/// # }
/// ```
pub async fn inquire_payout_status(
    client: &PaymobClient,
    params: TransactionInquiryParams,
) -> Result<TransactionInquiryResponse, PaymobError> {
    client.payouts().inquiries().transactions(params).await
}

fn split_wallet_destination(
    dest: ExpandedPayoutDestination,
) -> Result<(DisburseIssuer, MobileWalletCashinParams), ExpandedPayoutDestination> {
    match dest {
        ExpandedPayoutDestination::Vodafone(p) => Ok((DisburseIssuer::Vodafone, p)),
        ExpandedPayoutDestination::Etisalat(p) => Ok((DisburseIssuer::Etisalat, p)),
        ExpandedPayoutDestination::Orange(p) => Ok((DisburseIssuer::Orange, p)),
        ExpandedPayoutDestination::BankWallet(p) => Ok((DisburseIssuer::BankWallet, p)),
        other => Err(other),
    }
}

async fn dispatch_wallet_payout(
    client: &PaymobClient,
    issuer: DisburseIssuer,
    params: MobileWalletCashinParams,
) -> Result<UnifiedPayoutReceipt, PaymobError> {
    let fallback_amount = params.amount;
    let cashin = client.payouts().cashin();
    let resp = match issuer {
        DisburseIssuer::Vodafone => cashin.vodafone(params).await?,
        DisburseIssuer::Etisalat => cashin.etisalat(params).await?,
        DisburseIssuer::Orange => cashin.orange(params).await?,
        _ => cashin.bank_wallet(params).await?,
    };
    Ok(to_payout_receipt(resp, issuer, fallback_amount))
}

async fn dispatch_bank_or_post_payout(
    client: &PaymobClient,
    dest: ExpandedPayoutDestination,
) -> Result<UnifiedPayoutReceipt, PaymobError> {
    let cashin = client.payouts().cashin();
    let (issuer, fallback_amount, resp) = match dest {
        ExpandedPayoutDestination::BankCard(params) => {
            let amt = params.amount;
            (
                DisburseIssuer::BankCard,
                amt,
                cashin.bank_card(params).await?,
            )
        }
        ExpandedPayoutDestination::InstantBank(params) => {
            let amt = params.amount;
            (
                DisburseIssuer::InstantBank,
                amt,
                cashin.bank_instant(params).await?,
            )
        }
        ExpandedPayoutDestination::EgyptianPost(params) => {
            let amt = params.amount;
            (
                DisburseIssuer::EgyptianPost,
                amt,
                cashin.egyptian_post(params).await?,
            )
        }
        _ => {
            return Err(PaymobError::ValidationError {
                field: "issuer",
                reason: "unexpected wallet destination in bank/post dispatch".to_owned(),
            });
        }
    };
    Ok(to_payout_receipt(resp, issuer, fallback_amount))
}

fn to_payout_receipt(
    resp: DisbursementResponse,
    fallback_issuer: DisburseIssuer,
    fallback_amount: u64,
) -> UnifiedPayoutReceipt {
    UnifiedPayoutReceipt {
        payout_id: resp.transaction_id,
        amount: MinorUnitAmount::new(resp.amount.unwrap_or(fallback_amount)),
        status: resp
            .disbursement_status
            .unwrap_or_else(|| "submitted".to_owned()),
        issuer: resp.issuer.unwrap_or(fallback_issuer).as_str().to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;
    use wiremock::matchers::{body_partial_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::resources::payouts::test_support::seeded_payouts_client;
    use crate::resources::payouts::{BankTransactionType, BulkDisbursementItem};

    async fn mount_disburse_mock(server: &MockServer, issuer: &str, tx_id: &str, amount: u64) {
        Mock::given(method("POST"))
            .and(path("/api/secure/disburse/"))
            .and(header("authorization", "Bearer adapter-jwt"))
            .and(body_partial_json(serde_json::json!({
                "issuer": issuer,
                "amount": amount
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "transaction_id": tx_id,
                "issuer": issuer,
                "amount": amount,
                "disbursement_status": "successful",
                "status_code": "200"
            })))
            .mount(server)
            .await;
    }

    fn wallet_issuer_test_cases() -> Vec<(&'static str, ExpandedPayoutDestination)> {
        vec![
            (
                "vodafone",
                ExpandedPayoutDestination::Vodafone(MobileWalletCashinParams::new(
                    "01023456789",
                    100,
                )),
            ),
            (
                "etisalat",
                ExpandedPayoutDestination::Etisalat(MobileWalletCashinParams::new(
                    "01123456789",
                    200,
                )),
            ),
            (
                "orange",
                ExpandedPayoutDestination::Orange(MobileWalletCashinParams::new(
                    "01223456789",
                    300,
                )),
            ),
            (
                "bank_wallet",
                ExpandedPayoutDestination::BankWallet(MobileWalletCashinParams::new(
                    "01523456789",
                    400,
                )),
            ),
        ]
    }

    fn bank_and_post_test_cases() -> Vec<(&'static str, ExpandedPayoutDestination)> {
        vec![
            (
                "bank_card",
                ExpandedPayoutDestination::BankCard(BankCardCashinParams {
                    amount: 500,
                    bank_card_number: SecretString::from("4111111111111234"),
                    bank_code: "CIB".to_owned(),
                    bank_transaction_type: BankTransactionType::Salary,
                    full_name: "Test Recipient".to_owned(),
                    client_reference_id: Some("ref_bc".to_owned()),
                    customer_bears_fees: Some(false),
                }),
            ),
            (
                "instant_bank",
                ExpandedPayoutDestination::InstantBank(InstantBankCashinParams {
                    amount: 600,
                    bank_code: "NBE".to_owned(),
                    bank_account_number: SecretString::from("EG380019000500000000263180002"),
                    full_name: "Test Recipient".to_owned(),
                    client_reference_id: Some("ref_ib".to_owned()),
                    customer_bears_fees: None,
                }),
            ),
            (
                "egyptian_post",
                ExpandedPayoutDestination::EgyptianPost(EgyptianPostCashinParams {
                    amount: 700,
                    msisdn: "01098765432".to_owned(),
                    full_name: "Test Recipient".to_owned(),
                    national_id: SecretString::from("29801011234567"),
                    client_reference_id: Some("ref_ep".to_owned()),
                    customer_bears_fees: None,
                }),
            ),
        ]
    }

    fn seven_issuer_test_cases() -> Vec<(&'static str, ExpandedPayoutDestination)> {
        let mut cases = wallet_issuer_test_cases();
        cases.extend(bank_and_post_test_cases());
        cases
    }

    #[tokio::test]
    async fn dispatch_expanded_payout_covers_all_seven_issuers() {
        let server = MockServer::start().await;
        let client = seeded_payouts_client(&server.uri(), "adapter-jwt");

        for (issuer, dest) in seven_issuer_test_cases() {
            let expected_amount = dest.amount();
            let amount = expected_amount.as_u64();
            let tx_id = format!("tx_{issuer}");
            assert_eq!(dest.issuer().as_str(), issuer);
            mount_disburse_mock(&server, issuer, &tx_id, amount).await;
            let receipt = dispatch_expanded_payout(&client, dest)
                .await
                .expect("payout should succeed");
            assert_eq!(receipt.payout_id, tx_id);
            assert_eq!(receipt.issuer, issuer);
            assert_eq!(receipt.amount, expected_amount);
            assert_eq!(receipt.status, "successful");
        }
    }

    #[tokio::test]
    async fn dispatch_bulk_payout_succeeds_and_validates() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/disburse/api/v1/disburse/bulk_transaction"))
            .and(header("authorization", "Bearer adapter-jwt"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "ok",
                "status_code": "200",
                "results": [{
                    "transaction_id": "tx_bulk_1",
                    "issuer": "vodafone",
                    "amount": 350,
                    "disbursement_status": "successful"
                }]
            })))
            .mount(&server)
            .await;
        let client = seeded_payouts_client(&server.uri(), "adapter-jwt");
        let bulk_params = BulkDisbursementParams::new(vec![BulkDisbursementItem {
            issuer: DisburseIssuer::Vodafone,
            amount: 350,
            msisdn: Some("01023456789".to_owned()),
            full_name: Some("Driver One".to_owned()),
            bank_code: None,
            client_reference_id: Some("batch_ref_1".to_owned()),
        }]);
        let bulk_resp = dispatch_bulk_payout(&client, bulk_params)
            .await
            .expect("bulk payout should succeed");
        assert_eq!(bulk_resp.results.len(), 1);
        assert_eq!(bulk_resp.results[0].transaction_id, "tx_bulk_1");
        assert!(matches!(
            dispatch_bulk_payout(&client, BulkDisbursementParams::new(vec![])).await,
            Err(PaymobError::ValidationError {
                field: "transactions",
                ..
            })
        ));
    }

    #[tokio::test]
    async fn inquire_payout_status_succeeds_and_validates() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/secure/transaction/inquire/"))
            .and(header("authorization", "Bearer adapter-jwt"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "results": [{
                    "transaction_id": "tx_bulk_1",
                    "issuer": "vodafone",
                    "amount": 350,
                    "disbursement_status": "successful"
                }],
                "status_code": "200"
            })))
            .mount(&server)
            .await;
        let client = seeded_payouts_client(&server.uri(), "adapter-jwt");
        let inq_resp = inquire_payout_status(
            &client,
            TransactionInquiryParams::new(vec!["tx_bulk_1".to_owned()]),
        )
        .await
        .expect("status inquiry should succeed");
        assert_eq!(inq_resp.results.len(), 1);
        assert_eq!(
            inq_resp.results[0].disbursement_status.as_deref(),
            Some("successful")
        );
        assert!(matches!(
            inquire_payout_status(&client, TransactionInquiryParams::new(vec![])).await,
            Err(PaymobError::ValidationError {
                field: "transactions_ids",
                ..
            })
        ));
    }
}

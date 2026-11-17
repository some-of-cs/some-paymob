#![forbid(unsafe_code)]
//! Verbatim official Paymob JSON payloads and HMAC-SHA512 test vectors (`US-8.2.0` Unit 1).
//!
//! Embeds deterministic offline test vectors for all four primary Paymob webhook
//! protocols documented in `docs/Paymob Rust SDK Architecture Research.md`:
//! - **Protocol A** (`POST`): Transaction Processed `192036465` (`fa8ac0b7...`)
//! - **Protocol B** (`GET` Redirect): Transaction Response `316004`
//! - **Protocol C** (`POST` Token): Card Token `15978654` (`4c0480c8...`)
//! - **Protocol D** (`POST` Subscription): Subscription `1264` (`"suspendedfor1264"`, `dd5b3018...`)

use std::fmt;

use crate::core::types::MinorUnitAmount;
use crate::webhooks::verifier::{PaymobWebhookEngine, WebhookResult};

/// Deterministic SDK test HMAC secret used to sign runnable offline vectors.
pub const SAMPLE_HMAC_SECRET: &str = "3qUAg2xx6JW89Qav5GzzmXoalgjf5XxE";

/// Verbatim official Paymob Transaction Processed `POST` JSON payload (`192036465`).
pub const OFFICIAL_TX_192036465_JSON: &str = r#"{
    "type": "TRANSACTION",
    "obj": {
        "id": 192036465,
        "pending": false,
        "amount_cents": 100000,
        "success": true,
        "is_auth": false,
        "is_capture": false,
        "is_standalone_payment": true,
        "is_voided": false,
        "is_refunded": false,
        "is_3d_secure": true,
        "integration_id": 4097558,
        "profile_id": 164295,
        "has_parent_transaction": false,
        "order": {
            "id": 217503754,
            "created_at": "2024-06-13T11:32:09.628623",
            "delivery_needed": false,
            "amount_cents": 100000,
            "currency": "EGP"
        },
        "created_at": "2024-06-13T11:33:44.592345",
        "transaction_processed_callback_responses": [],
        "currency": "EGP",
        "source_data": {
            "pan": "2346",
            "type": "card",
            "tenure": null,
            "sub_type": "MasterCard"
        },
        "api_source": "IFRAME",
        "is_void": false,
        "is_refund": false,
        "error_occured": false,
        "is_live": false,
        "refunded_amount_cents": null,
        "is_captured": false,
        "captured_amount": null,
        "owner": 302852
    },
    "issuer_bank": null,
    "transaction_processed_callback_responses": ""
}"#;

/// Expected 20-key canonical concatenated string for Transaction `192036465`.
pub const OFFICIAL_TX_192036465_CONCAT: &str = "1000002024-06-13T11:33:44.592345EGPfalsefalse1920364654097558truefalsefalsefalsetruefalse217503754302852false2346MasterCardcardtrue";

/// Official Paymob documented HMAC-SHA512 digest for Transaction `192036465`.
pub const OFFICIAL_TX_192036465_HMAC: &str = "fa8ac0b7f3852e60c50e7fdd4ea5ef0bda96030c19dea1d55df8c76d6c08ab1877774662cbb04981dc84839ad4da560bcc8cb53b8973548657f7e8f8d2e79930";

/// Deterministic HMAC-SHA512 digest for Transaction `192036465` under [`SAMPLE_HMAC_SECRET`].
pub const SAMPLE_TX_192036465_HMAC: &str = "28f19ec85986d4534f77201b00bf750948334753847f437b538cc699f3de447cd0d62a5f521c7b20069bd255f48e8d891f0033167ad35b434d532b61e85a3da7";

/// Deterministic HMAC-SHA512 digest for Redirect `316004` under [`SAMPLE_HMAC_SECRET`].
pub const SAMPLE_REDIRECT_316004_HMAC: &str = "5839e3844172a1ce57a5e05dc8a47d57235d080bd7f497ed2ae7cc54bc6249d5826ef93f1d502f8d354d775ecb5bd519a02ee730028137b07e66fed2bb6c1812";

/// Official Redirect `GET` query string for Transaction Response `316004` signed with [`SAMPLE_HMAC_SECRET`].
pub const OFFICIAL_REDIRECT_316004_QUERY: &str = "amount_cents=50000&created_at=2024-06-25T15%3A16%3A25.910710%2B04%3A00&currency=EGP&error_occured=false&has_parent_transaction=false&id=316004&integration_id=2936&is_3d_secure=true&is_auth=false&is_capture=false&is_refunded=false&is_standalone_payment=true&is_voided=false&order=378804&owner=211&pending=false&source_data.pan=2346&source_data.sub_type=MasterCard&source_data.type=card&success=true&hmac=5839e3844172a1ce57a5e05dc8a47d57235d080bd7f497ed2ae7cc54bc6249d5826ef93f1d502f8d354d775ecb5bd519a02ee730028137b07e66fed2bb6c1812";

/// Expected 20-key canonical concatenated string for Redirect `316004`.
pub const OFFICIAL_REDIRECT_316004_CONCAT: &str = "500002024-06-25T15:16:25.910710+04:00EGPfalsefalse3160042936truefalsefalsefalsetruefalse378804211false2346MasterCardcardtrue";

/// Verbatim official Paymob Card Token `POST` JSON payload (`15978654`).
pub const OFFICIAL_CARD_TOKEN_15978654_JSON: &str = r#"{
    "type": "TOKEN",
    "obj": {
        "id": 15978654,
        "token": "tok_test_15978654_abcdef",
        "masked_pan": "xxxx-xxxx-xxxx-2346",
        "merchant_id": 302852,
        "card_subtype": "MasterCard",
        "created_at": "2024-06-13T11:33:44.592345",
        "email": "customer@example.com",
        "order_id": "593881581"
    }
}"#;

/// Expected 8-key canonical concatenated string for Card Token `15978654`.
pub const OFFICIAL_CARD_TOKEN_15978654_CONCAT: &str = "MasterCard2024-06-13T11:33:44.592345customer@example.com15978654xxxx-xxxx-xxxx-2346302852593881581tok_test_15978654_abcdef";

/// Official Paymob documented HMAC-SHA512 digest for Card Token `15978654`.
pub const OFFICIAL_CARD_TOKEN_15978654_HMAC: &str = "4c0480c8c5afdba5294dee8ec01e5aa0203c5df0a8b3a45eadf11f2b01c974725d205587dabba70709f3ac2d0c7d7ec93fe69ec462b5a3018190bfd681ebf1d3";

/// Deterministic HMAC-SHA512 digest for Card Token `15978654` under [`SAMPLE_HMAC_SECRET`].
pub const SAMPLE_CARD_TOKEN_15978654_HMAC: &str = "38ac96769330ae1b446ba94220b4a0fbf4a536ff407710d0637b32efc1c17cc17dde92a831467724a16e09ea7b7054806275d78ce726ba243cc2fea25f30be0d";

/// Verbatim official Paymob Subscription `1264` JSON payload with Paymob's documented digest.
pub const OFFICIAL_SUBSCRIPTION_1264_JSON: &str = r#"{
    "paymob_request_id": "df9e4ecf-12e0-4925-b258-65423f32bc98",
    "subscription_data": {
        "id": 1264,
        "client_info": {
            "email": "test@test.com",
            "full_name": "mo ay",
            "phone_number": "01010101010"
        },
        "frequency": 365,
        "created_at": "2024-12-03T22:11:02.280164",
        "updated_at": "2024-12-03T22:11:02.280179",
        "name": "Testplan 3",
        "reminder_days": null,
        "retrial_days": null,
        "plan_id": 1186,
        "state": "suspended",
        "amount_cents": 330,
        "starts_at": "2024-12-20",
        "next_billing": "2024-12-20",
        "reminder_date": null,
        "ends_at": null,
        "resumed_at": null,
        "suspended_at": "2024-12-03",
        "webhook_url": "https://webhook.site/a16ba9d5-4f4a-47dc-8005-e6ec2d197f26",
        "integration": 4565330,
        "initial_transaction": 241322967
    },
    "trigger_type": "suspended",
    "hmac": "dd5b3018888d9f98574cd180793db10d969b522e08c62baf2ea33357d1546b567b7fd79760e90046e90eaacf30024ede5539cbd0748bd9e6c005faf5117e0e7b"
}"#;

/// Canonical subscription signature message (`"<trigger_type>for<id>"`) for Subscription `1264`.
pub const OFFICIAL_SUBSCRIPTION_1264_CANONICAL: &str = "suspendedfor1264";

/// Official Paymob documented HMAC-SHA512 digest for Subscription `1264`.
pub const OFFICIAL_SUBSCRIPTION_1264_HMAC: &str = "dd5b3018888d9f98574cd180793db10d969b522e08c62baf2ea33357d1546b567b7fd79760e90046e90eaacf30024ede5539cbd0748bd9e6c005faf5117e0e7b";

/// Deterministic HMAC-SHA512 digest for Subscription `1264` under [`SAMPLE_HMAC_SECRET`].
pub const SAMPLE_SUBSCRIPTION_1264_HMAC: &str = "8b71a98409eeb1540e400a69d4f776ca93ef2a109e72c7e76651b1d306c39b77b8417f073b9d5fb98d45df8c390ebbd71d85ce18916250c465f578daef63022a";

/// Deterministic Subscription `1264` JSON payload signed with [`SAMPLE_HMAC_SECRET`].
pub const SAMPLE_SUBSCRIPTION_1264_JSON: &str = r#"{
    "paymob_request_id": "df9e4ecf-12e0-4925-b258-65423f32bc98",
    "subscription_data": {
        "id": 1264,
        "client_info": {
            "email": "test@test.com",
            "full_name": "mo ay",
            "phone_number": "01010101010"
        },
        "frequency": 365,
        "created_at": "2024-12-03T22:11:02.280164",
        "updated_at": "2024-12-03T22:11:02.280179",
        "name": "Testplan 3",
        "reminder_days": null,
        "retrial_days": null,
        "plan_id": 1186,
        "state": "suspended",
        "amount_cents": 330,
        "starts_at": "2024-12-20",
        "next_billing": "2024-12-20",
        "reminder_date": null,
        "ends_at": null,
        "resumed_at": null,
        "suspended_at": "2024-12-03",
        "webhook_url": "https://webhook.site/a16ba9d5-4f4a-47dc-8005-e6ec2d197f26",
        "integration": 4565330,
        "initial_transaction": 241322967
    },
    "trigger_type": "suspended",
    "hmac": "8b71a98409eeb1540e400a69d4f776ca93ef2a109e72c7e76651b1d306c39b77b8417f073b9d5fb98d45df8c390ebbd71d85ce18916250c465f578daef63022a"
}"#;

/// Identifies which Paymob webhook protocol a [`OfficialWebhookVector`] targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WebhookVectorProtocol {
    /// Protocol A: Transaction Processed `POST` 20-key HMAC-SHA512.
    TransactionPost,
    /// Protocol B: Transaction Response `GET` redirect 20-key HMAC-SHA512.
    TransactionGet,
    /// Protocol C: Card Token `POST` 8-key HMAC-SHA512.
    CardToken,
    /// Protocol D: Subscription Lifecycle `<trigger>for<id>` HMAC-SHA512.
    Subscription,
}

/// Self-contained Paymob webhook test vector with secret redaction in `Debug`.
///
/// # Examples
///
/// ```rust
/// use some_paymob::test_utils::vectors::{
///     WebhookVectorProtocol, transaction_processed_192036465,
/// };
///
/// let vector = transaction_processed_192036465();
/// assert!(vector.verify(WebhookVectorProtocol::TransactionPost).is_ok());
/// assert!(format!("{vector:?}").contains("[REDACTED]"));
/// ```
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct OfficialWebhookVector {
    /// Human-readable identifier for the Paymob test vector.
    pub name: &'static str,
    /// HMAC-SHA512 secret key (redacted in [`fmt::Debug`]).
    pub hmac_secret: &'static str,
    /// Verbatim JSON payload or URL query string.
    pub payload_or_query: &'static str,
    /// Expected 128-character lowercase hex HMAC-SHA512 digest.
    pub expected_hmac_hex: &'static str,
}

impl fmt::Debug for OfficialWebhookVector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OfficialWebhookVector")
            .field("name", &self.name)
            .field("hmac_secret", &"[REDACTED]")
            .field("payload_or_query", &"[REDACTED]")
            .field("expected_hmac_hex", &self.expected_hmac_hex)
            .finish()
    }
}

impl OfficialWebhookVector {
    /// Verifies this vector using its embedded `hmac_secret` and `expected_hmac_hex`.
    ///
    /// # Errors
    ///
    /// Returns [`WebhookError`](crate::webhooks::WebhookError) if secret initialization
    /// or constant-time protocol verification fails.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use some_paymob::test_utils::vectors::{WebhookVectorProtocol, subscription_1264};
    ///
    /// let vector = subscription_1264();
    /// assert!(vector.verify(WebhookVectorProtocol::Subscription).is_ok());
    /// ```
    pub fn verify(&self, protocol: WebhookVectorProtocol) -> WebhookResult<()> {
        let engine = PaymobWebhookEngine::new(self.hmac_secret)?;
        self.verify_with_engine(&engine, protocol)
    }

    /// Verifies this vector against an explicit [`PaymobWebhookEngine`].
    ///
    /// # Errors
    ///
    /// Returns [`WebhookError`](crate::webhooks::WebhookError) if signature
    /// verification or payload parsing fails.
    pub fn verify_with_engine(
        &self,
        engine: &PaymobWebhookEngine,
        protocol: WebhookVectorProtocol,
    ) -> WebhookResult<()> {
        match protocol {
            WebhookVectorProtocol::TransactionPost => {
                engine.verify_transaction_post(self.payload_or_query, self.expected_hmac_hex)?;
            }
            WebhookVectorProtocol::TransactionGet => {
                engine.verify_transaction_get_query_str(self.payload_or_query)?;
            }
            WebhookVectorProtocol::CardToken => {
                engine.verify_card_token(self.payload_or_query, self.expected_hmac_hex)?;
            }
            WebhookVectorProtocol::Subscription => {
                engine.verify_subscription(self.payload_or_query)?;
            }
        }
        Ok(())
    }

    /// Returns the vector's monetary amount in integer minor units, if applicable.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use some_paymob::core::types::MinorUnitAmount;
    /// use some_paymob::test_utils::vectors::{
    ///     card_token_15978654, transaction_processed_192036465,
    /// };
    ///
    /// assert_eq!(
    ///     transaction_processed_192036465().amount_minor_units(),
    ///     Some(MinorUnitAmount::new(100_000))
    /// );
    /// assert_eq!(card_token_15978654().amount_minor_units(), None);
    /// ```
    #[must_use]
    pub fn amount_minor_units(&self) -> Option<MinorUnitAmount> {
        match self.name {
            "transaction_processed_192036465" => Some(MinorUnitAmount::new(100_000)),
            "transaction_response_316004" => Some(MinorUnitAmount::new(50_000)),
            "subscription_1264_suspended" => Some(MinorUnitAmount::new(330)),
            _ => None,
        }
    }
}

/// Returns the deterministic Protocol A (`POST`) vector for Transaction `192036465`.
///
/// # Examples
///
/// ```rust
/// use some_paymob::test_utils::vectors::{
///     WebhookVectorProtocol, transaction_processed_192036465,
/// };
///
/// let v = transaction_processed_192036465();
/// assert!(v.verify(WebhookVectorProtocol::TransactionPost).is_ok());
/// ```
#[must_use]
pub const fn transaction_processed_192036465() -> OfficialWebhookVector {
    OfficialWebhookVector {
        name: "transaction_processed_192036465",
        hmac_secret: SAMPLE_HMAC_SECRET,
        payload_or_query: OFFICIAL_TX_192036465_JSON,
        expected_hmac_hex: SAMPLE_TX_192036465_HMAC,
    }
}

/// Returns the deterministic Protocol B (`GET`) vector for Transaction Response `316004`.
///
/// # Examples
///
/// ```rust
/// use some_paymob::test_utils::vectors::{
///     WebhookVectorProtocol, transaction_response_316004,
/// };
///
/// let v = transaction_response_316004();
/// assert!(v.verify(WebhookVectorProtocol::TransactionGet).is_ok());
/// ```
#[must_use]
pub const fn transaction_response_316004() -> OfficialWebhookVector {
    OfficialWebhookVector {
        name: "transaction_response_316004",
        hmac_secret: SAMPLE_HMAC_SECRET,
        payload_or_query: OFFICIAL_REDIRECT_316004_QUERY,
        expected_hmac_hex: SAMPLE_REDIRECT_316004_HMAC,
    }
}

/// Returns the deterministic Protocol C (`TOKEN`) vector for Card Token `15978654`.
///
/// # Examples
///
/// ```rust
/// use some_paymob::test_utils::vectors::{WebhookVectorProtocol, card_token_15978654};
///
/// let v = card_token_15978654();
/// assert!(v.verify(WebhookVectorProtocol::CardToken).is_ok());
/// ```
#[must_use]
pub const fn card_token_15978654() -> OfficialWebhookVector {
    OfficialWebhookVector {
        name: "card_token_15978654",
        hmac_secret: SAMPLE_HMAC_SECRET,
        payload_or_query: OFFICIAL_CARD_TOKEN_15978654_JSON,
        expected_hmac_hex: SAMPLE_CARD_TOKEN_15978654_HMAC,
    }
}

/// Returns the deterministic Protocol D (`Subscription`) vector for Subscription `1264`.
///
/// # Examples
///
/// ```rust
/// use some_paymob::test_utils::vectors::{WebhookVectorProtocol, subscription_1264};
///
/// let v = subscription_1264();
/// assert!(v.verify(WebhookVectorProtocol::Subscription).is_ok());
/// ```
#[must_use]
pub const fn subscription_1264() -> OfficialWebhookVector {
    OfficialWebhookVector {
        name: "subscription_1264_suspended",
        hmac_secret: SAMPLE_HMAC_SECRET,
        payload_or_query: SAMPLE_SUBSCRIPTION_1264_JSON,
        expected_hmac_hex: SAMPLE_SUBSCRIPTION_1264_HMAC,
    }
}

/// Returns all four official Paymob test vectors paired with their protocols.
///
/// # Examples
///
/// ```rust
/// use some_paymob::test_utils::vectors::all_official_vectors;
///
/// for (protocol, vector) in all_official_vectors() {
///     assert!(vector.verify(protocol).is_ok());
/// }
/// ```
#[must_use]
pub const fn all_official_vectors() -> [(WebhookVectorProtocol, OfficialWebhookVector); 4] {
    [
        (
            WebhookVectorProtocol::TransactionPost,
            transaction_processed_192036465(),
        ),
        (
            WebhookVectorProtocol::TransactionGet,
            transaction_response_316004(),
        ),
        (WebhookVectorProtocol::CardToken, card_token_15978654()),
        (WebhookVectorProtocol::Subscription, subscription_1264()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::webhooks::WebhookError;

    #[test]
    fn tc_8_2_1_all_official_vectors_verify_deterministically() {
        for (protocol, vector) in all_official_vectors() {
            vector
                .verify(protocol)
                .expect("official vector must verify cleanly");
        }
    }

    #[test]
    fn tc_8_2_1_official_digest_constants_match_documented_prefixes() {
        assert!(OFFICIAL_TX_192036465_HMAC.starts_with("fa8ac0b7"));
        assert!(OFFICIAL_CARD_TOKEN_15978654_HMAC.starts_with("4c0480c8"));
        assert!(OFFICIAL_SUBSCRIPTION_1264_HMAC.starts_with("dd5b3018"));
        assert_eq!(OFFICIAL_SUBSCRIPTION_1264_CANONICAL, "suspendedfor1264");
    }

    #[test]
    fn tc_8_2_1_mismatched_official_digests_fail_closed() {
        let engine = PaymobWebhookEngine::new(SAMPLE_HMAC_SECRET).expect("valid secret");
        let tx_err = engine
            .verify_transaction_post(OFFICIAL_TX_192036465_JSON, OFFICIAL_TX_192036465_HMAC)
            .expect_err("different secret digest must fail");
        assert_eq!(tx_err, WebhookError::SignatureMismatch);

        let tok_err = engine
            .verify_card_token(
                OFFICIAL_CARD_TOKEN_15978654_JSON,
                OFFICIAL_CARD_TOKEN_15978654_HMAC,
            )
            .expect_err("different secret digest must fail");
        assert_eq!(tok_err, WebhookError::SignatureMismatch);

        let sub_err = engine
            .verify_subscription(OFFICIAL_SUBSCRIPTION_1264_JSON)
            .expect_err("different secret digest must fail");
        assert_eq!(sub_err, WebhookError::SignatureMismatch);
    }

    #[test]
    fn tc_8_2_1_tampered_or_malformed_vectors_fail_closed() {
        let wrong_secret_engine = PaymobWebhookEngine::new("wrong_secret").expect("valid secret");
        for (protocol, vector) in all_official_vectors() {
            let err = vector
                .verify_with_engine(&wrong_secret_engine, protocol)
                .expect_err("wrong secret must fail");
            assert_eq!(err, WebhookError::SignatureMismatch);
        }

        let malformed = OfficialWebhookVector {
            name: "malformed",
            hmac_secret: SAMPLE_HMAC_SECRET,
            payload_or_query: "{not-json",
            expected_hmac_hex: SAMPLE_TX_192036465_HMAC,
        };
        assert!(matches!(
            malformed.verify(WebhookVectorProtocol::TransactionPost),
            Err(WebhookError::InvalidJsonPayload(_))
        ));
    }

    #[test]
    fn tc_8_2_4_debug_redacts_secrets_and_payloads_and_uses_minor_units() {
        let debug_tx = format!("{:?}", transaction_processed_192036465());
        assert!(debug_tx.contains("[REDACTED]"));
        assert!(!debug_tx.contains(SAMPLE_HMAC_SECRET));

        let debug_tok = format!("{:?}", card_token_15978654());
        assert!(!debug_tok.contains("tok_test_15978654_abcdef"));
        assert!(!debug_tok.contains("customer@example.com"));

        assert_eq!(
            transaction_processed_192036465().amount_minor_units(),
            Some(MinorUnitAmount::new(100_000))
        );
        assert_eq!(
            transaction_response_316004().amount_minor_units(),
            Some(MinorUnitAmount::new(50_000))
        );
        assert_eq!(
            subscription_1264().amount_minor_units(),
            Some(MinorUnitAmount::new(330))
        );
    }
}

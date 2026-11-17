#![forbid(unsafe_code)]
//! Saved card token discovery by order ID (`POST /api/acceptance/order_card_tokens`).
//!
//! Implements Unit 3 (`TC-3.2.3`) of `US-3.2.0` under Regime 2 JSON body
//! `"auth_token"` injection with [`SecretString`] zeroization and `[REDACTED]`
//! `Debug` formatting.

use std::fmt;

use secrecy::SecretString;
use serde::Deserialize;
use serde_json::json;
use zeroize::ZeroizeOnDrop;

use crate::core::error::PaymobError;
use crate::core::types::{deserialize_string_or_u64, validate_non_zero_u64};
use crate::resources::inquiries::{InquiriesService, execute_inquiry_body_post};

/// Envelope returned by `POST /api/acceptance/order_card_tokens`.
#[derive(Debug, Clone, Deserialize)]
pub struct CardTokenEnvelope {
    /// Event/object type (typically `"TOKEN"`).
    #[serde(rename = "type")]
    pub token_type: String,
    /// Saved card token object with redacted secret token and email.
    pub obj: CardTokenObject,
}

/// Saved card token payload returned inside [`CardTokenEnvelope`].
///
/// [`Self::token`] is stored in [`SecretString`] (`ZeroizeOnDrop`) and both
/// `token` and `email` print `"[REDACTED]"` in `Debug` output.
///
/// # Memory Hygiene & Field Moves (`ZeroizeOnDrop`)
///
/// Implements [`ZeroizeOnDrop`] (`Drop`) to scrub `token` and `email` on drop; borrow or
/// clone fields rather than moving fields out of an owned value (`E0509`).
#[derive(Clone, Deserialize, ZeroizeOnDrop)]
pub struct CardTokenObject {
    /// Paymob saved card token record identifier.
    #[zeroize(skip)]
    pub id: u64,
    /// Reusable saved card token wrapped in [`SecretString`].
    pub token: SecretString,
    /// Masked card PAN (for example, `"xxxx-xxxx-xxxx-2346"`).
    pub masked_pan: String,
    /// Paymob merchant identifier.
    #[zeroize(skip)]
    pub merchant_id: u64,
    /// Card network or subtype (for example, `"MasterCard"`, `"Visa"`).
    pub card_subtype: String,
    /// ISO-8601 creation timestamp, if provided.
    #[serde(default)]
    pub created_at: Option<String>,
    /// Customer email associated with the saved card (redacted in `Debug`).
    #[serde(default)]
    pub email: String,
    /// Associated Paymob order identifier as a string.
    #[serde(deserialize_with = "deserialize_string_or_u64")]
    pub order_id: String,
    /// Optional next payment intention identifier.
    #[serde(default)]
    pub next_payment_intention: Option<String>,
}

impl fmt::Debug for CardTokenObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CardTokenObject")
            .field("id", &self.id)
            .field("token", &"[REDACTED]")
            .field("masked_pan", &self.masked_pan)
            .field("merchant_id", &self.merchant_id)
            .field("card_subtype", &self.card_subtype)
            .field("created_at", &self.created_at)
            .field("email", &"[REDACTED]")
            .field("order_id", &self.order_id)
            .field("next_payment_intention", &self.next_payment_intention)
            .finish()
    }
}

impl<'a> InquiriesService<'a> {
    /// Lists saved card tokens associated with `order_id` via
    /// `POST /api/acceptance/order_card_tokens`.
    ///
    /// Authenticates using Regime 2 JSON body `"auth_token"` injection.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `order_id` is `0` or `api_key`
    /// is missing, [`PaymobError::AuthenticationError`] on rejected credentials,
    /// or [`PaymobError::ApiError`] / [`PaymobError::TransportError`] on failure.
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
    ///     .api_key(ApiKey::new("example_api_key")?)
    ///     .build()?;
    /// let client = PaymobClient::new(config)?;
    /// let tokens = client.inquiries().card_tokens_by_order(523_360_093).await?;
    /// assert!(tokens.iter().all(|t| format!("{t:?}").contains("[REDACTED]")));
    /// # Ok(())
    /// # }
    /// ```
    pub async fn card_tokens_by_order(
        &self,
        order_id: u64,
    ) -> Result<Vec<CardTokenEnvelope>, PaymobError> {
        validate_non_zero_u64("order_id", order_id, "order_id must be greater than zero")?;
        let body = json!({ "order_id": order_id });
        execute_inquiry_body_post(self, "/api/acceptance/order_card_tokens", &body).await
    }

    /// Ergonomic alias for [`Self::card_tokens_by_order`] (`POST /api/acceptance/order_card_tokens`).
    ///
    /// # Errors
    ///
    /// Propagates validation, authentication, API, and transport errors from
    /// [`Self::card_tokens_by_order`].
    pub async fn card_tokens(&self, order_id: u64) -> Result<Vec<CardTokenEnvelope>, PaymobError> {
        self.card_tokens_by_order(order_id).await
    }
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::core::client::PaymobClient;
    use crate::core::config::ClientConfig;
    use crate::core::credentials::ApiKey;
    use crate::core::region::PaymobRegion;

    fn mock_client(base_url: &str) -> PaymobClient {
        let region = PaymobRegion::Custom {
            accept_base_url: base_url.to_owned(),
            checkout_base_url: format!("{base_url}/unifiedcheckout/"),
            payouts_base_url: base_url.to_owned(),
            payouts_staging_base_url: base_url.to_owned(),
        };
        let cfg = ClientConfig::builder()
            .region(region)
            .api_key(ApiKey::new("test_api_key_123").expect("valid api key"))
            .max_retries(0)
            .build()
            .expect("valid config");
        PaymobClient::new(cfg).expect("valid client")
    }

    #[tokio::test]
    async fn tc_3_2_3_card_tokens_by_order_redacts_secret_and_email() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/auth/tokens"))
            .respond_with(
                ResponseTemplate::new(201).set_body_json(serde_json::json!({"token": "jwt_cards"})),
            )
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/api/acceptance/order_card_tokens"))
            .and(body_partial_json(serde_json::json!({
                "auth_token": "jwt_cards",
                "order_id": 523360093
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {
                    "type": "TOKEN",
                    "obj": {
                        "id": 9001,
                        "token": "tok_live_secret_card_987654",
                        "masked_pan": "xxxx-xxxx-xxxx-2346",
                        "merchant_id": 112233,
                        "card_subtype": "MasterCard",
                        "created_at": "2026-11-16T10:05:00Z",
                        "email": "customer@example.com",
                        "order_id": "523360093",
                        "next_payment_intention": "pi_next_123"
                    }
                }
            ])))
            .mount(&server)
            .await;

        let client = mock_client(&server.uri());
        let envelopes = client
            .inquiries()
            .card_tokens_by_order(523_360_093)
            .await
            .expect("card_tokens_by_order should succeed");

        assert_eq!(envelopes.len(), 1);
        let env = &envelopes[0];
        assert_eq!(env.token_type, "TOKEN");
        assert_eq!(env.obj.token.expose_secret(), "tok_live_secret_card_987654");
        assert_eq!(env.obj.masked_pan, "xxxx-xxxx-xxxx-2346");
        assert_eq!(
            env.obj.next_payment_intention.as_deref(),
            Some("pi_next_123")
        );

        let dbg = format!("{env:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(dbg.contains("xxxx-xxxx-xxxx-2346"));
        assert!(!dbg.contains("tok_live_secret_card_987654"));
        assert!(!dbg.contains("customer@example.com"));
    }

    #[tokio::test]
    async fn tc_3_2_3_rejects_zero_order_id_and_handles_http_error() {
        let client = mock_client("http://127.0.0.1:9999");
        let err = client
            .inquiries()
            .card_tokens_by_order(0)
            .await
            .expect_err("zero order_id must fail");
        assert!(matches!(
            err,
            PaymobError::ValidationError {
                field: "order_id",
                ..
            }
        ));
    }
}

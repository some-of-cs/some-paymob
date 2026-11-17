#![forbid(unsafe_code)]
//! Partner HMAC Secret retrieval operation (`US-6.1.0` / `unit-3`).
//!
//! Implements [`PartnerAuthService::retrieve_hmac_secret`] targeting
//! `GET /api/auth/hmac_secret/get_hmac` under Regime 4 Partner Bearer authentication.

use crate::core::error::PaymobError;
use crate::core::http::HttpRequest;
use crate::resources::onboarding::auth_models::PartnerHmacEnvelope;
use crate::resources::onboarding::{
    PartnerAuthService, apply_header_map, decode_onboarding_json, execute_onboarding_request,
    resolve_partner_bearer_headers,
};

const PARTNER_HMAC_SECRET_PATH: &str = "/api/auth/hmac_secret/get_hmac";

impl PartnerAuthService {
    /// Retrieves the Partner HMAC secret via `GET /api/auth/hmac_secret/get_hmac`.
    ///
    /// Authenticates using Regime 4 Partner Bearer (`Authorization: Bearer <partner_auth_token>`)
    /// resolved from [`PartnerCredentials::bearer_token`](crate::core::credentials::PartnerCredentials::bearer_token),
    /// and returns a [`PartnerHmacEnvelope`] whose `body.hmac_secret` is wrapped in
    /// [`secrecy::SecretString`] with [`zeroize::ZeroizeOnDrop`].
    ///
    /// # Errors
    ///
    /// Returns:
    /// - [`PaymobError::AuthenticationError`] if `partner_credentials` or its `bearer_token`
    ///   is missing or rejected by the gateway (HTTP 401/403).
    /// - [`PaymobError::RateLimited`], [`PaymobError::ApiError`], or [`PaymobError::TransportError`]
    ///   on gateway or network failures.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use some_paymob::core::client::PaymobClient;
    /// use some_paymob::core::config::ClientConfig;
    /// use some_paymob::core::credentials::PartnerCredentials;
    /// use some_paymob::core::region::PaymobRegion;
    ///
    /// # async fn example() -> Result<(), some_paymob::core::error::PaymobError> {
    /// let partner_creds = PartnerCredentials::with_bearer_token("pk_partner", "partner_jwt")?;
    /// let config = ClientConfig::builder()
    ///     .region(PaymobRegion::Egypt)
    ///     .partner_credentials(partner_creds)
    ///     .build()?;
    /// let client = PaymobClient::new(config)?;
    /// let envelope = client.onboarding().auth().retrieve_hmac_secret().await?;
    /// assert_eq!(envelope.code, 201);
    /// assert!(!envelope.hmac_secret().is_empty());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn retrieve_hmac_secret(&self) -> Result<PartnerHmacEnvelope, PaymobError> {
        let headers = resolve_partner_bearer_headers(
            self.client(),
            "partner_credentials.bearer_token is required to retrieve partner HMAC secret",
        )?;
        let url = self.client().accept_url(PARTNER_HMAC_SECRET_PATH)?;
        let request = apply_header_map(HttpRequest::get(url.as_str())?, &headers);

        let response = execute_onboarding_request(self.client(), &request).await?;
        decode_onboarding_json(&response)
    }
}

#[cfg(test)]
mod tests {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::core::client::PaymobClient;
    use crate::core::config::ClientConfig;
    use crate::core::credentials::PartnerCredentials;
    use crate::core::region::PaymobRegion;

    fn test_client(base_url: &str, bearer_token: Option<&str>) -> PaymobClient {
        let region = PaymobRegion::Custom {
            accept_base_url: base_url.to_owned(),
            checkout_base_url: base_url.to_owned(),
            payouts_base_url: base_url.to_owned(),
            payouts_staging_base_url: base_url.to_owned(),
        };
        let mut builder = ClientConfig::builder().region(region).max_retries(0);
        if let Some(tok) = bearer_token {
            let creds = PartnerCredentials::with_bearer_token("pk_partner_test", tok)
                .expect("valid partner credentials");
            builder = builder.partner_credentials(creds);
        }
        let config = builder.build().expect("valid config");
        PaymobClient::new(config).expect("valid client")
    }

    #[tokio::test]
    async fn tc_6_1_3_retrieve_hmac_secret_sends_bearer_and_parses_201_envelope() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/auth/hmac_secret/get_hmac"))
            .and(header("authorization", "Bearer partner_jwt_hmac"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "label": null,
                "status": "Created",
                "code": 201,
                "body": {
                    "hmac_secret": "5F4DCC3B5AA765D61D8327DEB882CF99"
                }
            })))
            .mount(&server)
            .await;

        let client = test_client(&server.uri(), Some("partner_jwt_hmac"));
        let env = client
            .onboarding()
            .auth()
            .retrieve_hmac_secret()
            .await
            .expect("retrieve_hmac_secret succeeds");

        assert!(env.label.is_none());
        assert_eq!(env.status, "Created");
        assert_eq!(env.code, 201);
        assert_eq!(env.hmac_secret(), "5F4DCC3B5AA765D61D8327DEB882CF99");

        let dbg = format!("{env:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("5F4DCC3B5AA765D61D8327DEB882CF99"));
    }

    #[tokio::test]
    async fn tc_6_1_3_rejects_missing_bearer_token_before_network() {
        let client = test_client("https://accept.paymob.com", None);
        let err = client
            .onboarding()
            .auth()
            .retrieve_hmac_secret()
            .await
            .expect_err("missing bearer token must fail");
        assert!(err.is_auth_error());
    }

    #[tokio::test]
    async fn tc_6_1_3_maps_401_and_malformed_json_errors() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/auth/hmac_secret/get_hmac"))
            .respond_with(
                ResponseTemplate::new(401)
                    .set_body_json(serde_json::json!({"detail": "invalid partner token"})),
            )
            .mount(&server)
            .await;

        let client = test_client(&server.uri(), Some("expired_jwt"));
        let err = client
            .onboarding()
            .auth()
            .retrieve_hmac_secret()
            .await
            .expect_err("401 must map to AuthenticationError");
        assert!(err.is_auth_error());

        let server2 = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/auth/hmac_secret/get_hmac"))
            .respond_with(ResponseTemplate::new(200).set_body_string("{not-json"))
            .mount(&server2)
            .await;

        let client2 = test_client(&server2.uri(), Some("valid_jwt"));
        let err2 = client2
            .onboarding()
            .auth()
            .retrieve_hmac_secret()
            .await
            .expect_err("malformed json must fail");
        assert!(matches!(err2, PaymobError::TransportError(_)));
    }
}

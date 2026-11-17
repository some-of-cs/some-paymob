#![forbid(unsafe_code)]
//! Partner Login & API Key provisioning operations (`US-6.1.0` / `unit-2`).
//!
//! Implements [`PartnerAuthService::login`] and [`PartnerAuthService::create_api_key`]
//! under Regime 4 Partner Delegated Authentication (`crate::core::auth::partner`).

use crate::core::error::PaymobError;
use crate::core::http::HttpRequest;
use crate::resources::onboarding::auth_models::{
    CreatePartnerApiKeyParams, PartnerApiKeyResponse, PartnerAuthTokenResponse,
    PartnerLoginCredentials,
};
use crate::resources::onboarding::{
    PartnerAuthService, apply_header_map, decode_onboarding_json, execute_onboarding_request,
    resolve_partner_bearer_headers,
};

const PARTNER_LOGIN_PATH: &str = "/api/auth/tokens";
const PARTNER_API_KEY_PATH: &str = "/api/auth/api_keys";

impl PartnerAuthService {
    /// Authenticates a Paymob Partner using username and password credentials.
    ///
    /// Sends `POST /api/auth/tokens` with [`PartnerLoginCredentials`] and returns
    /// a [`PartnerAuthTokenResponse`] wrapping the Partner Bearer token in a
    /// [`secrecy::SecretString`].
    ///
    /// # Errors
    ///
    /// Returns:
    /// - [`PaymobError::ValidationError`] if `creds` contains an empty username or password.
    /// - [`PaymobError::AuthenticationError`] if the gateway rejects the credentials (HTTP 401/403).
    /// - [`PaymobError::RateLimited`], [`PaymobError::ApiError`], or [`PaymobError::TransportError`]
    ///   on gateway or network failures.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use some_paymob::core::client::PaymobClient;
    /// use some_paymob::core::config::ClientConfig;
    /// use some_paymob::core::region::PaymobRegion;
    /// use some_paymob::resources::onboarding::auth_models::PartnerLoginCredentials;
    ///
    /// # async fn example() -> Result<(), some_paymob::core::error::PaymobError> {
    /// let config = ClientConfig::builder()
    ///     .region(PaymobRegion::Egypt)
    ///     .build()?;
    /// let client = PaymobClient::new(config)?;
    /// let creds = PartnerLoginCredentials::try_new("partner@example.com", "secret-pass")?;
    /// let resp = client.onboarding().auth().login(creds).await?;
    /// assert!(!resp.token().is_empty());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn login(
        &self,
        creds: PartnerLoginCredentials,
    ) -> Result<PartnerAuthTokenResponse, PaymobError> {
        creds.validate()?;
        let url = self.client().accept_url(PARTNER_LOGIN_PATH)?;
        let request = HttpRequest::post(url.as_str())?
            .with_json(&creds)
            .map_err(|err| PaymobError::ValidationError {
                field: "creds",
                reason: err.to_string(),
            })?;

        let response = execute_onboarding_request(self.client(), &request).await?;
        decode_onboarding_json(&response)
    }

    /// Provisions a new Partner API Key under Regime 4 Partner Bearer authentication.
    ///
    /// Sends `POST /api/auth/api_keys` with `Authorization: Bearer <partner_auth_token>`
    /// resolved from [`PartnerCredentials::bearer_token`](crate::core::credentials::PartnerCredentials::bearer_token).
    ///
    /// # Errors
    ///
    /// Returns:
    /// - [`PaymobError::ValidationError`] if `params` contains an empty label.
    /// - [`PaymobError::AuthenticationError`] if `partner_credentials` or its `bearer_token`
    ///   is missing or rejected by the gateway.
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
    /// use some_paymob::resources::onboarding::auth_models::CreatePartnerApiKeyParams;
    ///
    /// # async fn example() -> Result<(), some_paymob::core::error::PaymobError> {
    /// let partner_creds = PartnerCredentials::with_bearer_token("pk_partner", "partner_jwt")?;
    /// let config = ClientConfig::builder()
    ///     .region(PaymobRegion::Egypt)
    ///     .partner_credentials(partner_creds)
    ///     .build()?;
    /// let client = PaymobClient::new(config)?;
    /// let params = CreatePartnerApiKeyParams::new().with_label("ci-onboarding");
    /// let key = client.onboarding().auth().create_api_key(params).await?;
    /// assert!(!key.api_key().is_empty());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn create_api_key(
        &self,
        params: CreatePartnerApiKeyParams,
    ) -> Result<PartnerApiKeyResponse, PaymobError> {
        params.validate()?;
        let headers = resolve_partner_bearer_headers(
            self.client(),
            "partner_credentials.bearer_token is required for Regime 4 API key provisioning",
        )?;
        let url = self.client().accept_url(PARTNER_API_KEY_PATH)?;
        let request = HttpRequest::post(url.as_str())?
            .with_json(&params)
            .map_err(|err| PaymobError::ValidationError {
                field: "params",
                reason: err.to_string(),
            })?;
        let request = apply_header_map(request, &headers);

        let response = execute_onboarding_request(self.client(), &request).await?;
        decode_onboarding_json(&response)
    }
}

#[cfg(test)]
mod tests {
    use wiremock::matchers::{body_json, header, method, path};
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
    async fn tc_6_1_2_login_posts_credentials_and_returns_secret_token() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/auth/tokens"))
            .and(body_json(serde_json::json!({
                "username": "partner@acme.io",
                "password": "my-password"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token": "eyJhbGciOiJIUzI1NiJ9.partner"
            })))
            .mount(&server)
            .await;

        let client = test_client(&server.uri(), None);
        let creds = PartnerLoginCredentials::try_new("partner@acme.io", "my-password").unwrap();
        let resp = client
            .onboarding()
            .auth()
            .login(creds)
            .await
            .expect("login succeeds");

        assert_eq!(resp.token(), "eyJhbGciOiJIUzI1NiJ9.partner");
        assert!(!format!("{resp:?}").contains("eyJhbGciOiJIUzI1NiJ9.partner"));
    }

    #[tokio::test]
    async fn tc_6_1_2_create_api_key_uses_regime4_bearer_and_returns_redacted_key() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/auth/api_keys"))
            .and(header("authorization", "Bearer partner_jwt_abc"))
            .and(body_json(serde_json::json!({
                "label": "onboarding-prod"
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "api_key": "pk_partner_provisioned_999",
                "label": "onboarding-prod"
            })))
            .mount(&server)
            .await;

        let client = test_client(&server.uri(), Some("partner_jwt_abc"));
        let params = CreatePartnerApiKeyParams::new().with_label("onboarding-prod");
        let resp = client
            .onboarding()
            .auth()
            .create_api_key(params)
            .await
            .expect("create_api_key succeeds");

        assert_eq!(resp.api_key(), "pk_partner_provisioned_999");
        assert_eq!(resp.label.as_deref(), Some("onboarding-prod"));
        assert!(!format!("{resp:?}").contains("pk_partner_provisioned_999"));
    }

    #[tokio::test]
    async fn tc_6_1_2_rejects_invalid_inputs_and_missing_bearer_before_network() {
        let client = test_client("https://accept.paymob.com", None);

        let bad_creds = PartnerLoginCredentials::new("   ", "pass");
        let err = client
            .onboarding()
            .auth()
            .login(bad_creds)
            .await
            .expect_err("empty username must fail");
        assert!(err.is_validation_error());

        let bad_params = CreatePartnerApiKeyParams::new().with_label(" ");
        let err = client
            .onboarding()
            .auth()
            .create_api_key(bad_params)
            .await
            .expect_err("empty label must fail");
        assert!(err.is_validation_error());

        let err = client
            .onboarding()
            .auth()
            .create_api_key(CreatePartnerApiKeyParams::new())
            .await
            .expect_err("missing bearer token must fail");
        assert!(err.is_auth_error());
    }

    #[tokio::test]
    async fn tc_6_1_2_maps_401_and_malformed_json_errors() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/auth/tokens"))
            .respond_with(
                ResponseTemplate::new(401)
                    .set_body_json(serde_json::json!({"detail": "incorrect credentials"})),
            )
            .mount(&server)
            .await;

        let client = test_client(&server.uri(), None);
        let creds = PartnerLoginCredentials::try_new("partner@acme.io", "wrong").unwrap();
        let err = client
            .onboarding()
            .auth()
            .login(creds)
            .await
            .expect_err("401 must map to AuthenticationError");
        assert!(err.is_auth_error());

        let server2 = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/auth/api_keys"))
            .respond_with(ResponseTemplate::new(200).set_body_string("{not-json"))
            .mount(&server2)
            .await;

        let client2 = test_client(&server2.uri(), Some("partner_jwt_abc"));
        let err2 = client2
            .onboarding()
            .auth()
            .create_api_key(CreatePartnerApiKeyParams::new())
            .await
            .expect_err("malformed json must fail");
        assert!(matches!(err2, PaymobError::TransportError(_)));
    }
}

#![forbid(unsafe_code)]
//! Optional [`some_payment_core::PaymentProvider`] adapter for Paymob (`US-9.2.0` Unit 3).
//!
//! Wires the seven `src/alignment/*` primitives into a single northbound adapter:
//! - [`crate::adapter::paymob_provider::PaymobProviderConfig`] holds regional routing,
//!   integration routing (`auth_integration_id` fail-closed Manual capture guard),
//!   redacted credentials, and optional offline `wiremock` overrides.
//! - [`crate::adapter::paymob_provider::PaymobProvider`] implements
//!   [`some_payment_core::PaymentProvider`] across Intention creation, Unified Checkout,
//!   transaction inquiry, capture, void, refund, and triple-HMAC callback dispatch.
//! - [`crate::adapter::paymob_provider::map_synthesized_status`] maps deterministic
//!   Paymob boolean-flag status synthesis into [`some_payment_core::PaymentStatus`].
//!
//! # Example
//!
//! ```rust
//! use some_payment_core::{PaymentCapabilities, PaymentProvider};
//! use some_paymob::adapter::paymob_provider::{PaymobProvider, PaymobProviderConfig};
//! use some_paymob::alignment::integration_validation::IntegrationRoutingConfig;
//! use some_paymob::alignment::region_checkout::PaymobRegion;
//!
//! let routing = IntegrationRoutingConfig::new(vec![1001]).with_auth_integration_id(2002);
//! let config = PaymobProviderConfig::new(
//!     PaymobRegion::Egypt,
//!     routing,
//!     "egy_sk_test_example",
//!     "api_key_example",
//!     "hmac_secret_example",
//!     "egy_pk_test_example",
//! );
//! let provider = PaymobProvider::new(config).expect("valid config");
//! assert_eq!(provider.id().as_str(), "paymob");
//! assert!(
//!     !provider
//!         .capabilities()
//!         .contains(PaymentCapabilities::NATIVE_MUTATION_IDEMPOTENCY)
//! );
//! assert!(
//!     provider
//!         .capabilities()
//!         .contains(PaymentCapabilities::AUTH_CAPTURE)
//! );
//! ```

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use async_trait::async_trait;
use reqwest::header::AUTHORIZATION;
use reqwest::{Client, Response, StatusCode};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use some_payment_core::{
    CaptureMode, CaptureRequest, CheckoutSessionRequest, CreatePaymentRequest, HttpMethod, Money,
    NextAction, NormalizedWebhookEvent, PaymentCapabilities, PaymentError, PaymentProvider,
    PaymentResult, PaymentStatus, ProviderId, ProviderReference, RawWebhookRequest, RefundRequest,
    RefundResult, RefundStatus, VoidRequest,
};
use url::Url;

use crate::alignment::callback_dispatcher::{
    CallbackAuthority, CallbackDispatchError, CardTokenCallbackData, DispatchedPaymobCallback,
    PaymobCallbackInput, SubscriptionCallbackData, TransactionCallbackData,
    dispatch_and_verify_paymob_callback,
};
use crate::alignment::dual_auth::{AuthTokenConfig, AuthTokenManager, DualAuthError};
use crate::alignment::integration_validation::{
    AlignmentCaptureMode, IntegrationRoutingConfig, IntegrationValidationError,
    IntentionBillingData, IntentionPreflightInput, ValidatedIntentionRouting,
    validate_intention_preflight,
};
use crate::alignment::region_checkout::{
    PaymobRegion, RegionCheckoutError, build_unified_checkout_url,
};
use crate::alignment::status_synthesizer::{
    ChildTransactionKind, ParentTransactionCorrelation, PaymobTransactionFlags,
    SynthesizedPaymentStatus, extract_parent_correlation, synthesize_paymob_status,
};
use crate::alignment::tx_correlation::{
    TransactionLookupRef, TxCorrelationError, resolve_full_refund_amount, resolve_transaction_id,
};

const PROVIDER_SLUG: &str = "paymob";
const REDACTED: &str = "[REDACTED]";
const DEFAULT_TIMEOUT_SECS: u64 = 30;
const INTENTION_PATH: &str = "/v1/intention/";
const TRANSACTIONS_PREFIX: &str = "/api/acceptance/transactions/";
const CAPTURE_PATH: &str = "/api/acceptance/capture";
const VOID_PATH: &str = "/api/acceptance/void_refund/void";
const REFUND_PATH: &str = "/api/acceptance/void_refund/refund";
const ALIAS_METADATA_KEY: &str = "paymob_payment_method_alias";

/// Configuration for [`PaymobProvider`].
///
/// All secret material (`secret_key`, `api_key`, `hmac_secret`, `public_key`) is
/// stored in [`SecretString`] wrappers and redacted as `[REDACTED]` in [`fmt::Debug`].
#[derive(Clone)]
pub struct PaymobProviderConfig {
    region: PaymobRegion,
    integration_routing: IntegrationRoutingConfig,
    secret_key: SecretString,
    api_key: SecretString,
    hmac_secret: SecretString,
    public_key: SecretString,
    auth_base_url_override: Option<String>,
    checkout_base_url_override: Option<String>,
    http_client: Option<Client>,
    livemode: bool,
    notification_url: Option<String>,
    redirection_url: Option<String>,
}

impl fmt::Debug for PaymobProviderConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PaymobProviderConfig")
            .field("region", &self.region)
            .field("integration_routing", &self.integration_routing)
            .field("secret_key", &REDACTED)
            .field("api_key", &REDACTED)
            .field("hmac_secret", &REDACTED)
            .field("public_key", &REDACTED)
            .field("auth_base_url_override", &self.auth_base_url_override)
            .field(
                "checkout_base_url_override",
                &self.checkout_base_url_override,
            )
            .field("custom_http_client", &self.http_client.is_some())
            .field("livemode", &self.livemode)
            .field("notification_url", &self.notification_url)
            .field("redirection_url", &self.redirection_url)
            .finish()
    }
}

impl PaymobProviderConfig {
    /// Creates a new [`PaymobProviderConfig`] with the required Paymob credentials and routing.
    ///
    /// By default, `livemode` is inferred from whether `secret_key` contains `"_live_"`.
    /// Override it explicitly with [`Self::with_livemode`] when needed.
    #[must_use]
    pub fn new(
        region: PaymobRegion,
        integration_routing: IntegrationRoutingConfig,
        secret_key: impl Into<SecretString>,
        api_key: impl Into<SecretString>,
        hmac_secret: impl Into<SecretString>,
        public_key: impl Into<SecretString>,
    ) -> Self {
        let secret_key = secret_key.into();
        let livemode = secret_key.expose_secret().contains("_live_");
        Self {
            region,
            integration_routing,
            secret_key,
            api_key: api_key.into(),
            hmac_secret: hmac_secret.into(),
            public_key: public_key.into(),
            auth_base_url_override: None,
            checkout_base_url_override: None,
            http_client: None,
            livemode,
            notification_url: None,
            redirection_url: None,
        }
    }

    /// Overrides the API and `/api/auth/tokens` base URL (supports `http://` for offline `wiremock` tests).
    #[must_use]
    pub fn with_auth_base_url_override(mut self, base_url: impl Into<String>) -> Self {
        self.auth_base_url_override = Some(base_url.into());
        self
    }

    /// Overrides the HTTPS base URL used when generating Unified Checkout redirect links.
    #[must_use]
    pub fn with_checkout_base_url_override(mut self, checkout_base_url: impl Into<String>) -> Self {
        self.checkout_base_url_override = Some(checkout_base_url.into());
        self
    }

    /// Injects a custom [`reqwest::Client`] (for custom TLS, timeouts, or offline tests).
    #[must_use]
    pub fn with_http_client(mut self, client: Client) -> Self {
        self.http_client = Some(client);
        self
    }

    /// Explicitly sets whether this provider instance operates in live mode.
    #[must_use]
    pub const fn with_livemode(mut self, livemode: bool) -> Self {
        self.livemode = livemode;
        self
    }

    /// Configures a default webhook `notification_url` sent on Intention creation requests.
    #[must_use]
    pub fn with_notification_url(mut self, url: impl Into<String>) -> Self {
        self.notification_url = Some(url.into());
        self
    }

    /// Configures a default customer `redirection_url` sent on Intention creation requests.
    #[must_use]
    pub fn with_redirection_url(mut self, url: impl Into<String>) -> Self {
        self.redirection_url = Some(url.into());
        self
    }

    /// Returns the configured [`PaymobRegion`].
    #[must_use]
    pub const fn region(&self) -> &PaymobRegion {
        &self.region
    }

    /// Returns the configured [`IntegrationRoutingConfig`].
    #[must_use]
    pub const fn integration_routing(&self) -> &IntegrationRoutingConfig {
        &self.integration_routing
    }

    /// Returns the optional API/auth base URL override.
    #[must_use]
    pub fn auth_base_url_override(&self) -> Option<&str> {
        self.auth_base_url_override.as_deref()
    }

    /// Returns the optional checkout base URL override.
    #[must_use]
    pub fn checkout_base_url_override(&self) -> Option<&str> {
        self.checkout_base_url_override.as_deref()
    }

    /// Returns whether this configuration is marked as live mode.
    #[must_use]
    pub const fn livemode(&self) -> bool {
        self.livemode
    }
}

/// Optional [`some_payment_core::PaymentProvider`] adapter backed by Paymob's REST APIs.
pub struct PaymobProvider {
    id: ProviderId,
    config: PaymobProviderConfig,
    api_base_url: String,
    auth_manager: AuthTokenManager,
    http: Client,
}

impl fmt::Debug for PaymobProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PaymobProvider")
            .field("id", &self.id)
            .field("api_base_url", &self.api_base_url)
            .field("config", &self.config)
            .field("auth_manager", &self.auth_manager)
            .finish()
    }
}

impl PaymobProvider {
    /// Builds a validated [`PaymobProvider`] from a [`PaymobProviderConfig`].
    ///
    /// # Errors
    ///
    /// Returns [`PaymentError::ConfigurationError`] if any required secret is empty,
    /// the resolved base URL is invalid, or the HTTP client cannot be constructed.
    pub fn new(config: PaymobProviderConfig) -> Result<Self, PaymentError> {
        validate_required_secrets(&config)?;
        let api_base_url = resolve_api_base_url(&config)?;
        let http = resolve_http_client(&config)?;
        let auth_config = AuthTokenConfig::new(
            &api_base_url,
            config.api_key.clone(),
            config.secret_key.clone(),
        )
        .map_err(map_dual_auth_config_error)?
        .with_http_client(http.clone());
        let auth_manager =
            AuthTokenManager::new(auth_config).map_err(map_dual_auth_config_error)?;
        Ok(Self {
            id: ProviderId::new(PROVIDER_SLUG),
            config,
            api_base_url,
            auth_manager,
            http,
        })
    }

    /// Builds a [`PaymobProvider`] using an explicitly supplied [`reqwest::Client`].
    ///
    /// # Errors
    ///
    /// Returns [`PaymentError::ConfigurationError`] if configuration validation fails.
    pub fn with_http_client(
        config: PaymobProviderConfig,
        client: Client,
    ) -> Result<Self, PaymentError> {
        Self::new(config.with_http_client(client))
    }

    /// Returns a reference to the redacted [`PaymobProviderConfig`].
    #[must_use]
    pub const fn config(&self) -> &PaymobProviderConfig {
        &self.config
    }

    /// Returns the resolved API base URL used for outbound Paymob requests.
    #[must_use]
    pub fn api_base_url(&self) -> &str {
        &self.api_base_url
    }

    async fn execute_intention(
        &self,
        spec: IntentionExecutionSpec<'_>,
    ) -> Result<PaymentResult, PaymentError> {
        let preflight = build_preflight_input(&spec);
        let validated = validate_intention_preflight(&self.config.integration_routing, &preflight)
            .map_err(map_integration_error)?;
        let payload = build_intention_payload(&spec, &validated);
        let auth_header = self
            .auth_manager
            .secret_key_header()
            .map_err(|err| map_dual_auth_error(&self.id, err))?;
        let url = format!("{}{INTENTION_PATH}", self.api_base_url);
        let response = self
            .http
            .post(&url)
            .header(AUTHORIZATION, auth_header)
            .json(&payload)
            .send()
            .await
            .map_err(|err| map_transport_error(&self.id, "create_intention", err))?;
        let body: IntentionApiResponse =
            parse_api_response(&self.id, "create_intention", response).await?;
        self.build_intention_payment_result(&spec, body)
    }

    fn build_intention_payment_result(
        &self,
        spec: &IntentionExecutionSpec<'_>,
        body: IntentionApiResponse,
    ) -> Result<PaymentResult, PaymentError> {
        let checkout_url = build_unified_checkout_url(
            &self.config.region,
            self.config.public_key.expose_secret(),
            &body.client_secret,
            self.config.checkout_base_url_override.as_deref(),
        )
        .map_err(map_region_error)?;
        let reference = build_intention_reference(
            &self.id,
            body.id.as_deref(),
            body.intention_order_id,
            spec.order_id,
            spec.is_checkout_session,
        )?;
        Ok(PaymentResult {
            reference,
            status: PaymentStatus::RequiresAction,
            money: spec.money.clone(),
            captured_amount: None,
            refunded_amount: None,
            next_action: Some(NextAction::Redirect {
                url: checkout_url.clone(),
            }),
            checkout_url: Some(checkout_url),
            livemode: self.config.livemode,
        })
    }

    async fn resolve_numeric_tx_id(
        &self,
        reference: &ProviderReference,
    ) -> Result<u64, PaymentError> {
        let lookup = build_lookup_ref(reference);
        if let Some(direct_id) = lookup.direct_transaction_id() {
            return Ok(direct_id);
        }
        let initial_token = self
            .auth_manager
            .get_auth_token()
            .await
            .map_err(|err| map_dual_auth_error(&self.id, err))?;
        match resolve_transaction_id(&self.http, &self.api_base_url, &initial_token, &lookup).await
        {
            Ok(id) => Ok(id),
            Err(TxCorrelationError::HttpStatus { status: 401, .. }) => {
                self.retry_resolve_tx_id(&initial_token, &lookup).await
            }
            Err(err) => Err(map_tx_correlation_error(&self.id, err)),
        }
    }

    async fn retry_resolve_tx_id(
        &self,
        stale_token: &SecretString,
        lookup: &TransactionLookupRef,
    ) -> Result<u64, PaymentError> {
        let refreshed = self
            .auth_manager
            .invalidate_and_refresh(Some(stale_token))
            .await
            .map_err(|err| map_dual_auth_error(&self.id, err))?;
        resolve_transaction_id(&self.http, &self.api_base_url, &refreshed, lookup)
            .await
            .map_err(|err| map_tx_correlation_error(&self.id, err))
    }

    async fn resolve_remaining_refund_cents(&self, tx_id: u64) -> Result<u64, PaymentError> {
        let initial_token = self
            .auth_manager
            .get_auth_token()
            .await
            .map_err(|err| map_dual_auth_error(&self.id, err))?;
        match resolve_full_refund_amount(&self.http, &self.api_base_url, &initial_token, tx_id)
            .await
        {
            Ok(amount) => Ok(amount),
            Err(TxCorrelationError::HttpStatus { status: 401, .. }) => {
                self.retry_resolve_refund_amount(&initial_token, tx_id)
                    .await
            }
            Err(err) => Err(map_tx_correlation_error(&self.id, err)),
        }
    }

    async fn retry_resolve_refund_amount(
        &self,
        stale_token: &SecretString,
        tx_id: u64,
    ) -> Result<u64, PaymentError> {
        let refreshed = self
            .auth_manager
            .invalidate_and_refresh(Some(stale_token))
            .await
            .map_err(|err| map_dual_auth_error(&self.id, err))?;
        resolve_full_refund_amount(&self.http, &self.api_base_url, &refreshed, tx_id)
            .await
            .map_err(|err| map_tx_correlation_error(&self.id, err))
    }

    async fn fetch_transaction(
        &self,
        tx_id: u64,
    ) -> Result<PaymobTransactionPayload, PaymentError> {
        let url = format!("{}{TRANSACTIONS_PREFIX}{tx_id}", self.api_base_url);
        let http = self.http.clone();
        let response = self
            .auth_manager
            .execute_with_auth_retry(move |token| {
                let client = http.clone();
                let target = url.clone();
                async move {
                    client
                        .get(&target)
                        .bearer_auth(token.expose_secret())
                        .send()
                        .await
                }
            })
            .await
            .map_err(|err| map_dual_auth_error(&self.id, err))?;
        parse_api_response(&self.id, "get_payment", response).await
    }

    async fn resolve_capture_amount_cents(
        &self,
        tx_id: u64,
        requested: Option<&Money>,
    ) -> Result<u64, PaymentError> {
        if let Some(money) = requested {
            return Ok(money.amount());
        }
        let tx = self.fetch_transaction(tx_id).await?;
        if tx.flags.amount_cents == 0 {
            return Err(PaymentError::validation(
                "transaction amount_cents must be greater than zero for full capture",
            ));
        }
        Ok(tx.flags.amount_cents)
    }

    fn map_tx_payload_to_payment_result(
        &self,
        payload: &PaymobTransactionPayload,
        fallback_ref: Option<&ProviderReference>,
        fallback_currency: Option<&str>,
    ) -> Result<PaymentResult, PaymentError> {
        let status = synthesize_effective_status(&payload.flags);
        let money = extract_payload_money(payload, fallback_currency, &self.id)?;
        let reference = build_tx_reference(&self.id, payload, fallback_ref)?;
        let captured_amount = positive_u64(payload.flags.captured_amount);
        let refunded_amount = positive_u64(payload.flags.refunded_amount_cents);
        Ok(PaymentResult {
            reference,
            status,
            money,
            captured_amount,
            refunded_amount,
            next_action: None,
            checkout_url: None,
            livemode: payload.is_live.unwrap_or(self.config.livemode),
        })
    }
}

#[async_trait]
impl PaymentProvider for PaymobProvider {
    fn id(&self) -> &ProviderId {
        &self.id
    }

    fn capabilities(&self) -> PaymentCapabilities {
        let mut caps = PaymentCapabilities::HOSTED_CHECKOUT
            | PaymentCapabilities::EMBEDDED_INTENT
            | PaymentCapabilities::VOID_AUTHORIZED
            | PaymentCapabilities::VOID_SETTLED_WINDOW
            | PaymentCapabilities::REFUND
            | PaymentCapabilities::PARTIAL_REFUND
            | PaymentCapabilities::SAVED_CARDS
            | PaymentCapabilities::SPLITS;
        if self
            .config
            .integration_routing
            .auth_integration_id
            .is_some()
        {
            caps |= PaymentCapabilities::AUTH_CAPTURE | PaymentCapabilities::PARTIAL_CAPTURE;
        }
        caps
    }

    async fn create_payment(
        &self,
        req: &CreatePaymentRequest,
    ) -> Result<PaymentResult, PaymentError> {
        req.validate()?;
        let spec = IntentionExecutionSpec {
            money: &req.money,
            order_id: &req.order_id,
            capture_mode: req.capture_mode,
            customer_email: req.customer_email.as_deref(),
            customer_phone: req.customer_phone.as_deref(),
            notification_url: req
                .callback_url
                .as_deref()
                .or(self.config.notification_url.as_deref()),
            redirection_url: self.config.redirection_url.as_deref(),
            metadata: &req.metadata,
            is_checkout_session: false,
        };
        self.execute_intention(spec).await
    }

    async fn get_payment(
        &self,
        reference: &ProviderReference,
    ) -> Result<PaymentResult, PaymentError> {
        let tx_id = self.resolve_numeric_tx_id(reference).await?;
        let payload = self.fetch_transaction(tx_id).await?;
        self.map_tx_payload_to_payment_result(&payload, Some(reference), None)
    }

    async fn create_checkout(
        &self,
        req: &CheckoutSessionRequest,
    ) -> Result<PaymentResult, PaymentError> {
        req.validate()?;
        let spec = IntentionExecutionSpec {
            money: &req.money,
            order_id: &req.order_id,
            capture_mode: req.capture_mode,
            customer_email: req.customer_email.as_deref(),
            customer_phone: req.customer_phone.as_deref(),
            notification_url: self.config.notification_url.as_deref(),
            redirection_url: Some(req.success_url.as_str()),
            metadata: &req.metadata,
            is_checkout_session: true,
        };
        self.execute_intention(spec).await
    }

    async fn capture(&self, req: &CaptureRequest) -> Result<PaymentResult, PaymentError> {
        req.validate()?;
        let tx_id = self.resolve_numeric_tx_id(&req.reference).await?;
        let amount_cents = self
            .resolve_capture_amount_cents(tx_id, req.amount.as_ref())
            .await?;
        let url = format!("{}{CAPTURE_PATH}", self.api_base_url);
        let http = self.http.clone();
        let response = self
            .auth_manager
            .execute_with_auth_retry(move |token| {
                let client = http.clone();
                let target = url.clone();
                async move {
                    let body = CaptureApiRequest {
                        auth_token: token.expose_secret(),
                        transaction_id: tx_id,
                        amount_cents,
                    };
                    client
                        .post(&target)
                        .bearer_auth(token.expose_secret())
                        .json(&body)
                        .send()
                        .await
                }
            })
            .await
            .map_err(|err| map_dual_auth_error(&self.id, err))?;
        let payload: PaymobTransactionPayload =
            parse_api_response(&self.id, "capture", response).await?;
        let fallback_currency = req.amount.as_ref().map(|m| m.currency().as_str());
        self.map_tx_payload_to_payment_result(&payload, Some(&req.reference), fallback_currency)
    }

    async fn void_payment(&self, req: &VoidRequest) -> Result<PaymentResult, PaymentError> {
        req.validate()?;
        let tx_id = self.resolve_numeric_tx_id(&req.reference).await?;
        let auth_header = self
            .auth_manager
            .secret_key_header()
            .map_err(|err| map_dual_auth_error(&self.id, err))?;
        let url = format!("{}{VOID_PATH}", self.api_base_url);
        let body = VoidApiRequest {
            transaction_id: tx_id,
        };
        let response = self
            .http
            .post(&url)
            .header(AUTHORIZATION, auth_header)
            .json(&body)
            .send()
            .await
            .map_err(|err| map_transport_error(&self.id, "void_payment", err))?;
        let payload: PaymobTransactionPayload =
            parse_api_response(&self.id, "void_payment", response).await?;
        self.map_tx_payload_to_payment_result(&payload, Some(&req.reference), None)
    }

    async fn refund(&self, req: &RefundRequest) -> Result<RefundResult, PaymentError> {
        req.validate()?;
        let tx_id = self.resolve_numeric_tx_id(&req.reference).await?;
        let amount_cents = match &req.amount {
            Some(money) => money.amount(),
            None => self.resolve_remaining_refund_cents(tx_id).await?,
        };
        let auth_header = self
            .auth_manager
            .secret_key_header()
            .map_err(|err| map_dual_auth_error(&self.id, err))?;
        let url = format!("{}{REFUND_PATH}", self.api_base_url);
        let body = RefundApiRequest {
            transaction_id: tx_id,
            amount_cents,
        };
        let response = self
            .http
            .post(&url)
            .header(AUTHORIZATION, auth_header)
            .json(&body)
            .send()
            .await
            .map_err(|err| map_transport_error(&self.id, "refund", err))?;
        let payload: PaymobTransactionPayload =
            parse_api_response(&self.id, "refund", response).await?;
        build_refund_result(&self.id, tx_id, amount_cents, req, &payload)
    }

    async fn parse_and_verify_webhook(
        &self,
        raw: &RawWebhookRequest,
    ) -> Result<NormalizedWebhookEvent, PaymentError> {
        let (input, parsed_post_body) = build_callback_input(&self.id, raw)?;
        let dispatched =
            dispatch_and_verify_paymob_callback(&input, self.config.hmac_secret.expose_secret())
                .map_err(|err| map_callback_error(&self.id, err))?;
        match dispatched {
            DispatchedPaymobCallback::Transaction(tx) => Ok(map_transaction_webhook(
                &self.id,
                self.config.livemode,
                tx,
                parsed_post_body.as_ref(),
            )),
            DispatchedPaymobCallback::CardToken(token) => {
                Ok(map_card_token_webhook(&self.id, self.config.livemode, token))
            }
            DispatchedPaymobCallback::Subscription(sub) => {
                Ok(map_subscription_webhook(&self.id, self.config.livemode, sub))
            }
        }
    }
}

/// Maps a Paymob [`SynthesizedPaymentStatus`] to a canonical [`PaymentStatus`].
///
/// # Example
///
/// ```rust
/// use some_payment_core::PaymentStatus;
/// use some_paymob::adapter::paymob_provider::map_synthesized_status;
/// use some_paymob::alignment::status_synthesizer::SynthesizedPaymentStatus;
///
/// assert_eq!(
///     map_synthesized_status(SynthesizedPaymentStatus::Authorized),
///     PaymentStatus::Authorized
/// );
/// assert_eq!(
///     map_synthesized_status(SynthesizedPaymentStatus::PartiallyRefunded),
///     PaymentStatus::PartiallyRefunded
/// );
/// ```
#[must_use]
pub const fn map_synthesized_status(status: SynthesizedPaymentStatus) -> PaymentStatus {
    match status {
        SynthesizedPaymentStatus::Processing => PaymentStatus::Processing,
        SynthesizedPaymentStatus::Failed => PaymentStatus::Failed,
        SynthesizedPaymentStatus::Voided => PaymentStatus::Voided,
        SynthesizedPaymentStatus::Refunded => PaymentStatus::Refunded,
        SynthesizedPaymentStatus::PartiallyRefunded => PaymentStatus::PartiallyRefunded,
        SynthesizedPaymentStatus::Authorized => PaymentStatus::Authorized,
        SynthesizedPaymentStatus::PartiallyCaptured => PaymentStatus::PartiallyCaptured,
        SynthesizedPaymentStatus::Captured => PaymentStatus::Captured,
        SynthesizedPaymentStatus::Paid => PaymentStatus::Paid,
    }
}

// ---------------------------------------------------------------------------
// Internal Wire DTOs
// ---------------------------------------------------------------------------

struct IntentionExecutionSpec<'a> {
    money: &'a Money,
    order_id: &'a str,
    capture_mode: CaptureMode,
    customer_email: Option<&'a str>,
    customer_phone: Option<&'a str>,
    notification_url: Option<&'a str>,
    redirection_url: Option<&'a str>,
    metadata: &'a BTreeMap<String, String>,
    is_checkout_session: bool,
}

#[derive(Serialize)]
struct IntentionApiRequest<'a> {
    amount: u64,
    currency: &'a str,
    payment_methods: Vec<u64>,
    special_reference: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    billing_data: Option<IntentionBillingPayload<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    notification_url: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    redirection_url: Option<&'a str>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    extras: &'a BTreeMap<String, String>,
}

#[derive(Serialize)]
struct IntentionBillingPayload<'a> {
    phone_number: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<&'a str>,
}

#[derive(Deserialize)]
struct IntentionApiResponse {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    intention_order_id: Option<u64>,
    client_secret: String,
}

#[derive(Serialize)]
struct CaptureApiRequest<'a> {
    auth_token: &'a str,
    transaction_id: u64,
    amount_cents: u64,
}

#[derive(Serialize)]
struct VoidApiRequest {
    transaction_id: u64,
}

#[derive(Serialize)]
struct RefundApiRequest {
    transaction_id: u64,
    amount_cents: u64,
}

#[derive(Deserialize)]
struct PaymobTransactionPayload {
    #[serde(flatten)]
    flags: PaymobTransactionFlags,
    #[serde(default)]
    currency: Option<String>,
    #[serde(default)]
    order: Option<Value>,
    #[serde(default)]
    is_live: Option<bool>,
}

// ---------------------------------------------------------------------------
// Configuration & Validation Helpers
// ---------------------------------------------------------------------------

fn validate_required_secrets(config: &PaymobProviderConfig) -> Result<(), PaymentError> {
    ensure_non_empty_secret(&config.secret_key, "secret_key")?;
    ensure_non_empty_secret(&config.api_key, "api_key")?;
    ensure_non_empty_secret(&config.hmac_secret, "hmac_secret")?;
    ensure_non_empty_secret(&config.public_key, "public_key")
}

fn ensure_non_empty_secret(secret: &SecretString, field: &str) -> Result<(), PaymentError> {
    if secret.expose_secret().trim().is_empty() {
        return Err(PaymentError::configuration(format!(
            "paymob {field} must not be empty"
        )));
    }
    Ok(())
}

fn resolve_api_base_url(config: &PaymobProviderConfig) -> Result<String, PaymentError> {
    let raw = match &config.auth_base_url_override {
        Some(override_url) => override_url.trim().to_owned(),
        None => config.region.api_base_url().map_err(map_region_error)?,
    };
    let parsed = Url::parse(&raw)
        .map_err(|err| PaymentError::configuration(format!("invalid paymob base URL: {err}")))?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return Err(PaymentError::configuration(
            "paymob base URL must use http or https with a valid host",
        ));
    }
    Ok(raw.trim_end_matches('/').to_owned())
}

fn resolve_http_client(config: &PaymobProviderConfig) -> Result<Client, PaymentError> {
    if let Some(client) = &config.http_client {
        return Ok(client.clone());
    }
    Client::builder()
        .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
        .build()
        .map_err(|_| PaymentError::configuration("failed to initialize reqwest HTTP client"))
}

// ---------------------------------------------------------------------------
// Intention & Lookup Helpers
// ---------------------------------------------------------------------------

const fn to_alignment_capture_mode(mode: CaptureMode) -> AlignmentCaptureMode {
    match mode {
        CaptureMode::Automatic => AlignmentCaptureMode::Automatic,
        CaptureMode::Manual => AlignmentCaptureMode::Manual,
    }
}

fn build_preflight_input(spec: &IntentionExecutionSpec<'_>) -> IntentionPreflightInput {
    let billing_data = spec.customer_phone.map(|phone| IntentionBillingData {
        phone_number: phone.to_owned(),
        email: spec.customer_email.map(ToOwned::to_owned),
        first_name: None,
        last_name: None,
    });
    IntentionPreflightInput {
        order_id: spec.order_id.to_owned(),
        capture_mode: to_alignment_capture_mode(spec.capture_mode),
        payment_method_alias: spec.metadata.get(ALIAS_METADATA_KEY).cloned(),
        billing_data,
        items: Vec::new(),
    }
}

fn build_intention_payload<'a>(
    spec: &'a IntentionExecutionSpec<'a>,
    validated: &ValidatedIntentionRouting,
) -> IntentionApiRequest<'a> {
    let billing_data = spec.customer_phone.map(|phone| IntentionBillingPayload {
        phone_number: phone,
        email: spec.customer_email,
    });
    IntentionApiRequest {
        amount: spec.money.amount(),
        currency: spec.money.currency().as_str(),
        payment_methods: validated.payment_methods.clone(),
        special_reference: validated.special_reference.clone(),
        billing_data,
        notification_url: spec.notification_url,
        redirection_url: spec.redirection_url,
        extras: spec.metadata,
    }
}

fn build_intention_reference(
    provider_id: &ProviderId,
    intent_id: Option<&str>,
    intention_order_id: Option<u64>,
    merchant_order_id: &str,
    is_checkout_session: bool,
) -> Result<ProviderReference, PaymentError> {
    let mut builder = ProviderReference::builder(provider_id.clone());
    if let Some(id) = intent_id.map(str::trim).filter(|s| !s.is_empty()) {
        builder = builder.intent_id(id);
        if is_checkout_session {
            builder = builder.checkout_session_id(id);
        }
    }
    let resolved_order = intention_order_id
        .map(|id| id.to_string())
        .unwrap_or_else(|| merchant_order_id.to_owned());
    builder = builder.order_id(resolved_order);
    builder.build()
}

fn build_lookup_ref(reference: &ProviderReference) -> TransactionLookupRef {
    let direct_tx = reference
        .transaction_id()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|&id| id > 0);
    let (numeric_order, merchant_order) = classify_order_id(reference.order_id());
    TransactionLookupRef {
        transaction_id: direct_tx,
        payment_id: reference.payment_id().map(ToOwned::to_owned),
        order_id: numeric_order,
        merchant_order_id: merchant_order,
        special_reference: reference.intent_id().map(ToOwned::to_owned),
    }
}

fn classify_order_id(order_id: Option<&str>) -> (Option<String>, Option<String>) {
    let Some(raw) = order_id.map(str::trim).filter(|s| !s.is_empty()) else {
        return (None, None);
    };
    if raw.parse::<u64>().is_ok() {
        (Some(raw.to_owned()), None)
    } else {
        (None, Some(raw.to_owned()))
    }
}

// ---------------------------------------------------------------------------
// Response & Status Mapping Helpers
// ---------------------------------------------------------------------------

fn synthesize_effective_status(flags: &PaymobTransactionFlags) -> PaymentStatus {
    let correlation = extract_parent_correlation(flags);
    let succeeded = flags.success && !flags.pending && !flags.error_occured;
    if succeeded && correlation.child_kind == Some(ChildTransactionKind::Void) {
        return PaymentStatus::Voided;
    }
    map_synthesized_status(synthesize_paymob_status(flags))
}

fn extract_payload_money(
    payload: &PaymobTransactionPayload,
    fallback_currency: Option<&str>,
    provider_id: &ProviderId,
) -> Result<Money, PaymentError> {
    let currency = payload
        .currency
        .as_deref()
        .or(fallback_currency)
        .unwrap_or("EGP");
    if payload.flags.amount_cents == 0 {
        return Err(PaymentError::ProviderError {
            provider: provider_id.clone(),
            http_status: None,
            vendor_code: None,
            message: "paymob transaction payload returned zero amount_cents".to_owned(),
        });
    }
    Money::new(payload.flags.amount_cents, currency)
}

fn extract_order_id_from_value(order: Option<&Value>) -> Option<String> {
    let val = order?;
    if let Some(n) = val.as_u64() {
        return Some(n.to_string());
    }
    if let Some(s) = val.as_str() {
        return Some(s.to_owned());
    }
    val.get("id").and_then(|id| {
        id.as_u64()
            .map(|n| n.to_string())
            .or_else(|| id.as_str().map(ToOwned::to_owned))
    })
}

fn build_tx_reference(
    provider_id: &ProviderId,
    payload: &PaymobTransactionPayload,
    fallback_ref: Option<&ProviderReference>,
) -> Result<ProviderReference, PaymentError> {
    let correlation = extract_parent_correlation(&payload.flags);
    let mut builder = ProviderReference::builder(provider_id.clone());
    if correlation.canonical_payment_id > 0 {
        builder = builder.payment_id(correlation.canonical_payment_id.to_string());
    }
    if payload.flags.id > 0 {
        builder = builder.transaction_id(payload.flags.id.to_string());
    }
    let order_id = extract_order_id_from_value(payload.order.as_ref())
        .or_else(|| fallback_ref.and_then(|r| r.order_id().map(ToOwned::to_owned)));
    if let Some(oid) = order_id {
        builder = builder.order_id(oid);
    }
    builder.build()
}

fn build_refund_result(
    provider_id: &ProviderId,
    tx_id: u64,
    amount_cents: u64,
    req: &RefundRequest,
    payload: &PaymobTransactionPayload,
) -> Result<RefundResult, PaymentError> {
    let refund_id = if payload.flags.id > 0 {
        payload.flags.id.to_string()
    } else {
        format!("refund-{tx_id}")
    };
    let status = classify_refund_status(&payload.flags);
    let money = match &req.amount {
        Some(m) => m.clone(),
        None => Money::new(amount_cents, payload.currency.as_deref().unwrap_or("EGP"))?,
    };
    let payment_reference = build_refund_payment_ref(provider_id, tx_id, &req.reference)?;
    Ok(RefundResult {
        refund_id,
        payment_reference,
        status,
        money,
        reason_detail: req.reason.clone(),
    })
}

const fn classify_refund_status(flags: &PaymobTransactionFlags) -> RefundStatus {
    if flags.pending {
        return RefundStatus::Pending;
    }
    if flags.success && !flags.error_occured {
        return RefundStatus::Succeeded;
    }
    RefundStatus::Failed
}

fn build_refund_payment_ref(
    provider_id: &ProviderId,
    tx_id: u64,
    original: &ProviderReference,
) -> Result<ProviderReference, PaymentError> {
    let mut builder =
        ProviderReference::builder(provider_id.clone()).transaction_id(tx_id.to_string());
    if let Some(pid) = original.payment_id() {
        builder = builder.payment_id(pid);
    }
    if let Some(oid) = original.order_id() {
        builder = builder.order_id(oid);
    }
    builder.build()
}

const fn positive_u64(value: u64) -> Option<u64> {
    if value > 0 { Some(value) } else { None }
}

// ---------------------------------------------------------------------------
// Webhook / Callback Mapping Helpers
// ---------------------------------------------------------------------------

fn build_callback_input(
    provider_id: &ProviderId,
    raw: &RawWebhookRequest,
) -> Result<(PaymobCallbackInput, Option<Value>), PaymentError> {
    match raw.method {
        HttpMethod::Get => Ok((PaymobCallbackInput::get(raw.query_params.clone()), None)),
        HttpMethod::Post => {
            let body: Value = serde_json::from_slice(&raw.raw_body).map_err(|_| {
                PaymentError::WebhookVerificationFailed {
                    provider: provider_id.clone(),
                    reason: "invalid JSON body in POST webhook".to_owned(),
                }
            })?;
            let input = PaymobCallbackInput::post(raw.query_params.clone(), body.clone());
            Ok((input, Some(body)))
        }
    }
}

fn build_webhook_tx_flags(
    tx: &TransactionCallbackData,
    post_body: Option<&Value>,
) -> PaymobTransactionFlags {
    let parsed_from_obj = post_body
        .and_then(|b| b.get("obj"))
        .and_then(|obj| serde_json::from_value::<PaymobTransactionFlags>(obj.clone()).ok());
    if let Some(flags) = parsed_from_obj {
        return flags;
    }
    PaymobTransactionFlags {
        id: tx
            .transaction_id
            .as_deref()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0),
        pending: tx.pending.unwrap_or(false),
        success: tx.success.unwrap_or(false),
        error_occured: tx.error_occured.unwrap_or(false),
        is_voided: tx.is_voided.unwrap_or(false),
        is_refunded: tx.is_refunded.unwrap_or(false),
        amount_cents: tx
            .amount_cents
            .and_then(|v| u64::try_from(v).ok())
            .unwrap_or(0),
        is_auth: tx.is_auth.unwrap_or(false),
        is_capture: tx.is_capture.unwrap_or(false),
        ..PaymobTransactionFlags::default()
    }
}

fn map_transaction_webhook(
    provider_id: &ProviderId,
    default_livemode: bool,
    tx: TransactionCallbackData,
    post_body: Option<&Value>,
) -> NormalizedWebhookEvent {
    let flags = build_webhook_tx_flags(&tx, post_body);
    let correlation = extract_parent_correlation(&flags);
    let status = synthesize_effective_status(&flags);
    let requires_hydration = tx.authority == CallbackAuthority::CustomerGetReturn;
    let event_type = resolve_tx_event_type(tx.authority, correlation.child_kind);
    let reference = build_webhook_tx_reference(provider_id, &tx, &correlation);
    let money = extract_webhook_money(&tx);
    let livemode = post_body
        .and_then(|b| b.get("obj"))
        .and_then(|o| o.get("is_live"))
        .and_then(Value::as_bool)
        .unwrap_or(default_livemode);
    let event_id = tx
        .transaction_id
        .unwrap_or_else(|| correlation.canonical_payment_id.to_string());
    NormalizedWebhookEvent {
        provider_id: provider_id.clone(),
        event_id,
        event_type,
        livemode,
        requires_hydration,
        reference,
        status: Some(status),
        money,
        verification_challenge: None,
        raw_redacted: tx.raw_redacted,
    }
}

fn resolve_tx_event_type(
    authority: CallbackAuthority,
    child_kind: Option<ChildTransactionKind>,
) -> String {
    if authority == CallbackAuthority::CustomerGetReturn {
        return "paymob.transaction.return".to_owned();
    }
    match child_kind {
        Some(ChildTransactionKind::Void) => "paymob.transaction.void".to_owned(),
        Some(ChildTransactionKind::Refund) => "paymob.transaction.refund".to_owned(),
        Some(ChildTransactionKind::Capture) => "paymob.transaction.capture".to_owned(),
        None => "paymob.transaction".to_owned(),
    }
}

fn build_webhook_tx_reference(
    provider_id: &ProviderId,
    tx: &TransactionCallbackData,
    correlation: &ParentTransactionCorrelation,
) -> Option<ProviderReference> {
    let mut builder = ProviderReference::builder(provider_id.clone());
    if correlation.canonical_payment_id > 0 {
        builder = builder.payment_id(correlation.canonical_payment_id.to_string());
    }
    let tx_id = correlation
        .child_transaction_id
        .map(|id| id.to_string())
        .or_else(|| tx.transaction_id.clone());
    if let Some(id) = tx_id {
        builder = builder.transaction_id(id);
    }
    if let Some(oid) = &tx.order_id {
        builder = builder.order_id(oid.clone());
    }
    builder.build().ok()
}

fn extract_webhook_money(tx: &TransactionCallbackData) -> Option<Money> {
    let amount = tx.amount_cents.and_then(|v| u64::try_from(v).ok())?;
    let currency = tx.currency.as_deref()?;
    Money::new(amount, currency).ok()
}

fn map_card_token_webhook(
    provider_id: &ProviderId,
    livemode: bool,
    token: CardTokenCallbackData,
) -> NormalizedWebhookEvent {
    let event_id = token
        .id
        .clone()
        .or_else(|| token.order_id.clone())
        .unwrap_or_else(|| "card_token".to_owned());
    let mut builder = ProviderReference::builder(provider_id.clone());
    if let Some(id) = &token.id {
        builder = builder.payment_id(id.clone());
    }
    if let Some(oid) = &token.order_id {
        builder = builder.order_id(oid.clone());
    }
    NormalizedWebhookEvent {
        provider_id: provider_id.clone(),
        event_id,
        event_type: "paymob.card_token".to_owned(),
        livemode,
        requires_hydration: false,
        reference: builder.build().ok(),
        status: Some(PaymentStatus::SetupCompleted),
        money: None,
        verification_challenge: None,
        raw_redacted: token.raw_redacted,
    }
}

fn map_subscription_webhook(
    provider_id: &ProviderId,
    livemode: bool,
    sub: SubscriptionCallbackData,
) -> NormalizedWebhookEvent {
    let reference = ProviderReference::builder(provider_id.clone())
        .payment_id(sub.subscription_id.clone())
        .build()
        .ok();
    NormalizedWebhookEvent {
        provider_id: provider_id.clone(),
        event_id: sub.subscription_id,
        event_type: format!("paymob.subscription.{}", sub.trigger_type),
        livemode,
        requires_hydration: false,
        reference,
        status: None,
        money: None,
        verification_challenge: None,
        raw_redacted: sub.raw_redacted,
    }
}

// ---------------------------------------------------------------------------
// HTTP & Error Mapping Helpers
// ---------------------------------------------------------------------------

async fn parse_api_response<T: for<'de> Deserialize<'de>>(
    provider_id: &ProviderId,
    operation: &'static str,
    response: Response,
) -> Result<T, PaymentError> {
    let status = response.status();
    if !status.is_success() {
        return Err(map_http_status_error(provider_id, operation, status));
    }
    response
        .json::<T>()
        .await
        .map_err(|_| PaymentError::ProviderError {
            provider: provider_id.clone(),
            http_status: Some(status.as_u16()),
            vendor_code: None,
            message: format!("failed to decode paymob {operation} JSON response"),
        })
}

fn map_http_status_error(
    provider_id: &ProviderId,
    operation: &'static str,
    status: StatusCode,
) -> PaymentError {
    let code = status.as_u16();
    match code {
        401 | 403 => PaymentError::AuthenticationError {
            provider: provider_id.clone(),
            message: format!("paymob rejected credentials for {operation}"),
        },
        429 => PaymentError::RateLimited {
            provider: provider_id.clone(),
            retry_after_secs: None,
        },
        500..=599 => PaymentError::ProviderUnavailable {
            provider: provider_id.clone(),
            http_status: Some(code),
            indeterminate: true,
            message: format!("paymob returned HTTP {code} during {operation}"),
        },
        _ => PaymentError::ProviderError {
            provider: provider_id.clone(),
            http_status: Some(code),
            vendor_code: None,
            message: format!("paymob returned HTTP {code} during {operation}"),
        },
    }
}

fn map_transport_error(
    provider_id: &ProviderId,
    operation: &'static str,
    err: reqwest::Error,
) -> PaymentError {
    let kind = if err.is_timeout() {
        "timeout"
    } else if err.is_connect() {
        "connection error"
    } else {
        "transport error"
    };
    PaymentError::ProviderUnavailable {
        provider: provider_id.clone(),
        http_status: None,
        indeterminate: true,
        message: format!("paymob {operation} failed with {kind}"),
    }
}

fn map_integration_error(err: IntegrationValidationError) -> PaymentError {
    match err {
        IntegrationValidationError::ConfigurationError(msg) => PaymentError::configuration(msg),
        IntegrationValidationError::ValidationError(msg) => PaymentError::validation(msg),
    }
}

fn map_region_error(err: RegionCheckoutError) -> PaymentError {
    PaymentError::configuration(err.to_string())
}

fn map_dual_auth_config_error(err: DualAuthError) -> PaymentError {
    PaymentError::configuration(err.to_string())
}

fn map_dual_auth_error(provider_id: &ProviderId, err: DualAuthError) -> PaymentError {
    match err {
        DualAuthError::Unauthorized => PaymentError::AuthenticationError {
            provider: provider_id.clone(),
            message: "paymob authentication rejected (HTTP 401)".to_owned(),
        },
        DualAuthError::UnexpectedStatus { status, detail } => PaymentError::ProviderUnavailable {
            provider: provider_id.clone(),
            http_status: Some(status),
            indeterminate: status >= 500,
            message: detail,
        },
        DualAuthError::Transport(detail) => PaymentError::ProviderUnavailable {
            provider: provider_id.clone(),
            http_status: None,
            indeterminate: true,
            message: detail,
        },
        other => PaymentError::configuration(other.to_string()),
    }
}

fn map_tx_correlation_error(provider_id: &ProviderId, err: TxCorrelationError) -> PaymentError {
    match err {
        TxCorrelationError::MissingLookupReference
        | TxCorrelationError::InvalidTransactionId(_)
        | TxCorrelationError::ArithmeticUnderflow { .. }
        | TxCorrelationError::NothingRemainingToRefund { .. } => {
            PaymentError::validation(err.to_string())
        }
        TxCorrelationError::HttpStatus { status, endpoint } => {
            let status_code = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
            map_http_status_error(provider_id, endpoint, status_code)
        }
        TxCorrelationError::Transport { endpoint, detail } => PaymentError::ProviderUnavailable {
            provider: provider_id.clone(),
            http_status: None,
            indeterminate: true,
            message: format!("{endpoint}: {detail}"),
        },
        TxCorrelationError::Decode { endpoint, detail } => PaymentError::ProviderError {
            provider: provider_id.clone(),
            http_status: None,
            vendor_code: None,
            message: format!("{endpoint}: {detail}"),
        },
        TxCorrelationError::InvalidBaseUrl | TxCorrelationError::EmptyAuthToken => {
            PaymentError::configuration(err.to_string())
        }
    }
}

fn map_callback_error(provider_id: &ProviderId, err: CallbackDispatchError) -> PaymentError {
    PaymentError::WebhookVerificationFailed {
        provider: provider_id.clone(),
        reason: err.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alignment::triple_hmac::compute_hmac_sha512_hex;
    use serde_json::json;
    use some_payment_core::ErrorKind;

    fn sample_config(with_auth_id: bool) -> PaymobProviderConfig {
        let mut routing = IntegrationRoutingConfig::new(vec![1001]);
        if with_auth_id {
            routing = routing.with_auth_integration_id(2002);
        }
        PaymobProviderConfig::new(
            PaymobRegion::Egypt,
            routing,
            "egy_sk_test_SUPER_SECRET_KEY",
            "SUPER_SECRET_API_KEY",
            "SUPER_SECRET_HMAC_KEY",
            "egy_pk_test_SUPER_PUBLIC_KEY",
        )
    }

    #[test]
    fn provider_id_is_paymob() {
        let provider = PaymobProvider::new(sample_config(false)).expect("provider");
        assert_eq!(provider.id(), &ProviderId::new("paymob"));
    }

    #[test]
    fn capabilities_disable_native_mutation_idempotency_and_gate_auth_capture() {
        let without_auth = PaymobProvider::new(sample_config(false)).expect("provider");
        let caps_no_auth = without_auth.capabilities();
        assert!(caps_no_auth.contains(PaymentCapabilities::HOSTED_CHECKOUT));
        assert!(caps_no_auth.contains(PaymentCapabilities::REFUND));
        assert!(caps_no_auth.contains(PaymentCapabilities::PARTIAL_REFUND));
        assert!(caps_no_auth.contains(PaymentCapabilities::VOID_AUTHORIZED));
        assert!(!caps_no_auth.contains(PaymentCapabilities::AUTH_CAPTURE));
        assert!(!caps_no_auth.contains(PaymentCapabilities::PARTIAL_CAPTURE));
        assert!(!caps_no_auth.contains(PaymentCapabilities::NATIVE_MUTATION_IDEMPOTENCY));

        let with_auth = PaymobProvider::new(sample_config(true)).expect("provider");
        let caps_with_auth = with_auth.capabilities();
        assert!(caps_with_auth.contains(PaymentCapabilities::AUTH_CAPTURE));
        assert!(caps_with_auth.contains(PaymentCapabilities::PARTIAL_CAPTURE));
        assert!(!caps_with_auth.contains(PaymentCapabilities::NATIVE_MUTATION_IDEMPOTENCY));
    }

    #[test]
    fn debug_redacts_all_secret_fields() {
        let config = sample_config(true);
        let cfg_debug = format!("{config:?}");
        let provider = PaymobProvider::new(config).expect("provider");
        let prov_debug = format!("{provider:?}");

        for output in [&cfg_debug, &prov_debug] {
            assert!(output.contains("[REDACTED]"));
            assert!(!output.contains("SUPER_SECRET_KEY"));
            assert!(!output.contains("SUPER_SECRET_API_KEY"));
            assert!(!output.contains("SUPER_SECRET_HMAC_KEY"));
            assert!(!output.contains("SUPER_PUBLIC_KEY"));
        }
    }

    #[tokio::test]
    async fn manual_capture_fails_closed_without_auth_integration_id() {
        let provider = PaymobProvider::new(sample_config(false)).expect("provider");
        let req = CreatePaymentRequest::new(Money::new(10_000, "EGP").expect("money"), "ORD-1")
            .with_capture_mode(CaptureMode::Manual);
        let err = provider
            .create_payment(&req)
            .await
            .expect_err("must fail closed");
        assert_eq!(err.kind(), ErrorKind::Configuration);
    }

    #[test]
    fn maps_all_synthesized_statuses() {
        let cases = [
            (
                SynthesizedPaymentStatus::Processing,
                PaymentStatus::Processing,
            ),
            (SynthesizedPaymentStatus::Failed, PaymentStatus::Failed),
            (SynthesizedPaymentStatus::Voided, PaymentStatus::Voided),
            (SynthesizedPaymentStatus::Refunded, PaymentStatus::Refunded),
            (
                SynthesizedPaymentStatus::PartiallyRefunded,
                PaymentStatus::PartiallyRefunded,
            ),
            (
                SynthesizedPaymentStatus::Authorized,
                PaymentStatus::Authorized,
            ),
            (
                SynthesizedPaymentStatus::PartiallyCaptured,
                PaymentStatus::PartiallyCaptured,
            ),
            (SynthesizedPaymentStatus::Captured, PaymentStatus::Captured),
            (SynthesizedPaymentStatus::Paid, PaymentStatus::Paid),
        ];
        for (input, expected) in cases {
            assert_eq!(map_synthesized_status(input), expected);
        }
    }

    #[tokio::test]
    async fn webhook_rejects_tampered_hmac() {
        let provider = PaymobProvider::new(sample_config(false)).expect("provider");
        let mut query = BTreeMap::new();
        query.insert("hmac".to_owned(), "0".repeat(128));
        let raw = RawWebhookRequest {
            raw_body: serde_json::to_vec(&json!({
                "type": "TRANSACTION",
                "obj": { "id": 123, "success": true }
            }))
            .expect("json"),
            headers: BTreeMap::new(),
            query_params: query,
            method: HttpMethod::Post,
        };
        let err = provider
            .parse_and_verify_webhook(&raw)
            .await
            .expect_err("tampered hmac must fail");
        assert_eq!(err.kind(), ErrorKind::WebhookVerificationFailed);
    }

    #[tokio::test]
    async fn webhook_distinguishes_get_return_authority_and_redacts_payload() {
        let provider = PaymobProvider::new(sample_config(false)).expect("provider");
        let params: BTreeMap<String, String> = [
            ("amount_cents", "10000"),
            ("created_at", "2026-01-01T00:00:00"),
            ("currency", "EGP"),
            ("error_occured", "false"),
            ("has_parent_transaction", "false"),
            ("id", "998877"),
            ("integration_id", "1001"),
            ("is_3d_secure", "true"),
            ("is_auth", "false"),
            ("is_capture", "false"),
            ("is_refunded", "false"),
            ("is_standalone_payment", "true"),
            ("is_voided", "false"),
            ("order", "445566"),
            ("owner", "77"),
            ("pending", "false"),
            ("source_data.pan", "2346"),
            ("source_data.sub_type", "MasterCard"),
            ("source_data.type", "card"),
            ("success", "true"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
        let concat = concat!(
            "10000",
            "2026-01-01T00:00:00",
            "EGP",
            "false",
            "false",
            "998877",
            "1001",
            "true",
            "false",
            "false",
            "false",
            "true",
            "false",
            "445566",
            "77",
            "false",
            "2346",
            "MasterCard",
            "card",
            "true"
        );
        let hmac = compute_hmac_sha512_hex(concat, "SUPER_SECRET_HMAC_KEY");
        let mut query = params;
        query.insert("hmac".to_owned(), hmac);
        let raw = RawWebhookRequest {
            raw_body: Vec::new(),
            headers: BTreeMap::new(),
            query_params: query,
            method: HttpMethod::Get,
        };
        let event = provider
            .parse_and_verify_webhook(&raw)
            .await
            .expect("valid GET return");
        assert!(event.requires_hydration);
        assert_eq!(event.event_type, "paymob.transaction.return");
        assert_eq!(event.status, Some(PaymentStatus::Paid));
        assert_eq!(event.event_id, "998877");
    }
}

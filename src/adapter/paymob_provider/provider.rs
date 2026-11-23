use std::fmt;
use std::future::Future;

use async_trait::async_trait;
use reqwest::Client;
use reqwest::header::AUTHORIZATION;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use some_payment_core::{
    CaptureRequest, CheckoutSessionRequest, CreatePaymentRequest, Money, NextAction,
    NormalizedWebhookEvent, PaymentCapabilities, PaymentError, PaymentProvider, PaymentResult,
    PaymentStatus, ProviderId, ProviderReference, RawWebhookRequest, RefundRequest, RefundResult,
    VoidRequest,
};

use crate::alignment::dual_auth::AuthTokenManager;
use crate::alignment::integration_validation::validate_intention_preflight;
use crate::alignment::region_checkout::build_unified_checkout_url;
use crate::alignment::tx_correlation::{
    TxCorrelationError, resolve_full_refund_amount, resolve_transaction_id,
};

use super::config::{
    PaymobProviderConfig, build_auth_manager, resolve_api_base_url, resolve_capabilities,
    resolve_http_client, validate_required_secrets,
};
use super::errors::{
    map_dual_auth_error, map_integration_error, map_region_error, map_transport_error,
    map_tx_correlation_error, parse_api_response,
};
use super::webhook::parse_and_verify_paymob_webhook;
use super::wire::{
    CaptureApiRequest, IntentionApiResponse, IntentionExecutionSpec, PaymobTransactionPayload,
    RefundApiRequest, RefundExecutionContext, TxResultContext, VoidApiRequest,
    build_intention_payload, build_intention_reference, build_lookup_ref, build_preflight_input,
    build_refund_result, build_tx_payment_result,
};

const PROVIDER_SLUG: &str = "paymob";
const INTENTION_PATH: &str = "/v1/intention/";
const TRANSACTIONS_PREFIX: &str = "/api/acceptance/transactions/";
const CAPTURE_PATH: &str = "/api/acceptance/capture";
const VOID_PATH: &str = "/api/acceptance/void_refund/void";
const REFUND_PATH: &str = "/api/acceptance/void_refund/refund";

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
        let auth_manager = build_auth_manager(&api_base_url, &config, &http)?;
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

    async fn post_with_secret_key<Req: Serialize + Sync, Res: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        operation: &'static str,
        body: &Req,
    ) -> Result<Res, PaymentError> {
        let auth_header = self
            .auth_manager
            .secret_key_header()
            .map_err(|err| map_dual_auth_error(&self.id, err))?;
        let url = format!("{}{path}", self.api_base_url);
        let response = self
            .http
            .post(&url)
            .header(AUTHORIZATION, auth_header)
            .json(body)
            .send()
            .await
            .map_err(|err| map_transport_error(&self.id, operation, err))?;
        parse_api_response(&self.id, operation, response).await
    }

    async fn with_tx_auth_retry<T, F, Fut>(&self, call: F) -> Result<T, PaymentError>
    where
        F: Fn(SecretString) -> Fut,
        Fut: Future<Output = Result<T, TxCorrelationError>>,
    {
        let token = self
            .auth_manager
            .get_auth_token()
            .await
            .map_err(|err| map_dual_auth_error(&self.id, err))?;
        match call(token.clone()).await {
            Ok(val) => Ok(val),
            Err(TxCorrelationError::HttpStatus { status: 401, .. }) => {
                let refreshed = self
                    .auth_manager
                    .invalidate_and_refresh(Some(&token))
                    .await
                    .map_err(|err| map_dual_auth_error(&self.id, err))?;
                call(refreshed)
                    .await
                    .map_err(|err| map_tx_correlation_error(&self.id, err))
            }
            Err(err) => Err(map_tx_correlation_error(&self.id, err)),
        }
    }

    async fn execute_intention(
        &self,
        spec: IntentionExecutionSpec<'_>,
    ) -> Result<PaymentResult, PaymentError> {
        let preflight = build_preflight_input(&spec);
        let validated = validate_intention_preflight(self.config.integration_routing(), &preflight)
            .map_err(map_integration_error)?;
        let payload = build_intention_payload(&spec, &validated);
        let body: IntentionApiResponse = self
            .post_with_secret_key(INTENTION_PATH, "create_intention", &payload)
            .await?;
        let checkout_url = build_unified_checkout_url(
            self.config.region(),
            self.config.credentials().public_key().expose_secret(),
            &body.client_secret,
            self.config.checkout_base_url_override(),
        )
        .map_err(map_region_error)?;
        let reference = build_intention_reference(&self.id, &spec, &body)?;
        Ok(PaymentResult {
            reference,
            status: PaymentStatus::RequiresAction,
            money: spec.money.clone(),
            captured_amount: None,
            refunded_amount: None,
            next_action: Some(NextAction::Redirect { url: checkout_url.clone() }),
            checkout_url: Some(checkout_url),
            livemode: self.config.livemode(),
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
        self.with_tx_auth_retry(|token| {
            let (http, base, lookup_ref) = (&self.http, &self.api_base_url, &lookup);
            async move { resolve_transaction_id(http, base, &token, lookup_ref).await }
        })
        .await
    }

    async fn resolve_remaining_refund_cents(&self, tx_id: u64) -> Result<u64, PaymentError> {
        self.with_tx_auth_retry(|token| {
            let (http, base) = (&self.http, &self.api_base_url);
            async move { resolve_full_refund_amount(http, base, &token, tx_id).await }
        })
        .await
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
                let (client, target) = (http.clone(), url.clone());
                async move { client.get(&target).bearer_auth(token.expose_secret()).send().await }
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

    fn tx_result(
        &self,
        payload: &PaymobTransactionPayload,
        fallback_ref: Option<&ProviderReference>,
        fallback_currency: Option<&str>,
    ) -> Result<PaymentResult, PaymentError> {
        let ctx = TxResultContext {
            default_livemode: self.config.livemode(),
            fallback_ref,
            fallback_currency,
        };
        build_tx_payment_result(&self.id, payload, &ctx)
    }
}

#[async_trait]
impl PaymentProvider for PaymobProvider {
    fn id(&self) -> &ProviderId {
        &self.id
    }

    fn capabilities(&self) -> PaymentCapabilities {
        resolve_capabilities(&self.config)
    }

    async fn create_payment(
        &self,
        req: &CreatePaymentRequest,
    ) -> Result<PaymentResult, PaymentError> {
        req.validate()?;
        let notification_url = req
            .callback_url
            .as_deref()
            .or_else(|| self.config.notification_url());
        let spec = IntentionExecutionSpec {
            money: &req.money,
            order_id: &req.order_id,
            capture_mode: req.capture_mode,
            customer_email: req.customer_email.as_deref(),
            customer_phone: req.customer_phone.as_deref(),
            notification_url,
            redirection_url: self.config.redirection_url(),
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
        self.tx_result(&payload, Some(reference), None)
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
            notification_url: self.config.notification_url(),
            redirection_url: Some(req.success_url.as_str()),
            metadata: &req.metadata,
            is_checkout_session: true,
        };
        self.execute_intention(spec).await
    }

    async fn capture(&self, req: &CaptureRequest) -> Result<PaymentResult, PaymentError> {
        req.validate()?;
        let tx_id = self.resolve_numeric_tx_id(&req.reference).await?;
        let amount_cents = self.resolve_capture_amount_cents(tx_id, req.amount.as_ref()).await?;
        let url = format!("{}{CAPTURE_PATH}", self.api_base_url);
        let http = self.http.clone();
        let response = self
            .auth_manager
            .execute_with_auth_retry(move |token| {
                let (client, target) = (http.clone(), url.clone());
                async move {
                    let body = CaptureApiRequest {
                        auth_token: token.expose_secret(),
                        transaction_id: tx_id,
                        amount_cents,
                    };
                    client.post(&target).bearer_auth(token.expose_secret()).json(&body).send().await
                }
            })
            .await
            .map_err(|err| map_dual_auth_error(&self.id, err))?;
        let payload: PaymobTransactionPayload = parse_api_response(&self.id, "capture", response).await?;
        let fallback_currency = req.amount.as_ref().map(|m| m.currency().as_str());
        self.tx_result(&payload, Some(&req.reference), fallback_currency)
    }

    async fn void_payment(&self, req: &VoidRequest) -> Result<PaymentResult, PaymentError> {
        req.validate()?;
        let tx_id = self.resolve_numeric_tx_id(&req.reference).await?;
        let body = VoidApiRequest { transaction_id: tx_id };
        let payload: PaymobTransactionPayload =
            self.post_with_secret_key(VOID_PATH, "void_payment", &body).await?;
        self.tx_result(&payload, Some(&req.reference), None)
    }

    async fn refund(&self, req: &RefundRequest) -> Result<RefundResult, PaymentError> {
        req.validate()?;
        let tx_id = self.resolve_numeric_tx_id(&req.reference).await?;
        let amount_cents = match &req.amount {
            Some(money) => money.amount(),
            None => self.resolve_remaining_refund_cents(tx_id).await?,
        };
        let body = RefundApiRequest { transaction_id: tx_id, amount_cents };
        let payload: PaymobTransactionPayload =
            self.post_with_secret_key(REFUND_PATH, "refund", &body).await?;
        let ctx = RefundExecutionContext { tx_id, amount_cents };
        build_refund_result(&self.id, ctx, req, &payload)
    }

    async fn parse_and_verify_webhook(
        &self,
        raw: &RawWebhookRequest,
    ) -> Result<NormalizedWebhookEvent, PaymentError> {
        parse_and_verify_paymob_webhook(&self.id, &self.config, raw)
    }
}

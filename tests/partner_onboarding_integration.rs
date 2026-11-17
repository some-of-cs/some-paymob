#![forbid(unsafe_code)]
#![cfg(all(
    feature = "onboarding",
    feature = "intentions",
    feature = "inquiries",
    feature = "manage"
))]
//! End-to-end integration, boundary, security, and negative tests for Module 6
//! (`src/resources/onboarding/`).

use serde_json::{Map, Value};
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

use some_paymob::prelude::*;
use some_paymob::resources::inquiries::by_order::TransactionInquiryParams as OrderInquiryParams;
use some_paymob::resources::manage::refund::RefundParams;
use some_paymob::resources::manage::void_capture::{CaptureParams, VoidParams};

fn mock_region(base_url: &str) -> PaymobRegion {
    PaymobRegion::Custom {
        accept_base_url: base_url.to_owned(),
        checkout_base_url: format!("{base_url}/unifiedcheckout/"),
        payouts_base_url: base_url.to_owned(),
        payouts_staging_base_url: base_url.to_owned(),
    }
}

fn build_partner_client(base_url: &str, api_key: &str, bearer: Option<&str>) -> PaymobClient {
    let creds = match bearer {
        Some(tok) => PartnerCredentials::with_bearer_token(api_key, tok).expect("valid creds"),
        None => PartnerCredentials::new(api_key).expect("valid creds"),
    };
    let config = ClientConfig::builder()
        .region(mock_region(base_url))
        .partner_credentials(creds)
        .max_retries(0)
        .build()
        .expect("valid config");
    PaymobClient::new(config).expect("valid client")
}

async fn mount_partner_auth_mocks(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/api/auth/tokens"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "token": "jwt_partner_live_001"
        })))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path("/api/auth/api_keys"))
        .and(header("authorization", "Bearer jwt_partner_live_001"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "api_key": "pk_partner_e2e_777",
            "label": "e2e-key"
        })))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/auth/hmac_secret/get_hmac"))
        .and(header("authorization", "Bearer jwt_partner_live_001"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "label": "primary-hmac",
            "status": "Created",
            "code": 201,
            "body": { "hmac_secret": "E2E_HMAC_SECRET_HEX_998877" }
        })))
        .mount(server)
        .await;
}

async fn mount_partner_flow_mocks(server: &MockServer) {
    for (endpoint, status, body) in [
        (
            "/api/onboarding/register",
            201_u16,
            serde_json::json!({
                "paymob_mid": 777888,
                "partner": "KeyPartner",
                "status": "pending_kyc"
            }),
        ),
        (
            "/api/onboarding/flow/step",
            200_u16,
            serde_json::json!({
                "paymob_mid": 777888,
                "step_id": "kyc_docs",
                "status": "completed",
                "completed": true
            }),
        ),
    ] {
        Mock::given(method("POST"))
            .and(path(endpoint))
            .and(header("x-api-key", "pk_partner_e2e_777"))
            .respond_with(ResponseTemplate::new(status).set_body_json(body))
            .mount(server)
            .await;
    }

    Mock::given(method("GET"))
        .and(path("/api/onboarding/flow/schema"))
        .and(query_param("partner", "KeyPartner"))
        .and(query_param("paymob_mid", "777888"))
        .and(header("x-api-key", "pk_partner_e2e_777"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "partner": "KeyPartner",
            "resubmission": false,
            "steps": [
                {
                    "step_id": "kyc_docs",
                    "order": 1,
                    "fields": [{"name": "tax_id", "type": "text", "required": true}]
                }
            ]
        })))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/onboarding/merchant/777888"))
        .and(header("x-api-key", "pk_partner_e2e_777"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "paymob_mid": 777888,
            "status": "APPROVED",
            "is_live": true,
            "live_integration_ids": [4097558],
            "test_integration_ids": [100200],
            "pending_steps": []
        })))
        .mount(server)
        .await;
}

async fn mount_scoped_intentions_and_inquiries_mocks(server: &MockServer) {
    for (verb, status, state) in [("POST", 201_u16, "intended"), ("PUT", 200_u16, "updated")] {
        Mock::given(method(verb))
            .and(path("/v1/intention/"))
            .and(header("x-api-key", "pk_partner_e2e_777"))
            .and(header("x-paymob-merchant-id", "777888"))
            .and(header("x-merchant-id", "777888"))
            .respond_with(
                ResponseTemplate::new(status).set_body_json(serde_json::json!({
                    "id": "pi_e2e_1",
                    "intention_order_id": 9001,
                    "client_secret": "egy_csk_test_e2e",
                    "status": state
                })),
            )
            .mount(server)
            .await;
    }

    Mock::given(method("GET"))
        .and(path("/api/acceptance/transactions/555"))
        .and(header("x-api-key", "pk_partner_e2e_777"))
        .and(header("x-paymob-merchant-id", "777888"))
        .and(header("x-merchant-id", "777888"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": 555,
            "amount_cents": 15000,
            "success": true
        })))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path("/api/ecommerce/orders/transaction_inquiry"))
        .and(header("x-api-key", "pk_partner_e2e_777"))
        .and(header("x-paymob-merchant-id", "777888"))
        .and(header("x-merchant-id", "777888"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": 555,
            "amount_cents": 15000,
            "success": true,
            "currency": "EGP"
        })))
        .mount(server)
        .await;
}

async fn mount_scoped_manage_mocks(server: &MockServer) {
    for (endpoint, body) in [
        (
            "/api/acceptance/void_refund/void",
            serde_json::json!({
                "id": 556, "amount_cents": 15000, "is_voided": true, "is_void": true
            }),
        ),
        (
            "/api/acceptance/capture",
            serde_json::json!({"id": 557, "amount_cents": 10000, "is_capture": true}),
        ),
        (
            "/api/acceptance/void_refund/refund",
            serde_json::json!({"id": 558, "amount_cents": 5000, "is_refund": true}),
        ),
    ] {
        Mock::given(method("POST"))
            .and(path(endpoint))
            .and(header("x-api-key", "pk_partner_e2e_777"))
            .and(header("x-paymob-merchant-id", "777888"))
            .and(header("x-merchant-id", "777888"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(server)
            .await;
    }
}

async fn verify_scoped_execution(scoped: &MerchantScopedClient, integration_id: u64) {
    let create_intent = CreateIntentionParams::builder()
        .amount(15_000_u64)
        .currency(Currency::EGP)
        .payment_methods(vec![PaymentMethodInput::IntegrationId(integration_id)])
        .billing_data(
            BillingData::builder()
                .phone_number("+201116491564")
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();
    let intent = scoped.intentions().create(&create_intent).await.unwrap();
    assert_eq!(intent.id, "pi_e2e_1");

    let update_intent = UpdateIntentionParams::builder()
        .amount(20_000_u64)
        .build()
        .unwrap();
    let updated = scoped.intentions().update(&update_intent).await.unwrap();
    assert_eq!(updated.status, "updated");

    let raw_tx = scoped.inquiries().transaction_by_id(555).await.unwrap();
    assert_eq!(raw_tx["id"], 555);
    let typed_tx = scoped.inquiries().transaction(555).await.unwrap();
    assert_eq!(typed_tx.amount_cents, 15_000);
    let by_order_tx = scoped
        .inquiries()
        .by_order(&OrderInquiryParams::by_order_id(9001))
        .await
        .unwrap();
    assert_eq!(by_order_tx.id, 555);

    let raw_void = scoped.manage().void_transaction(555).await.unwrap();
    assert_eq!(raw_void["is_voided"], true);
    let typed_void = scoped.manage().void(&VoidParams::new(555)).await.unwrap();
    assert!(typed_void.is_void);
    let captured = scoped
        .manage()
        .capture(&CaptureParams::new(555, 10_000))
        .await
        .unwrap();
    assert!(captured.is_capture);
    let refunded = scoped
        .manage()
        .refund(&RefundParams::new(555, 5_000))
        .await
        .unwrap();
    assert!(refunded.is_refund);
}

async fn execute_partner_auth_phase(base_url: &str) -> String {
    let unauth_client = PaymobClient::new(
        ClientConfig::builder()
            .region(mock_region(base_url))
            .max_retries(0)
            .build()
            .unwrap(),
    )
    .unwrap();

    let creds = PartnerLoginCredentials::try_new("partner@acme.io", "top-secret-pw").unwrap();
    let tok_resp = unauth_client
        .onboarding()
        .auth()
        .login(creds)
        .await
        .unwrap();
    assert_eq!(tok_resp.token(), "jwt_partner_live_001");

    let bearer_client = build_partner_client(base_url, "pk_bootstrap", Some(tok_resp.token()));
    let key_resp = bearer_client
        .onboarding()
        .auth()
        .create_api_key(CreatePartnerApiKeyParams::new().with_label("e2e-key"))
        .await
        .unwrap();
    assert_eq!(key_resp.api_key(), "pk_partner_e2e_777");

    let hmac_env = bearer_client
        .onboarding()
        .auth()
        .retrieve_hmac_secret()
        .await
        .unwrap();
    assert_eq!(hmac_env.hmac_secret(), "E2E_HMAC_SECRET_HEX_998877");
    key_resp.api_key().to_owned()
}

#[tokio::test]
async fn e2e_partner_onboarding_lifecycle_and_scoped_operations() {
    let server = MockServer::start().await;
    mount_partner_auth_mocks(&server).await;
    mount_partner_flow_mocks(&server).await;
    mount_scoped_intentions_and_inquiries_mocks(&server).await;
    mount_scoped_manage_mocks(&server).await;

    let partner_api_key = execute_partner_auth_phase(&server.uri()).await;
    let partner_client = build_partner_client(&server.uri(), &partner_api_key, None);
    let reg_params = RegisterMerchantParams::new(
        "KeyPartner",
        "merchant@sub.example",
        "+201116491564",
        "Nadia",
        "Saleh",
    )
    .unwrap()
    .with_company_name("Nadia Stores")
    .with_country("EGY");
    let registered = partner_client
        .onboarding()
        .flow()
        .register_merchant(&reg_params)
        .await
        .unwrap();
    assert_eq!(registered.paymob_mid, 777_888);

    let schema_query = OnboardingSchemaQuery::new("KeyPartner")
        .unwrap()
        .with_paymob_mid(registered.paymob_mid);
    let schema = partner_client
        .onboarding()
        .flow()
        .get_schema(&schema_query)
        .await
        .unwrap();
    assert_eq!(schema.steps.len(), 1);

    let mut step_data = Map::new();
    step_data.insert("tax_id".into(), Value::String("TX-777888".into()));
    let step_params =
        SubmitOnboardingStepParams::new(registered.paymob_mid, "kyc_docs", step_data).unwrap();
    let step_resp = partner_client
        .onboarding()
        .flow()
        .submit_step(&step_params)
        .await
        .unwrap();
    assert_eq!(step_resp.completed, Some(true));

    let inquiry = partner_client
        .onboarding()
        .flow()
        .merchant_inquiry(registered.paymob_mid)
        .await
        .unwrap();
    assert!(inquiry.is_approved());
    assert!(inquiry.has_live_integrations());

    let scoped = partner_client.with_merchant(registered.paymob_mid).unwrap();
    verify_scoped_execution(&scoped, inquiry.live_integration_ids[0]).await;
}

#[test]
fn boundary_and_deserialization_security_cases() {
    let min_client = build_partner_client("https://accept.paymob.com", "pk_test", None);
    assert_eq!(min_client.with_merchant(1).unwrap().merchant_id(), 1);
    assert_eq!(
        min_client.with_merchant(u64::MAX).unwrap().merchant_id(),
        u64::MAX
    );

    let empty_schema: OnboardingFlowSchema = serde_json::from_str(r#"{"steps":[]}"#).unwrap();
    assert!(empty_schema.partner.is_none());
    assert!(empty_schema.steps.is_empty());

    let approved_upper: PartnerMerchantInquiryResponse = serde_json::from_str(
        r#"{"paymob_mid": 1, "status": "APPROVED", "live_integration_ids": []}"#,
    )
    .unwrap();
    assert!(approved_upper.is_approved());
    assert!(!approved_upper.has_live_integrations());

    let active_mixed: PartnerMerchantInquiryResponse = serde_json::from_str(
        r#"{"paymob_mid": 999999999999, "status": "Active", "live_integration_ids": [1]}"#,
    )
    .unwrap();
    assert!(active_mixed.is_approved());
    assert!(active_mixed.has_live_integrations());

    let live_flag_only: PartnerMerchantInquiryResponse =
        serde_json::from_str(r#"{"paymob_mid": 42, "status": "pending", "is_live": true}"#)
            .unwrap();
    assert!(live_flag_only.is_approved());

    assert!(serde_json::from_str::<PartnerAuthTokenResponse>(r#"{"token":""}"#).is_err());
    assert!(serde_json::from_str::<PartnerAuthTokenResponse>(r#"{"token":"   "}"#).is_err());
    assert!(serde_json::from_str::<PartnerAuthTokenResponse>(r#"{"token":"a\nb"}"#).is_err());
    assert!(serde_json::from_str::<PartnerApiKeyResponse>(r#"{"api_key":"\t"}"#).is_err());
    assert!(serde_json::from_str::<PartnerHmacBody>(r#"{"hmac_secret":""}"#).is_err());
    assert!(serde_json::from_str::<RegisteredMerchantResponse>(r#"{"paymob_mid":0}"#).is_err());
    assert!(serde_json::from_str::<PartnerMerchantInquiryResponse>(r#"{"paymob_mid":0}"#).is_err());
}

async fn mount_error_status_mocks(server: &MockServer) {
    for (status, body) in [
        (400_u16, r#"{"detail":"bad request"}"#),
        (401_u16, r#"{"detail":"unauthorized"}"#),
        (403_u16, r#"{"detail":"forbidden"}"#),
        (404_u16, r#"{"detail":"not found"}"#),
        (422_u16, r#"{"detail":"unprocessable"}"#),
        (500_u16, r#"{"detail":"internal server error"}"#),
        (502_u16, "Bad Gateway"),
    ] {
        Mock::given(method("GET"))
            .and(path(format!("/api/onboarding/merchant/{status}")))
            .respond_with(ResponseTemplate::new(status).set_body_string(body))
            .mount(server)
            .await;
    }

    Mock::given(method("GET"))
        .and(path("/api/onboarding/merchant/429"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("Retry-After", "17")
                .set_body_string(r#"{"detail":"throttled"}"#),
        )
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/onboarding/merchant/999"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{truncated-json"))
        .mount(server)
        .await;
}

#[tokio::test]
async fn negative_http_status_codes_retry_after_and_malformed_json() {
    let server = MockServer::start().await;
    mount_error_status_mocks(&server).await;

    let client = build_partner_client(&server.uri(), "pk_partner_err", None);
    let flow = client.onboarding().flow();

    assert!(matches!(
        flow.merchant_inquiry(400).await.unwrap_err(),
        PaymobError::ApiError { status: 400, .. }
    ));
    assert!(
        flow.merchant_inquiry(401)
            .await
            .unwrap_err()
            .is_auth_error()
    );
    assert!(
        flow.merchant_inquiry(403)
            .await
            .unwrap_err()
            .is_auth_error()
    );
    assert!(matches!(
        flow.merchant_inquiry(404).await.unwrap_err(),
        PaymobError::ApiError { status: 404, .. }
    ));
    assert!(matches!(
        flow.merchant_inquiry(422).await.unwrap_err(),
        PaymobError::ApiError { status: 422, .. }
    ));
    assert!(matches!(
        flow.merchant_inquiry(500).await.unwrap_err(),
        PaymobError::ApiError { status: 500, .. }
    ));

    let rate_err = flow.merchant_inquiry(429).await.unwrap_err();
    assert!(rate_err.is_rate_limited());
    assert_eq!(rate_err.retry_after_secs(), Some(17));

    let gw_err = flow.merchant_inquiry(502).await.unwrap_err();
    assert!(gw_err.is_retryable());

    assert!(
        flow.merchant_inquiry(999)
            .await
            .unwrap_err()
            .is_validation_error()
    );
}

#[tokio::test]
async fn concurrent_cross_tenant_isolation_between_scoped_merchants() {
    let server = MockServer::start().await;

    for (tx_id, mid, amount) in [(10_u64, "111", 11_100_u64), (20_u64, "222", 22_200_u64)] {
        Mock::given(method("GET"))
            .and(path(format!("/api/acceptance/transactions/{tx_id}")))
            .and(header("x-api-key", "pk_shared_partner"))
            .and(header("x-paymob-merchant-id", mid))
            .and(header("x-merchant-id", mid))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": tx_id,
                "amount_cents": amount,
                "success": true
            })))
            .mount(&server)
            .await;
    }

    let client = build_partner_client(&server.uri(), "pk_shared_partner", None);
    let tenant_a = client.with_merchant(111).unwrap();
    let tenant_b = client.with_merchant(222).unwrap();

    let inq_a = tenant_a.inquiries();
    let inq_b = tenant_b.inquiries();
    let (res_a, res_b) = tokio::join!(inq_a.transaction(10), inq_b.transaction(20));

    let tx_a = res_a.expect("tenant 111 request succeeds");
    let tx_b = res_b.expect("tenant 222 request succeeds");
    assert_eq!(tx_a.amount_cents, 11_100);
    assert_eq!(tx_b.amount_cents, 22_200);
    assert_eq!(tenant_a.merchant_id(), 111);
    assert_eq!(tenant_b.merchant_id(), 222);
}

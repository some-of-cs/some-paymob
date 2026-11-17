#![forbid(unsafe_code)]
//! Cross-unit integration tests for User Story `US-8.2.0` (`test-utils` feature).

#[cfg(feature = "test-utils")]
mod suite {
    use std::time::Duration;

    use secrecy::{ExposeSecret, SecretString};
    use serde_json::{Value, json};
    use some_paymob::core::auth::accept_jwt::{AcceptJwtError, AcceptJwtProvider};
    use some_paymob::core::client::PaymobClient;
    use some_paymob::core::config::ClientConfig;
    use some_paymob::core::credentials::{PublicKey, SecretKey};
    use some_paymob::core::http::{HttpClient, HttpClientConfig, HttpRequest, RetryPolicy};
    use some_paymob::core::types::MinorUnitAmount;
    use some_paymob::test_utils::{
        MockHost, PaymobMockServer, SandboxCheckRequest, SandboxConstraintError, SandboxGuard,
        SandboxPaymentChannel, SandboxWarning, WebhookVectorProtocol, all_official_vectors,
        generate_signed_subscription_post, generate_signed_transaction_post,
    };
    use some_paymob::webhooks::PaymobWebhookEngine;

    async fn send_inquiry(
        client: &reqwest::Client,
        url: &str,
        tok: &SecretString,
    ) -> Result<reqwest::Response, AcceptJwtError> {
        Ok(client
            .post(url)
            .json(&json!({ "auth_token": tok.expose_secret() }))
            .send()
            .await?)
    }

    #[test]
    fn ac_1_official_test_vectors_roundtrip_and_redaction() {
        for (protocol, vector) in all_official_vectors() {
            vector
                .verify(protocol)
                .expect("every embedded official Paymob vector must verify");
            let dbg = format!("{vector:?}");
            assert!(dbg.contains("[REDACTED]"));
        }
    }

    #[tokio::test]
    async fn ac_2_mock_server_drives_paymob_client_jwt_refresh_and_429_backoff() {
        let server = PaymobMockServer::start().await;
        server
            .mount_accept_auth_sequence(&["stale-jwt", "fresh-jwt"])
            .await;
        server
            .mount_jwt_expiry_then_ok(
                "POST",
                "/api/ecommerce/orders/transaction_inquiry",
                1,
                json!({ "id": 192036465, "success": true }),
            )
            .await;
        server
            .mount_payouts_429_then_ok(
                "GET",
                "/api/secure/budget/",
                1,
                Some(0),
                "Too many requests",
                "429",
                json!({ "available_cents": 100_000 }),
            )
            .await;
        server
            .mount_json(
                MockHost::Accept,
                "POST",
                "/v1/intention/",
                201,
                json!({ "id": "pi_820" }),
            )
            .await;

        let config = ClientConfig::builder()
            .region(server.custom_region())
            .secret_key(SecretKey::new("egy_sk_test_820").expect("valid key"))
            .public_key(PublicKey::new("egy_pk_test_820").expect("valid pk"))
            .build()
            .expect("valid config");
        let client = PaymobClient::new(config).expect("client initializes against mock");
        let accept_url = client
            .accept_url("/api/ecommerce/orders/transaction_inquiry")
            .expect("accept url");
        let payouts_url = client
            .payouts_url("/api/secure/budget/")
            .expect("payouts url");

        let jwt_provider =
            AcceptJwtProvider::new(&server.accept_uri(), SecretString::from("test_api_key"))
                .expect("provider");
        let reqwest_client = reqwest::Client::new();
        let jwt_resp = jwt_provider
            .execute_with_retry(|tok| {
                let c = reqwest_client.clone();
                let u = accept_url.to_string();
                async move { send_inquiry(&c, &u, &tok).await }
            })
            .await
            .expect("401 triggers refresh and succeeds");
        assert_eq!(jwt_resp.status().as_u16(), 200);

        let http = HttpClient::new(HttpClientConfig {
            allow_insecure_http: true,
            retry: RetryPolicy {
                max_retries: 2,
                base_delay: Duration::from_millis(1),
                max_delay: Duration::from_millis(5),
            },
            ..HttpClientConfig::default()
        })
        .expect("http client");
        let req = HttpRequest::get(payouts_url.as_str()).expect("get req");
        let budget_resp = http.execute(&req).await.expect("429 recovers");
        let body: Value = budget_resp.json().expect("json");
        assert_eq!(body["available_cents"], 100_000);
    }

    #[test]
    fn ac_3_and_ac_4_sandbox_guard_and_webhook_testing_tool_integration() {
        let warn_report = SandboxGuard::check_constraints(&SandboxCheckRequest {
            is_sandbox: true,
            credential_age_days: 27,
            channel: SandboxPaymentChannel::Card,
        });
        assert!(warn_report.is_ok());
        assert_eq!(
            warn_report.warnings,
            vec![SandboxWarning::CredentialExpiringSoon {
                age_days: 27,
                days_remaining: 3,
            }]
        );

        let blocked = SandboxGuard::check_constraints(&SandboxCheckRequest {
            is_sandbox: true,
            credential_age_days: 31,
            channel: SandboxPaymentChannel::Bnpl,
        });
        assert!(!blocked.is_ok());
        assert_eq!(
            blocked.errors,
            vec![
                SandboxConstraintError::CredentialExpired { age_days: 31 },
                SandboxConstraintError::UnsupportedSandboxChannel { channel: "BNPL" },
            ]
        );

        let secret = SecretString::from("integration_hmac_secret");
        let tx = generate_signed_transaction_post(
            &secret,
            192036465,
            217503754,
            MinorUnitAmount::new(100_000),
            "EGP",
            true,
        )
        .expect("signed tx");
        let sub = generate_signed_subscription_post(
            &secret,
            "req-int-1",
            1264,
            "suspended",
            MinorUnitAmount::new(330),
        )
        .expect("signed sub");

        let engine = PaymobWebhookEngine::new("integration_hmac_secret").expect("engine");
        assert!(
            engine
                .verify_transaction_post(&tx.json_body, &tx.hmac_hex)
                .is_ok()
        );
        assert!(engine.verify_subscription(&sub.json_body).is_ok());
        assert!(format!("{tx:?}").contains("[REDACTED]"));
        let _ = WebhookVectorProtocol::TransactionPost;
    }
}

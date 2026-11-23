#![forbid(unsafe_code)]
use std::sync::Arc;
use std::time::Duration;

use reqwest::{Client, StatusCode};
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};
use wiremock::matchers::{body_string_contains, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use some_paymob::core::auth::cache::{CachedToken, TokenCache};
use some_paymob::core::auth::payouts_oauth::{
    PAYOUTS_OAUTH_TOKEN_PATH, PayoutsCredentials, PayoutsOAuthError, PayoutsOAuthProvider,
    format_basic_auth_header,
};

struct PayoutsMockSpec<'a> {
    grant_type: &'a str,
    extra_body_fragment: &'a str,
    response_body: Value,
    status: u16,
    expected: u64,
}

fn default_payouts_creds() -> PayoutsCredentials {
    PayoutsCredentials::new("cid", "csec", "alice", "s3cr3t").expect("valid payouts credentials")
}

fn provider_with_cache(server: &MockServer, cache: Arc<TokenCache>) -> PayoutsOAuthProvider {
    PayoutsOAuthProvider::with_client_and_cache(
        &server.uri(),
        default_payouts_creds(),
        Client::new(),
        cache,
    )
    .expect("valid payouts provider")
}

fn payouts_token_json(access: &str, refresh: Option<&str>, expires_in: u64) -> Value {
    json!({
        "access_token": access,
        "refresh_token": refresh,
        "expires_in": expires_in,
    })
}

async fn mount_payouts_grant_mock(server: &MockServer, spec: PayoutsMockSpec<'_>) {
    Mock::given(method("POST"))
        .and(path(PAYOUTS_OAUTH_TOKEN_PATH))
        .and(header("authorization", "Basic Y2lkOmNzZWM="))
        .and(body_string_contains(format!(
            "grant_type={}",
            spec.grant_type
        )))
        .and(body_string_contains(spec.extra_body_fragment))
        .respond_with(ResponseTemplate::new(spec.status).set_body_json(spec.response_body))
        .expect(spec.expected)
        .mount(server)
        .await;
}

#[tokio::test]
async fn tc_1_2_4_payouts_password_grant_single_flight_20_tasks() {
    let server = MockServer::start().await;
    mount_payouts_grant_mock(
        &server,
        PayoutsMockSpec {
            grant_type: "password",
            extra_body_fragment: "username=alice",
            response_body: payouts_token_json("po-acc-1", Some("po-ref-1"), 3600),
            status: 200,
            expected: 1,
        },
    )
    .await;

    Mock::given(method("GET"))
        .and(path("/api/secure/disburse/status/"))
        .and(header("authorization", "Bearer po-acc-1"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let provider = Arc::new(
        PayoutsOAuthProvider::new(&server.uri(), default_payouts_creds())
            .expect("valid payouts provider"),
    );

    let mut handles = Vec::with_capacity(20);
    for _ in 0..20 {
        let p = Arc::clone(&provider);
        handles.push(tokio::spawn(async move { p.access_token().await }));
    }
    let mut tokens = Vec::with_capacity(20);
    for handle in handles {
        let tok = handle.await.expect("join").expect("access_token");
        tokens.push(tok.expose_secret().to_owned());
    }
    assert!(tokens.iter().all(|tok| tok == "po-acc-1"));

    let url = format!("{}/api/secure/disburse/status/", server.uri());
    let req = provider
        .attach_bearer_header(Client::new().get(url))
        .await
        .expect("attach payouts bearer");
    assert_eq!(req.send().await.expect("send").status(), StatusCode::OK);
}

#[tokio::test]
async fn tc_1_2_4_payouts_refresh_token_renewal() {
    let server = MockServer::start().await;
    mount_payouts_grant_mock(
        &server,
        PayoutsMockSpec {
            grant_type: "password",
            extra_body_fragment: "username=alice",
            response_body: payouts_token_json("po-acc-1", Some("po-ref-1"), 10),
            status: 200,
            expected: 1,
        },
    )
    .await;
    mount_payouts_grant_mock(
        &server,
        PayoutsMockSpec {
            grant_type: "refresh_token",
            extra_body_fragment: "refresh_token=po-ref-1",
            response_body: payouts_token_json("po-acc-2", Some("po-ref-2"), 3600),
            status: 200,
            expected: 1,
        },
    )
    .await;

    let cache = Arc::new(TokenCache::with_refresh_margin(Duration::from_secs(60)));
    let provider = provider_with_cache(&server, cache);

    assert_eq!(
        provider
            .access_token()
            .await
            .expect("initial")
            .expose_secret(),
        "po-acc-1"
    );
    let rt = provider
        .cache()
        .peek()
        .and_then(|t| t.refresh_token.clone());
    provider.cache().store(CachedToken::with_expires_at(
        "po-acc-1",
        rt,
        std::time::Instant::now() + Duration::from_secs(5),
    ));
    assert_eq!(
        provider
            .access_token()
            .await
            .expect("refreshed")
            .expose_secret(),
        "po-acc-2"
    );
}

#[tokio::test]
async fn tc_1_2_4_payouts_401_refresh_fallback_to_password() {
    let fallback_server = MockServer::start().await;
    mount_payouts_grant_mock(
        &fallback_server,
        PayoutsMockSpec {
            grant_type: "refresh_token",
            extra_body_fragment: "refresh_token=stale-ref",
            response_body: json!({ "error": "invalid_grant" }),
            status: 401,
            expected: 1,
        },
    )
    .await;
    mount_payouts_grant_mock(
        &fallback_server,
        PayoutsMockSpec {
            grant_type: "password",
            extra_body_fragment: "username=alice",
            response_body: payouts_token_json("po-fallback", Some("po-ref-3"), 3600),
            status: 200,
            expected: 1,
        },
    )
    .await;

    let fb_cache = Arc::new(TokenCache::with_refresh_margin(Duration::from_secs(60)));
    fb_cache.store(CachedToken::with_expires_at(
        "stale-acc",
        Some(SecretString::from("stale-ref")),
        std::time::Instant::now() + Duration::from_secs(5),
    ));
    let fb_provider = provider_with_cache(&fallback_server, fb_cache);
    assert_eq!(
        fb_provider
            .access_token()
            .await
            .expect("fallback password grant")
            .expose_secret(),
        "po-fallback"
    );
}

#[test]
fn tc_1_2_4_format_basic_auth_header_is_sensitive() {
    let basic = format_basic_auth_header(&SecretString::from("cid"), &SecretString::from("csec"))
        .expect("basic header");
    assert!(basic.is_sensitive());
    assert_eq!(basic.to_str().expect("ascii"), "Basic Y2lkOmNzZWM=");
}

#[test]
fn tc_1_2_4_payouts_rejects_empty_credentials() {
    assert!(matches!(
        PayoutsCredentials::new("", "csec", "alice", "pass"),
        Err(PayoutsOAuthError::EmptyCredential("client_id"))
    ));
    assert!(matches!(
        PayoutsCredentials::new("cid", "csec", "alice", "   "),
        Err(PayoutsOAuthError::EmptyCredential("password"))
    ));
}

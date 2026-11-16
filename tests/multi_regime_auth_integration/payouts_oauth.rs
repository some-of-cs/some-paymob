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

fn payouts_creds(
    client_id: &str,
    client_secret: &str,
    username: &str,
    password: &str,
) -> PayoutsCredentials {
    PayoutsCredentials::new(client_id, client_secret, username, password)
        .expect("valid payouts credentials")
}

fn payouts_token_json(access: &str, refresh: Option<&str>, expires_in: u64) -> Value {
    json!({
        "access_token": access,
        "refresh_token": refresh,
        "expires_in": expires_in,
    })
}

async fn mount_payouts_grant_mock(
    server: &MockServer,
    grant_type: &str,
    extra_body_fragment: &str,
    response_body: Value,
    status: u16,
    expected: u64,
) {
    Mock::given(method("POST"))
        .and(path(PAYOUTS_OAUTH_TOKEN_PATH))
        .and(header("authorization", "Basic Y2lkOmNzZWM="))
        .and(body_string_contains(format!("grant_type={grant_type}")))
        .and(body_string_contains(extra_body_fragment))
        .respond_with(ResponseTemplate::new(status).set_body_json(response_body))
        .expect(expected)
        .mount(server)
        .await;
}

#[tokio::test]
async fn tc_1_2_4_payouts_password_grant_single_flight_20_tasks() {
    let server = MockServer::start().await;
    mount_payouts_grant_mock(
        &server,
        "password",
        "username=alice",
        payouts_token_json("po-acc-1", Some("po-ref-1"), 3600),
        200,
        1,
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
        PayoutsOAuthProvider::new(&server.uri(), payouts_creds("cid", "csec", "alice", "s3cr3t"))
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
        "password",
        "username=alice",
        payouts_token_json("po-acc-1", Some("po-ref-1"), 10),
        200,
        1,
    )
    .await;
    mount_payouts_grant_mock(
        &server,
        "refresh_token",
        "refresh_token=po-ref-1",
        payouts_token_json("po-acc-2", Some("po-ref-2"), 3600),
        200,
        1,
    )
    .await;

    let cache = Arc::new(TokenCache::with_refresh_margin(Duration::from_secs(3600)));
    let provider = PayoutsOAuthProvider::with_client_and_cache(
        &server.uri(),
        payouts_creds("cid", "csec", "alice", "s3cr3t"),
        Client::new(),
        cache,
    )
    .expect("valid provider");

    assert_eq!(
        provider.access_token().await.expect("initial").expose_secret(),
        "po-acc-1"
    );
    assert_eq!(
        provider.access_token().await.expect("refreshed").expose_secret(),
        "po-acc-2"
    );
}

#[tokio::test]
async fn tc_1_2_4_payouts_401_refresh_fallback_to_password() {
    let fallback_server = MockServer::start().await;
    mount_payouts_grant_mock(
        &fallback_server,
        "refresh_token",
        "refresh_token=stale-ref",
        json!({ "error": "invalid_grant" }),
        401,
        1,
    )
    .await;
    mount_payouts_grant_mock(
        &fallback_server,
        "password",
        "username=alice",
        payouts_token_json("po-fallback", Some("po-ref-3"), 3600),
        200,
        1,
    )
    .await;

    let fb_cache = Arc::new(TokenCache::with_refresh_margin(Duration::from_secs(3600)));
    fb_cache.store(CachedToken::new(
        "stale-acc",
        Some(SecretString::from("stale-ref")),
        Duration::from_secs(5),
    ));
    let fb_provider = PayoutsOAuthProvider::with_client_and_cache(
        &fallback_server.uri(),
        payouts_creds("cid", "csec", "alice", "s3cr3t"),
        Client::new(),
        fb_cache,
    )
    .expect("valid fallback provider");
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

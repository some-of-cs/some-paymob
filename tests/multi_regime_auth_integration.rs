#![forbid(unsafe_code)]
//! Integration tests for US-1.2.0 (4-Regime Auth Strategy, Lock-Free Cache, Accept JWT,
//! Payouts OAuth2, Partner Auth, and zero secret leakage in `Debug`).

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use reqwest::{Client, Method, StatusCode};
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};
use url::Url;
use wiremock::matchers::{body_json, body_string_contains, header, method, path, query_param};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

use some_paymob::core::auth::accept_jwt::{
    ACCEPT_AUTH_TOKENS_PATH, AcceptJwtError, AcceptJwtProvider, format_bearer_header,
    inject_body_auth_token, is_incorrect_credentials_401,
};
use some_paymob::core::auth::cache::{
    CachedToken, DEFAULT_TOKEN_TTL_SECS, PROACTIVE_REFRESH_MARGIN_SECS, TokenCache,
};
use some_paymob::core::auth::partner::{
    DEFAULT_MERCHANT_ID_HEADER, DEFAULT_PARTNER_API_KEY_HEADER,
    DEFAULT_PARTNER_API_KEY_QUERY_PARAM, PartnerApiKeyLocation, PartnerAuthContext,
    PartnerAuthError, PartnerAuthMode,
};
use some_paymob::core::auth::payouts_oauth::{
    PAYOUTS_OAUTH_TOKEN_PATH, PayoutsCredentials, PayoutsOAuthError, PayoutsOAuthProvider,
    format_basic_auth_header,
};
use some_paymob::core::auth::strategy::{
    AuthRegime, AuthStrategy, EndpointAuthSpec, StrategyError, inject_secret_key_token,
};

const ACCEPT_INQUIRY_PATH: &str = "/api/ecommerce/orders/transaction_inquiry";

fn assert_redacted_debug<T: fmt::Debug>(value: &T, secrets: &[&str], expect_marker: bool) {
    let rendered = format!("{value:?}");
    for secret in secrets {
        assert!(!rendered.contains(secret), "Debug output leaked secret");
    }
    if expect_marker {
        assert!(
            rendered.contains("REDACTED"),
            "Debug output missing redaction marker: {rendered}"
        );
    }
}

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

async fn mount_accept_token_mock(server: &MockServer, api_key: &str, token: &str, expected: u64) {
    Mock::given(method("POST"))
        .and(path(ACCEPT_AUTH_TOKENS_PATH))
        .and(body_json(json!({ "api_key": api_key })))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({ "token": token })))
        .expect(expected)
        .mount(server)
        .await;
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

async fn send_accept_inquiry(
    provider: &AcceptJwtProvider,
    client: &Client,
    url: &str,
) -> Result<reqwest::Response, AcceptJwtError> {
    provider
        .execute_with_retry(|tok| {
            let client = client.clone();
            let url = url.to_owned();
            async move {
                let mut body = json!({ "order_id": 101 });
                inject_body_auth_token(&mut body, &tok)?;
                Ok(client.post(url).json(&body).send().await?)
            }
        })
        .await
}

// ============================================================================
// TC-1.2.1: AuthStrategy taxonomy, EndpointAuthSpec, and Regime 1 Token header
// ============================================================================

#[test]
fn tc_1_2_1_strategy_taxonomy_and_serde_roundtrip() {
    let matrix = [
        (
            AuthStrategy::SecretKeyToken,
            AuthRegime::Regime1SecretKey,
            true,
            true,
            "SecretKeyToken",
        ),
        (
            AuthStrategy::AcceptJwtBearer,
            AuthRegime::Regime2AcceptJwt,
            true,
            true,
            "AcceptJwtBearer",
        ),
        (
            AuthStrategy::AcceptJwtBody,
            AuthRegime::Regime2AcceptJwt,
            true,
            false,
            "AcceptJwtBody",
        ),
        (
            AuthStrategy::PayoutsOAuth2,
            AuthRegime::Regime3PayoutsOAuth2,
            true,
            true,
            "PayoutsOAuth2",
        ),
        (
            AuthStrategy::PartnerBearer,
            AuthRegime::Regime4Partner,
            true,
            true,
            "PartnerBearer",
        ),
        (
            AuthStrategy::PartnerApiKey,
            AuthRegime::Regime4Partner,
            true,
            false,
            "PartnerApiKey",
        ),
        (
            AuthStrategy::PublicKeyOnly,
            AuthRegime::Public,
            false,
            false,
            "PublicKeyOnly",
        ),
    ];

    for (strategy, regime, requires_secret, uses_auth, label) in matrix {
        assert_eq!(strategy.regime(), regime);
        assert_eq!(strategy.requires_secret(), requires_secret);
        assert_eq!(strategy.uses_authorization_header(), uses_auth);
        assert_eq!(strategy.as_str(), label);
        assert_eq!(strategy.to_string(), label);

        let encoded = serde_json::to_string(&strategy).expect("serialize strategy");
        let decoded: AuthStrategy =
            serde_json::from_str(&encoded).expect("deserialize strategy");
        assert_eq!(decoded, strategy);
    }
}

#[test]
fn tc_1_2_1_endpoint_spec_validation_and_strategy_segregation() {
    let invalid_paths = ["", "v1/intention/", "/v1/bad path", "/v1/bad\npath"];
    for bad in invalid_paths {
        assert!(
            EndpointAuthSpec::new(bad, Method::POST, AuthStrategy::SecretKeyToken).is_err(),
            "expected invalid endpoint path rejection for {bad:?}"
        );
    }

    let secret = SecretString::from("egy_sk_test_segregation_01");
    let non_regime_1 = [
        AuthStrategy::AcceptJwtBearer,
        AuthStrategy::AcceptJwtBody,
        AuthStrategy::PayoutsOAuth2,
        AuthStrategy::PartnerBearer,
        AuthStrategy::PartnerApiKey,
        AuthStrategy::PublicKeyOnly,
    ];
    for strategy in non_regime_1 {
        let spec = EndpointAuthSpec::new("/api/test", Method::POST, strategy).expect("valid spec");
        let mut headers = HeaderMap::new();
        let err = spec
            .apply_secret_key(&mut headers, &secret)
            .expect_err("non-Regime-1 strategy must reject Regime 1 secret key");
        assert_eq!(
            err,
            StrategyError::StrategyMismatch {
                expected: AuthStrategy::SecretKeyToken,
                actual: strategy,
            }
        );
        assert!(!headers.contains_key(AUTHORIZATION));
    }
}

#[tokio::test]
async fn tc_1_2_1_regime_1_wire_header_injection() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/intention/"))
        .and(header("authorization", "Token egy_sk_test_wire_99"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({ "id": "int_1" })))
        .expect(1)
        .mount(&server)
        .await;

    let spec = EndpointAuthSpec::new("/v1/intention/", Method::POST, AuthStrategy::SecretKeyToken)
        .expect("valid intention spec");
    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer stale"));

    let secret = SecretString::from("egy_sk_test_wire_99");
    spec.apply_secret_key(&mut headers, &secret)
        .expect("Regime 1 header injection succeeds");
    let auth_val = headers.get(AUTHORIZATION).expect("authorization header");
    assert!(auth_val.is_sensitive());

    let url = format!("{}{}", server.uri(), spec.path());
    let resp = Client::new()
        .request(spec.method().clone(), url)
        .headers(headers)
        .send()
        .await
        .expect("intention request succeeds");
    assert_eq!(resp.status(), StatusCode::CREATED);
}

// ============================================================================
// TC-1.2.2: Lock-free TokenCache single-flight & 401 eviction
// ============================================================================

#[tokio::test]
async fn tc_1_2_2_token_cache_single_flight_50_tasks_and_eviction() {
    assert_eq!(DEFAULT_TOKEN_TTL_SECS, 3600);
    assert_eq!(PROACTIVE_REFRESH_MARGIN_SECS, 60);

    let cache = Arc::new(TokenCache::new());
    let refresh_calls = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::with_capacity(50);

    for _ in 0..50 {
        let cache_ref = Arc::clone(&cache);
        let calls_ref = Arc::clone(&refresh_calls);
        handles.push(tokio::spawn(async move {
            cache_ref
                .get_or_refresh(|| async move {
                    calls_ref.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(15)).await;
                    Ok::<_, &str>(CachedToken::with_default_ttl("sf-jwt-1", None))
                })
                .await
        }));
    }

    for handle in handles {
        let tok = handle
            .await
            .expect("task join")
            .expect("single-flight refresh");
        assert_eq!(tok.access_token.expose_secret(), "sf-jwt-1");
    }
    assert_eq!(refresh_calls.load(Ordering::SeqCst), 1);

    let fast = cache.get_if_fresh().expect("cached token is fresh");
    assert_eq!(fast.access_token.expose_secret(), "sf-jwt-1");

    cache.evict();
    assert!(cache.get_if_fresh().is_none());
    assert!(cache.peek().is_none());

    let after_evict = cache
        .get_or_refresh(|| async { Ok::<_, &str>(CachedToken::with_default_ttl("sf-jwt-2", None)) })
        .await
        .expect("post-eviction refresh");
    assert_eq!(after_evict.access_token.expose_secret(), "sf-jwt-2");
}

#[tokio::test]
async fn tc_1_2_2_token_cache_proactive_margin_and_error_recovery() {
    let cache = TokenCache::new();
    let soon = Instant::now() + Duration::from_secs(30);
    cache.store(CachedToken::with_expires_at("expiring-soon", None, soon));
    assert!(cache.get_if_fresh().is_none());

    let err = cache
        .get_or_refresh(|| async { Err::<CachedToken, &str>("upstream 503") })
        .await
        .expect_err("refresh failure propagates");
    assert_eq!(err, "upstream 503");

    let recovered = cache
        .get_or_refresh(|| async {
            Ok::<_, &str>(CachedToken::with_default_ttl("recovered-jwt", None))
        })
        .await
        .expect("cache is not poisoned after failed refresh");
    assert_eq!(recovered.access_token.expose_secret(), "recovered-jwt");
}

// ============================================================================
// TC-1.2.3: AcceptJwtProvider 401 refresh, Bearer header, & body auth_token
// ============================================================================

#[tokio::test]
async fn tc_1_2_3_accept_jwt_bearer_and_body_injection() {
    let server = MockServer::start().await;
    mount_accept_token_mock(&server, "accept-key-1", "jwt-v1", 1).await;

    Mock::given(method("GET"))
        .and(path("/api/acceptance/transactions/42"))
        .and(header("authorization", "Bearer jwt-v1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": 42 })))
        .expect(1)
        .mount(&server)
        .await;

    let provider =
        AcceptJwtProvider::new(&server.uri(), SecretString::from("accept-key-1"))
            .expect("valid provider");
    let client = Client::new();
    let tx_url = format!("{}/api/acceptance/transactions/42", server.uri());
    let req = provider
        .attach_bearer_header(client.get(tx_url))
        .await
        .expect("attach bearer header");
    assert_eq!(req.send().await.expect("send").status(), StatusCode::OK);

    let mut inquiry_body = json!({ "transaction_id": 42 });
    provider
        .attach_body_auth_token(&mut inquiry_body)
        .await
        .expect("attach body auth_token");
    assert_eq!(inquiry_body["auth_token"], "jwt-v1");
}

#[tokio::test]
async fn tc_1_2_3_accept_jwt_401_eviction_and_single_retry() {
    let server = MockServer::start().await;
    let auth_calls = Arc::new(AtomicUsize::new(0));
    let auth_calls_clone = Arc::clone(&auth_calls);

    Mock::given(method("POST"))
        .and(path(ACCEPT_AUTH_TOKENS_PATH))
        .respond_with(move |_req: &Request| {
            let n = auth_calls_clone.fetch_add(1, Ordering::SeqCst);
            let tok = if n == 0 { "stale-jwt" } else { "fresh-jwt" };
            ResponseTemplate::new(201).set_body_json(json!({ "token": tok }))
        })
        .expect(2)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path(ACCEPT_INQUIRY_PATH))
        .and(body_json(json!({ "order_id": 101, "auth_token": "stale-jwt" })))
        .respond_with(
            ResponseTemplate::new(401).set_body_json(json!({ "detail": "incorrect credentials" })),
        )
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path(ACCEPT_INQUIRY_PATH))
        .and(body_json(json!({ "order_id": 101, "auth_token": "fresh-jwt" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": 101 })))
        .expect(1)
        .mount(&server)
        .await;

    let provider =
        AcceptJwtProvider::new(&server.uri(), SecretString::from("accept-key-401"))
            .expect("valid provider");
    let client = Client::new();
    let inquiry_url = format!("{}{ACCEPT_INQUIRY_PATH}", server.uri());
    let resp = send_accept_inquiry(&provider, &client, &inquiry_url)
        .await
        .expect("401 retry succeeds");

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(auth_calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        provider.token().await.expect("cached fresh").expose_secret(),
        "fresh-jwt"
    );
}

#[test]
fn tc_1_2_3_accept_jwt_helpers_and_validation() {
    assert!(is_incorrect_credentials_401(
        StatusCode::UNAUTHORIZED,
        br#"{"detail": "incorrect credentials"}"#
    ));
    assert!(!is_incorrect_credentials_401(
        StatusCode::UNAUTHORIZED,
        br#"{"detail": "token revoked"}"#
    ));

    let hdr = format_bearer_header(&SecretString::from("jwt.part.sig")).expect("valid bearer");
    assert!(hdr.is_sensitive());
    assert_eq!(hdr.to_str().expect("ascii"), "Bearer jwt.part.sig");

    let mut non_object = json!(["invalid"]);
    assert!(matches!(
        inject_body_auth_token(&mut non_object, &SecretString::from("tok")),
        Err(AcceptJwtError::InvalidJsonBody)
    ));
}

// ============================================================================
// TC-1.2.4: PayoutsOAuthProvider password & refresh_token grants
// ============================================================================

#[tokio::test]
async fn tc_1_2_4_payouts_password_grant_and_single_flight_concurrency() {
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
    for handle in handles {
        let tok = handle.await.expect("join").expect("access_token");
        assert_eq!(tok.expose_secret(), "po-acc-1");
    }

    let client = Client::new();
    let url = format!("{}/api/secure/disburse/status/", server.uri());
    let req = provider
        .attach_bearer_header(client.get(url))
        .await
        .expect("attach payouts bearer");
    assert_eq!(req.send().await.expect("send").status(), StatusCode::OK);
}

#[tokio::test]
async fn tc_1_2_4_payouts_refresh_token_and_401_password_fallback() {
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

// ============================================================================
// TC-1.2.5: PartnerAuthContext & zero secret leakage in Debug across all regimes
// ============================================================================

#[tokio::test]
async fn tc_1_2_5_partner_bearer_and_api_key_wire_injection() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/partner/merchants"))
        .and(header("authorization", "Bearer partner_jwt_99"))
        .and(header(DEFAULT_MERCHANT_ID_HEADER, "sub_merchant_42"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/partner/hmac"))
        .and(query_param(DEFAULT_PARTNER_API_KEY_QUERY_PARAM, "partner_qk_1"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let bearer_ctx = PartnerAuthContext::bearer("partner_jwt_99")
        .expect("valid bearer")
        .with_merchant_id("sub_merchant_42")
        .expect("valid merchant");
    assert_eq!(bearer_ctx.mode(), PartnerAuthMode::PartnerBearer);
    assert_eq!(bearer_ctx.api_key_location(), None);
    assert!(bearer_ctx.is_delegated());

    let client = Client::new();
    let mut bearer_headers = HeaderMap::new();
    let mut bearer_url =
        Url::parse(&format!("{}/api/partner/merchants", server.uri())).expect("valid url");
    bearer_ctx
        .apply_request(&mut bearer_headers, &mut bearer_url)
        .expect("apply bearer request");
    let r1 = client
        .get(bearer_url)
        .headers(bearer_headers)
        .send()
        .await
        .expect("partner bearer request");
    assert_eq!(r1.status(), StatusCode::OK);

    let query_ctx =
        PartnerAuthContext::api_key_query("partner_qk_1").expect("valid query api key");
    assert_eq!(query_ctx.mode(), PartnerAuthMode::PartnerApiKey);
    assert_eq!(
        query_ctx.api_key_location(),
        Some(PartnerApiKeyLocation::Query)
    );

    let mut q_headers = HeaderMap::new();
    let mut q_url =
        Url::parse(&format!("{}/api/partner/hmac", server.uri())).expect("valid url");
    query_ctx
        .apply_request(&mut q_headers, &mut q_url)
        .expect("apply query request");
    assert!(q_headers.is_empty());
    let r2 = client.get(q_url).send().await.expect("partner query request");
    assert_eq!(r2.status(), StatusCode::OK);
}

#[test]
fn tc_1_2_5_partner_header_injection_and_validation() {
    let ctx = PartnerAuthContext::api_key_header("partner_hk_1")
        .expect("valid header key")
        .with_merchant_id("merch_7")
        .expect("valid merchant")
        .with_merchant_id_header("X-Sub-Merchant")
        .expect("valid custom merchant header");

    let mut headers = HeaderMap::new();
    ctx.apply_headers(&mut headers).expect("apply headers");
    assert_eq!(
        headers
            .get(DEFAULT_PARTNER_API_KEY_HEADER)
            .and_then(|v| v.to_str().ok()),
        Some("partner_hk_1")
    );
    assert_eq!(
        headers.get("x-sub-merchant").and_then(|v| v.to_str().ok()),
        Some("merch_7")
    );

    assert_eq!(
        PartnerAuthContext::bearer(""),
        Err(PartnerAuthError::EmptyBearerToken)
    );
    assert_eq!(
        PartnerAuthContext::api_key_header("   "),
        Err(PartnerAuthError::EmptyApiKey)
    );
}

#[test]
fn tc_1_2_5_zero_secret_leakage_in_debug_across_all_regimes() {
    let raw_sk = "egy_sk_live_secret_001";
    let raw_jwt = "jwt_secret_002";
    let raw_refresh = "refresh_secret_003";
    let raw_api_key = "accept_api_key_004";
    let raw_client_sec = "oauth_client_secret_005";
    let raw_pass = "oauth_password_006";
    let raw_partner = "partner_bearer_007";

    let mut headers = HeaderMap::new();
    inject_secret_key_token(&mut headers, &SecretString::from(raw_sk)).expect("inject sk");
    assert_redacted_debug(&headers, &[raw_sk], false);

    let cached = CachedToken::with_default_ttl(raw_jwt, Some(SecretString::from(raw_refresh)));
    assert_redacted_debug(&cached, &[raw_jwt, raw_refresh], true);

    let cache = TokenCache::new();
    cache.store(cached);
    assert_redacted_debug(&cache, &[raw_jwt, raw_refresh], false);

    let accept = AcceptJwtProvider::new("https://accept.paymob.com", SecretString::from(raw_api_key))
        .expect("accept provider");
    assert_redacted_debug(&accept, &[raw_api_key], true);

    let creds = payouts_creds("cid_005", raw_client_sec, "user_006", raw_pass);
    assert_redacted_debug(&creds, &[raw_client_sec, raw_pass], true);

    let payouts =
        PayoutsOAuthProvider::new("https://accept.paymob.com", creds).expect("payouts provider");
    assert_redacted_debug(&payouts, &[raw_client_sec, raw_pass], true);

    let partner = PartnerAuthContext::bearer(raw_partner).expect("partner bearer");
    assert_redacted_debug(&partner, &[raw_partner], true);
}

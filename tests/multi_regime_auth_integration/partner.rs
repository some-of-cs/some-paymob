use reqwest::header::{AUTHORIZATION, HeaderMap};
use reqwest::{Client, StatusCode};
use secrecy::SecretString;
use url::Url;
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

use some_paymob::core::auth::accept_jwt::AcceptJwtProvider;
use some_paymob::core::auth::cache::{CachedToken, TokenCache};
use some_paymob::core::auth::partner::{
    DEFAULT_MERCHANT_ID_HEADER, DEFAULT_PARTNER_API_KEY_HEADER,
    DEFAULT_PARTNER_API_KEY_QUERY_PARAM, PartnerApiKeyLocation, PartnerAuthContext,
    PartnerAuthError, PartnerAuthMode,
};
use some_paymob::core::auth::payouts_oauth::{PayoutsCredentials, PayoutsOAuthProvider};
use some_paymob::core::auth::strategy::inject_secret_key_token;

use crate::common::assert_redacted_debug;

#[tokio::test]
async fn tc_1_2_5_partner_bearer_wire_injection() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/partner/merchants"))
        .and(header("authorization", "Bearer partner_jwt_99"))
        .and(header(DEFAULT_MERCHANT_ID_HEADER, "sub_merchant_42"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let bearer_ctx = PartnerAuthContext::bearer("partner_jwt_99")
        .expect("valid bearer")
        .with_merchant_id("sub_merchant_42")
        .expect("valid merchant");
    assert_eq!(bearer_ctx.mode(), PartnerAuthMode::PartnerBearer);
    assert!(bearer_ctx.is_delegated());

    let mut headers = HeaderMap::new();
    let mut url =
        Url::parse(&format!("{}/api/partner/merchants", server.uri())).expect("valid url");
    bearer_ctx
        .apply_request(&mut headers, &mut url)
        .expect("apply bearer request");
    let resp = Client::new()
        .get(url)
        .headers(headers)
        .send()
        .await
        .expect("partner bearer request");
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn tc_1_2_5_partner_api_key_query_wire_injection() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/partner/hmac"))
        .and(query_param(
            DEFAULT_PARTNER_API_KEY_QUERY_PARAM,
            "partner_qk_1",
        ))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let query_ctx = PartnerAuthContext::api_key_query("partner_qk_1").expect("valid query api key");
    assert_eq!(
        query_ctx.api_key_location(),
        Some(PartnerApiKeyLocation::Query)
    );

    let mut headers = HeaderMap::new();
    let mut url = Url::parse(&format!("{}/api/partner/hmac", server.uri())).expect("valid url");
    query_ctx
        .apply_request(&mut headers, &mut url)
        .expect("apply query request");
    assert!(headers.is_empty());

    let resp = Client::new()
        .get(url)
        .send()
        .await
        .expect("partner query request");
    assert_eq!(resp.status(), StatusCode::OK);
}

#[test]
fn tc_1_2_5_partner_header_injection_and_sensitivity() {
    let ctx = PartnerAuthContext::api_key_header("partner_hk_1")
        .expect("valid header key")
        .with_merchant_id("merch_7")
        .expect("valid merchant")
        .with_merchant_id_header("X-Sub-Merchant")
        .expect("valid custom merchant header");

    let mut headers = HeaderMap::new();
    ctx.apply_headers(&mut headers).expect("apply headers");
    let key_header = headers
        .get(DEFAULT_PARTNER_API_KEY_HEADER)
        .expect("api key header");
    assert!(key_header.is_sensitive());
    assert_eq!(key_header.to_str().ok(), Some("partner_hk_1"));
    assert_eq!(
        headers.get("x-sub-merchant").and_then(|v| v.to_str().ok()),
        Some("merch_7")
    );
}

#[test]
fn tc_1_2_5_partner_bearer_header_is_sensitive() {
    let ctx = PartnerAuthContext::bearer("partner_jwt_sensitive").expect("valid bearer");
    let mut headers = HeaderMap::new();
    ctx.apply_headers(&mut headers).expect("apply headers");
    let auth_header = headers.get(AUTHORIZATION).expect("authorization header");
    assert!(auth_header.is_sensitive());
}

#[test]
fn tc_1_2_5_partner_rejects_empty_credentials() {
    assert_eq!(
        PartnerAuthContext::bearer("").expect_err("empty bearer must fail"),
        PartnerAuthError::EmptyBearerToken
    );
    assert_eq!(
        PartnerAuthContext::api_key_header("   ").expect_err("empty api key must fail"),
        PartnerAuthError::EmptyApiKey
    );
}

#[test]
fn tc_1_2_5_zero_secret_leakage_in_debug_regimes_1_to_2() {
    let raw_sk = "egy_sk_live_secret_001";
    let raw_jwt = "jwt_secret_002";
    let raw_refresh = "refresh_secret_003";
    let raw_api_key = "accept_api_key_004";

    let mut headers = HeaderMap::new();
    inject_secret_key_token(&mut headers, &SecretString::from(raw_sk)).expect("inject sk");
    assert_redacted_debug(&headers, &[raw_sk], false);

    let cached = CachedToken::with_default_ttl(raw_jwt, Some(SecretString::from(raw_refresh)));
    assert_redacted_debug(&cached, &[raw_jwt, raw_refresh], true);

    let cache = TokenCache::new();
    cache.store(cached);
    assert_redacted_debug(&cache, &[raw_jwt, raw_refresh], false);

    let accept =
        AcceptJwtProvider::new("https://accept.paymob.com", SecretString::from(raw_api_key))
            .expect("accept provider");
    assert_redacted_debug(&accept, &[raw_api_key], true);
}

#[test]
fn tc_1_2_5_zero_secret_leakage_in_debug_regimes_3_to_4() {
    let raw_client_sec = "oauth_client_secret_005";
    let raw_pass = "oauth_password_006";
    let raw_partner = "partner_bearer_007";

    let creds = PayoutsCredentials::new("cid_005", raw_client_sec, "user_006", raw_pass)
        .expect("valid payouts credentials");
    assert_redacted_debug(&creds, &[raw_client_sec, raw_pass], true);

    let payouts =
        PayoutsOAuthProvider::new("https://accept.paymob.com", creds).expect("payouts provider");
    assert_redacted_debug(&payouts, &[raw_client_sec, raw_pass], true);

    let partner = PartnerAuthContext::bearer(raw_partner).expect("partner bearer");
    assert_redacted_debug(&partner, &[raw_partner], true);
}

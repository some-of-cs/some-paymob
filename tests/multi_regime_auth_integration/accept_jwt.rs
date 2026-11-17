#![forbid(unsafe_code)]
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use reqwest::{Client, StatusCode};
use secrecy::{ExposeSecret, SecretString};
use serde_json::json;
use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

use some_paymob::core::auth::accept_jwt::{
    ACCEPT_AUTH_TOKENS_PATH, AcceptJwtError, AcceptJwtProvider, format_bearer_header,
    inject_body_auth_token, is_incorrect_credentials_401,
};

const ACCEPT_INQUIRY_PATH: &str = "/api/ecommerce/orders/transaction_inquiry";

async fn mount_accept_token_mock(server: &MockServer, api_key: &str, token: &str, expected: u64) {
    Mock::given(method("POST"))
        .and(path(ACCEPT_AUTH_TOKENS_PATH))
        .and(body_json(json!({ "api_key": api_key })))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({ "token": token })))
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

#[tokio::test]
async fn tc_1_2_3_accept_jwt_bearer_header_injection() {
    let server = MockServer::start().await;
    mount_accept_token_mock(&server, "accept-key-1", "jwt-v1", 1).await;

    Mock::given(method("GET"))
        .and(path("/api/acceptance/transactions/42"))
        .and(header("authorization", "Bearer jwt-v1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": 42 })))
        .expect(1)
        .mount(&server)
        .await;

    let provider = AcceptJwtProvider::new(&server.uri(), SecretString::from("accept-key-1"))
        .expect("valid provider");
    let tx_url = format!("{}/api/acceptance/transactions/42", server.uri());
    let req = provider
        .attach_bearer_header(Client::new().get(tx_url))
        .await
        .expect("attach bearer header");
    assert_eq!(req.send().await.expect("send").status(), StatusCode::OK);
}

#[tokio::test]
async fn tc_1_2_3_accept_jwt_body_auth_token_injection() {
    let server = MockServer::start().await;
    mount_accept_token_mock(&server, "accept-key-1", "jwt-v1", 1).await;

    let provider = AcceptJwtProvider::new(&server.uri(), SecretString::from("accept-key-1"))
        .expect("valid provider");
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
        .and(body_json(
            json!({ "order_id": 101, "auth_token": "stale-jwt" }),
        ))
        .respond_with(
            ResponseTemplate::new(401).set_body_json(json!({ "detail": "incorrect credentials" })),
        )
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path(ACCEPT_INQUIRY_PATH))
        .and(body_json(
            json!({ "order_id": 101, "auth_token": "fresh-jwt" }),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": 101 })))
        .expect(1)
        .mount(&server)
        .await;

    let provider = AcceptJwtProvider::new(&server.uri(), SecretString::from("accept-key-401"))
        .expect("valid provider");
    let inquiry_url = format!("{}{ACCEPT_INQUIRY_PATH}", server.uri());
    let resp = send_accept_inquiry(&provider, &Client::new(), &inquiry_url)
        .await
        .expect("401 retry succeeds");

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(auth_calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        provider
            .token()
            .await
            .expect("cached fresh")
            .expose_secret(),
        "fresh-jwt"
    );
}

#[test]
fn tc_1_2_3_incorrect_credentials_401_detection() {
    assert!(is_incorrect_credentials_401(
        StatusCode::UNAUTHORIZED,
        br#"{"detail": "incorrect credentials"}"#
    ));
    assert!(!is_incorrect_credentials_401(
        StatusCode::UNAUTHORIZED,
        br#"{"detail": "token revoked"}"#
    ));
}

#[test]
fn tc_1_2_3_format_bearer_header_is_sensitive() {
    let hdr = format_bearer_header(&SecretString::from("jwt.part.sig")).expect("valid bearer");
    assert!(hdr.is_sensitive());
    assert_eq!(hdr.to_str().expect("ascii"), "Bearer jwt.part.sig");
}

#[test]
fn tc_1_2_3_inject_body_rejects_non_object() {
    let mut non_object = json!(["invalid"]);
    assert!(matches!(
        inject_body_auth_token(&mut non_object, &SecretString::from("tok")),
        Err(AcceptJwtError::InvalidJsonBody)
    ));
}

#[tokio::test]
async fn tc_1_2_3_concurrent_401_eviction_race_refreshes_once_total_two_auth_calls() {
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
        .and(body_json(
            json!({ "order_id": 101, "auth_token": "stale-jwt" }),
        ))
        .respond_with(
            ResponseTemplate::new(401).set_body_json(json!({ "detail": "incorrect credentials" })),
        )
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path(ACCEPT_INQUIRY_PATH))
        .and(body_json(
            json!({ "order_id": 101, "auth_token": "fresh-jwt" }),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": 101 })))
        .mount(&server)
        .await;

    let provider = Arc::new(
        AcceptJwtProvider::new(&server.uri(), SecretString::from("accept-key-race"))
            .expect("valid provider"),
    );
    // Warm cache with stale-jwt so all 20 tasks read it concurrently and hit 401.
    let _ = provider.token().await.expect("initial stale token");

    let client = Client::new();
    let inquiry_url = format!("{}{ACCEPT_INQUIRY_PATH}", server.uri());
    let mut handles = Vec::with_capacity(20);
    for _ in 0..20 {
        let p = Arc::clone(&provider);
        let c = client.clone();
        let u = inquiry_url.clone();
        handles.push(tokio::spawn(async move {
            send_accept_inquiry(&p, &c, &u)
                .await
                .expect("retry succeeds")
                .status()
        }));
    }

    let mut statuses = Vec::with_capacity(20);
    for handle in handles {
        statuses.push(handle.await.expect("task join"));
    }
    assert!(statuses.iter().all(|&s| s == StatusCode::OK));
    assert_eq!(auth_calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn tc_1_2_3_single_flight_50_concurrent_tasks() {
    let server = MockServer::start().await;
    let auth_calls = Arc::new(AtomicUsize::new(0));
    let auth_calls_clone = Arc::clone(&auth_calls);

    Mock::given(method("POST"))
        .and(path(ACCEPT_AUTH_TOKENS_PATH))
        .respond_with(move |_req: &Request| {
            auth_calls_clone.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(201).set_body_json(json!({ "token": "sf-50-jwt" }))
        })
        .expect(1)
        .mount(&server)
        .await;

    let provider = Arc::new(
        AcceptJwtProvider::new(&server.uri(), SecretString::from("accept-key-50"))
            .expect("valid provider"),
    );
    let mut handles = Vec::with_capacity(50);
    for _ in 0..50 {
        let p = Arc::clone(&provider);
        handles.push(tokio::spawn(async move {
            p.token().await.expect("token").expose_secret().to_owned()
        }));
    }

    let mut tokens = Vec::with_capacity(50);
    for handle in handles {
        tokens.push(handle.await.expect("task join"));
    }
    assert!(tokens.iter().all(|t| t == "sf-50-jwt"));
    assert_eq!(auth_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn tc_1_2_3_negative_malformed_json_and_500_status() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(ACCEPT_AUTH_TOKENS_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_string("{malformed"))
        .expect(1)
        .mount(&server)
        .await;

    let provider = AcceptJwtProvider::new(&server.uri(), SecretString::from("accept-key-neg"))
        .expect("valid provider");
    assert!(matches!(
        provider.token().await,
        Err(AcceptJwtError::Transport(_))
    ));

    let server_500 = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(ACCEPT_AUTH_TOKENS_PATH))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({ "detail": "internal" })))
        .expect(1)
        .mount(&server_500)
        .await;
    let provider_500 =
        AcceptJwtProvider::new(&server_500.uri(), SecretString::from("accept-key-neg"))
            .expect("valid provider");
    assert!(matches!(
        provider_500.token().await,
        Err(AcceptJwtError::UnexpectedStatus { status: 500, .. })
    ));
}

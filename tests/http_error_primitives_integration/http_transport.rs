use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderName, HeaderValue, RETRY_AFTER};
use reqwest::{Method, StatusCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use wiremock::matchers::{header_exists, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use some_paymob::core::error::PaymobError;
use some_paymob::core::http::{
    HttpClient, HttpClientConfig, HttpError, HttpRequest, HttpResponse, REQUEST_ID_HEADER,
    RetryPolicy, compute_backoff_delay, is_retryable_status, parse_retry_after,
};

use crate::error_redaction::assert_redacted;

fn fast_config() -> HttpClientConfig {
    HttpClientConfig {
        connect_timeout: Duration::from_secs(2),
        request_timeout: Duration::from_secs(2),
        max_response_bytes: 1024,
        retry: RetryPolicy {
            max_retries: 2,
            base_delay: Duration::from_millis(5),
            max_delay: Duration::from_millis(25),
        },
        allow_insecure_http: true,
    }
}

async fn execute_on_server(
    server: &MockServer,
    cfg: HttpClientConfig,
    req_method: Method,
    route: &str,
) -> Result<HttpResponse, HttpError> {
    let client = HttpClient::new(cfg).expect("client builds");
    let req = HttpRequest::new(req_method, &format!("{}{route}", server.uri())).expect("valid URL");
    client.execute(&req).await
}

async fn execute_mock_get(
    cfg: HttpClientConfig,
    route: &str,
    template: ResponseTemplate,
    expected_calls: Option<u64>,
) -> Result<HttpResponse, HttpError> {
    let server = MockServer::start().await;
    let mut mock = Mock::given(method("GET"))
        .and(path(route))
        .and(header_exists(REQUEST_ID_HEADER))
        .respond_with(template);
    if let Some(calls) = expected_calls {
        mock = mock.expect(calls);
    }
    mock.mount(&server).await;

    execute_on_server(&server, cfg, Method::GET, route).await
}

async fn assert_retry_then_succeed(
    first_status: u16,
    retry_after: Option<&str>,
    req_method: Method,
    expected_body: &str,
) {
    let server = MockServer::start().await;
    let first_template = match retry_after {
        Some(val) => ResponseTemplate::new(first_status).insert_header("Retry-After", val),
        None => ResponseTemplate::new(first_status),
    };
    let route = "/retry";
    let stages = [
        (first_template, Some(1)),
        (
            ResponseTemplate::new(200).set_body_string(expected_body),
            None,
        ),
    ];

    for (template, limit) in stages {
        let mut mock = Mock::given(method(req_method.as_str()))
            .and(path(route))
            .and(header_exists(REQUEST_ID_HEADER))
            .respond_with(template);
        if let Some(n) = limit {
            mock = mock.up_to_n_times(n);
        }
        mock.mount(&server).await;
    }

    let resp = execute_on_server(&server, fast_config(), req_method, route)
        .await
        .expect("retry succeeds");

    assert_eq!(
        (resp.status, resp.body.as_slice(), resp.request_id.get_version_num()),
        (StatusCode::OK, expected_body.as_bytes(), 4)
    );
}

async fn assert_response_too_large(
    route: &str,
    template: ResponseTemplate,
    expected_actual: Option<u64>,
) {
    let err = execute_mock_get(fast_config(), route, template, None)
        .await
        .unwrap_err();

    match err {
        HttpError::ResponseTooLarge {
            limit_bytes,
            actual_bytes,
            ..
        } => {
            assert_eq!(limit_bytes, 1024);
            if let Some(expected) = expected_actual {
                assert_eq!(actual_bytes, Some(expected));
            }
        }
        other => panic!("expected ResponseTooLarge, got {other:?}"),
    }
}

fn assert_retry_after_header(raw: &'static str, expected: Option<Duration>) {
    let mut headers = HeaderMap::new();
    headers.insert(RETRY_AFTER, HeaderValue::from_static(raw));
    assert_eq!(parse_retry_after(&headers), expected);
}

fn assert_backoff_bounds(policy: &RetryPolicy) {
    for attempt in 0..=4 {
        assert!(compute_backoff_delay(policy, attempt, None) <= policy.max_delay);
    }
    assert_eq!(
        compute_backoff_delay(policy, 0, Some(Duration::from_secs(60))),
        policy.max_delay
    );
}

fn assert_request_builder_and_redaction() {
    assert!(matches!(
        HttpRequest::get("not a url"),
        Err(HttpError::InvalidConfig(_))
    ));
    let req = HttpRequest::post("https://accept.paymob.com/api/auth/tokens")
        .expect("valid URL")
        .with_header(
            HeaderName::from_static("authorization"),
            HeaderValue::from_static("Bearer secret_token_123"),
        )
        .with_body(b"{}".to_vec());
    assert_eq!(
        (req.method(), req.url().as_str()),
        (&Method::POST, "https://accept.paymob.com/api/auth/tokens")
    );
    assert_redacted(&format!("{req:?}"), &["secret_token_123"]);
}

#[test]
fn tc_1_3_2_retry_classification_backoff_and_request_redaction() {
    let status_cases = [
        (StatusCode::TOO_MANY_REQUESTS, true),
        (StatusCode::BAD_GATEWAY, true),
        (StatusCode::SERVICE_UNAVAILABLE, true),
        (StatusCode::GATEWAY_TIMEOUT, true),
        (StatusCode::OK, false),
        (StatusCode::BAD_REQUEST, false),
        (StatusCode::UNAUTHORIZED, false),
        (StatusCode::NOT_FOUND, false),
    ];
    for (status, expected) in status_cases {
        assert_eq!(is_retryable_status(status), expected);
    }

    assert_retry_after_header(" 15 ", Some(Duration::from_secs(15)));
    assert_retry_after_header("invalid", None);

    let policy = RetryPolicy {
        max_retries: 3,
        base_delay: Duration::from_millis(50),
        max_delay: Duration::from_millis(300),
    };
    assert_backoff_bounds(&policy);
    assert_request_builder_and_redaction();
}

#[tokio::test]
async fn tc_1_3_2_http_client_retries_429_502_503_504_and_handles_exhaustion() {
    assert_retry_then_succeed(429, Some("0"), Method::POST, r#"{"ok":true}"#).await;
    assert_retry_then_succeed(502, None, Method::GET, "recovered_502").await;
    assert_retry_then_succeed(504, None, Method::GET, "recovered_504").await;

    let exhausted = execute_mock_get(
        fast_config(),
        "/down",
        ResponseTemplate::new(503).set_body_string("service down"),
        Some(3),
    )
    .await
    .unwrap_err();

    match exhausted {
        HttpError::RetriesExhausted { status, body, .. } => {
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(body, b"service down");
        }
        other => panic!("expected RetriesExhausted, got {other:?}"),
    }
}

#[tokio::test]
async fn tc_1_3_2_http_client_no_retry_4xx_integrates_with_paymob_error() {
    let resp = execute_mock_get(
        fast_config(),
        "/auth-fail",
        ResponseTemplate::new(401).set_body_string(r#"{"detail": "incorrect credentials"}"#),
        Some(1),
    )
    .await
    .expect("401 returns response without retry");

    let body = String::from_utf8_lossy(&resp.body);
    let err = PaymobError::from_response(resp.status.as_u16(), &body, None);
    assert_eq!(
        err,
        PaymobError::AuthenticationError("incorrect credentials".to_string())
    );
}

#[tokio::test]
async fn tc_1_3_2_http_client_enforces_bounded_body_and_timeout() {
    assert_response_too_large(
        "/oversized-stream",
        ResponseTemplate::new(200).set_body_bytes(vec![b'x'; 2048]),
        None,
    )
    .await;

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let header_server = tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut req_buf = [0_u8; 1024];
            let _ = stream.read(&mut req_buf).await;
            let payload = "HTTP/1.1 200 OK\r\nContent-Length: 4096\r\nConnection: close\r\n\r\n";
            let _ = stream.write_all(payload.as_bytes()).await;
        }
    });

    let client = HttpClient::new(fast_config()).expect("client builds");
    let req = HttpRequest::get(&format!("http://{addr}/oversized-header")).expect("valid URL");
    let header_err = client.execute(&req).await.unwrap_err();
    let _ = header_server.await;

    assert!(matches!(
        header_err,
        HttpError::ResponseTooLarge {
            limit_bytes: 1024,
            actual_bytes: Some(4096),
            ..
        }
    ));

    let mut cfg = fast_config();
    cfg.request_timeout = Duration::from_millis(50);
    cfg.retry.max_retries = 0;

    let timeout_err = execute_mock_get(
        cfg,
        "/slow",
        ResponseTemplate::new(200).set_delay(Duration::from_millis(250)),
        None,
    )
    .await
    .unwrap_err();
    assert!(matches!(timeout_err, HttpError::Timeout { .. }));
}

#[tokio::test]
async fn tc_1_3_2_chunked_streaming_body_limit_without_content_length() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server_task = tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut req_buf = [0_u8; 1024];
            let _ = stream.read(&mut req_buf).await;
            let chunk = "28\r\n".to_string() + &"a".repeat(40) + "\r\n";
            let payload = format!(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{chunk}{chunk}0\r\n\r\n"
            );
            let _ = stream.write_all(payload.as_bytes()).await;
        }
    });

    let mut cfg = fast_config();
    cfg.max_response_bytes = 64;
    let client = HttpClient::new(cfg).expect("client");
    let req = HttpRequest::get(&format!("http://{addr}/chunked")).expect("url");
    let err = client.execute(&req).await.unwrap_err();
    let _ = server_task.await;

    assert!(matches!(
        err,
        HttpError::ResponseTooLarge {
            limit_bytes: 64,
            actual_bytes: Some(80),
            ..
        }
    ));
}

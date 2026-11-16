#![forbid(unsafe_code)]
//! Story-level integration tests for US-1.3.0 (`TC-1.3.1`..`TC-1.3.4`).
//!
//! Covers:
//! - `TC-1.3.1`: `PaymobError` multi-shape response parsing, HTTP status mapping,
//!   retryability classification, and PII/secret redaction in `Display` and `Debug`.
//! - `TC-1.3.2`: `HttpClient` transport pipeline, `X-Request-Id` UUID v4 tracing,
//!   exponential backoff with full jitter, `429`/`502`/`503`/`504` retries,
//!   `Retry-After` handling, bounded response bodies, timeouts, and non-retryable 4xx.
//! - `TC-1.3.3`: `MinorUnitAmount` zero-float checked arithmetic & serde, `Currency`
//!   ISO-4217 lookup & decimal precision, and `validate_prefixed_id`.
//! - `TC-1.3.4`: `PaginatedResponse<T>`, `PageQuery`, and `some_paymob::prelude::*`
//!   re-exports.

use std::any::type_name;
use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderName, HeaderValue, RETRY_AFTER};
use reqwest::{Method, StatusCode};
use wiremock::matchers::{header_exists, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use some_paymob::core::error::PaymobError;
use some_paymob::core::http::{
    HttpClient, HttpClientConfig, HttpError, HttpRequest, HttpResponse, REQUEST_ID_HEADER,
    RetryPolicy, compute_backoff_delay, is_retryable_status, parse_retry_after,
};
use some_paymob::core::pagination::{PageQuery, PaginatedResponse};
use some_paymob::core::types::{Currency, KNOWN_CURRENCIES, MinorUnitAmount, validate_prefixed_id};
use some_paymob::prelude as sdk_prelude;

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

    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(resp.body, expected_body.as_bytes());
    assert_eq!(resp.request_id.get_version_num(), 4);
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

fn assert_redacted(rendered: &str, forbidden_secrets: &[&str]) {
    assert!(rendered.contains("[REDACTED]"));
    for secret in forbidden_secrets {
        assert!(
            !rendered.contains(secret),
            "secret `{secret}` leaked in `{rendered}`"
        );
    }
}

fn assert_error_mapping_cases(
    cases: &[(u16, &str, Option<u64>, PaymobError, bool, Option<u16>)],
) {
    for (status, body, retry_after, expected, retryable, expected_status) in cases {
        let actual = PaymobError::from_response(*status, body, *retry_after);
        assert_eq!(&actual, expected);
        assert_eq!(actual.is_retryable(), *retryable);
        assert_eq!(actual.status_code(), *expected_status);
    }
}

#[test]
fn tc_1_3_1_paymob_error_auth_and_not_found_mapping() {
    assert_error_mapping_cases(&[
        (401, r#"{"detail": "incorrect credentials"}"#, None, PaymobError::AuthenticationError("incorrect credentials".to_string()), false, None),
        (403, r#"{"detail": "forbidden"}"#, None, PaymobError::AuthenticationError("forbidden".to_string()), false, None),
        (
            404,
            r#"{"detail": "Not found.", "code": "NOT_FOUND"}"#,
            None,
            PaymobError::ApiError { status: 404, message: "Not found.".to_string(), code: Some("NOT_FOUND".to_string()) },
            false,
            Some(404),
        ),
    ]);
}

#[test]
fn tc_1_3_1_paymob_error_refund_and_rate_limit_mapping() {
    assert_error_mapping_cases(&[
        (
            400,
            r#"{"message": "Requested Refund Amount exceeds permissible limit"}"#,
            None,
            PaymobError::RefundExceedsPermissibleAmount { message: "Requested Refund Amount exceeds permissible limit".to_string() },
            false,
            None,
        ),
        (
            429,
            r#"{"status_description": "Rate limit exceeded", "status_code": 429}"#,
            Some(12),
            PaymobError::RateLimited { message: "Rate limit exceeded".to_string(), retry_after_secs: Some(12) },
            true,
            Some(429),
        ),
    ]);
}

#[test]
fn tc_1_3_1_paymob_error_validation_shapes_mapping() {
    assert_error_mapping_cases(&[
        (
            400,
            r#"{"billing_data": {"phone_number": ["This field is required."]}}"#,
            None,
            PaymobError::ValidationError { field: "phone_number", reason: "This field is required.".to_string() },
            false,
            None,
        ),
        (
            422,
            r#"{"custom_block": {"unknown_attr": ["Invalid value"]}}"#,
            None,
            PaymobError::ValidationError { field: "payload", reason: "unknown_attr: Invalid value".to_string() },
            false,
            None,
        ),
    ]);
}

#[test]
fn tc_1_3_1_paymob_error_server_fallback_mapping() {
    assert_error_mapping_cases(&[
        (503, "Service Unavailable", None, PaymobError::ApiError { status: 503, message: "Service Unavailable".to_string(), code: None }, true, Some(503)),
        (500, "   ", None, PaymobError::ApiError { status: 500, message: "HTTP 500 error with empty response body".to_string(), code: None }, false, Some(500)),
    ]);
}

#[test]
fn tc_1_3_1_paymob_error_redacts_secrets_and_pii_in_display_and_debug() {
    let cases = [
        (
            PaymobError::AuthenticationError(
                "sk_live_abc123 egy_sk_secret999 Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig"
                    .to_string(),
            ),
            vec!["sk_live_abc123", "egy_sk_secret999", "eyJhbGciOiJIUzI1NiJ9"],
        ),
        (
            PaymobError::ValidationError {
                field: "payload",
                reason: "phone_number=+201012345678 pan=4111-1111-1111-1111 cvv=123 token=tok_xyz"
                    .to_string(),
            },
            vec!["+201012345678", "4111-1111-1111-1111", "123", "tok_xyz"],
        ),
        (
            PaymobError::WebhookError(
                "user@example.com card 4111 1111 1111 1111 mobile +20 101 234 5678".to_string(),
            ),
            vec!["user@example.com", "4111 1111 1111 1111", "+20 101 234 5678"],
        ),
    ];

    for (err, secrets) in cases {
        assert_redacted(&err.to_string(), &secrets);
        assert_redacted(&format!("{err:?}"), &secrets);
    }

    let env_err = PaymobError::EnvironmentMismatch("Test key with Live ID".to_string());
    assert!(!env_err.is_retryable());
    assert_eq!(env_err.status_code(), None);

    let transport_err = PaymobError::TransportError("connection reset".to_string());
    assert!(transport_err.is_retryable());
    assert_eq!(transport_err.status_code(), None);
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

    let mut headers = HeaderMap::new();
    headers.insert(RETRY_AFTER, HeaderValue::from_static(" 15 "));
    assert_eq!(parse_retry_after(&headers), Some(Duration::from_secs(15)));
    headers.insert(RETRY_AFTER, HeaderValue::from_static("invalid"));
    assert_eq!(parse_retry_after(&headers), None);

    let policy = RetryPolicy {
        max_retries: 3,
        base_delay: Duration::from_millis(50),
        max_delay: Duration::from_millis(300),
    };
    for attempt in 0..=4 {
        assert!(compute_backoff_delay(&policy, attempt, None) <= policy.max_delay);
    }
    assert_eq!(
        compute_backoff_delay(&policy, 0, Some(Duration::from_secs(60))),
        policy.max_delay
    );

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
    assert_eq!(req.method(), &Method::POST);
    assert_eq!(req.url().as_str(), "https://accept.paymob.com/api/auth/tokens");
    assert_redacted(&format!("{req:?}"), &["secret_token_123"]);
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

    assert_response_too_large(
        "/oversized-header",
        ResponseTemplate::new(200).insert_header("Content-Length", "4096"),
        Some(4096),
    )
    .await;

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

#[test]
fn tc_1_3_3_money_zero_float_arithmetic_and_serde() {
    let egp = MinorUnitAmount::from_major_checked(1000, 2).expect("1000 EGP");
    assert_eq!(egp.as_u64(), 100_000);
    assert_eq!(
        MinorUnitAmount::from_major_checked(25, 3).expect("25 OMR"),
        MinorUnitAmount::new(25_000)
    );
    assert_eq!(
        egp.checked_add(MinorUnitAmount::new(500)).expect("add"),
        MinorUnitAmount(100_500)
    );
    assert_eq!(
        egp.checked_sub(MinorUnitAmount::new(500)).expect("sub"),
        MinorUnitAmount(99_500)
    );

    let json = serde_json::to_string(&egp).expect("serialize integer");
    assert_eq!(json, "100000");
    let roundtrip: MinorUnitAmount = serde_json::from_str(&json).expect("deserialize integer");
    assert_eq!(roundtrip, egp);
    assert_eq!(u64::from(roundtrip), 100_000);
    assert_eq!(roundtrip.to_string(), "100000");

    let failure_cases = [
        (MinorUnitAmount::from_major_checked(1, 20), "decimals"),
        (MinorUnitAmount::from_major_checked(u64::MAX, 2), "amount"),
        (MinorUnitAmount(u64::MAX).checked_add(MinorUnitAmount(1)), "amount"),
        (MinorUnitAmount(10).checked_sub(MinorUnitAmount(11)), "amount"),
    ];
    for (res, expected_field) in failure_cases {
        assert!(matches!(
            res,
            Err(PaymobError::ValidationError { field, .. }) if field == expected_field
        ));
    }
}

#[test]
fn tc_1_3_3_currency_lookup_decimals_and_prefixed_id_validation() {
    assert_eq!(KNOWN_CURRENCIES.len(), 7);
    let currency_cases = [
        ("egp", Currency::EGP, "EGP", 2_u8),
        ("SAR", Currency::SAR, "SAR", 2_u8),
        (" aed ", Currency::AED, "AED", 2_u8),
        ("Omr", Currency::OMR, "OMR", 3_u8),
        ("pKr", Currency::PKR, "PKR", 2_u8),
        ("usd", Currency::USD, "USD", 2_u8),
        ("Eur", Currency::EUR, "EUR", 2_u8),
        ("kwd", Currency::Unknown("KWD".to_string()), "KWD", 2_u8),
    ];

    for (raw, expected, canonical, decimals) in currency_cases {
        let parsed = Currency::from_code(raw);
        assert_eq!(parsed, expected);
        assert_eq!(parsed.as_str(), canonical);
        assert_eq!(parsed.minor_unit_decimals(), decimals);
        assert_eq!(raw.parse::<Currency>().expect("infallible"), expected);

        let serialized = serde_json::to_string(&parsed).expect("serialize currency");
        let deserialized: Currency = serde_json::from_str(&serialized).expect("deserialize");
        assert_eq!(deserialized, parsed);
    }

    assert!(validate_prefixed_id("pi_abc123", "pi_", "intention_id").is_ok());
    assert!(validate_prefixed_id("pk_test_xyz", "pk_", "public_key").is_ok());

    for invalid in ["", "   ", " pi_123", "pi_12 3", "pk_123", "pi_"] {
        assert!(matches!(
            validate_prefixed_id(invalid, "pi_", "intention_id"),
            Err(PaymobError::ValidationError {
                field: "intention_id",
                ..
            })
        ));
    }
}

#[test]
fn tc_1_3_4_pagination_and_prelude_reexports() {
    let raw = r#"{
        "count": 42,
        "next": "https://accept.paymob.com/api/ecommerce/orders?page=3&page_size=20",
        "previous": "https://accept.paymob.com/api/ecommerce/orders?page=1&page_size=20",
        "results": [101, 102, 103]
    }"#;
    let page: PaginatedResponse<u64> = serde_json::from_str(raw).expect("valid page JSON");
    assert_eq!(page.count, 42);
    assert!(page.has_next());
    assert!(page.has_previous());
    assert!(!page.is_empty());
    assert_eq!(page.len(), 3);
    assert_eq!(page.next_page_number(), Some(3));
    assert_eq!(page.previous_page_number(), Some(1));

    let mapped = page.map(|id| format!("ord_{id}"));
    assert_eq!(mapped.results, vec!["ord_101", "ord_102", "ord_103"]);

    let query = PageQuery::new(0).with_page_size(0);
    assert_eq!(query.page(), 1);
    assert_eq!(query.page_size(), Some(1));
    assert_eq!(query.to_query_string(), "?page=1&page_size=1");
    assert_eq!(
        query.next_page().to_query_pairs(),
        vec![("page", "2".to_string()), ("page_size", "1".to_string())]
    );

    let roundtrip: PageQuery =
        serde_json::from_str(&serde_json::to_string(&PageQuery::new(3)).expect("serialize"))
            .expect("deserialize");
    assert_eq!(roundtrip, PageQuery::new(3));

    use sdk_prelude::*;
    assert!(!type_name::<CachedToken>().is_empty());
    assert!(!type_name::<AuthStrategy>().is_empty());
    assert!(!type_name::<PaymobClient>().is_empty());
    assert!(!type_name::<ClientConfig>().is_empty());
    assert!(!type_name::<ClientConfigBuilder>().is_empty());
    assert!(!type_name::<ApiKey>().is_empty());
    assert!(!type_name::<EnvironmentMode>().is_empty());
    assert!(!type_name::<HmacSecret>().is_empty());
    assert!(!type_name::<PartnerCredentials>().is_empty());
    assert!(!type_name::<PayoutsCredentials>().is_empty());
    assert!(!type_name::<PublicKey>().is_empty());
    assert!(!type_name::<SecretKey>().is_empty());
    assert!(!type_name::<PaymobError>().is_empty());
    assert!(!type_name::<PageQuery>().is_empty());
    assert!(!type_name::<PaginatedResponse<u8>>().is_empty());
    assert!(!type_name::<PaymobRegion>().is_empty());
    assert!(!type_name::<RegionalEndpoints>().is_empty());
    assert!(!type_name::<Currency>().is_empty());
    assert!(!type_name::<MinorUnitAmount>().is_empty());
}

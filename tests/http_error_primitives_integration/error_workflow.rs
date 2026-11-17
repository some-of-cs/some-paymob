#![forbid(unsafe_code)]
use reqwest::StatusCode;
use reqwest::header::{HeaderMap, HeaderValue, RETRY_AFTER};
use uuid::Uuid;

use some_paymob::core::error::PaymobError;
use some_paymob::core::http::{HttpError, HttpResponse};

type ErrorCase<'a> = (u16, &'a str, Option<u64>, PaymobError, bool, Option<u16>);

fn assert_error_mapping_cases(cases: &[ErrorCase<'_>]) {
    for (status, body, retry_after, expected, retryable, expected_status) in cases {
        let actual = PaymobError::from_response(*status, body, *retry_after);
        assert_eq!(&actual, expected);
        assert_eq!(
            (actual.is_retryable(), actual.status_code()),
            (*retryable, *expected_status)
        );
    }
}

#[test]
fn tc_1_3_1_paymob_error_auth_and_not_found_mapping() {
    assert_error_mapping_cases(&[
        (
            401,
            r#"{"detail": "incorrect credentials"}"#,
            None,
            PaymobError::AuthenticationError("incorrect credentials".to_string()),
            false,
            None,
        ),
        (
            403,
            r#"{"detail": "forbidden"}"#,
            None,
            PaymobError::AuthenticationError("forbidden".to_string()),
            false,
            None,
        ),
        (
            404,
            r#"{"detail": "Not found.", "code": "NOT_FOUND"}"#,
            None,
            PaymobError::ApiError {
                status: 404,
                message: "Not found.".to_string(),
                code: Some("NOT_FOUND".to_string()),
            },
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
            PaymobError::RefundExceedsPermissibleAmount {
                message: "Requested Refund Amount exceeds permissible limit".to_string(),
            },
            false,
            None,
        ),
        (
            429,
            r#"{"status_description": "Rate limit exceeded", "status_code": 429}"#,
            Some(12),
            PaymobError::RateLimited {
                message: "Rate limit exceeded".to_string(),
                retry_after_secs: Some(12),
            },
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
            PaymobError::ValidationError {
                field: "phone_number",
                reason: "This field is required.".to_string(),
            },
            false,
            None,
        ),
        (
            422,
            r#"{"custom_block": {"unknown_attr": ["Invalid value"]}}"#,
            None,
            PaymobError::ValidationError {
                field: "payload",
                reason: "unknown_attr: Invalid value".to_string(),
            },
            false,
            None,
        ),
    ]);
}

#[test]
fn tc_1_3_1_paymob_error_server_fallback_mapping() {
    assert_error_mapping_cases(&[
        (
            503,
            "Service Unavailable",
            None,
            PaymobError::ApiError {
                status: 503,
                message: "Service Unavailable".to_string(),
                code: None,
            },
            true,
            Some(503),
        ),
        (
            500,
            "   ",
            None,
            PaymobError::ApiError {
                status: 500,
                message: "HTTP 500 error with empty response body".to_string(),
                code: None,
            },
            false,
            Some(500),
        ),
    ]);
}

#[test]
fn tc_1_3_1_from_http_error_from_http_response_and_503_error_json() {
    let mut headers = HeaderMap::new();
    headers.insert(RETRY_AFTER, HeaderValue::from_static("9"));
    let http_resp = HttpResponse {
        status: StatusCode::TOO_MANY_REQUESTS,
        headers,
        body: br#"{"error":"rate limit hit"}"#.to_vec(),
        request_id: Uuid::new_v4(),
    };
    let from_resp = PaymobError::from_http_response(&http_resp);
    assert_eq!(
        (from_resp.is_rate_limited(), from_resp.retry_after_secs()),
        (true, Some(9))
    );

    let from_503 = PaymobError::from(HttpError::RetriesExhausted {
        request_id: Uuid::new_v4(),
        status: StatusCode::SERVICE_UNAVAILABLE,
        retry_after: None,
        body: br#"{"error":"upstream unavailable"}"#.to_vec(),
    });
    assert_eq!(
        from_503,
        PaymobError::ApiError {
            status: 503,
            message: "upstream unavailable".to_string(),
            code: None,
        }
    );
}

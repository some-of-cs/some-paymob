use std::collections::BTreeMap;

use serde_json::json;
use some_payment_core::{
    CaptureMode, CreatePaymentRequest, ErrorKind, HttpMethod, Money, PaymentCapabilities,
    PaymentProvider, PaymentStatus, ProviderId, ProviderReference, RawWebhookRequest,
    RefundRequest,
};

use crate::alignment::integration_validation::IntegrationRoutingConfig;
use crate::alignment::region_checkout::PaymobRegion;
use crate::alignment::status_synthesizer::{PaymobTransactionFlags, SynthesizedPaymentStatus};
use crate::alignment::triple_hmac::compute_hmac_sha512_hex;

use super::wire::{
    PaymobTransactionPayload, RefundExecutionContext, build_refund_result, extract_payload_money,
};
use super::{PaymobCredentials, PaymobProvider, PaymobProviderConfig, map_synthesized_status};

fn sample_config(with_auth_id: bool) -> PaymobProviderConfig {
    let mut routing = IntegrationRoutingConfig::new(vec![1001]);
    if with_auth_id {
        routing = routing.with_auth_integration_id(2002);
    }
    let credentials = PaymobCredentials::new(
        "egy_sk_test_SUPER_SECRET_KEY",
        "SUPER_SECRET_API_KEY",
        "SUPER_SECRET_HMAC_KEY",
        "egy_pk_test_SUPER_PUBLIC_KEY",
    );
    PaymobProviderConfig::new(PaymobRegion::Egypt, routing, credentials)
}

fn sample_get_return_query() -> BTreeMap<String, String> {
    let entries = [
        ("amount_cents", "10000"),
        ("created_at", "2026-01-01T00:00:00"),
        ("currency", "EGP"),
        ("error_occured", "false"),
        ("has_parent_transaction", "false"),
        ("id", "998877"),
        ("integration_id", "1001"),
        ("is_3d_secure", "true"),
        ("is_auth", "false"),
        ("is_capture", "false"),
        ("is_refunded", "false"),
        ("is_standalone_payment", "true"),
        ("is_voided", "false"),
        ("order", "445566"),
        ("owner", "77"),
        ("pending", "false"),
        ("source_data.pan", "2346"),
        ("source_data.sub_type", "MasterCard"),
        ("source_data.type", "card"),
        ("success", "true"),
    ];
    let concat: String = entries.iter().map(|(_, v)| *v).collect();
    let mut query: BTreeMap<String, String> = entries
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
    let hmac = compute_hmac_sha512_hex(&concat, "SUPER_SECRET_HMAC_KEY");
    query.insert("hmac".to_owned(), hmac);
    query
}

#[test]
fn provider_id_is_paymob() {
    let provider = PaymobProvider::new(sample_config(false)).expect("provider");
    assert_eq!(provider.id(), &ProviderId::new("paymob"));
}

#[test]
fn capabilities_disable_native_mutation_idempotency_and_gate_auth_capture() {
    let base_expected = PaymentCapabilities::HOSTED_CHECKOUT
        | PaymentCapabilities::REFUND
        | PaymentCapabilities::PARTIAL_REFUND
        | PaymentCapabilities::VOID_AUTHORIZED;
    let auth_caps = PaymentCapabilities::AUTH_CAPTURE | PaymentCapabilities::PARTIAL_CAPTURE;

    let caps_no_auth = PaymobProvider::new(sample_config(false))
        .expect("provider")
        .capabilities();
    assert!(caps_no_auth.contains(base_expected));
    assert!(!caps_no_auth.intersects(auth_caps | PaymentCapabilities::NATIVE_MUTATION_IDEMPOTENCY));

    let caps_with_auth = PaymobProvider::new(sample_config(true))
        .expect("provider")
        .capabilities();
    assert!(caps_with_auth.contains(auth_caps));
    assert!(!caps_with_auth.contains(PaymentCapabilities::NATIVE_MUTATION_IDEMPOTENCY));
}

#[test]
fn debug_redacts_all_secret_fields() {
    let config = sample_config(true);
    let cfg_debug = format!("{config:?}");
    let provider = PaymobProvider::new(config).expect("provider");
    let prov_debug = format!("{provider:?}");
    let forbidden = [
        "SUPER_SECRET_KEY",
        "SUPER_SECRET_API_KEY",
        "SUPER_SECRET_HMAC_KEY",
        "SUPER_PUBLIC_KEY",
    ];

    for output in [&cfg_debug, &prov_debug] {
        assert!(output.contains("[REDACTED]"));
        assert!(forbidden.iter().all(|secret| !output.contains(secret)));
    }
}

#[tokio::test]
async fn manual_capture_fails_closed_without_auth_integration_id() {
    let provider = PaymobProvider::new(sample_config(false)).expect("provider");
    let req = CreatePaymentRequest::new(Money::new(10_000, "EGP").expect("money"), "ORD-1")
        .with_capture_mode(CaptureMode::Manual);
    let err = provider
        .create_payment(&req)
        .await
        .expect_err("must fail closed");
    assert_eq!(err.kind(), ErrorKind::Configuration);
}

#[test]
fn maps_all_synthesized_statuses() {
    let cases = [
        (
            SynthesizedPaymentStatus::Processing,
            PaymentStatus::Processing,
        ),
        (SynthesizedPaymentStatus::Failed, PaymentStatus::Failed),
        (SynthesizedPaymentStatus::Voided, PaymentStatus::Voided),
        (SynthesizedPaymentStatus::Refunded, PaymentStatus::Refunded),
        (
            SynthesizedPaymentStatus::PartiallyRefunded,
            PaymentStatus::PartiallyRefunded,
        ),
        (
            SynthesizedPaymentStatus::Authorized,
            PaymentStatus::Authorized,
        ),
        (
            SynthesizedPaymentStatus::PartiallyCaptured,
            PaymentStatus::PartiallyCaptured,
        ),
        (SynthesizedPaymentStatus::Captured, PaymentStatus::Captured),
        (SynthesizedPaymentStatus::Paid, PaymentStatus::Paid),
    ];
    for (input, expected) in cases {
        assert_eq!(map_synthesized_status(input), expected);
    }
}

#[tokio::test]
async fn webhook_rejects_tampered_hmac() {
    let provider = PaymobProvider::new(sample_config(false)).expect("provider");
    let mut query = BTreeMap::new();
    query.insert("hmac".to_owned(), "0".repeat(128));
    let raw = RawWebhookRequest {
        raw_body: serde_json::to_vec(&json!({
            "type": "TRANSACTION",
            "obj": { "id": 123, "success": true }
        }))
        .expect("json"),
        headers: BTreeMap::new(),
        query_params: query,
        method: HttpMethod::Post,
    };
    let err = provider
        .parse_and_verify_webhook(&raw)
        .await
        .expect_err("tampered hmac must fail");
    assert_eq!(err.kind(), ErrorKind::WebhookVerificationFailed);
}

#[tokio::test]
async fn webhook_distinguishes_get_return_authority_and_redacts_payload() {
    let provider = PaymobProvider::new(sample_config(false)).expect("provider");
    let raw = RawWebhookRequest {
        raw_body: Vec::new(),
        headers: BTreeMap::new(),
        query_params: sample_get_return_query(),
        method: HttpMethod::Get,
    };
    let event = provider
        .parse_and_verify_webhook(&raw)
        .await
        .expect("valid GET return");
    assert_eq!(
        (
            event.requires_hydration,
            event.event_type.as_str(),
            event.status,
            event.event_id.as_str(),
        ),
        (
            true,
            "paymob.transaction.return",
            Some(PaymentStatus::Paid),
            "998877",
        )
    );
}

#[test]
fn sec02_rejects_non_loopback_http_and_accepts_loopback_http() {
    let remote_http = sample_config(false).with_auth_base_url_override("http://accept.paymob.com");
    let err = PaymobProvider::new(remote_http).expect_err("non-loopback http must fail");
    assert_eq!(err.kind(), ErrorKind::Configuration);

    for loopback in [
        "http://127.0.0.1:8080",
        "http://localhost:8080",
        "http://[::1]:8080",
    ] {
        let cfg = sample_config(false).with_auth_base_url_override(loopback);
        assert!(PaymobProvider::new(cfg).is_ok());
    }
}

#[test]
fn sec02_rejects_base_url_with_userinfo_query_or_fragment() {
    let invalid_urls = [
        "https://user:pass@accept.paymob.com",
        "https://user@accept.paymob.com",
        "https://accept.paymob.com?token=leak",
        "https://accept.paymob.com#fragment",
    ];
    for url in invalid_urls {
        let cfg = sample_config(false).with_auth_base_url_override(url);
        let err = PaymobProvider::new(cfg).expect_err("disallowed URL components must fail");
        assert_eq!(err.kind(), ErrorKind::Configuration);
    }
}

#[test]
fn sec03_missing_currency_fails_closed() {
    let provider_id = ProviderId::new("paymob");
    let payload = PaymobTransactionPayload {
        flags: PaymobTransactionFlags {
            id: 555,
            amount_cents: 10_000,
            success: true,
            ..PaymobTransactionFlags::default()
        },
        currency: None,
        order: None,
        is_live: None,
    };

    let tx_err = extract_payload_money(&payload, None, &provider_id)
        .expect_err("missing tx currency must fail closed");
    assert_eq!(tx_err.kind(), ErrorKind::ProviderError);

    let reference = ProviderReference::builder(provider_id.clone())
        .transaction_id("555")
        .build()
        .expect("ref");
    let refund_req = RefundRequest::new(reference);
    let ctx = RefundExecutionContext {
        tx_id: 555,
        amount_cents: 10_000,
    };
    let refund_err = build_refund_result(&provider_id, ctx, &refund_req, &payload)
        .expect_err("missing refund currency must fail closed");
    assert_eq!(refund_err.kind(), ErrorKind::ProviderError);
}

//! Integration tests for US-1.1.0 (Region Router, Credential Types, ClientConfig, PaymobClient).

#![forbid(unsafe_code)]

use std::time::Duration;

use some_paymob::core::client::PaymobClient;
use some_paymob::core::config::{
    ClientConfig, ClientConfigBuilder, DEFAULT_MAX_RETRIES, DEFAULT_TIMEOUT_SECS,
};
use some_paymob::core::credentials::{
    ApiKey, EnvironmentMode, HmacSecret, KeyKind, PartnerCredentials, PayoutsCredentials,
    PublicKey, SecretKey, parse_key_prefix,
};
use some_paymob::core::error::PaymobError;
use some_paymob::core::region::{PaymobRegion, RegionalEndpoints, normalize_endpoint_path};

struct BuiltInRegionCase {
    region: PaymobRegion,
    code: &'static str,
    accept: &'static str,
    checkout: &'static str,
    payouts: Option<&'static str>,
}

struct PrefixCase {
    raw: &'static str,
    kind: KeyKind,
    mode: EnvironmentMode,
    region: Option<PaymobRegion>,
}

fn assert_send_sync<T: Send + Sync>() {}

fn sample_secret_key(raw: &str) -> SecretKey {
    SecretKey::new(raw).expect("valid test secret key")
}

fn sample_public_key(raw: &str) -> PublicKey {
    PublicKey::new(raw).expect("valid test public key")
}

fn sample_custom_region(accept: &str, checkout: &str, payouts: &str, staging: &str) -> PaymobRegion {
    PaymobRegion::Custom {
        accept_base_url: accept.to_owned(),
        checkout_base_url: checkout.to_owned(),
        payouts_base_url: payouts.to_owned(),
        payouts_staging_base_url: staging.to_owned(),
    }
}

fn assert_region_endpoints(case: &BuiltInRegionCase) {
    let eps: RegionalEndpoints = case.region.endpoints().expect("built-in region resolves");
    assert_eq!(case.region.country_code(), case.code);
    assert_eq!(eps.accept_base_url, case.accept);
    assert_eq!(eps.checkout_base_url, case.checkout);
    assert_eq!(eps.payouts_base_url.as_deref(), case.payouts);
}

fn assert_redacted<T: std::fmt::Debug + std::fmt::Display>(value: &T, secret: &str) {
    let dbg = format!("{value:?}");
    let disp = format!("{value}");
    assert_eq!(dbg, "[REDACTED]");
    assert_eq!(disp, "[REDACTED]");
    assert!(!dbg.contains(secret));
}

fn build_egypt_test_config() -> ClientConfig {
    ClientConfig::builder()
        .region(PaymobRegion::Egypt)
        .secret_key(sample_secret_key("egy_sk_test_secret_123"))
        .public_key(sample_public_key("egy_pk_test_public_123"))
        .build()
        .expect("valid Egypt test config")
}

#[test]
fn tc_1_1_1_built_in_regions_resolve_dual_host_endpoints() {
    let cases = [
        BuiltInRegionCase {
            region: PaymobRegion::Egypt,
            code: "EGY",
            accept: "https://accept.paymob.com",
            checkout: "https://accept.paymob.com/unifiedcheckout/",
            payouts: Some("https://payouts.paymobsolutions.com"),
        },
        BuiltInRegionCase {
            region: PaymobRegion::SaudiArabia,
            code: "KSA",
            accept: "https://ksa.paymob.com",
            checkout: "https://ksa.paymob.com/unifiedcheckout/",
            payouts: Some("https://payouts.paymob.sa"),
        },
        BuiltInRegionCase {
            region: PaymobRegion::Uae,
            code: "UAE",
            accept: "https://uae.paymob.com",
            checkout: "https://uae.paymob.com/unifiedcheckout/",
            payouts: Some("https://payouts-uae.paymobsolutions.com"),
        },
        BuiltInRegionCase {
            region: PaymobRegion::Oman,
            code: "OMN",
            accept: "https://oman.paymob.com",
            checkout: "https://oman.paymob.com/unifiedcheckout/",
            payouts: Some("https://oman.paymob.com"),
        },
        BuiltInRegionCase {
            region: PaymobRegion::Pakistan,
            code: "PAK",
            accept: "https://pakistan.paymob.com",
            checkout: "https://pakistan.paymob.com/unifiedcheckout/",
            payouts: None,
        },
    ];
    cases.iter().for_each(assert_region_endpoints);
}

#[test]
fn tc_1_1_1_endpoint_trailing_slash_normalization_and_url_joining() {
    let cases = [
        ("v1/intention", "/v1/intention/"),
        ("/v1/intention/", "/v1/intention/"),
        ("//api//secure//disburse", "/api/secure/disburse/"),
        ("/api/auth/tokens/", "/api/auth/tokens"),
    ];
    for (raw, expected) in cases {
        assert_eq!(normalize_endpoint_path(raw), expected);
    }
    let url = PaymobRegion::SaudiArabia
        .resolve_accept_url("v1/intention")
        .expect("accept url");
    assert_eq!(url, "https://ksa.paymob.com/v1/intention/");
}

#[test]
fn tc_1_1_1_custom_region_and_pakistan_payouts_validation() {
    let local = sample_custom_region(
        "http://127.0.0.1:8080/",
        "http://localhost:8080/unifiedcheckout",
        "https://payouts.example.com/",
        "https://staging.example.com/",
    );
    let eps = local.endpoints().expect("loopback http allowed");
    assert_eq!(eps.accept_base_url, "http://127.0.0.1:8080");
    assert_eq!(eps.checkout_base_url, "http://localhost:8080/unifiedcheckout/");

    let invalid = sample_custom_region(
        "http://remote.example.com",
        "https://checkout.example.com",
        "https://payouts.example.com",
        "https://staging.example.com",
    );
    assert!(matches!(invalid.endpoints(), Err(PaymobError::ValidationError { .. })));

    let pak_err = PaymobRegion::Pakistan.resolve_payouts_url("/api/secure/disburse/", false);
    assert!(matches!(pak_err, Err(PaymobError::ValidationError { .. })));
    assert_eq!(PaymobRegion::from_key_prefix("KSA"), Some(PaymobRegion::SaudiArabia));
}

#[test]
fn tc_1_1_2_prefix_parser_infers_kind_mode_and_region() {
    let cases = [
        PrefixCase {
            raw: "egy_sk_test_abc",
            kind: KeyKind::Secret,
            mode: EnvironmentMode::Test,
            region: Some(PaymobRegion::Egypt),
        },
        PrefixCase {
            raw: "ksa_sk_live_abc",
            kind: KeyKind::Secret,
            mode: EnvironmentMode::Live,
            region: Some(PaymobRegion::SaudiArabia),
        },
        PrefixCase {
            raw: "uae_pk_test_abc",
            kind: KeyKind::Public,
            mode: EnvironmentMode::Test,
            region: Some(PaymobRegion::Uae),
        },
        PrefixCase {
            raw: "pk_live_generic",
            kind: KeyKind::Public,
            mode: EnvironmentMode::Live,
            region: None,
        },
    ];
    for case in cases {
        let parsed = parse_key_prefix(case.raw).expect("known prefix");
        assert_eq!(
            (parsed.kind, parsed.mode, parsed.region),
            (case.kind, case.mode, case.region)
        );
    }
    assert!(parse_key_prefix("unknown_prefix").is_none());
}

#[test]
fn tc_1_1_2_credentials_reject_mismatched_and_empty_inputs() {
    let sk_err = SecretKey::new("egy_pk_test_not_secret");
    let pk_err = PublicKey::new("ksa_sk_live_not_public");
    let api_err = ApiKey::new("   ");
    let hmac_err = HmacSecret::new("");
    let payouts_err = PayoutsCredentials::new("cid", "", "user", "pass");
    for res in [
        sk_err.map(|_| ()),
        pk_err.map(|_| ()),
        api_err.map(|_| ()),
        hmac_err.map(|_| ()),
        payouts_err.map(|_| ()),
    ] {
        assert!(matches!(res, Err(PaymobError::ValidationError { .. })));
    }
}

#[test]
fn tc_1_1_2_all_credential_types_redact_debug_and_display() {
    let sk = sample_secret_key("egy_sk_live_super_secret");
    let pk = sample_public_key("egy_pk_live_public_val");
    let api = ApiKey::new("api_secret_val").expect("valid api key");
    let hmac = HmacSecret::new("hmac_secret_val").expect("valid hmac");
    let payouts = PayoutsCredentials::new("cid", "csec", "usr", "pwd").expect("valid payouts");
    let partner = PartnerCredentials::with_bearer_token("p_api", "p_tok").expect("valid partner");

    assert_redacted(&sk, "egy_sk_live_super_secret");
    assert_redacted(&pk, "egy_pk_live_public_val");
    assert_redacted(&api, "api_secret_val");
    assert_redacted(&hmac, "hmac_secret_val");
    assert_redacted(&payouts, "csec");
    assert_redacted(&partner, "p_tok");
}

#[test]
fn tc_1_1_3_config_builder_defaults_and_custom_overrides() {
    let default_cfg = build_egypt_test_config();
    assert_eq!(default_cfg.timeout(), Duration::from_secs(DEFAULT_TIMEOUT_SECS));
    assert_eq!(default_cfg.max_retries(), DEFAULT_MAX_RETRIES);
    assert!(!default_cfg.use_payouts_staging() && !default_cfg.use_legacy_v2_bearer_for_capture());

    let custom_cfg = ClientConfigBuilder::new()
        .region(PaymobRegion::Uae)
        .environment(EnvironmentMode::Live)
        .secret_key(sample_secret_key("uae_sk_live_xyz"))
        .timeout(Duration::from_secs(12))
        .max_retries(5)
        .use_payouts_staging(true)
        .use_legacy_v2_bearer_for_capture(true)
        .build()
        .expect("valid custom config");
    assert_eq!(custom_cfg.environment(), EnvironmentMode::Live);
    assert_eq!(
        (custom_cfg.timeout(), custom_cfg.max_retries(), custom_cfg.use_payouts_staging()),
        (Duration::from_secs(12), 5, true)
    );
}

#[test]
fn tc_1_1_3_config_validation_and_environment_parity() {
    let missing_region = ClientConfig::builder().build();
    let zero_timeout = ClientConfig::builder()
        .region(PaymobRegion::Egypt)
        .timeout(Duration::ZERO)
        .build();
    let key_mismatch = ClientConfig::builder()
        .region(PaymobRegion::Egypt)
        .secret_key(sample_secret_key("egy_sk_test_1"))
        .public_key(sample_public_key("egy_pk_live_1"))
        .build();
    let explicit_mismatch = ClientConfig::builder()
        .region(PaymobRegion::Egypt)
        .environment(EnvironmentMode::Live)
        .secret_key(sample_secret_key("egy_sk_test_1"))
        .build();

    assert!(matches!(missing_region, Err(PaymobError::ValidationError { field: "region", .. })));
    assert!(matches!(zero_timeout, Err(PaymobError::ValidationError { field: "timeout", .. })));
    assert!(matches!(key_mismatch, Err(PaymobError::EnvironmentMismatch(_))));
    assert!(matches!(explicit_mismatch, Err(PaymobError::EnvironmentMismatch(_))));

    let dbg = format!("{:?}", build_egypt_test_config());
    assert!(dbg.contains("[REDACTED]") && !dbg.contains("egy_sk_test_secret_123"));
}

#[test]
fn tc_1_1_4_paymob_client_construction_arc_clone_and_urls() {
    assert_send_sync::<PaymobClient>();
    let client = PaymobClient::new(build_egypt_test_config()).expect("client initializes");
    let cloned = client.clone();

    assert!(client.ptr_eq(&cloned));
    assert_eq!(cloned.config().region(), &PaymobRegion::Egypt);
    assert_eq!(
        cloned.accept_url("/v1/intention/").expect("accept url").as_str(),
        "https://accept.paymob.com/v1/intention/"
    );
    assert_eq!(
        cloned.payouts_url("/api/secure/disburse/").expect("payouts url").as_str(),
        "https://payouts.paymobsolutions.com/api/secure/disburse/"
    );
    let dbg = format!("{client:?}");
    assert!(dbg.contains("[REDACTED]") && !dbg.contains("egy_sk_test_secret_123"));
}

#[test]
fn tc_1_1_4_paymob_client_rejects_absolute_or_scheme_relative_paths() {
    let client = PaymobClient::new(build_egypt_test_config()).expect("client initializes");
    let abs_err = client.accept_url("https://evil.example.com/steal");
    let proto_rel_err = client.checkout_url("//evil.example.com/steal");

    assert!(matches!(abs_err, Err(PaymobError::ValidationError { field: "path", .. })));
    assert!(matches!(proto_rel_err, Err(PaymobError::ValidationError { field: "path", .. })));
}

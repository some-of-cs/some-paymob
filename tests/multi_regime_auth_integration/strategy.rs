use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use reqwest::{Client, Method, StatusCode};
use secrecy::SecretString;
use serde_json::json;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use some_paymob::core::auth::strategy::{
    AuthRegime, AuthStrategy, EndpointAuthSpec, StrategyError,
};

struct StrategyExpectation {
    strategy: AuthStrategy,
    regime: AuthRegime,
    requires_secret: bool,
    uses_auth_header: bool,
    label: &'static str,
}

const STRATEGY_MATRIX: [StrategyExpectation; 7] = [
    StrategyExpectation {
        strategy: AuthStrategy::SecretKeyToken,
        regime: AuthRegime::Regime1SecretKey,
        requires_secret: true,
        uses_auth_header: true,
        label: "SecretKeyToken",
    },
    StrategyExpectation {
        strategy: AuthStrategy::AcceptJwtBearer,
        regime: AuthRegime::Regime2AcceptJwt,
        requires_secret: true,
        uses_auth_header: true,
        label: "AcceptJwtBearer",
    },
    StrategyExpectation {
        strategy: AuthStrategy::AcceptJwtBody,
        regime: AuthRegime::Regime2AcceptJwt,
        requires_secret: true,
        uses_auth_header: false,
        label: "AcceptJwtBody",
    },
    StrategyExpectation {
        strategy: AuthStrategy::PayoutsOAuth2,
        regime: AuthRegime::Regime3PayoutsOAuth2,
        requires_secret: true,
        uses_auth_header: true,
        label: "PayoutsOAuth2",
    },
    StrategyExpectation {
        strategy: AuthStrategy::PartnerBearer,
        regime: AuthRegime::Regime4Partner,
        requires_secret: true,
        uses_auth_header: true,
        label: "PartnerBearer",
    },
    StrategyExpectation {
        strategy: AuthStrategy::PartnerApiKey,
        regime: AuthRegime::Regime4Partner,
        requires_secret: true,
        uses_auth_header: false,
        label: "PartnerApiKey",
    },
    StrategyExpectation {
        strategy: AuthStrategy::PublicKeyOnly,
        regime: AuthRegime::Public,
        requires_secret: false,
        uses_auth_header: false,
        label: "PublicKeyOnly",
    },
];

#[test]
fn tc_1_2_1_strategy_taxonomy_properties() {
    for item in &STRATEGY_MATRIX {
        let actual = (
            item.strategy.regime(),
            item.strategy.requires_secret(),
            item.strategy.uses_authorization_header(),
            item.strategy.as_str(),
            item.strategy.to_string(),
        );
        let expected = (
            item.regime,
            item.requires_secret,
            item.uses_auth_header,
            item.label,
            item.label.to_owned(),
        );
        assert_eq!(actual, expected);
    }
}

#[test]
fn tc_1_2_1_strategy_serde_roundtrip() {
    for item in &STRATEGY_MATRIX {
        let encoded = serde_json::to_string(&item.strategy).expect("serialize strategy");
        let decoded: AuthStrategy = serde_json::from_str(&encoded).expect("deserialize strategy");
        assert_eq!(decoded, item.strategy);
    }
}

#[test]
fn tc_1_2_1_endpoint_spec_rejects_invalid_paths() {
    let invalid_paths = ["", "v1/intention/", "/v1/bad path", "/v1/bad\npath"];
    for bad in invalid_paths {
        assert!(
            EndpointAuthSpec::new(bad, Method::POST, AuthStrategy::SecretKeyToken).is_err(),
            "expected invalid endpoint path rejection for {bad:?}"
        );
    }
}

#[test]
fn tc_1_2_1_endpoint_spec_segregates_non_regime_1_strategies() {
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

#![forbid(unsafe_code)]
//! Integration tests for universal `$ENV_VARNAME` / `${ENV_VARNAME}` and `.env`
//! secret resolution across client credentials, webhooks, checkout, legacy,
//! saved cards, and subscription services.

use std::sync::Mutex;

use secrecy::{ExposeSecret, SecretString};
use some_paymob::core::auth::accept_jwt::AcceptJwtProvider;
use some_paymob::core::auth::partner::PartnerAuthContext;
use some_paymob::core::auth::payouts_oauth::PayoutsCredentials as AuthPayoutsCredentials;
use some_paymob::core::client::PaymobClient;
use some_paymob::core::config::ClientConfig;
use some_paymob::core::credentials::{
    ApiKey, EnvironmentMode, HmacSecret, PartnerCredentials, PayoutsCredentials, PublicKey,
    SecretKey, parse_dotenv_content, parse_env_secret_reference, resolve_secret_or_env,
    resolve_secret_or_env_with,
};
use some_paymob::core::error::PaymobError;
use some_paymob::core::region::PaymobRegion;

static ENV_LOCK: Mutex<()> = Mutex::new(());

struct TempEnvGuard {
    prev_dir: std::path::PathBuf,
    temp_dir: std::path::PathBuf,
}

impl Drop for TempEnvGuard {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.prev_dir);
        let _ = std::fs::remove_dir_all(&self.temp_dir);
    }
}

fn with_temp_env<F, R>(vars: &[(&str, &str)], f: F) -> R
where
    F: FnOnce() -> R,
{
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let temp_dir =
        std::env::temp_dir().join(format!("some_paymob_env_test_{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&temp_dir).expect("create temp dir");
    let dotenv_path = temp_dir.join(".env");
    let mut content = String::new();
    for (k, v) in vars {
        content.push_str(&format!("{k}={v}\n"));
    }
    std::fs::write(&dotenv_path, &content).expect("write .env");

    let prev_dir = std::env::current_dir().expect("current dir");
    std::env::set_current_dir(&temp_dir).expect("chdir temp_dir");
    let _cleanup = TempEnvGuard { prev_dir, temp_dir };
    f()
}

#[test]
fn env_secret_resolution_works_for_core_keys_and_client_builder() {
    with_temp_env(
        &[
            ("TEST_PAYMOB_SK", "egy_sk_test_dotenv_secret_123"),
            ("TEST_PAYMOB_PK", "\"egy_pk_test_dotenv_public_456\""),
            ("TEST_PAYMOB_API_KEY", "'dotenv_api_key_789'"),
            (
                "TEST_PAYMOB_HMAC",
                "dotenv_hmac_secret_abc # inline comment",
            ),
        ],
        || {
            let sk = SecretKey::new("$TEST_PAYMOB_SK").expect("SecretKey from .env");
            assert_eq!(sk.expose_secret(), "egy_sk_test_dotenv_secret_123");
            assert_eq!(sk.mode(), EnvironmentMode::Test);
            assert_eq!(sk.region(), Some(&PaymobRegion::Egypt));
            assert_eq!(format!("{sk:?}"), "[REDACTED]");

            let pk = PublicKey::new("${TEST_PAYMOB_PK}").expect("PublicKey from .env");
            assert_eq!(pk.expose_secret(), "egy_pk_test_dotenv_public_456");

            let api = ApiKey::new("$TEST_PAYMOB_API_KEY").expect("ApiKey from .env");
            assert_eq!(api.expose_secret(), "dotenv_api_key_789");

            let hmac = HmacSecret::new("${TEST_PAYMOB_HMAC}").expect("HmacSecret from .env");
            assert_eq!(hmac.expose_secret(), "dotenv_hmac_secret_abc");

            let config = ClientConfig::builder()
                .region(PaymobRegion::Egypt)
                .try_secret_key("$TEST_PAYMOB_SK")
                .expect("try_secret_key $VAR")
                .try_public_key("${TEST_PAYMOB_PK}")
                .expect("try_public_key ${VAR}")
                .try_api_key("$TEST_PAYMOB_API_KEY")
                .expect("try_api_key $VAR")
                .try_hmac_secret("${TEST_PAYMOB_HMAC}")
                .expect("try_hmac_secret ${VAR}")
                .build()
                .expect("ClientConfig build");
            let client = PaymobClient::new(config).expect("PaymobClient new");
            assert_eq!(client.config().environment(), EnvironmentMode::Test);
        },
    );
}

#[test]
fn env_secret_resolution_works_for_payouts_partner_and_auth_providers() {
    with_temp_env(
        &[
            ("TEST_PAYMOB_API_KEY", "dotenv_api_key_789"),
            ("TEST_PAYOUT_CID", "payout_cid_env"),
            ("TEST_PAYOUT_CSEC", "payout_csec_env"),
            ("TEST_PAYOUT_USER", "payout_user_env"),
            ("TEST_PAYOUT_PASS", "payout_pass_env"),
            ("TEST_PARTNER_KEY", "partner_api_key_env"),
            ("TEST_PARTNER_BEARER", "partner_bearer_env"),
        ],
        || {
            let payouts = PayoutsCredentials::new(
                "$TEST_PAYOUT_CID",
                "${TEST_PAYOUT_CSEC}",
                "$TEST_PAYOUT_USER",
                "${TEST_PAYOUT_PASS}",
            )
            .expect("PayoutsCredentials from .env");
            assert_eq!(payouts.client_id(), "payout_cid_env");
            assert_eq!(payouts.client_secret(), "payout_csec_env");

            let partner = PartnerCredentials::with_bearer_token(
                "$TEST_PARTNER_KEY",
                "${TEST_PARTNER_BEARER}",
            )
            .expect("PartnerCredentials from .env");
            assert_eq!(partner.api_key(), "partner_api_key_env");
            assert_eq!(partner.bearer_token(), Some("partner_bearer_env"));

            let auth_jwt = AcceptJwtProvider::new(
                "https://accept.paymob.com",
                SecretString::from("$TEST_PAYMOB_API_KEY"),
            )
            .expect("AcceptJwtProvider with $VAR");
            assert!(format!("{auth_jwt:?}").contains("[REDACTED]"));

            let auth_payouts = AuthPayoutsCredentials::new(
                "$TEST_PAYOUT_CID",
                "$TEST_PAYOUT_CSEC",
                "$TEST_PAYOUT_USER",
                "$TEST_PAYOUT_PASS",
            )
            .expect("AuthPayoutsCredentials with $VAR");
            assert!(format!("{auth_payouts:?}").contains("[REDACTED]"));

            let partner_ctx = PartnerAuthContext::bearer("$TEST_PARTNER_BEARER")
                .expect("PartnerAuthContext bearer $VAR");
            assert!(format!("{partner_ctx:?}").contains("[REDACTED]"));
        },
    );
}

#[cfg(feature = "webhooks")]
#[test]
fn env_secret_resolution_works_on_webhook_engine_and_rejects_missing_vars() {
    use some_paymob::webhooks::{PaymobWebhookEngine, WebhookError};

    with_temp_env(
        &[
            ("TEST_WEBHOOK_HMAC", "test_hmac_secret"),
            ("TEST_PAYOUT_WEBHOOK_HMAC", "payout_secret_key"),
        ],
        || {
            let engine = PaymobWebhookEngine::new("$TEST_WEBHOOK_HMAC")
                .expect("webhook engine from $VAR")
                .with_payouts_secret("${TEST_PAYOUT_WEBHOOK_HMAC}")
                .expect("payouts secret from ${VAR}");
            let sig = "b0c960da53f0c16e9d7478563f3fd8063633f9fd9b009025f568aba9252542ac637c171bdee453b160d89b957f4ef93cd30814ddb147f4c1a1497443d150c68d";
            assert_eq!(engine.verify_concatenated_str("100020003000", sig), Ok(()));

            let env_sec = SecretString::from("$TEST_PAYOUT_WEBHOOK_HMAC");
            let payout_sig = "6fc165775a3b285e6058f68cadeafbec94978a28d6a29c3fd17b118fb527219cbe11bf5d64dd38e2b04ad2bd15bcbd13fa24901b50abe7fc51ac54520812485a";
            assert_eq!(
                PaymobWebhookEngine::verify_concatenated_with_secret(
                    &env_sec,
                    "payout_payload_123",
                    payout_sig
                ),
                Ok(())
            );

            assert_eq!(
                PaymobWebhookEngine::new("$NON_EXISTENT_WEBHOOK_SECRET_VAR").unwrap_err(),
                WebhookError::InvalidSecretKeyLength
            );
        },
    );

    with_temp_env(
        &[("TEST_DOLLAR_HMAC", "$DOLLAR_PREFIXED_SECRET")],
        || {
            let engine = PaymobWebhookEngine::new("$TEST_DOLLAR_HMAC")
                .expect("resolved secret starting with $");
            let sig = "2bcf72fe6b6d331ce42b0dbffa1378ed6f00c49a482d497e25bc11d07f579f41c18406f07889c8b316dce20c8fb986dfb693da5ffa20d3659c925e0117813a42";
            assert_eq!(engine.verify_concatenated_str("100020003000", sig), Ok(()));
        },
    );
}

#[cfg(all(feature = "intentions", feature = "legacy-v2"))]
#[test]
fn env_secret_resolution_works_for_checkout_and_legacy_v2() {
    use some_paymob::resources::checkout::{PixelConfig, PixelPaymentMethod};

    with_temp_env(
        &[
            ("TEST_SK", "egy_sk_test_111"),
            ("TEST_PK", "egy_pk_test_222"),
            ("TEST_API_KEY", "accept_api_key_333"),
            ("TEST_CSK", "egy_csk_test_client_secret_444"),
            ("TEST_PAY_TOK", "pay_tok_from_env_555"),
        ],
        || {
            let cfg = ClientConfig::builder()
                .region(PaymobRegion::Egypt)
                .try_secret_key("$TEST_SK")
                .unwrap()
                .try_public_key("$TEST_PK")
                .unwrap()
                .try_api_key("$TEST_API_KEY")
                .unwrap()
                .build()
                .unwrap();
            let client = PaymobClient::new(cfg).unwrap();

            let checkout_url = client
                .checkout()
                .unified_url(&SecretString::from("$TEST_CSK"))
                .expect("unified_url with $TEST_CSK");
            assert!(
                checkout_url
                    .as_str()
                    .contains("clientSecret=egy_csk_test_client_secret_444")
            );

            let pk = PublicKey::new("$TEST_PK").unwrap();
            let pixel = PixelConfig::builder(&pk, SecretString::from("${TEST_CSK}"))
                .add_payment_method(PixelPaymentMethod::Card)
                .build()
                .expect("PixelConfig with ${TEST_CSK}");
            assert_eq!(
                pixel.client_secret.expose_secret(),
                "egy_csk_test_client_secret_444"
            );

            let legacy_url = client
                .legacy_v2()
                .unwrap()
                .iframe_url(812_345, &SecretString::from("$TEST_PAY_TOK"))
                .expect("iframe_url with $TEST_PAY_TOK");
            assert!(
                legacy_url
                    .as_str()
                    .contains("payment_token=pay_tok_from_env_555")
            );
        },
    );
}

#[cfg(all(feature = "saved-cards", feature = "subscriptions"))]
#[test]
fn env_secret_resolution_works_for_saved_cards_and_subscriptions() {
    use some_paymob::resources::saved_cards::cit_mit::{CitCardTokenConfig, MitChargeParams};
    use some_paymob::resources::saved_cards::service::{KioskPayParams, MitPayParams};
    use some_paymob::resources::saved_cards::sources::PaymentSource;
    use some_paymob::resources::subscriptions::cards::AddSecondaryCardParams;

    with_temp_env(
        &[
            ("TEST_PAY_TOK", "pay_tok_from_env_555"),
            ("TEST_SAVED_TOK", "saved_tok_from_env_666"),
            ("TEST_CVN", "789"),
        ],
        || {
            let cit = CitCardTokenConfig::from_single(SecretString::from("$TEST_SAVED_TOK"))
                .expect("CitCardTokenConfig with $TEST_SAVED_TOK");
            assert_eq!(cit.to_wire_tokens(), vec!["saved_tok_from_env_666"]);

            let mit = MitChargeParams::with_moto_cvc(
                SecretString::from("$TEST_PAY_TOK"),
                SecretString::from("${TEST_SAVED_TOK}"),
                SecretString::from("$TEST_CVN"),
            )
            .expect("MitChargeParams with $VAR");
            assert_eq!(mit.payment_token().expose_secret(), "pay_tok_from_env_555");
            assert_eq!(mit.saved_token().expose_secret(), "saved_tok_from_env_666");
            assert_eq!(mit.cvn().unwrap().expose_secret(), "789");

            let tok_pay = MitPayParams::new("$TEST_PAY_TOK", "${TEST_SAVED_TOK}")
                .unwrap()
                .with_cvn("$TEST_CVN")
                .unwrap();
            assert_eq!(
                tok_pay.payment_token().expose_secret(),
                "pay_tok_from_env_555"
            );
            assert_eq!(
                tok_pay.saved_token().expose_secret(),
                "saved_tok_from_env_666"
            );
            assert_eq!(tok_pay.cvn().unwrap().expose_secret(), "789");

            let kiosk_pay = KioskPayParams::new("$TEST_PAY_TOK").unwrap();
            assert_eq!(
                kiosk_pay.payment_token().expose_secret(),
                "pay_tok_from_env_555"
            );

            let src = PaymentSource::saved_token_with_cvn("$TEST_SAVED_TOK", "$TEST_CVN").unwrap();
            assert_eq!(src.subtype(), "TOKEN");

            let sec_card = AddSecondaryCardParams::new("$TEST_SAVED_TOK").unwrap();
            assert!(format!("{sec_card:?}").contains("[REDACTED]"));
        },
    );
}

#[test]
fn env_secret_resolution_negative_and_edge_cases() {
    for invalid in [
        "$",
        "${}",
        "${UNCLOSED",
        "$9INVALID",
        "$BAD-CHAR",
        "$SPACE VAR",
    ] {
        assert!(parse_env_secret_reference("secret_key", invalid).is_err());
        assert!(SecretKey::new(invalid).is_err());
        assert!(PublicKey::new(invalid).is_err());
        assert!(ApiKey::new(invalid).is_err());
        assert!(HmacSecret::new(invalid).is_err());
    }

    assert!(matches!(
        resolve_secret_or_env("secret_key", "$PAYMOB_VAR_THAT_DOES_NOT_EXIST_987654"),
        Err(PaymobError::ValidationError {
            field: "secret_key",
            ..
        })
    ));

    let pk_in_sk_err = resolve_secret_or_env_with("secret_key", "$MY_PK_VAR", |_| {
        Some("egy_pk_test_ accidentally_public".to_owned())
    })
    .and_then(|sec| SecretKey::new(sec.expose_secret()));
    assert!(matches!(
        pk_in_sk_err,
        Err(PaymobError::ValidationError {
            field: "secret_key",
            ..
        })
    ));

    let secret_like_err = SecretKey::new("$p@ss word!").unwrap_err();
    assert!(!secret_like_err.to_string().contains("$p@ss word!"));

    let dotenv = "
        # leading comment
        export KEY_A = \"val_a\" # double-quoted comment
        KEY_B = 'val_b' # single-quoted comment
        KEY_C = val_c # comment
    ";
    assert_eq!(
        parse_dotenv_content(dotenv, "KEY_A").as_deref(),
        Some("val_a")
    );
    assert_eq!(
        parse_dotenv_content(dotenv, "KEY_B").as_deref(),
        Some("val_b")
    );
    assert_eq!(
        parse_dotenv_content(dotenv, "KEY_C").as_deref(),
        Some("val_c")
    );
}

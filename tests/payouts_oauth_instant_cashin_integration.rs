#![forbid(unsafe_code)]
//! Story-level integration tests for `US-5.1.0` (Payouts OAuth2 + 7-issuer Instant Cashin + Aman Cancel).

use secrecy::SecretString;
use some_paymob::core::client::PaymobClient;
use some_paymob::core::config::ClientConfig;
use some_paymob::core::credentials::PayoutsCredentials;
use some_paymob::core::region::PaymobRegion;
use some_paymob::resources::payouts::{
    BankCardCashinParams, BankTransactionType, CancelAmanParams, DisburseIssuer,
    EgyptianPostCashinParams, InstantBankCashinParams, MobileWalletCashinParams,
};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn make_client(base_url: &str) -> PaymobClient {
    let creds =
        PayoutsCredentials::new("cid", "csec", "user", "pass").expect("valid payouts creds");
    let cfg = ClientConfig::builder()
        .region(PaymobRegion::Custom {
            accept_base_url: base_url.to_owned(),
            checkout_base_url: base_url.to_owned(),
            payouts_base_url: base_url.to_owned(),
            payouts_staging_base_url: base_url.to_owned(),
        })
        .payouts_credentials(creds)
        .build()
        .expect("valid config");
    PaymobClient::new(cfg).expect("valid client")
}

async fn mount_disburse_mock(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/api/secure/disburse/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "transaction_id": "tx_e2e_1",
            "issuer": "vodafone",
            "amount": 150,
            "disbursement_status": "successful"
        })))
        .mount(server)
        .await;
}

#[tokio::test]
async fn us_5_1_0_oauth_token_generation() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/secure/o/token/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "e2e_access",
            "refresh_token": "e2e_refresh",
            "expires_in": 3600,
            "scope": "read write",
            "token_type": "Bearer"
        })))
        .mount(&server)
        .await;

    let client = make_client(&server.uri());
    let tok = client.payouts().auth().generate_token().await.unwrap();
    assert_eq!(tok.expires_in, 3600);
}

#[tokio::test]
async fn us_5_1_0_mobile_and_bank_wallet_issuers() {
    let server = MockServer::start().await;
    mount_disburse_mock(&server).await;
    let client = make_client(&server.uri());
    client
        .auth()
        .payouts_cache()
        .store(some_paymob::core::auth::CachedToken::with_default_ttl(
            "jwt", None,
        ));
    let cashin = client.payouts().cashin();

    let vf = cashin
        .vodafone(MobileWalletCashinParams::new("01023456789", 150))
        .await
        .unwrap();
    assert_eq!(vf.issuer, Some(DisburseIssuer::Vodafone));
    cashin
        .etisalat(MobileWalletCashinParams::new("01123456789", 150))
        .await
        .unwrap();
    cashin
        .orange(MobileWalletCashinParams::new("01223456789", 150))
        .await
        .unwrap();
    cashin
        .bank_wallet(MobileWalletCashinParams::new("01523456789", 150))
        .await
        .unwrap();
}

#[tokio::test]
async fn us_5_1_0_bank_post_and_aman_cancel() {
    let server = MockServer::start().await;
    mount_disburse_mock(&server).await;
    Mock::given(method("POST"))
        .and(path("/api/secure/transaction/aman/cancel/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "transaction_id": "tx_aman_cancel",
            "disbursement_status": "cancelled"
        })))
        .mount(&server)
        .await;

    let client = make_client(&server.uri());
    client
        .auth()
        .payouts_cache()
        .store(some_paymob::core::auth::CachedToken::with_default_ttl(
            "jwt", None,
        ));
    let cashin = client.payouts().cashin();

    cashin
        .bank_card(BankCardCashinParams {
            amount: 500,
            bank_card_number: SecretString::from("4111111111111234"),
            bank_code: String::from("CIB"),
            bank_transaction_type: BankTransactionType::Salary,
            full_name: String::from("Maher Mansour"),
            client_reference_id: None,
            customer_bears_fees: None,
        })
        .await
        .unwrap();
    cashin
        .bank_instant(InstantBankCashinParams {
            amount: 500,
            bank_code: String::from("NBE"),
            bank_account_number: SecretString::from("EG1234567890"),
            full_name: String::from("Maher Mansour"),
            client_reference_id: None,
            customer_bears_fees: None,
        })
        .await
        .unwrap();
    cashin
        .egyptian_post(EgyptianPostCashinParams {
            amount: 500,
            msisdn: String::from("01023456789"),
            full_name: String::from("Maher Mansour"),
            national_id: SecretString::from("29901010101234"),
            client_reference_id: None,
            customer_bears_fees: None,
        })
        .await
        .unwrap();
    let aman = cashin
        .cancel_aman(CancelAmanParams::new("tx_aman_cancel"))
        .await
        .unwrap();
    assert_eq!(aman.disbursement_status.as_deref(), Some("cancelled"));
}

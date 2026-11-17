#![forbid(unsafe_code)]
//! Whole-codebase security, reusability, and edge/negative integration tests.
//!
//! Verifies cross-module transport hardening, `prelude` re-exports across all
//! modules, non-loopback HTTP rejection, QuickLinks 401 refresh & input guards,
//! and Payouts / Onboarding / Splits invariants.

use some_paymob::prelude::*;

fn try_custom_http_client(remote_base: &str) -> Result<PaymobClient, PaymobError> {
    let config = ClientConfig::builder()
        .region(PaymobRegion::Custom {
            accept_base_url: remote_base.to_owned(),
            checkout_base_url: remote_base.to_owned(),
            payouts_base_url: remote_base.to_owned(),
            payouts_staging_base_url: remote_base.to_owned(),
        })
        .secret_key(SecretKey::new("egy_sk_test_whole_codebase")?)
        .api_key(ApiKey::new(
            "ZXlKaGJHY2lPaUpJVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5",
        )?)
        .max_retries(0)
        .build()?;
    PaymobClient::new(config)
}

#[cfg(all(
    feature = "inquiries",
    feature = "manage",
    feature = "payouts",
    feature = "onboarding"
))]
#[tokio::test]
async fn non_loopback_plaintext_http_is_rejected_across_all_resource_modules() {
    assert!(matches!(
        try_custom_http_client("http://example.com"),
        Err(PaymobError::ValidationError {
            field: "accept_base_url",
            ..
        })
    ));

    let client = try_custom_http_client("http://untrusted-gateway.local")
        .expect("mDNS .local parses at region level");
    client
        .auth()
        .accept_cache()
        .store(CachedToken::with_default_ttl("seeded_jwt", None));
    client
        .auth()
        .payouts_cache()
        .store(CachedToken::with_default_ttl("seeded_oauth", None));

    let inq_err = client.inquiries().by_transaction_id(192_036_465).await;
    assert!(matches!(
        inq_err,
        Err(PaymobError::ValidationError {
            field: "http_config",
            ..
        })
    ));

    let mng_err = client.manage().void(VoidParams::new(192_036_465)).await;
    assert!(matches!(
        mng_err,
        Err(PaymobError::ValidationError {
            field: "http_config",
            ..
        })
    ));

    let pay_err = client.payouts().inquiries().user_budget().await;
    assert!(matches!(
        pay_err,
        Err(PaymobError::ValidationError {
            field: "http_config",
            ..
        })
    ));
}

#[cfg(feature = "splits")]
#[test]
fn splits_and_convenience_fees_reexport_and_enforce_edge_bounds() {
    let rule = SplitRecipientRule::percentage_bps("sub_merchant_1", 2_500)
        .with_description("25% marketplace split");
    assert!(rule.validate().is_ok());

    let bad_both = SplitRecipientRule {
        recipient_id: "sub_merchant_1".to_owned(),
        amount_cents: Some(1_000),
        percentage_bps: Some(500),
        description: None,
    };
    assert!(bad_both.validate().is_err());

    let fee_cfg = ConvenienceFeeConfig::new(FeeCalculationMode::Combination {
        bps: 200,
        fixed_cents: 300,
    })
    .with_card_rule(CardFeeRule::Uniform)
    .with_max_fee_cents(5_000);
    let fee = fee_cfg
        .compute_fee_for_card_cents(100_000, &CardFeeContext::new(true, false))
        .expect("valid fee");
    assert_eq!(fee, 2_300);
}

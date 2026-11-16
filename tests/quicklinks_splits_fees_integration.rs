#![forbid(unsafe_code)]
//! Integration tests for `US-3.3.0` (`AC-1..4` / `TC-3.3.1..4`).

#[cfg(feature = "quicklinks")]
mod quicklinks_integration {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use some_paymob::core::client::PaymobClient;
    use some_paymob::core::config::ClientConfig;
    use some_paymob::core::credentials::ApiKey;
    use some_paymob::core::region::PaymobRegion;
    use some_paymob::resources::quicklinks::CreateQuickLinkParams;

    #[tokio::test]
    async fn ac_1_tc_3_3_1_create_and_cancel_quicklink_end_to_end() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/auth/tokens"))
            .respond_with(
                ResponseTemplate::new(201)
                    .set_body_json(serde_json::json!({ "token": "jwt_story_330" })),
            )
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/api/ecommerce/payment-links"))
            .and(header("Authorization", "Bearer jwt_story_330"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "id": "ql_330_001",
                "url": "https://accept.paymob.com/standalone/?ref=ql_330_001",
                "client_url": "https://accept.paymob.com/api/acceptance/post_pay?ref=ql_330_001"
            })))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/api/ecommerce/payment-links/cancel"))
            .and(header("Authorization", "Bearer jwt_story_330"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "detail": "cancelled"
            })))
            .mount(&server)
            .await;

        let uri = server.uri();
        let config = ClientConfig::builder()
            .region(PaymobRegion::Custom {
                accept_base_url: uri.clone(),
                checkout_base_url: format!("{uri}/unifiedcheckout/"),
                payouts_base_url: None,
            })
            .api_key(ApiKey::new("story_330_api_key_secret").expect("valid api key"))
            .build()
            .expect("valid config");
        let client = PaymobClient::new(config).expect("valid client");

        let params = CreateQuickLinkParams::new(150_000, "EGP", vec![4097558])
            .with_description("Marketplace Order #330")
            .with_full_name("Maher Alaa")
            .with_email("buyer@example.com")
            .with_phone_number("+201001234567")
            .with_redirection_url("https://merchant.example.com/callback");

        // AC-4 / TC-3.3.4: PII redaction in Debug
        let dbg = format!("{params:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("buyer@example.com"));
        assert!(!dbg.contains("+201001234567"));

        let resp = client
            .quicklinks()
            .create(&params)
            .await
            .expect("create ok");
        assert_eq!(resp.id, "ql_330_001");
        assert!(resp.url.contains("ql_330_001"));
        assert!(resp.client_url.contains("ql_330_001"));

        client
            .quicklinks()
            .cancel(&resp.id)
            .await
            .expect("cancel ok");
    }
}

#[cfg(feature = "splits")]
mod splits_integration {
    use some_paymob::core::error::PaymobError;
    use some_paymob::resources::splits::convenience_fees::{
        CardFeeContext, CardFeeRule, ConvenienceFeeConfig, FeeCalculationMode,
    };
    use some_paymob::resources::splits::models::{
        SplitCardPortion, SplitDescription, SplitPaymentConfig, SplitRecipientRule,
    };

    #[test]
    fn ac_2_tc_3_3_2_multi_card_split_cap_and_marketplace_rules() {
        let split_desc = SplitDescription::new(vec![
            SplitRecipientRule::percentage_bps("seller_egy_1", 8_500),
            SplitRecipientRule::percentage_bps("platform_fee", 1_500),
        ])
        .expect("valid split description");
        assert_eq!(split_desc.total_percentage_bps().expect("bps"), 10_000);

        let three_cards = SplitPaymentConfig::new(vec![
            SplitCardPortion::new(50_000).with_card_token("tok_card_1"),
            SplitCardPortion::new(50_000).with_card_token("tok_card_2"),
            SplitCardPortion::new(50_000).with_card_token("tok_card_3"),
        ])
        .expect("3 cards allowed");
        assert!(three_cards.validate_total(150_000).is_ok());
        assert!(format!("{three_cards:?}").contains("[REDACTED]"));
        assert!(!format!("{three_cards:?}").contains("tok_card_1"));

        let four_cards = vec![
            SplitCardPortion::new(10_000),
            SplitCardPortion::new(10_000),
            SplitCardPortion::new(10_000),
            SplitCardPortion::new(10_000),
        ];
        assert!(matches!(
            SplitPaymentConfig::new(four_cards),
            Err(PaymobError::ValidationError { field: "cards", .. })
        ));
    }

    #[test]
    fn ac_3_ac_4_tc_3_3_3_convenience_fee_engine_and_redaction() {
        let cfg = ConvenienceFeeConfig::new(FeeCalculationMode::Combination {
            bps: 250,
            fixed_cents: 300,
        })
        .with_max_fee_cents(5_000)
        .with_refundable(true);

        // 2.5% of 300_000 = 7_500 + 300 = 7_800, capped at 5_000
        assert_eq!(cfg.compute_fee_cents(300_000).expect("capped fee"), 5_000);
        assert_eq!(cfg.total_with_fee_cents(300_000).expect("total"), 305_000);

        let intl_cfg = ConvenienceFeeConfig::new(FeeCalculationMode::FixedCents(0)).with_card_rule(
            CardFeeRule::DomesticVsInternational {
                domestic_mode: FeeCalculationMode::PercentageBps(100),
                international_mode: FeeCalculationMode::PercentageBps(350),
            },
        );
        let intl_ctx = CardFeeContext::new(true, true).with_bin_prefix("411111");
        assert_eq!(
            intl_cfg
                .compute_fee_for_card_cents(200_000, &intl_ctx)
                .expect("intl fee"),
            7_000
        );
        let ctx_dbg = format!("{intl_ctx:?}");
        assert!(ctx_dbg.contains("[REDACTED]"));
        assert!(!ctx_dbg.contains("411111"));
    }
}

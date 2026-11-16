use std::any::type_name;

use some_paymob::core::error::PaymobError;
use some_paymob::core::pagination::{PageQuery, PaginatedResponse};
use some_paymob::core::types::{Currency, KNOWN_CURRENCIES, MinorUnitAmount, validate_prefixed_id};
use some_paymob::prelude as sdk_prelude;

fn assert_minor_unit_arithmetic(egp: MinorUnitAmount) {
    assert_eq!(
        (
            egp.as_u64(),
            MinorUnitAmount::from_major_checked(25, 3).expect("25 OMR"),
        ),
        (100_000, MinorUnitAmount::new(25_000))
    );
    assert_eq!(
        (
            egp.checked_add(MinorUnitAmount::new(500)).expect("add"),
            egp.checked_sub(MinorUnitAmount::new(500)).expect("sub"),
        ),
        (MinorUnitAmount(100_500), MinorUnitAmount(99_500))
    );
}

fn assert_minor_unit_serde(egp: MinorUnitAmount) {
    let json = serde_json::to_string(&egp).expect("serialize integer");
    assert_eq!(json, "100000");
    let roundtrip: MinorUnitAmount = serde_json::from_str(&json).expect("deserialize integer");
    assert_eq!(
        (roundtrip, u64::from(roundtrip), roundtrip.to_string()),
        (egp, 100_000, "100000".to_string())
    );
}

#[test]
fn tc_1_3_3_money_zero_float_arithmetic_and_serde() {
    let egp = MinorUnitAmount::from_major_checked(1000, 2).expect("1000 EGP");
    assert_minor_unit_arithmetic(egp);
    assert_minor_unit_serde(egp);

    let failure_cases = [
        (MinorUnitAmount::from_major_checked(1, 20), "decimals"),
        (MinorUnitAmount::from_major_checked(u64::MAX, 2), "amount"),
        (
            MinorUnitAmount(u64::MAX).checked_add(MinorUnitAmount(1)),
            "amount",
        ),
        (
            MinorUnitAmount(10).checked_sub(MinorUnitAmount(11)),
            "amount",
        ),
    ];
    for (res, expected_field) in failure_cases {
        assert!(matches!(
            res,
            Err(PaymobError::ValidationError { field, .. }) if field == expected_field
        ));
    }
}

fn assert_currency_case(raw: &str, expected: Currency, canonical: &str, decimals: u8) {
    let parsed = Currency::from_code(raw);
    assert_eq!(
        (&parsed, parsed.as_str(), parsed.minor_unit_decimals()),
        (&expected, canonical, decimals)
    );

    let serialized = serde_json::to_string(&parsed).expect("serialize currency");
    let deserialized: Currency = serde_json::from_str(&serialized).expect("deserialize");
    assert_eq!(
        (raw.parse::<Currency>().expect("infallible"), deserialized),
        (expected, parsed)
    );
}

fn assert_prefixed_id_validation() {
    for (id, prefix, field) in [
        ("pi_abc123", "pi_", "intention_id"),
        ("pk_test_xyz", "pk_", "public_key"),
    ] {
        assert!(validate_prefixed_id(id, prefix, field).is_ok());
    }

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
        ("kwd", Currency::Unknown("KWD".to_string()), "KWD", 3_u8),
    ];

    for (raw, expected, canonical, decimals) in currency_cases {
        assert_currency_case(raw, expected, canonical, decimals);
    }
    assert_prefixed_id_validation();
}

#[test]
fn tc_1_3_3_currency_iso_serde_and_kwd_three_decimal_arithmetic() {
    let kwd = Currency::from_code("kwd");
    let json = serde_json::to_string(&kwd).expect("serialize");
    let roundtrip: Currency = serde_json::from_str(&json).expect("deserialize");
    let amount =
        MinorUnitAmount::from_major_checked(10, roundtrip.minor_unit_decimals()).expect("10 KWD");
    assert_eq!(
        (json.as_str(), roundtrip, amount),
        (
            r#""KWD""#,
            Currency::Unknown("KWD".to_string()),
            MinorUnitAmount(10_000)
        )
    );
}

fn assert_paginated_response_bounds(page: &PaginatedResponse<u64>) {
    assert_eq!((page.count, page.len(), page.is_empty()), (42, 3, false));
}

fn assert_paginated_response_nav(page: &PaginatedResponse<u64>) {
    assert_eq!((page.has_next(), page.has_previous()), (true, true));
    assert_eq!(
        (page.next_page_number(), page.previous_page_number()),
        (Some(3), Some(1))
    );
}

fn assert_page_query_behavior() {
    let query = PageQuery::new(0).with_page_size(0);
    assert_eq!(
        (query.page(), query.page_size(), query.to_query_string()),
        (1, Some(1), "?page=1&page_size=1".to_string())
    );

    let roundtrip: PageQuery =
        serde_json::from_str(&serde_json::to_string(&PageQuery::new(3)).expect("serialize"))
            .expect("deserialize");
    assert_eq!(
        (query.next_page().to_query_pairs(), roundtrip),
        (
            vec![("page", "2".to_string()), ("page_size", "1".to_string())],
            PageQuery::new(3)
        )
    );
}

fn assert_prelude_reexports() {
    use sdk_prelude::*;
    let exported = [
        type_name::<CachedToken>(),
        type_name::<AuthStrategy>(),
        type_name::<PaymobClient>(),
        type_name::<ClientConfig>(),
        type_name::<ClientConfigBuilder>(),
        type_name::<ApiKey>(),
        type_name::<EnvironmentMode>(),
        type_name::<HmacSecret>(),
        type_name::<PartnerCredentials>(),
        type_name::<PayoutsCredentials>(),
        type_name::<PublicKey>(),
        type_name::<SecretKey>(),
        type_name::<PaymobError>(),
        type_name::<PageQuery>(),
        type_name::<PaginatedResponse<u8>>(),
        type_name::<PaymobRegion>(),
        type_name::<RegionalEndpoints>(),
        type_name::<Currency>(),
        type_name::<MinorUnitAmount>(),
        type_name::<HttpClient>(),
        type_name::<HttpClientConfig>(),
        type_name::<HttpError>(),
        type_name::<HttpRequest>(),
        type_name::<HttpResponse>(),
        type_name::<RetryPolicy>(),
        type_name::<fn(&str, &str, &'static str) -> Result<(), PaymobError>>(),
    ];
    let _ = validate_prefixed_id;
    for name in exported {
        assert!(!name.is_empty());
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
    assert_paginated_response_bounds(&page);
    assert_paginated_response_nav(&page);
    let mapped = page.map(|id| format!("ord_{id}"));
    assert_eq!(mapped.results, vec!["ord_101", "ord_102", "ord_103"]);

    assert_page_query_behavior();
    assert_prelude_reexports();
}

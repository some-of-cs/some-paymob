# Integrating `some-paymob` with `some-payment`

This guide documents how [`some-paymob`](https://github.com/some-of-cs/some-paymob) plugs into the [`some-payment`](https://github.com/some-of-cs/some-payment) multi-gateway router as a regional provider for Egypt (`EGP`), Saudi Arabia (`SAR`), UAE (`AED`), Oman (`OMR`), and Pakistan (`PKR`).

Enabling the `some-payments-adapter` Cargo feature (or its `some-payment-trait` alias) exposes the northbound unified adapter layer while preserving all `some-paymob` safety invariants: `#![forbid(unsafe_code)]`, integer minor-unit amounts (`MinorUnitAmount`), `secrecy::SecretString` + `ZeroizeOnDrop` credential hygiene, and `[REDACTED]` `Debug` formatting.

---

## 1. Orthogonal Capability Mapping

Rather than forcing every payment gateway behind a single monolithic trait, `some-payment` separates routing policies from object-safe (`dyn`-compatible) orthogonal capability traits. `some-paymob` maps onto those capabilities as follows:

| `some-payment` Capability | `some-paymob` Adapter / Native Surface | Underlying Paymob APIs & Behavior |
| :--- | :--- | :--- |
| **`DynPaymentCapability`** | `PaymentProvider` (`src/adapter/dyn_traits.rs`, `src/adapter/some_payments.rs`), `client.intentions()`, `client.manage()`, `client.saved_cards()` | Unified Intention creation (`POST /v1/intention/`), saved-token CIT/MIT charges (`POST /api/acceptance/payments/pay`), capture (`POST /api/acceptance/capture`), void (`POST /api/acceptance/void_refund/void`), refund (`POST /api/acceptance/void_refund/refund`), and smart `refund_or_void` reversal routing. |
| **`DynWebhookCapability`** | `WebhookVerifier` (`src/adapter/dyn_traits.rs`, `src/adapter/webhook_adapter.rs`), `PaymobWebhookEngine`, `IdempotentWebhookGuard` | Constant-time `HMAC-SHA512` verification (`subtle::ConstantTimeEq`) across all 5 Paymob callback protocols (Protocols A–E, including Protocol B `GET` redirects) normalized into unified webhook events with replay deduplication. |
| **`DynPayoutCapability`** | `PayoutProvider` (`src/adapter/dyn_traits.rs`, `src/adapter/payout_adapter.rs`), `client.payouts()` | Paymob Send Regime 3 OAuth 2.0 (`POST /api/secure/o/token/`), single disbursements across all 7 issuers (`POST /api/secure/disburse/`), bulk disbursements (`POST /disburse/api/v1/disburse/bulk_transaction/`), Aman cancellation, and transaction/reference/budget/topup inquiries. |
| **`DynSplitSettlementCapability`** | `some_paymob::resources::splits` (`SplitRecipientRule`, `SplitPaymentConfig`, `ConvenienceFeeConfig`) | Marketplace multi-recipient splits enforcing `amount_cents` XOR `percentage_bps`, 3-card split payment rules, and integer basis-point convenience fees attached to intentions. |

For Paymob-specific workflows that fall outside the lowest-common-denominator traits (such as Affordability Widget installment plans, Fawry Kiosk aggregators, ValU BNPL, or Partner Onboarding via `MerchantScopedClient`), downcast through the `PaymobExt` / `ProviderExt::Paymob` escape hatch in `some_paymob::adapter`.

---

## 2. Protocol A–E Webhook Verification (Including Protocol B GET Redirects)

Paymob signs callbacks using `HMAC-SHA512` over protocol-specific lexicographically concatenated field strings. `PaymobWebhookEngine` verifies all five protocols in strict constant time (`subtle::ConstantTimeEq`) and pairs with `IdempotentWebhookGuard` / `InMemoryWebhookDeduplicator` to prevent replay processing.

| Protocol | Transport | Verification Rule & Canonical Builder | Verified Type |
| :--- | :---: | :--- | :--- |
| **Protocol A** — Transaction Processed | `POST` JSON + `?hmac=` | 20-key lexicographical concatenation (`TX_HMAC_KEYS`, `build_protocol_a_canonical_string`) over `obj` including nested `order.id` and `source_data.*` | `TransactionProcessedEvent` |
| **Protocol B** — Transaction Response Redirect | `GET` Query String | 20-key query-parameter concatenation (`build_protocol_b_canonical_string`) with automatic `order_id` / `order` key fallback via `QueryParams`, verified with `verify_transaction_get` or `verify_transaction_get_query_str` | `TransactionRedirectParams` |
| **Protocol C** — Card Token Saved | `POST` JSON + `?hmac=` | 8-key lexicographical concatenation (`TOKEN_HMAC_KEYS`, `build_protocol_c_canonical_string`) | `CardTokenWebhookEvent` |
| **Protocol D** — Subscription Lifecycle | `POST` JSON + `?hmac=` | 12 known lifecycle triggers (`KNOWN_SUBSCRIPTION_TRIGGERS`) verified over `"{trigger_type}for{subscription_data.id}"` (`canonical_subscription_message`) | `SubscriptionWebhookEvent` |
| **Protocol E** — Payouts Disbursement & Topup | `POST` JSON | Paymob Send disbursement and topup callback parsing & verification | `DisbursementCallback`, `TopupCallback` |

### Handling Both `POST` Webhooks and Protocol B `GET` Redirects

```rust,no_run
use some_paymob::prelude::*;
use some_paymob::webhooks::{
    IdempotentWebhookGuard, InMemoryWebhookDeduplicator, PaymobWebhookEngine, WebhookError,
    WebhookEvent,
};

fn handle_post_webhook(
    engine: &PaymobWebhookEngine,
    dedup: &InMemoryWebhookDeduplicator,
    raw_body: &str,
    query_hmac: Option<&str>,
) -> Result<(), WebhookError> {
    let event = engine.construct_event(raw_body, query_hmac)?;

    match event {
        WebhookEvent::TransactionProcessed(tx) => {
            let key = format!("tx:{}", tx.obj.id);
            if dedup.check_and_record(&key) {
                println!(
                    "Verified Protocol A tx_id={} order_id={} amount_cents={}",
                    tx.obj.id, tx.obj.order.id, tx.obj.amount_cents
                );
            }
        }
        WebhookEvent::CardTokenSaved(token) => {
            println!("Verified Protocol C card token id={}", token.obj.id);
        }
        WebhookEvent::SubscriptionLifecycle(sub) => {
            println!("Verified Protocol D subscription id={}", sub.subscription_data.id);
        }
        WebhookEvent::PayoutDisbursement(payout) => {
            println!("Verified Protocol E disbursement tx_id={}", payout.transaction_id);
        }
        _ => {}
    }

    Ok(())
}

fn handle_protocol_b_redirect(
    engine: &PaymobWebhookEngine,
    raw_query_string: &str,
) -> Result<(), WebhookError> {
    // Handles both `order=<id>` and `order_id=<id>` redirect query formats in constant time.
    let redirect = engine.verify_transaction_get_query_str(raw_query_string)?;
    if redirect.is_approved() && !redirect.is_pending() {
        println!(
            "Verified Protocol B redirect tx_id={} order_id={} amount_cents={}",
            redirect.transaction_id_u64()?,
            redirect.order_id_u64()?,
            redirect.amount_cents_u64()?,
        );
    }
    Ok(())
}
```

---

## 3. Paymob Send Payouts: All 7 Issuers, Bulk Disbursements & Inquiries

Paymob Send uses Regime 3 OAuth 2.0 (`POST /api/secure/o/token/`) with automatic single-flight token caching and `refresh_token` / `password` renewal via `client.auth().payouts_cache()`.

### All 7 Supported `DisburseIssuer` Targets

| # | `DisburseIssuer` Variant | Wire `issuer` Value | `client.payouts().cashin()` Method | Parameter Struct |
| :-: | :--- | :--- | :--- | :--- |
| 1 | `DisburseIssuer::Vodafone` | `"vodafone"` | `.vodafone(params)` | `MobileWalletCashinParams` |
| 2 | `DisburseIssuer::Etisalat` | `"etisalat"` | `.etisalat(params)` | `MobileWalletCashinParams` |
| 3 | `DisburseIssuer::Orange` | `"orange"` | `.orange(params)` | `MobileWalletCashinParams` |
| 4 | `DisburseIssuer::BankWallet` | `"bank_wallet"` | `.bank_wallet(params)` | `MobileWalletCashinParams` |
| 5 | `DisburseIssuer::BankCard` | `"bank_card"` | `.bank_card(params)` | `BankCardCashinParams` |
| 6 | `DisburseIssuer::InstantBank` | `"instant_bank"` | `.bank_instant(params)` | `InstantBankCashinParams` |
| 7 | `DisburseIssuer::EgyptianPost` | `"egyptian_post"` | `.egyptian_post(params)` | `EgyptianPostCashinParams` |

Additional cashin and funding operations:

- **Aman Cancellation**: `client.payouts().cashin().cancel_aman(CancelAmanParams::new(tx_id))` (`POST /api/secure/transaction/aman/cancel/`).
- **Bulk Disbursements**: `client.payouts().cashin().bulk(BulkDisbursementParams)` (`POST /disburse/api/v1/disburse/bulk_transaction/`), supporting up to `MAX_BULK_DISBURSEMENT_ITEMS` (`1_000`) `BulkDisbursementItem` entries per request with `.with_bank_transaction(bool)` for bank vs. wallet batches.
- **Payout Inquiries (`client.payouts().inquiries()`)**:
  - **By Transaction ID**: `.transactions(TransactionInquiryParams)` (`POST /api/secure/transaction/inquire/`, or `/disburse/api/v1/bulk_transaction/inquire/` when `.with_bulk(true)` is set; up to `MAX_INQUIRY_IDS = 1_000`).
  - **By Client Reference ID**: `.by_reference(ReferenceInquiryParams)` (`POST /disburse/api/v1/bulk_transaction/inquire/by_reference/`).
  - **User Budget & Topup Inquiries**: Available via `client.payouts().inquiries()` and `client.payouts().topups()` (enforcing the `<= 2.8 MB` topup proof size guard `MAX_TOPUP_PROOF_BYTES`).

### Single Issuer, Bulk Disbursement & Inquiry Example

```rust,no_run
use some_paymob::prelude::*;
use some_paymob::resources::payouts::{
    BulkDisbursementItem, BulkDisbursementParams, MobileWalletCashinParams,
    ReferenceInquiryParams, TransactionInquiryParams,
};

async fn run_payout_pipeline(paymob: &PaymobClient) -> Result<(), PaymobError> {
    // 1. Single instant cashin (e.g., Vodafone Cash)
    let single = MobileWalletCashinParams::new("01012345678", 150_000)
        .with_client_reference_id("PAYOUT-DRIVER-8841")
        .with_customer_bears_fees(false);
    let receipt = paymob.payouts().cashin().vodafone(single).await?;

    // 2. Bulk disbursement batch (up to MAX_BULK_DISBURSEMENT_ITEMS = 1_000)
    let bulk_params = BulkDisbursementParams::new(vec![
        BulkDisbursementItem::wallet("vodafone", "01012345678", 50_000)
            .with_client_reference_id("BATCH-001"),
    ])
    .with_bank_transaction(false);
    let _bulk = paymob.payouts().cashin().bulk(bulk_params).await?;

    // 3. Transaction ID and client-reference inquiries
    let _by_id = paymob
        .payouts()
        .inquiries()
        .transactions(TransactionInquiryParams::new(vec![receipt.transaction_id]))
        .await?;
    let _by_ref = paymob
        .payouts()
        .inquiries()
        .by_reference(ReferenceInquiryParams::new(vec!["BATCH-001".to_owned()]))
        .await?;

    Ok(())
}
```

---

## 4. TLS Feature-Flag Hygiene (`rustls-tls` vs `native-tls`)

When composing `some-paymob` inside a `some-payment` workspace alongside `some-stripe` and `some-moyasar`, keep TLS backends aligned across crates to avoid compiling both `rustls` and OpenSSL in the same binary.

- **`rustls-tls` (Default)**: Pure-Rust TLS 1.3 via `reqwest/rustls-tls`. Recommended for scratch/distroless containers, `musl` static builds, and uniform multi-gateway builds across `some-payment`.
- **`native-tls` (Opt-in)**: Uses the platform TLS stack via `reqwest/native-tls` (for corporate PKI trust stores or FIPS/OpenSSL environments).
- **Adapter Feature Alias**: Both `some-payments-adapter` and `some-payment-trait` enable the exact same adapter dependency set (`core`, `webhooks`, `intentions`, `manage`, `saved-cards`, `subscriptions`, `splits`, `payouts`).

### Recommended `Cargo.toml` for `some-payment` Workspaces (Pure-Rust `rustls-tls`)

```toml
[dependencies]
some-paymob = { version = "0.1.0", default-features = false, features = [
    "some-payments-adapter",
    "rustls-tls",
] }
```

### Opting Into Platform `native-tls`

```toml
[dependencies]
some-paymob = { version = "0.1.0", default-features = false, features = [
    "some-payments-adapter",
    "native-tls",
] }
```

---

## 5. `PaymobClient::from_secret_key` Ergonomics

For rapid onboarding or single-region Unified Intention flows, `PaymobClient::from_secret_key` constructs a ready-to-use client from a raw Paymob secret key or a `"$ENV_VARNAME"` / `"${ENV_VARNAME}"` reference (resolved automatically from process environment variables or `.env` files):

```rust,no_run
use some_paymob::prelude::*;

fn build_quick_client() -> Result<PaymobClient, PaymobError> {
    // Resolves PAYMOB_SECRET_KEY from process env or local `.env`
    PaymobClient::from_secret_key("$PAYMOB_SECRET_KEY")
}
```

When you also need `public_key` (for Unified Checkout URLs), `hmac_secret` (for `paymob.webhooks()`), `payouts_credentials` (for Regime 3 Paymob Send), or a non-default `PaymobRegion` (`SaudiArabia`, `Uae`, `Oman`, `Pakistan`, or `Custom`), use `ClientConfig::builder()`:

```rust,no_run
use some_paymob::prelude::*;

fn build_full_client() -> Result<PaymobClient, PaymobError> {
    let config = ClientConfig::builder()
        .region(PaymobRegion::Egypt)
        .secret_key(SecretKey::new("$PAYMOB_SECRET_KEY")?)
        .public_key(PublicKey::new("$PAYMOB_PUBLIC_KEY")?)
        .hmac_secret(HmacSecret::new("$PAYMOB_HMAC_SECRET")?)
        .build()?;

    PaymobClient::new(config)
}
```

---

## 6. Reference Servers & Offline Verification

All four framework reference servers in [`examples/`](../examples) exercise the full 14-service surface and Protocols A–E with `PaymobMockServer` (`test-utils`) for deterministic offline testing:

- `cargo run --example actix_server --features full`
- `cargo run --example axum_server --features full`
- `cargo run --example rocket_server --features full`
- `cargo run --example tonic_grpc_server --features full`

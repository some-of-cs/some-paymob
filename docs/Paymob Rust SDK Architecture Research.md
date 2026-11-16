# **some-paymob: Production-Grade Rust Microkernel SDK & Constant-Time Webhook Engine for Paymob**

some-paymob is an idiomatic, memory-safe, zero-data-race Rust SDK and cryptographic webhook verification engine for the **Paymob API** across Egypt (EGY), Saudi Arabia (KSA), the United Arab Emirates (UAE), Oman (OMN), and Pakistan (PAK). Inspired by the resource-oriented ergonomics of the official [stripe-node](https://github.com/stripe/stripe-node) client (paymob.intentions().create(...), paymob.manage().refund(...), paymob.subscriptions().plans().create(...), paymob.webhooks().construct\_event(...)) and engineered around the **Some(CS)** 4-tier Rust microkernel paradigm, some-paymob is structured as a modular core with granular Cargo feature flags. Developers can compile a minimal, zero-bloat core binary containing only the v1 Payment Intention API and constant-time HMAC-SHA512 webhook verifier, and progressively opt into specialized domain plugins—spanning **Manage Payments (Refund/Void/Capture)**, **Transaction & Order Inquiries**, **Saved Cards (CIT/MIT) & Direct Wallet/Kiosk Execution**, **Subscriptions & Recurring Billing**, **QuickLinks (Payment Links)**, **Split Payments & Convenience Fees**, **Payouts & Instant Cashin**, **Partner Merchant Onboarding**, and **Legacy Accept v2 Flows**.  
A foundational architectural challenge of the Paymob ecosystem—and the primary reason naive SDK wrappers fail in production—is that Paymob is not a single monolithic REST surface. Instead, it spans **two distinct host topologies** (Accept Acquiring vs. Payouts Disbursement) and **four incompatible authentication regimes**: static Token \<secret\_key\> headers for v1 Intentions and Void/Refund/Capture; short-lived 60-minute JWT Bearer \<auth\_token\> headers for Subscriptions, QuickLinks, and ID-based Transaction Inquiries; body-injected "auth\_token" JSON properties for Order/Card-Token Inquiries and Legacy v2 checkouts; and OAuth 2.0 application/x-www-form-urlencoded Basic Auth password/refresh token grants for Payouts. Simultaneously, Paymob's webhook engine dispatches **four distinct callback schemas** (Transaction Processed POST, Transaction Response GET, Card Token POST, and Subscription Lifecycle POST, alongside optional Payouts callbacks) that differ in field count (20 keys vs. 8 keys vs. {trigger\_type}for{id}), field nesting (obj.id vs. id), and signature placement (?hmac= query string vs. JSON body "hmac"). some-paymob encapsulates all four authentication life cycles behind lock-free atomic token caches and enforces fail-closed, constant-time HMAC-SHA512 verification across every callback surface.  
Finally, some-paymob is architected from the ground up as a provider plugin for the **some-payments** unified multi-gateway workspace alongside some-stripe and some-moyasar. *(Note on evidence scope: while maheraladdin's public GitHub profile documents the 4-tier Rust microkernel architecture used in Some(CS) systems such as EstateStack, a public repository named some-stripe is not publicly indexed on GitHub, crates.io, or docs.rs; similarly, where Paymob's developer portal or published OpenAPI specifications omit exact request/response schemas for specific sub-endpoints such as PUT /v1/intention/ body fields, certain secondary subscription action paths, or individual Partner Onboarding step payloads, those documentation boundaries are explicitly flagged in the tables below).*

## **Crate Badges, Ergonomic Quickstart & stripe-node Parity**

To mirror the developer experience of stripe-node while leveraging Rust's type system, some-paymob exposes hierarchical service namespaces attached to an Arc-backed, cheaply cloneable PaymobClient. Secrets are wrapped in secrecy::SecretString and automatically zeroed in memory on drop (zeroize), preventing accidental exposure in Debug logs or panic traces.

### **Installation (Cargo.toml)**

`[dependencies]`  
`# Minimal Core: v1 Intention API + Constant-Time Webhook Verification Engine`  
`some-paymob = "0.1.0"`

`# Full Enterprise Suite: Enable specific domain plugins as your workflow grows`  
`# some-paymob = { version = "0.1.0", features = [`  
`#     "intentions",`  
`#     "webhooks",`  
`#     "manage",`  
`#     "inquiries",`  
`#     "saved-cards",`  
`#     "subscriptions",`  
`#     "quicklinks",`  
`#     "splits",`  
`#     "payouts",`  
`#     "onboarding",`  
`#     "legacy-v2",`  
`#     "some-payments-adapter"`  
`# ] }`

### **Ergonomic Usage Example (stripe-node Style in Idiomatic Rust)**

`use some_paymob::{`  
    `ClientConfig, PaymobClient, PaymobRegion,`  
    `resources::intentions::{BillingData, CreateIntentionParams, IntentionItem, PaymentMethodInput},`  
    `resources::manage::RefundParams,`  
    `webhooks::{PaymobWebhookEngine, WebhookEvent},`  
`};`

`#[tokio::main]`  
`async fn main() -> Result<(), some_paymob::PaymobError> {`  
    `// 1. Initialize the Microkernel Client (Send + Sync, Arc-wrapped internally)`  
    `let config = ClientConfig::builder()`  
        `.region(PaymobRegion::Egypt) // Routes to https://accept.paymob.com & https://payouts.paymobsolutions.com`  
        `.secret_key("sk_test_626xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")`  
        `.public_key("egy_pk_test_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")`  
        `.api_key("ZXlKaGJHY2lPaUpJxxxxxxxxxxxxxxxxxxxxxxxxxxx")`  
        `.hmac_secret("3qUAg2xx6JW89Qav5GzzmXoalgjf5XxE")`  
        `.build()?;`

    `let paymob = PaymobClient::new(config)?;`

    `// 2. Create a Payment Intention (v1 Unified Checkout / Pixel Flow)`  
    `` // Mirrors `stripe.paymentIntents.create({...})` ``  
    `let intention = paymob`  
        `.intentions()`  
        `.create(`  
            `CreateIntentionParams::builder()`  
                `.amount(100_000) // 1,000.00 EGP in piasters/cents`  
                `.currency("EGP")`  
                `.payment_methods(vec![`  
                    `PaymentMethodInput::IntegrationId(4097558),`  
                    `PaymentMethodInput::MethodName("card".into()),`  
                `])`  
                `.items(vec![IntentionItem::new("Pro Portfolio Commercial License", 100_000, 1)])`  
                `.billing_data(`  
                    `BillingData::builder()`  
                        `.first_name("Maher")`  
                        `.last_name("Mansour")`  
                        `.email("maher.aladdin.mansour@gmail.com")`  
                        `.phone_number("+201116491564") // Strictly validated at builder time`  
                        `.city("Mansoura")`  
                        `.country("EG")`  
                        `.build()?,`  
                `)`  
                `.special_reference("order_estatestack_2026_001")`  
                `.notification_url("https://api.yourdomain.com/webhooks/paymob")`  
                `.redirection_url("https://yourdomain.com/checkout/complete")`  
                `.build()?,`  
        `)`  
        `.await?;`

    `// Generate the PCI-compliant Unified Checkout Redirect URL`  
    `let checkout_url = paymob.checkout().unified_url(&intention.client_secret)?;`  
    `println!("Redirect customer to: {checkout_url}");`

    ``// 3. Issue a Partial Refund (Requires `feature = "manage"`)``  
    `` // Mirrors `stripe.refunds.create({ payment_intent, amount })` ``  
    `#[cfg(feature = "manage")]`  
    `let refund_tx = paymob`  
        `.manage()`  
        `.refund(RefundParams::new(192036465, 25_000)) // Refund 250.00 EGP`  
        `.await?;`

    ``// 4. Verify Incoming Webhook in Constant Time (Requires `feature = "webhooks"`)``  
    `` // Mirrors `stripe.webhooks.constructEvent(payload, sig, secret)` ``  
    `let raw_body: &[u8] = b"{...raw JSON from Paymob POST callback...}";`  
    `let query_hmac = "fa8ac0b7f3852e60c50e7fdd4ea5ef0bda96030c19dea1d55df8c76d6c08ab1877774662cbb04981dc84839ad4da560bcc8cb53b8973548657f7e8f8d2e79930";`

    `match paymob.webhooks().construct_event(raw_body, Some(query_hmac))? {`  
        `WebhookEvent::TransactionProcessed(tx) => {`  
            `println!("Verified Transaction ID: {}, Success: {}", tx.obj.id, tx.obj.success);`  
        `}`  
        `WebhookEvent::CardTokenSaved(token_evt) => {`  
            `println!("Verified Saved Card Token for PAN: {}", token_evt.obj.masked_pan);`  
        `}`  
        `WebhookEvent::SubscriptionLifecycle(sub_evt) => {`  
            `println!("Verified Subscription {} -> {}", sub_evt.subscription_data.id, sub_evt.trigger_type);`  
        `}`  
        `_ => {}`  
    `}`

    `Ok(())`  
`}`

## **Microkernel Architecture & Feature Flag Design**

To guarantee minimal compile times, a small binary footprint, and strict isolation between Paymob's subsystems, some-paymob employs a **4-tier microkernel architecture** modeled after modular Rust systems design. Instead of compiling hundreds of unused data structures for B2B payouts or marketplace onboarding when a developer only needs a simple checkout redirect, the **Core Kernel (PaymobCore)** provides the foundational primitives: regional host routing, multi-regime authentication state machines, HTTP middleware pipelines, error normalization, and minor-unit money types. Every business domain attaches to the kernel as an opt-in feature module.

### **Cargo Feature Matrix & Compilation Profiles**

By structuring Cargo.toml around additive, orthogonal feature flags, downstream applications pay zero compilation or dependency cost for unused Paymob services.

| Cargo Feature Flag | Default? | Paymob API Surface Unlocked | Auth Regime(s) Used | Internal Module Path |
| :---- | :---- | :---- | :---- | :---- |
| **core** *(implicit)* | **Yes** | Regional URL router (EGY, KSA, UAE, OMN, PAK), PaymobClient, ClientConfig, minor-unit amount helpers, error types, and lock-free token cache. | All 4 Regimes (Lazy initialization) | some\_paymob::core |
| **intentions** | **Yes** | POST /v1/intention/, PUT /v1/intention/, Unified Checkout redirect builder, Pixel config, and Affordability Widget types. | Regime 1 (Token \<secret\_key\>) | some\_paymob::resources::intentions |
| **webhooks** | **Yes** | Constant-time HMAC-SHA512 verifier (subtle \+ hmac \+ sha2) for Transaction (POST/GET), Card Token (POST), Subscription (POST), and Payout callbacks. | HmacSecret \+ Payouts HMAC Secret | some\_paymob::webhooks |
| **manage** | No | POST /api/acceptance/void\_refund/refun\[span\_22\](start\_span)\[span\_22\](end\_span)\[span\_26\](start\_span)\[span\_26\](end\_span)\[span\_30\](start\_span)\[span\_30\](end\_span)\[span\_34\](start\_span)\[span\_34\](end\_span)d, POST /api/acceptance/void\_refund/void, and POST /api/acceptance/capture. | Regime 1 (Token \<secret\_key\>) / Regime 2 (Bearer) | some\_paymob::resources::manage |
| **inquiries** | No | GET /api/acceptance/transactions/{id}, POST /api/ecommerce/orders/transaction\_inquiry, POST /api/acceptance/order\_card\_tokens, and GET /api/ecommerce/orders/{id}. | Regime 2 (Bearer \+ Body auth\_token) | some\_paymob::resources::inquiries |
| **saved-cards** | No | Card tokenization helpers, CIT (card\_tokens Intention), MIT headless MOTO charges, Mobile Wallet direct pay, and Kiosk aggregator pay via POST /api/acceptance/payments/pay. | Regime 1 & Regime 2 (Bearer \+ payment\_token) | some\_paymob::resources::saved\_cards |
| **subscriptions** | No | Full Subscription Plan CRUD (POST/PUT/GET/suspend/resume /api/acceptance/subscription-plans), Subscription lifecycle actions (/api/acceptance/subscriptions/{id}/...), secondary/primary card management, and subscription transaction refunds. | Regime 2 (Bearer \<auth\_token\>) \+ Regime 1 (Refunds) | some\_paymob::resources::subscriptions |
| **quicklinks** | No | Programmatic Payment Links: POST /api/ecommerce/payment-links and POST /api/ecommerce/payment-links/cancel. | Regime 2 (Bearer \<auth\_token\>) | some\_paymob::resources::quicklinks |
| **splits** | No | Marketplace **Split Amount** (multi-recipient settlement rules), **Split Payment** (up to 3 cards per purchase), and Convenience Fee models. | Regime 1 & Regime 2 | some\_paymob::resources::splits |
| **payouts** | No | Payouts OAuth2 token lifecycle (/api/secure/o/token/), Instant & Bulk Cashin (/api/secure/disburse/ for Vodafone, Etisalat, Orange, Bank Wallet, Bank Card, Instant Bank, Egypt Post), Budget/Tx Inquiries, and Bank/Accept Balance Topups. | Regime 3 (OAuth 2.0 Basic \+ Bearer) | some\_paymob::resources::payouts |
| **onboarding** | No | Partner Onboarding APIs: Partner Login, Partner API Key creation, GET /api/auth/hmac\_secret/get\_hmac, Register Merchant, GET /api/onboarding/flow/schema, Submit Step, and Partner Merchant Inquiry. | Regime 4 (Partner Bearer \+ Partner API Key) | some\_paymob::resources::onboarding |
| **legacy-v2** | No | Classic 3-step checkout flow: POST /api/auth/tokens \-\> POST /api/ecommerce/orders \-\> POST /api/acceptance/payment\_keys \+ Iframe URL builder. | Regime 2 (Body auth\_token) | some\_paymob::resources::legacy |
| **some-payments-adapter** | No | Implements the unified some\_payments\_core::{PaymentProvider, WebhookVerifier, SubscriptionProvider, PayoutProvider} traits for cross-gateway orchestration with some-stripe and some-moyasar. | Delegates to Kernel | some\_paymob::adapter |
| **full** | No | Meta-feature enabling all domain plugins (intentions, webhooks, manage, inquiries, saved-cards, subscriptions, quicklinks, splits, payouts, onboarding, legacy-v2). | All Regimes | All modules |

## **Core Kernel Mechanics: Regional Routing & The 4 Authentication Regimes**

### **1\. Multi-Region Dual-Host Routing (PaymobRegion)**

Unlike single-host gateways, Paymob partitions its infrastructure by **country** and by **product line** (Accept Acquiring vs. Payouts Disbursement). Furthermore, a structural API changelog in version 0.6.3 (April 20, 2026\) highlighted path sensitivity around trailing slashes on /v1/intention/ vs. v1/intention, while Payouts endpoints (/api/secure/disburse/, /api/secure/budget/inquire/, /api/secure/topup/request/) consistently use trailing slashes in Paymob's cURL specifications. some-paymob's RegionalRouter resolves the exact host and normalizes path slashes per endpoint contract.

| Region Variant (PaymobRegion) | Accept Acquiring Base URL | Unified Checkout Base URL | Payouts Production Base URL | Payouts Staging Base URL |
| :---- | :---- | :---- | :---- | :---- |
| **PaymobRegion::Egypt** (EGY) | https\://accept.paymob.com/ | https\://accept.paymob.com/unifiedcheckout/ or https\://eg.checkout.paymob.com/ | https\://payouts.paymobsolutions.com/ (or https\://accept.paymob.com/api/secure/) | https\://stagingpayouts.paymobsolutions.com/ (also https\://stg-payouts.paymobsolutions.com in OpenAPI specs) |
| **PaymobRegion::SaudiArabia** (KSA) | https\://ksa.paymob.com | https\://ksa.paymob.com/unifiedcheckout/ | https\://payouts.paymob.sa/ | https\://stagingpayouts.paymob\[span\_1\](start\_span)\[span\_1\](end\_span)\[span\_6\](start\_span)\[span\_6\](end\_span).sa/ |
| **PaymobRegion::Uae** (UAE) | https\://uae.paymob.com | https\://uae.paymob.com/unifiedcheckout/ | https\://payouts-uae.paymobsolutions.com/ | https\://stagingpayouts-uae.paymobsolutions.com/ |
| **PaymobRegion::Oman** (OMN) | https\://oman.paymob.com | https\://oman.paymob.com/unifiedcheckout/ | Routed via https\://oman.paymob.com | Routed via https\://oman.paymob.com |
| **PaymobRegion::Pakistan** (PAK) | https\://pakistan.paymob.com | https\://pakistan.paymob.com/unifiedcheckout/ | Not listed in Payouts docs | Not listed in Payouts docs |
| **PaymobReg\[span\_3\](start\_span)\[span\_3\](end\_span)\[span\_8\](start\_span)\[span\_8\](end\_span)ion::Custom { ... }\[span\_139\](start\_span)\[span\_139\](end\_span)** | User-defined URL (for mock servers / testing) | User-defined URL | User-defined URL | User-defined URL |

*Engineering Note on Minor Units:* Paymob's Accept APIs require all monetary amounts (amount or amount\_cents) to be expressed in integer cents/piasters (for example, 10000 \= 100.00 EGP), and the request currency must match the currency configured on the selected Integration ID. Passing base currency units instead of cents/piasters causes a 100x amount error. some-paymob provides a strongly-typed MinorUnitAmount(u64) newtype with explicit constructors to prevent unit-scaling bugs.

### **2\. Zero-Race Multi-Regime Authentication State Machine**

A frequent source of production failures in Paymob integrations is mixing authentication headers across endpoints—for example, sending Authorization: Bearer \<secret\_key\> instead of Authorization: Token \<secret\_key\> on POST /v1/intention/ (which triggers a 401 Unauthorized error), or allowing the 1-hour JWT auth\_token to expire mid-flight during subscription or inquiry calls. some-paymob prevents these failures inside PaymobCore by binding every internal EndpointSpec to a dedicated AuthStrategy state machine.  
Under **Regime 1 (AuthStrategy::SecretKeyToken)**, the client injects Authorization: Token \<secret\_key\> directly from ClientConfig::secret\_key for Intention creation/updates and payment management actions (refund, void, capture). At initialization and request builder time, the kernel validates that the secret key matches the environment status (Test vs. Live) of the target Integration IDs and that a client-side Public Key (pk\_\*) was not accidentally passed where a server-side Secret Key is required. *(Note: While Paymob's official developer portal and the Paymob.Net SDK authenticate refund, void, and capture with Authorization: Token \<secret\_key\>, the third-party APIs.io Legacy v2 Capture OpenAPI specification declares BearerAuth for those three endpoints; some-paymob defaults to Token \<secret\_key\> per Paymob's primary documentation and exposes a configuration toggle to use Bearer \<auth\_token\> if targeting a legacy v2 gateway configuration).*  
Under **Regime 2 (AuthStrategy::AcceptJwtBearer and AuthStrategy::AcceptJwtBody)**, the kernel manages the lifecycle of the short-lived Accept JWT token obtained via POST /api/auth/tokens with JSON body { "api\_key": "\<api\_key\>" }. Because each Accept auth token has a **60-minute (1-hour) TTL**, PaymobCore caches the active token inside a thread-safe ArcSwapOption\<CachedJwt\> paired with an asynchronous tokio::sync::Mutex\<()\> single-flight refresh guard. When a token approaches expiration—or if an endpoint returns 401 Unauthorized ({ "detail": "incorrect credentials" })—only a single task acquires the refresh lock to fetch a fresh JWT while concurrent requests await the updated token, guaranteeing zero data races and eliminating thundering-herd token requests. Depending on the target endpoint's contract, the middleware either attaches Authorization: Bearer \<auth\_token\> (used by Subscriptions, QuickLinks, GET /api/acceptance/transactions/{id}, and POST /api/acceptance/payments/pay) or injects "auth\_token": "\<auth\_token\>" into the JSON request body (used by POST /api/ecommerce/orders/transaction\_inquiry, POST /api/acceptance/order\_card\_tokens, and Legacy v2 Order/Payment Key endpoints).  
Under **Regime 3 (AuthStrategy::PayoutsOAuth2)**, the kernel manages the Payouts OAuth 2.0 state machine via POST /api/secure/o/token/ (or {ENV}/o/token/) using Content-Type: application/x-www-form-urlencoded and HTTP Basic Auth ({client\_id}:{client\_secret}). Initial token generation sends grant\_type=password\&username={username}\&password={password}, caching both the access\_token (expires\_in: 3600, which must be updated every 60 minutes) and the long-lived refresh\_token (which remains valid until consumed). Subsequent token refreshes automatically execute grant\_type=refresh\_token\&refresh\_token={refresh\_token} and attach Authorization: Bearer \<access\_token\> to all Payouts requests.  
Under **Regime 4 (Au\[span\_165\](start\_span)\[span\_165\](end\_span)thStrategy::PartnerDelegated)**, the kernel supports Partner Onboarding authentication: exchanging partner login credentials for a Partner Bearer token (used to call GET /api/auth/hmac\_secret/get\_hmac), generating a Partner API Key (used for merchant onboarding endpoints), and authenticating transaction processing on behalf of onboarded sub-merchants by combining the **Partner API Key** with the target **merchant's ID**.

## **Complete Paymob Services & API Specification Catalog**

Below is the research catalog of every service and API endpoint provided by Paymob, mapped to its some-paymob Cargo feature, Rust service method, HTTP contract, request/response schemas, and error handling rules.

### **Service 1: Payment Intentions & Checkout Experiences (feature \= "intentions")**

The **Intention API** is Paymob's primary payment initialization layer, used across standard web redirects (Unified Checkout), embedded web components (Pixel), native Mobile SDKs (iOS, Android, Flutter, React Native), Subscriptions, Auth/Capture, and Saved Card transactions.

#### **1.1 Endpoints Summary**

| Rust SDK Method | HTTP Method & Path | Auth Regime | Description & Evidence Scope |
| :---- | :---- | :---- | :---- |
| paymob.intentions().create(params) | POST /v1/intention/ | Token \<secret\_key\> | Creates a Payment Intention and returns id, intention\_order\_id, client\_secret, and payment\_keys. *(Note: Changelog 0.6.3 notes a breaking path update between /v1/intention/ and v1/intention).* |
| paymob.intentions().update(params) | PUT /v1/intention/ | Token \<secret\_key\> | Updates an existing Payment Intention by passing updated amounts, customer info, and payment details. *(Caveat: Paymob's Intention overview confirms PUT Update Intention and its purpose, but the exact URL path/body schema for PUT is not separately itemized in the available documentation snippets).* |
| paymob.checkout().unified\_url(csk) | Local URL Builder | PublicKey (pk\_\*) | Constructs {checkout\_host}/?publicKey={pk}\&clientSecret={client\_secret} for redirect checkout. |
| paymob.checkout().pixel\_config(csk, ...) | Local Struct Builder | PublicKey (pk\_\*) | Generates strongly-typed configuration structs for Paymob's embedded **Pixel** JS SDK (supporting embedded Cards, Apple Pay, and Google Pay; requires domain verification and Apple Pay certificate setup). |
| paymob.checkout().affordability\_widget(...) | Local Struct Builder | PublicKey (pk\_\*) | Generates frontend widget configuration for bank installment plans and wires the selected plan ID into CreateIntentionParams::pre\_selected\_plan. |

#### **1.2 POST /v1/intention/ Request & Response Specification**

When constructing CreateIntentionParams, some-paymob enforces three critical invariants at the type/builder level before dispatching an HTTP request:

> 1. **Environment Parity**: The Test/Live mode of all integration IDs in payment\_methods must match the Test/Live status of the Secret Key; a mismatch causes Paymob to return 404 Not Found ({"detail": "Integration ID/Name does not exist in our system . You can find the list of Integration ID'/Names from Merchant Dashboard under Developers → Payment Integrations Tab"}).  
> 2. **Item Completeness**: Whenever the optional items array is populated, every item object must include both name and amount; omitting either returns 400 Bad Request ({"items": {"name": \["This field is required."\]}} or {"items": {"amount": \["This field is required."\]}}). 3\. **Billing Phone Number Requirement**: When billing\_data is provided, phone\_number is mandatory; omitting it triggers 400 Bad Request ({"billing\_data": {"phone\_number": \["This field is required."\]}}).

| Parameter Field | Rust Type | Req? | Technical Specification & Constraints |
| :---- | :---- | :---- | :---- |
| amount | u64 | **Yes** | Total transaction amount expressed in cents/piasters. |
| currenc\[span\_144\](start\_span)\[span\_144\](end\_span)y | String | **Yes** | Currency code in which the transaction is processed (e.g., "EGP"). Must match the currency of the selected Integration ID. |
| payment\_methods | Vec\<PaymentMethodInput\> | **Yes** | Untag-serialized enum accepting Integration IDs as integers (e.g., 158, 1256\) or method names as strings (e.g., "card"). Test/Live status must match the Secret Key. |
| items | Option\<V\[span\_146\](start\_span)\[span\_146\](end\_span)ec\<IntentionItem\>\> | No | Array of item objects. Child attributes: name (Required), amount (Required), description, quantity, image. |
| billing\_data | Option\<BillingData\> | No | Customer billing details. Child attributes: phone\_number (Required if billing\_data is present), apartment, first\_name, last\_name, street, building, city, country, email, floor, st\[span\_148\](start\_span)\[span\_148\](end\_span)ate, postal\_code, shipping\_method. |
| customer | Option\<IntentionCustomer\> | No | { first\_name, last\_name, email } (supported in SDK intention models such as Paymob.Net). |
| extras | Option\<serde\_json::Value\> | No | Custom merchant key-value parameters; returned in Intention response under extras.creation\_extras and in webhooks under obj.payment\_key\_claims.extra. |
| special\_reference | Option\<String\> | No | Unique merchant reference for the transaction or order; returned in transaction callbacks under obj.order.merchant\_order\_id. |
| expiration | Option\<u64\> | No | Time in seconds until the intention expires (e.g., 3600). |
| notification\_url | Option\<String\> | No | Callback URL receiving a POST request with full transaction details after the transaction succeeds or fails (supported across all payment methods) and the card token object (for saved card features). |
| redirection\_url | Option\<String\> | No | Client redirect URL after transaction completion with transaction details appended as query parameters (supported for Card and Wallet payment methods only). |
|  | pre\_selected\_plan | Option\<u64\> | No |

**Response Model (IntentionResponse — HTTP 201 Created)**: Deserializes id: String (e.g., "pi\_test\_bd49bb7fb4da48cfac4ec71ab4d8c433", usable like an Order ID for correlation), intention\_order\_id: u64 (e.g., 265\[span\_153\](start\_span)\[span\_153\](end\_span)715202, the Paymob Order ID received in callbacks), client\_secret: SecretString (e.g., "egy\_csk\_test\_...", a single-use token for Unified Checkout or Pixel), payment\_keys: Vec\<IntentionPaymentKey\> ({ integration, key, gateway\_type, iframe\_id, order\_id }), intention\_detail: IntentionDetail ({ amount\[span\_154\](start\_span)\[span\_154\](end\_span), items, currency, billing\_data }), payment\_methods: Vec\<ConfiguredPaymentMethod\> ({ integration\_id, alias, name, method\_type, currency, live, use\_cvc\_with\_moto }), special\_reference\[span\_186\](start\_span)\[span\_186\](end\_span): Option\<String\>, extras: IntentionExtras ({ creation\_extras, confirmation\_extras }), confirmed: bool, status: String ("intended"), created: String, card\_detail: Option\<String\>, card\_tokens: Vec\<serde\_json::Value\>, and object: String ("paymentintention").

### **Service 2: Payment Management — Refund, Void & Capture (feature \= "manage")**

Once a payment is authorized or completed, merchants manage its financial lifecycle through three operations: **Refund** (full or multiple partial returns on successful transactions, up to the original transaction amount), **Void** (canceling an unsettled transaction before batch settlement), and **Capture** (settling full or partial funds held via a two-step Auth/Cap card integration, where any uncaptured remainder is voided at release time).

#### **2.1 Endpoints & Contracts**

| Rust SDK Method | HTTP Method & Path | Auth Regime | Request Body Schema | Webhook Side-Effect & Response |
| :---- | :---- | :---- | :---- | :---- |
| paymob.manage().refund(params) | POST /api/acceptance/void\_refund/refund | Token \<secret\_key\> | { "transaction\_id": "574588", "amount\_cents": "1000" } (accepts integer or stringified integer). | Returns 20\[span\_271\](start\_span)\[span\_271\](end\_span)\[span\_273\](start\_span)\[span\_273\](end\_span)0 OK child Transaction (is\_refund: true, parent\_transaction: 574588\) AND fires a callback for the parent transaction with "is\_refunded": true and cumulative refunded\_amount\_cents. |
| paymob.manage().void(params) | POST /api/acceptance/void\_refund/void | Token \<secret\_key\> | { "transaction\_id": "574588" }. | Returns 20\[span\_279\](start\_span)\[span\_279\](end\_span)\[span\_282\](start\_span)\[span\_282\](end\_span)0 OK child Transaction (is\_void: true, parent\_transaction: 578645\) AND fires a callback for the parent transaction with "is\_voided": true. |
| paymob.manage().capture(params) | POST /api/acceptance/capture | Token \<secret\_key\> (or Bearer in Legacy v2 spec) | { "transaction\_id": 574588, "amount\_cents": 1000 }. | Returns 200 OK child Transaction (is\_capture: true) AND fires a callback for the parent transaction with "is\_captured": true and cumulative captured\_amount. |

*Error Handling & Dispute Note:* If amount\_cents exceeds the permissible refundable balance, Paymob returns 400 Bad Request with {"message": "Requested Refund Amou\[span\_193\](start\_span)\[span\_193\](end\_span)nt is greater than the maximum refund amount permissible. Maximum\[span\_194\](start\_span)\[span\_194\](end\_span) Refund Amount is EGP 100.0"}. Additionally, Paymob's dashboard documentation notes that if a merchant issues a full refund before a chargeback dispute is raised, Paymob automatically responds to the dispute using the refund record without requiring manual evidence submission.

### **Service 3: Transaction, Order & Card Token Inquiries (feature \= "inquiries")**

While HMAC-verified webhooks serve as the primary source of truth for payment state transitions, **Transaction Inquiry APIs** are used for manual verification or as an automated reconciliation fallback when a callback is missed or when an order remains pending on offline cash/kiosk channels.

#### **3.1 Endpoints & Contracts**

| Rust SDK Method | HTTP Method & Path | Auth Regime | Parameters / Request Body | Response Type & Key Attributes |
| :---- | :---- | :---- | :---- | :---- |
| paymob.inquiries().by\_transaction\_id(tx\_id) | GET /api/acceptance/transactions/{transaction\_id} | Bearer \<auth\_token\> | Path parameter: transaction\_id: u64. | Transaction object (id, pending, amount\_cents, success, is\_auth, is\_capture, is\_void, is\_refund, is\_3d\_secure, integration\_id, order, currency, source\_data, merchant\_commission, installment, created\_at). |
| paymob.inquiries().by\_order\_or\_reference(params) | POST /api/ecommerce/orders/transaction\_inquiry | Body "auth\_token" (and Bearer in OpenAPI spec) | JSON Body: { "auth\_token": "...", "order\_id": "212245716", "merchant\_order\_id": "" }. At least one of order\_id or merchant\_order\_id (special\_reference) must be passed. | InquiredTransaction (200 OK) — rich transaction record including paid\_at, fees, vat, accept\_fees\_cents\_int, vat\_cents\_int, settlement\_amount\_cents\_int, is\_settled, is\_reconciled, reconciliation\_id, cogs, installment\_info, split\_description, is\_split\_payment, allow\_cardless\_refund, public\_customer\_fingerprint. |
| paymob.inquiries().card\_tokens\_by\_order(order\_id) | POST /api/acceptance/order\_card\_tokens | Body "auth\_token" | JSON Body: { "auth\_token": "...", "order\_id": 523360093 }. | Vec\<CardTokenEnvelope\> (200 OK) where each item has type: "TOKEN" and obj: CardTokenObject (id, token, masked\_pan, merchant\_id, card\_subtype, created\_at, email, order\_id, user\_added, next\_payment\_intention). |
| paymob.inquiries().order(order\_id) | GET Order Inquiry (referenced in Paymob.Net GetOrderAsync) | Bearer \<auth\_token\> | order\_id: u64. | Retrieves the order record alongside nested transactions for every payment attempt tied to the order. *(Note: Exact relative path is not printed in the Paymob.Net README snippet).* |

### **Service 4: Pay With Saved Cards (CIT/MIT) & Headless Payments (feature \= "saved-cards")**

Paymob supports card tokenization and repeat charging through two workflows: **Customer Initiated Transactions (CIT)** and **Merchant Initiated Transactions (MIT)**. In addition, Paymob exposes the headless POST /api/acceptance/payments/pay endpoint for MOTO saved-card charges, direct **Mobile Wallet** charges, and **Kiosk** aggregator payments.

#### **4.1 Tokenization & Headless Execution Workflows**

To **create a Card Token**, the merchant first creates a Payment Intention (POST /v1/intention/) using a Card Integration ID of type Verification, Normal 3DS, or Auth, and renders Unified Checkout or Pixel. When the customer completes the payment and elects to save their card, Paymob sends a TOKEN callback object to notification\_url (and makes it queryable via POST /api/acceptance/order\_card\_tokens) containing obj.id, obj.token, obj.masked\_pan, obj.merchant\_id, obj.card\_subtype, obj.created\_at, obj.email, obj.order\_id, obj.user\_added, obj.next\_payment\_intention, obj.cardholder\_name, obj.expiry\_month, and obj.expiry\_year.  
Once tokenized, the saved card token can be charged via **CIT** (where the customer initiates the payment in checkout) or **MIT** (where the merchant initiates the charge off-session). While the dedicated CIT and MIT sub-pages in Paymob's developer portal navigation were only partially captured in the available documentation snippets, the Create Intention response schema (card\_tokens array and use\_cvc\_with\_moto flag) and Paymob's published OpenAPI specification for POST /api/acceptance/payments/pay (payWithPaymentMethod) plus Paymob.Net define the headless payment contract:

| Payment Channel | POST /api/acceptance/payments/p\[span\_312\](start\_span)\[span\_312\](end\_span)\[span\_315\](start\_span)\[span\_315\](end\_span)ay Request Body (BearerAuth) | Response Behavior |
| :---- | :---- | :---- |
| **Headless Card / MIT Saved Token (MOTO)** | { "payment\_token": "\<payment\_key\>", "source": { ... } } describing the card or saved token. | Processes the payment headlessly and returns 200 OK with the Transaction object. |
| **Mobile Wallet Direct Charge** (Vodafone Cash, Orange Cash, etc.) | { "payment\_token": "\<payment\_key\>", "source": { "identifier": "\<wallet\_phone\_number\>", "subtype": "WALLET" } }. | Returns the Transaction data plus RedirectUrl to redirect the customer to authorize the wallet payment. |
| **Kiosk Payment** | { "payment\_token": "\<payment\_key\>", "source": { ... } } for Kiosk / Aggregator. | Generates a payment reference for the customer to complete payment at supported offline kiosks. |

### **Service 5: Subscriptions & Recurring Billing Module (feature \= "subscriptions")**

Paymob's **Subscriptions Module** allows merchants to configure periodic subscription plans and deduct recurring amounts automatically without manual intervention on subsequent billing cycles, using a **MIGS MOTO Integration ID** for recurring deductions. All Subscription endpoints authenticate via Regime 2 (Authorization: Bearer \<auth\_token\>, where each token is valid for 1 hour).

#### **5.1 Complete Subscription Plans & Lifecycle Endpoints (18 Operations)**

Paymob's navigation menu defines **18 operations** across Subscription Plans and Subscription Actions. Where the full endpoint specification was extracted from Paymob's documentation pages, the exact URL path and body parameters are provided below; where a sub-page was inaccessible or only appeared in navigation/cURL previews, that caveat is explicitly noted.

| Sub-Namespace & Rust Method | HTTP Method & Path | Request Parameters / Body | Response & Documentation Scope |
| :---- | :---- | :---- | :---- |
| subscriptions().plans().create(params) | POST /api/acceptance/subscription-plans | **Required**: frequency: PlanFrequency (7, 15, 30, 60, 90, 180, or 360 days), name: String (max 200 chars), integration: u64 (MIGS MOTO ID). **Optional**: webhook\_url, reminder\_days, retrial\_days, plan\_type ("rent"), number\_of\_deductions, amount\_cents, use\_transaction\_amount: bool, is\_active: bool, fee. | Returns 200 OK SubscriptionPlan. Passing an unlisted frequency (such as 5\) returns 400 Bad Request {"frequency": \["\\"5\\" is not a valid choice."\]}. |
| subscriptions().plans().update(plan\_id, params) | PUT /api/acceptance/subscription-plans/{Subscription\_Plan\_Id} | Path: Subscription\_Plan\_Id. Body: { "number\_of\_deductions": 3, "amount\_cents": 1000, "integration": 11111 }. | Returns 200 OK updated SubscriptionPlan. |
| subscriptions().plans().list(page) | GET /api/acceptance/subscription-plans | Optional query parameter ?page=2. | Paginated { "next": "...", "previous": null, "results": \[ ... \] }. |
| subscriptions().plans().suspend(plan\_id) | POST Suspend Subscription Plan | Plan identifier. | Listed in Plan Actions navigation; full sub-page was inaccessible in snippets. |
| subscriptions().plans().resume(plan\_id) | POST Resume Subscription Plan | Plan identifier. | Listed in Plan Actions navigation; full sub-page was inaccessible in snippets. |
| subscriptions().create(params) | Create Subscription (via Intention API) | Uses Intention API (POST /v1/intention/) to process the initial 3DS transaction and enroll the subscription. | Triggers "Subscription Created" webhook upon enrollment. |
| subscriptions().retrieve\_or\_list(params) | GET /api/acceptance/subscriptions/{Subscription\_id} | Path: Subscription\_id (returns 404 {"detail": "not found."} if invalid). Query filters: transaction, plan\_id, Subscriptions state. | Retrieves detailed info for a specific subscription ID or lists filtered merchant subscriptions. |
| subscriptions().update(sub\_id, params) | PUT Update Subscription | Subscription parameters update. | Listed in Subscription Actions navigation; specific endpoint path/body not detailed in snippet. Triggers "u\[span\_379\](start\_span)\[span\_379\](end\_span)pdated" webhook. |
| subscriptions().suspend(sub\_id) | POST /api/accep\[span\_360\](start\_span)\[span\_360\](end\_span)tance/subscriptions/{subscription\_id}/suspend | Path: subscription\_id. | Suspends active subscription and triggers "suspended" webhook. |
| subscriptions().resume(sub\_id) | POST Resume Subscription | Subscription identifier. | Listed in Subscription Actions navigation (POST); triggers "resumed" webhook. |
| subscriptions().cancel(sub\_id) | POST Cancel Subscription | Subscription identifier. | Listed in Subscription Actions navigation (POST); triggers "canceled" webhook. |
| subscriptions().cards().list(sub\_id) | GET List Subscription Cards | Subscription identifier. | Retrieves the list of cards associated with a subscription so the merchant can inspect card IDs before changing the primary card. |
| subscriptions().cards().add\_secondary(...) | Add Secondary Card | Subscription card addition flow. | Listed in Subscription Actions navigation; triggers "add\_secondry\_card" webhook. |
| subscriptions().cards().change\_primary(sub\_id, card\_id) | POST /api/acceptance/subscriptions/{Subscription\_Id}/change-primary-card | Path: Subscription\_Id. Body: { "card": 374 } (card ID from List Subscription Cards). | Returns 200 OK (id, card\_data, token, created\_at, is\_primary: true, masked\_pan, failed\_attempts). Returns 404 {"message": "Card not found."} if wrong card ID. |
| subscriptions().cards().delete\_secondary(sub\_id, card\_id) | POST /api/acceptance/subscriptions/{Subscription\_id}/delete-card | Path: Subscription\_id. | Deletes a secondary card and triggers "delete\_card" webhook. *(Full body schema page was inaccessible).* |
| subscr\[span\_415\](start\_span)\[span\_415\](end\_span)iptions().register\_webhook(sub\_id, url) | POST Register Webhook | Registers webhook URL on a subscription. | Listed in Subscription Actions navigation; triggers "register\_webhook" callback. |
| subscriptions().last\_transaction(sub\_id) | GET /api/acceptance/subscriptions/{Subscription\_Id}/last-transaction | Path: Subscription\_Id. | Returns 200 OK full Transaction object (api\_source: "SUBSCRIPTION") for the subscription's most recent deduction. |
| subscriptions().list\_transactions(sub\_id) | GET /api/acceptance/subscriptions/{Subscription\_id}/transactions | Path: Subscription\_id. | Lists all transactions associated with the subscription. *(Detailed response page was not separately extracted).* |

#### **5.2 How some-paymob Handles Subscription Refunds (refund\_last\_transaction)**

In Paymob's data model, subscription charges are processed as standard Paymob transactions (api\_source: "SUBSCRIPTION") with their own unique transaction id (initial\_transaction on the subscription record, and individual transaction IDs returned by GET /api/acceptance/subscriptions/{Subscription\_Id}/last-transaction and GET /api/acceptance/subscriptions/{Subscription\_id}/transactions). Because Paymob links every refund to an underlying successful transaction via POST /api/acceptance/void\_refund/refund (transaction\_id \+ amount\_cents), some-paymob provides a composite helper method **paymob.subscriptions().refund\_last\_transaction(sub\_id, Option\<u64\>)** (enabled when both subscriptions and manage features are active). This method fetches the latest transaction for sub\_id via last-transaction, verifies success \== true and is\_refunded \== false, and invokes /api/acceptance/void\_refund/refund for either the specified partial amount\_cents or the full amount\_cents of that deduction.

### **Service 6: QuickLinks / Payment Links API (feature \= "quicklinks")**

QuickLinks allow merchants to programmatically generate and cancel hosted payment links from their backend. While Paymob's QuickLinks Overview page describes POST Create QuickLink and POST Cancel QuickLink at a high level, the exact endpoint paths and schemas are published in Paymob's Payment Links OpenAPI specification:

| Rust SDK Method | HTTP Method & Path | Auth Regime | Request Body Schema | Response Schema |
| :---- | :---- | :---- | :---- | :---- |
| paymob.quicklinks().create(params) | POST /api/ecommerce/payment-links | Bearer \<auth\_token\> | **Required**: amount\_cents: u64, currency: String, integrations: Vec\<u64\>. **Optional**: description: Option\<String\>, full\_name: Option\<String\>, email: Option\<String\>, phone\_number: Option\<String\>, redirection\_url: Option\<String\>. | 201 Created: { "id": String, "url": String, "client\_url": String }. |
| paymob.quicklinks().cancel(link\_id) | POST /api/ecommerce/payment-links/cancel | Bearer \<auth\_token\> | { "id": "\<link\_id\>" }. | 200 OK: Link cancelled and invalidated for future payments. |

### **Service 7: Split Features & Convenience Fees (feature \= "splits")**

Paymob provides two split payment modes and a convenience fee engine. While the step-by-step Split Features Implementation developer reference page was only referenced by title in the documentation navigation, the functional mechanics and transaction schema fields are documented across the Core Features and Transaction Inquiry specifications:

> 1. **Split Amount (One Payment, Multiple Recipients)**: Divides a single customer payment among multiple recipient parties according to predefined settlement rules, supporting multi-seller marketplaces, commission platforms, and revenue-sharing partnerships (split\_description array in transaction inquiry responses).  
> 2. **Split Payment (One Payment, Multiple Cards)**: Allows a customer to split a single checkout total across **up to 3 cards** per transaction, completing the payment once all card portions succeed (is\_split\_payment boolean in transaction inquiry responses; activated in dashboard payment experience settings).  
> 3. **Convenience Fee Models**: Represents Paymob's convenience fee configuration options—supporting Percentage (%), Fixed amount, or Combination fees, optional Maximum Fee limits, Refundable vs. Non-refundable settings, and card-level fee rules (Uniform, Debit vs. Credit, BIN-based ranges, and Domestic vs. International cards).

### **Service 8: Payouts, Instant Cashin, Inquiries & Topups (feature \= "payouts")**

The **Payouts API** enables instant and bulk disbursements across mobile wallets, bank cards, bank accounts, and cash networks in Egypt, Saudi Arabia, and the UAE, alongside budget topups and transaction inquiries.

#### **8.1 Complete Payouts API Surface (17 Operations)**

| Category | Rust SDK Method | HTTP Method & Path | Request Payload / Parameters | Response Schema & Documentation Scope |
| :---- | :---- | :---- | :---- | :---- |
| **OAuth2 Auth** | payouts().auth().generate\_token() | POST /api/secure/o/token/ | Basic Auth {CLIENT\_ID}:{CLIENT\_SECRET} \+ Form grant\_type=password\&username={USERNAME}\&password={PASSWORD}. | { access\_token, refresh\_token, expires\_in: 3600, scope, token\_type: "Bearer" }. On failure returns {"error": "invalid\_grant", "error\_description": "Invalid credentials given."}. |
| **OAuth2 Auth** | payouts().auth().refresh\_token() | POST /api/secure/o/t\[span\_85\](start\_span)\[span\_85\](end\_span)\[span\_89\](start\_span)\[span\_89\](end\_span)oken/ | Basic Auth {CLIENT\_ID}:{CLIENT\_SECRET} \+ Form grant\_type=refresh\_token\&refresh\_token={REFRESH\_TOKEN}. | Refreshes the 60-minute access\_token. |
| **Cashin** | payouts().cashin().vodafone(params) | POST /api/secure/disburse/ | { "issuer": "vodafone", "amount": "112", "msisdn": "01023456789", "client\_reference\_id": "\<uuid\>", "customer\_bears\_fees": false }. | 200 OK: { transaction\_id, msisdn, issuer, amount, full\_name, disbursement\_status, status\_code, status\_description, aman\_cashing\_details, created\_at, updated\_at }. |
| **Cashin** | payouts().cashin().etisalat(params) | POST /api/secure/disburse/ | { "issuer": "etisalat", "amount": 100, "msisdn": "01123456789", "client\_reference\_id": "\<uuid\>", "customer\_bears\_fees": false }. | 200 OK: Instant disbursement to Etisalat Cash mobile wallet. |
| **Cashin** | payouts().cashin().orange(params) | POST /api/secure/disburse/ | Orange Cashin parameters (issuer, amount, msisdn, etc.). | Listed in Cashin API navigation (POST); individual sub-page not separately extracted. |
| **Cashin** | payouts().cashin().bank\_wallet(params) | POST /api/secure/disburse/ | Bank Wallet parameters (issuer: "bank\_wallet", etc.). | Listed in Cashin API navigation (POST); supports Disbursement callbacks. |
| **Cashin** | payouts().cashin().bank\_card(params) | PO\[span\_215\](start\_span)\[span\_215\](end\_span)\[span\_218\](start\_span)\[span\_218\](end\_span)ST /api/secure/disburse/ (or /disburse/api/v1/disburse/instant\_cashin/) | Includes issuer: "bank\_card", amount, bank\_card\_number, full\_name, bank\_code, bank\_transaction\_type (salary \| credit\_card \| prepaid\_card \| cash\_transfer), reference, callback\_url. | Bank card disbursement; triggers Disbursement webhook on status update. |
| **Cashin** | payouts(\[span\_216\](start\_span)\[span\_216\](end\_span)\[span\_219\](start\_span)\[span\_219\](end\_span)).cashin\[span\_168\](start\_span)\[span\_168\](end\_span)().bank\_instant(params) | POST /api/secure/disburse/ | Instant bank transfer parameters (issuer: "insta\[span\_475\](start\_span)\[span\_475\](end\_span)nt\_bank"). | Listed in Cashin API navigation (POST); supports Disbursement callbacks. |
| **Cashin** | payouts().cashin().egyptian\_post\[span\_477\](start\_span)\[span\_477\](end\_span)(params) | POST /api/secure/disburse/ | Egyptian POST parameters. | Listed in Cashin API navigation (POST). |
| **Cashin** | payouts().cashin(\[span\_170\](start\_span)\[span\_170\](end\_span)).bulk(params) | POST /disburse/api/v1/d\[span\_171\](start\_span)\[span\_171\](end\_span)isburse/bulk\_transaction/ | Bulk disbursement request body. | Defined in Paymob Disbursement OpenAPI spec (bulkDisbursement). |
| **Cashin** | payouts().cashin().cancel\_aman(params) | POST /api/secure/transaction/aman/cancel/ | Aman transaction cancellation payload. | Defined in Payouts Portal Swagger UI (Cancel aman transaction). |
| **Inquiries** | payouts().inquiries().transactions(params) | GET / POST /api/secure/transaction/inquire/ (and POST /disburse/api/v1/bulk\_transaction/inquire/) | Covers Bulk Transaction Inquiry non banking and Bulk Transaction Inquiry banking. | Detailed parameter page was inaccessible in snippets, though cURL URL and Swagger methods are confirmed. |
| **Inquiries** | payouts().inquiries().by\_reference(params) | GET / POST /disburse/api/v1/bulk\_transaction/inquire\_by\_reference/ | Looks up disbursement status by reference. | Listed in Payouts Inquiries navigation and Disbursement OpenAPI spec. |
| **Inquiries** | payouts().inquiries().user\_budget() | GET /api/secure/budget/inquire/ | Header: Authorization: Bearer {{TOKEN}}. | 200 OK: { "current\_budget": "Your current budget is 888.25 LE" }. 429 Too Many Requests: { status\_description, status\_code }. |
| **Inquiries** | payouts().inquiries().topup(params) | GET /api/secure/topup/inquire/ | Header: Authorization: {{TOKEN}}, Content-Type: application/json. | Checks status of a topup request (specific query/response schema not provided in snippet). |
| **Topup** | payouts().topups().from\_bank\_transfer(p) | POST /api/secure/topup/request/ | { "amount": "1000", "type": "from\_bank\_transfer", "currency": "egyptian\_pound", "from\_bank": "Commercial International Bank", "from\_account\_number": "1234567890", "from\_account\_name": "John Doe", "from\_date": "2024-01-15", "to\_attach\_proof": "\<max 2.8 MB\>" }. | 200 OK: { id, client\_id, amount, transfer\_type, username, from\_bank, to\_bank, from\_account\_number, to\_account\_number, from\_account\_name, to\_account\_name, from\_date, to\_attach\_proof, automatic, accept\_balance\_transfer\_id, status, reason }. |
| **Topup** | payouts().topups().from\_accept\_balance(p) | POST /api/secure/topup/request/ | { "amount": 500, "type": "from\_accept\_balance", "currency": "egyptian\_pound", "username": "accept\_user\_123" }. | 200 OK: Returns the created TopupRecord (transfer\_type: "from\_accept\_balance", status: "pending"). |

### **Service 9: Partner Merchant Onboarding APIs (feature \= "onboarding")**

For SaaS platforms and marketplaces that onboard sub-merchants onto Paymob directly inside their own software, some-paymob encapsulates the **Partner Onboarding API** (partner-onboarding-apis-1). *(Note on evidence scope: Paymob's Partner Onboarding overview and auth pages document the 7 operations and provide exact cURL/schema details for Retrieve Partner HMAC Secret and the URL structure for Get Onboarding Schema, while the individual request/response payload pages for the remaining 5 endpoints were either inaccessible or not included in the overview document).*

| Rust SDK Method | HTTP Method & Path | Auth Regime | Description & Documented Contract Details |
| :---- | :---- | :---- | :---- |
| onboarding().auth().login(creds) | POST Login | Partner Credentials | Generates the Partner auth token required for subsequent Partner Auth endpoints. |
| onboarding().auth().create\_api\_key(...) | POST Create and Use Partner API Key | Partner Auth Token | Creates/retrieves the Partner API Key used for onboarding and partner transaction processing. |
| onboarding().auth().retrieve\_hmac\_secret() | GET /api/auth/hmac\_secret/get\_hm\[span\_161\](start\_span)\[span\_161\](end\_span)ac | Bearer \<aut\[span\_526\](start\_span)\[span\_526\](end\_span)h\_token\> | Returns { "\[span\_527\](start\_span)\[span\_527\](end\_span)label": null, "status": "Created", "code": 201, "body": { "hmac\_secret": "3qUAg2xx6JW89Qav5Gzz\[span\_162\](start\_span)\[span\_162\](end\_span)mXoalgjf5XxE" } }. |
| onboardi\[span\_528\](start\_span)\[span\_528\](end\_span)ng().flow().register\_merchant(p) | POST Register Merchant | Partner API Key | Registers a new merchant account under the partner integration. |
| onboarding().flow().get\_schema(params) | GET /api/onboarding/flow/schema | Partner API Key | Query parameters: ?partner=KeyPartner\&resubmission=true\&paymob\_mid=123 (partner is the partner name). *(Full response JSON page was inaccessible).* |
| onboarding().flow().submit\_step(params) | POST Submit Onboarding Step | Partner API Key | Submits merchant verification documents and onboarding step data. |
| onboarding().flow().merchant\_inquiry(mid) | GET Partner Merchant Inquiry | Partner API Key | Checks merchant approval status and retrieves live integration details. |
| paymob.with\_merchant(merchant\_id) | Client Scoped Wrapper | Partner API Key \+ merchant\_id | Creates a scoped client view that processes intentions and inquiries on behalf of an onboarded sub-merchant. |

### **Service 10: Legacy Accept v2 3-Step Flow (feat\[span\_533\](start\_span)\[span\_533\](end\_span)ure \= "legacy-v2")**

For existing applications migrating to Rust or workflows that require the classic 3-step token-order-payment\_key sequence, some-paymob supports the **Paymob Accept Legacy (v2) API** documented in Paymob's OpenAPI specifications and reference SDKs:

> 1. **legacy().generate\_auth\_token()**: POST /api/auth/tokens with JSON body { "api\_key": "\<api\_key\>" } \-\> returns { "token": "\<auth\_token\>" } (60-minute TTL).  
> 2. **legacy().create\_order(params)**: POST /api/ecommerce/orders with required { "auth\_token", "amount\_cents", "currency" } and optional merchant\_order\_id, items \-\> returns Order (id, amount\_cents, currency, merchant\_order\[span\_223\](start\_span)\[span\_223\](end\_span)\[span\_229\](start\_span)\[span\_229\](end\_span)\_id, created\_at, items).  
> 3. **legacy().create\_payment\_key(params)**: POST /api/acceptance/payment\_keys \-\> exchanges auth\_token, order\_id, amount\_cents, currency, integration\_id, and \[span\_224\](start\_span)\[span\_224\](end\_span)\[span\_230\](start\_span)\[span\_230\](end\_span)billing\_data for a payment\_token.  
> 4. **legacy().iframe\_url(iframe\_id, payment\_token)**: Builds https\://accept.paymob.com/api/acceptance/iframes/{iframe\_id}?payment\_token={url\_encoded\_token}.  
> 5. **legacy().create\_checkout(params)**: High-level one-call helper (auth \-\> order \-\> payment\_key \-\> iframe\_url) mirroring Paymob.Net's CreateCheckoutAsync.

## **Constant-Time Cryptographic Webhook Verification Engine (feature \= "\[span\_101\](start\_span)\[span\_101\](end\_span)\[span\_104\](start\_span)\[span\_104\](end\_span)\[span\_107\](start\_span)\[span\_107\](end\_span)webhooks")**

Paymob's official security engineering guidelines establish three strict requirements for webhook processing:

> 1. **Webhook Callback as the Source of Truth**: Browser redirect parameters (GET response callbacks) and mobile SDK return values must never be trusted to update order state; only HMAC-verified backend callbacks (POST) should trigger fulfillment.  
> 2. **SHA-512 & Constant-Time Comparison**: Signatures must be computed using HMAC-SHA512 (never SHA-256) and verified using a timing-safe comparison that fails closed (causing zero state change) on any mismatch.  
> 3. **Atomic Idempotency on obj.id**: Because a single Paymob Order (order.id / special\_reference) can have multiple payment attempts, webhook handlers must enforce a unique database constraint on obj.id (the transaction ID) alongside a compare-and-set state lock on the order and a transactional outbox within a single database transaction.

What makes Paymob webhook verification uniquely intricate is that Paymob uses **four distinct HMAC concatenation and signature transport protocols** across its services, plus optional Payouts webhook signing.

### **Detailed Specification of the Webhook Verification Protocols**

#### **Protocol A & B: Transaction Processed (POST JSON) & Transaction Response (GET Query)**

Both Transaction callbacks extract **20 exact parameters** sorted lexicographically by their canonical key names and concatenate their values into a continuous string without separators before computing HMAC-SHA512 against the ?hmac= query parameter. Boolean values serialize as lowercase "true" or "false".

| Order | Canonical Key (Lexicographical) | POST Processed JSON Path (in body) | GET Response Query Parameter Key | Sample Value (Official Test Vector) |
| :---- | :---- | :---- | :---- | :---- |
| **1** | amount\_cents | obj.amount\_cents | amount\_cents | 100000 |
| **2** | created\_at | obj.created\_at | created\_at | 2024-06-13T11:33:44.592345 |
| **3** | currency | obj.currency | currency | EGP |
| **4** | error\_occured *(spelled with 1 'r')* | obj.error\_occured | error\_occured | false |
| **5** | has\_parent\_t\[span\_110\](start\_span)\[span\_110\](end\_span)\[span\_113\](start\_span)\[span\_113\](end\_span)\[span\_116\](start\_span)\[span\_116\](end\_span)\[span\_119\](start\_span)\[span\_119\](end\_span)ransaction | obj.has\_parent\_transaction | has\_parent\_transaction | false |
| **6** | obj.id (POST) \| id (GET) | obj.id | id | 192036465 |
| **7** | integration\_id | obj.integration\_id | integration\_id | 4097558 |
| **8** | is\_3d\_secure | obj.is\_3d\_secure | is\_3d\_secure | true |
| **9** | is\_auth | obj.is\_auth | is\_auth | false |
| **10** | is\_capture | obj.is\_capture | is\_capture | false |
| **11** | is\_refunded | obj.is\_refunded | is\_refunded | false |
| **12** | is\_standalone\_payment | obj.is\_standalone\_payment | is\_standalone\_payment | true |
| **13** | is\_voided | obj.is\_voided | is\_voided | false |
| **14** | order.id (POST) \| order\_id (GET) | obj.order.id | order\_id *(or order in redirect URL sample)* | 217503754 |
| **15** | owner | obj.owner | owner | 302852 |
| **16** | pending | obj.pending | pending | false |
| **17** | source\_data.pan | obj.source\_data.pan | source\_data.pan | 2346 |
| **18** | source\_data.sub\_type | obj.source\_data.sub\_type | source\_data.sub\_type | MasterCard |
| **19** | source\_data.type | obj.source\_data.type | source\_data.type | card |
| **20** | success | obj.success | success | true |

*Implementation Nuance on Key \#14 in GET Redirects:* While Paymob's HMAC Transaction Callback documentation specifies order\_id for GET responses, Paymob's Transaction Response Callback sample URL emits order=378804 in the query string. some-paymob's query verifier checks params.get("order\_id").or\_else(\|\| params.get("order")) so client redirect verification succeeds under both parameter names.

#### **Protocol C: Card Token Callback (POST JSON { "type": "TOKEN", "obj": { ... } })**

When a card is saved, Paymob sends a POST request with ?hmac=\<digest\> in the query parameters and concatenates **8 exact keys** in lexicographical order from body.obj: card\_subtype ("MasterCard"), created\_at ("2026-08-24T13:28:31.015314"), email ("kiyedi3052@claspira.com"), id (15978654), masked\_pan ("xxxx-xxxx-xxxx-2346"), merchant\_id\[span\_38\](start\_span)\[span\_38\](end\_span) (1053928), order\_id ("593881581"), and token ("3f22ce8a4e77125c70f0bc69830e34c36df469351e2fa6be76428be4"), producing the official HMAC-SHA512 test vector 4c0480c8c5afdba5294dee8ec01e5aa0203c5df0a8b3a45eadf11f2b01c974725d205587dabba70709f3ac2d0c7d7ec93fe69ec462b5a3018190bfd681ebf1d3.

#### **Protocol D: Subscription Callback (POST JSON with Body hmac)**

When any lifecycle action or recurring billing event occurs on a subscription, Paymob sends a POST callback to the registered webhook\_url where the hmac signature is provided **in the JSON request body** (body.hmac) rather than the query string. The concatenated string is formed by joining trigger\_type, the literal word "for", and subscription\_data.id: "{trigger\_type}for{subscription\_data.id}" (for example, "suspendedfor1264", which hashes to dd5b3018888d9f98574cd180793db10d969b522e08c62baf2ea33357d1546b567b7fd79760e90046e90eaacf30024ede5539cbd0748bd9e6c005faf5117e0e7b).  
Paymob defines **12 trigger\_type values** in the Subscription Trigger Types Catalog, which some-paymob models as the strongly-typed SubscriptionTriggerType enum:

| Action Category | SubscriptionTriggerType Rust Variant | Exact Paymob Wire String (trigger\_type) |
| :---- | :---- | :---- |
| **CREATED** | SubscriptionTriggerType::Created | "Subscription Created" |
| **SUSPENDED** | SubscriptionTriggerType::Suspended | "suspended" |
| **CANCELED** | SubscriptionTriggerType::Canceled | "canceled" |
| **RESUMED** | SubscriptionTriggerType::Resumed | "resumed" |
| **UPDATED** | SubscriptionTriggerType::Updated | "updated" |
| **SECONDRY\_CARD** | SubscriptionTriggerType::SecondaryCardAdded | "add\_secondry\_card" *(exact spelling preserved)* |
| **PRIMARY\_CARD** | SubscriptionTriggerType::PrimaryCardChanged | "change\_primary\_card" |
| **DELETE\_SECONDARY\_CARD** | SubscriptionTriggerType::SecondaryCardDeleted | "delete\_card" |
| **REGISTER\_WEBHOOK** | SubscriptionTriggerType::WebhookRegistered | "register\_webhook" |
| **Next billing cycle** | SubscriptionTriggerType::SuccessfulTransaction | "Successful Transaction" |
| **Failed deduction transaction** | SubscriptionT\[span\_361\](start\_span)\[span\_361\](end\_span)riggerType::FailedTransaction | "Failed Transaction" |
| **Failed retrial deduction transaction** | SubscriptionTriggerType::FailedOverdueTransaction | "Failed Overdue Transaction" |

#### **Protocol E: Payouts Callbacks (Disbursement & Topup POST Webhooks)**

Payouts sends two separate POST callbacks configured in the Payouts Dashboard: **Disbursement Callbacks** (supported for bank\_card, bank\_wallet, and instant\_bank; Aman is not supported) and **Topup Callbacks** (fired when a topup request is Approved or Rejected). In Payouts, HMAC signing is not enabled by default; once activated via the merchant's Payout account manager, a single account-wide HMAC secret is emailed and shared across both disbursement and topup callbacks. *(Note: Paymob's Payout Callbacks documentation page describes the callback fields and states that the emailed HMAC secret verifies incoming requests, but does not specify the exact field-concatenation order or signature header/query parameter name for Payouts HMAC; some-paymob deserializes DisbursementCallback and TopupCallback and provides a configurable Payouts HMAC verifier hook).*

### **Reference Rust Implementation of the Constant-Time Verifier**

`#![forbid(unsafe_code)]`

`use hmac::{Hmac, Mac};`  
`use secrecy::{ExposeSecret, SecretString};`  
`use sh[span_371](start_span)[span_371](end_span)a2::Sha512;`  
`use subtle::ConstantTimeEq;`

`type HmacSha512 = Hmac<Sha512>;`

`p[span_483](start_span)[span_483](end_span)ub struct PaymobWebh[span_372](start_span)[span_372](end_span)ookEngine {`  
    `hmac_secret: SecretString,`  
`}`

`impl PaymobWebhookEngine {`  
    `pub fn new(hmac_secret: impl I[span_373](start_span)[span_373](end_span)nto<SecretString>) -> Self {`  
        `Self {`  
            `hmac_secret: hmac_secret.into(),`  
        `}`  
    `}`

   ``[span_374](start_span)[span_374](end_span) /// Computes HMAC-SHA512 over [span_484](start_span)[span_484](end_span)`concatenated_payload` and compares it in``  
    ``/// strict constant time (`O(1)` branchless byte comp[span_375](start_span)[span_375](end_span)arison) against `received_hmac_hex`.``  
    `pub fn verify_concatenated_str(`  
        `&self,`  
        `concatenated_payload: &str,`  
        `received_hmac_hex: &str,`  
    `) -> Result<(), WebhookError> {`  
        `let received_bytes = hex::decode(received_hmac_hex.trim())`  
            `.map_err(|_| WebhookError::MalformedSignatureHex)?;`

        `let mut mac = HmacSha512::new_from_slice(self.hmac_secret.expose_secret().as_bytes())`  
            `.map_err(|_| WebhookError::InvalidSecretKeyLength)?;`  
        `mac.update(concatenated_payload.as_bytes());`  
        `let expected_bytes = mac.finalize().into_bytes();`

        `// Constant-time comparison prevents timing side-channel attacks`  
        `if expected_bytes.as_slice().ct_eq(received_bytes.as_slice()).into() {`  
            `Ok(())`  
        `} else {`  
            `Err(WebhookError::SignatureMismatch)`  
        `}`  
    `}`  
`}`

## **Crate Module Structure & Workspace Organization**

To support clean feature gating and maintain idiomatic Rust ergonomics, some-paymob organizes its source files into isolated domain modules inside src/:

| Module Path | Feature Gate | Responsibility & Key Exported Types |
| :---- | :---- | :---- |
| src/lib.rs | Always on | Crate root (\#\!\[forbid(unsafe\_code)\], \#\!\[cfg\_attr(docsrs, feature(doc\_cfg))\]), re-exports PaymobClient, ClientConfig, PaymobRegion, PaymobError. |
| src/core/config.rs | Always on | ClientConfig, ClientConfigBuilder, PaymobRegion, EnvironmentMode (Test vs Live key-prefix validator). |
| src/core/auth.rs | Always on | AuthManager implementing lock-free ArcSwapOption token caching and single-flight refresh for Regime 1 (Token), Regime 2 (Bearer / Body auth\_token), Regime 3 (Payouts OAuth2), and Regime 4 (Partner). |
| src/core/http.rs | Always on | HttpClient wrapper around reqwest::Client with exponential backoff retry on 429 / 502 / 503 / 504, trailing-slash policy, and correlation logging. |
| src/core/error.rs | Always on | PaymobError enum (ApiError, AuthenticationError, EnvironmentMismatch, RefundExceedsPermissibleAmount, RateLimited, WebhookError). |
| src/resources/intentions.rs | intentions | IntentionsService (create, update), CheckoutService (unified\_url, pixel\_config, affordability\_widget), CreateIntentionParams, IntentionResponse. |
| src/resources/manage.rs | manage | ManageService (refund, void, capture), RefundParams, VoidParams, CaptureParams. |
| src/resources/inquiries.rs | inquiries | InquiriesService (by\_transaction\_id, by\_order\_or\_reference, card\_tokens\_by\_order, order), InquiredTransaction, CardTokenEnvelope. |
| src/resources/saved\_cards.rs | saved-cards | SavedCardsService (pay\_with\_token\_mit, pay\_with\_wallet, pay\_with\_kiosk, pay\_raw), PaymentSource enum (TOKEN, WALLET, AGGREGATOR). |
| src/resources/subscriptions.rs | subscriptions | SubscriptionsService & SubscriptionPlansService (all 18 plan, lifecycle, card, webhook, transaction history, and refund\_last\_transaction operations). |
| src/resources/quicklinks.rs | quicklinks | QuickLinksService (create, cancel), CreateQuickLinkParams, QuickLinkResponse. |
| src/resources/splits.rs | splits | SplitDescription, SplitPaymentConfig (up to 3 cards), ConvenienceFeeConfig. |
| src/resources/payouts.rs | payouts | PayoutsService (cashin, inquiries, topups, auth), DisburseIssuer enum (vodafone, etisalat, orange, bank\_wallet, bank\_card, instant\_bank, egyptian\_post). |
| src/resources/onboarding.rs | onboarding | PartnerOnboardingService (auth, flow), OnboardingSchemaQuery, PartnerHmacResponse. |
| src/resources/legacy.rs | legacy-v2 | LegacyV2Service (generate\_auth\_token, create\_order, create\_payment\_key, iframe\_url, create\_checkout). |
| src/webhooks/mod.rs | webhooks | PaymobWebhookEngine (construct\_event, verify\_transaction\_post, verify\_transaction\_get, verify\_card\_token, verify\_subscription, verify\_payout), WebhookEvent enum. |
| src/adapter/some\_payments.rs | some-payments-adapter | Implements northbound some-payments unified gateway traits and maps PaymobSpecificOptions extensions. |

## **Designing for some-payments: Cross-Gateway Unification Strategy**

Because some-paymob will join some-stripe and some-moyasar inside the **some-payments** workspace, its internal domain models are structured so that implementing the unified some-payments traits requires zero data copying or leaky abstractions.

| Unified some-payments Operation | some-stripe Concept | some-moyasar Concept | some-paymob Implementation (some-payments-adapter) |
| :---- | :---- | :---- | :---- |
| **create\_payment\_session** | PaymentIntent / Checkout Session | Payment / Invoice creation | POST /v1/intention/ \-\> maps id (pi\_\*), intention\_order\_id, client\_secret, and checkout().unified\_url(...). |
| **capture\_payment** | Capture PaymentIntent | Capture authorized payment | POST /api/acceptance/capture (transaction\_id, amount\_cents). |
| **refund\_payment** | Create Refund | Refund payment | POST /api/acceptance/void\_refund/refund (transaction\_id, amount\_cents) — also used for subscription deduction refunds via last-transaction lookup. |
| **void\_payment** | Cancel uncaptured PaymentIntent | Void authorized payment | POST /api/acceptance/void\_refund/void (transaction\_id). |
| **charge\_saved\_method (MIT)** | Off-session PaymentIntent | Token payment source | POST /api/acceptance/payments/pay (payment\_token \+ source for saved card token). |
| **verify\_webhook** | Stripe-Signature verification | Webhook secret\_token check | PaymobWebhookEngine::construct\_event (auto-detecting 20-key Transaction, 8-key Card Token, or {trigger\_type}for{id} Subscription HMAC-SHA512). |
| **Idempotency & Deduplication** | Event ID (evt\_...) | Event / Payment ID | Transaction obj.id (for payments) and paymob\_request\_id (UUID in Subscription webhooks), keeping order.id / special\_reference for order correlation. |
| **Provider Extension Escape Hatch** | ProviderExt::Stripe(...) | ProviderExt::Moyasar(...) | ProviderExt::Paymob(PaymobExt) exposing pre\_selected\_plan (Affordability Widget), special\_reference\[span\_51\](start\_span)\[span\_51\](end\_span)\[span\_53\](start\_span)\[span\_53\](end\_span)\[span\_55\](start\_span)\[span\_55\](end\_span), split\_description, and Kiosk/Wallet execution. |

## **Production Hardening, Testing & Security Checklist**

To ensure some-paymob meets production reliability standards from v0.1.0, the crate enforces three core engineering guardrails derived directly from Paymob's operational documentation:

> 1. **Compile-Time & Builder-Time Pitfall Prevention**:  
   * Rejects CreateIntentionParams at builder time if billing\_data is supplied without phone\_number or if any IntentionItem lacks name or amount.  
   * Validates that SecretKey (sk\_\* / egy\_sk\_\*) and PublicKey (pk\_\* / egy\_pk\_\*) are never swapped, preventing the common integration failure where a Secret Key is passed to frontend checkout or Bearer is sent instead of Token on Intention creation.  
> 2. **Official Test Vector Suite & Sandbox Constraints**:  
   * Embeds the verbatim JSON payloads and HMAC-SHA512 digests from Paymob's official documentation (Transaction Processed 192036465, Transaction Response 316004, Card Token 15978654, and Subscription 1264 "suspendedfor1264") directly into cargo test unit suites.  
   * Includes a mock server suite (wiremock) simulating 1-hour JWT expiration (401 {\[span\_102\](start\_span)\[span\_102\](end\_span)\[span\_105\](start\_span)\[span\_105\](end\_span)\[span\_108\](start\_span)\[span\_108\](end\_span)"detail": "incorrect credentials"}) and Payouts 429 Too Many Requests responses.  
   * Documents Paymob Sandbox constraints in rustdoc: sandbox test card/wallet credentials expire after **30 days**, and **Kiosk and BNPL payment methods cannot be tested in sandbox mode** (requiring live mode verification or webhook simulation via Paymob's Webhook Testing Tool https\://hooks.paymob.com/...).  
> 3. **Database Idempotency Helper (IdempotentWebhookGuard)**: \- Exposes a helper trait in some\_paymob::webhooks that extracts (idempotency\_key, order\_correlation\_id) from any verified WebhookEvent—returning (obj.id.to\_string(), obj.order.id.to\_string()) for transactions and (paymob\_request\_id, subscription\_data\[span\_196\](start\_span)\[span\_196\](end\_span).id.to\_string()) for subscriptions—so downstream PostgreSQL or MongoDB handlers can enforce a unique constraint on obj.id and compare-and-set state locking inside a single atomic transaction.

#### **Works cited**

1\. Create Intention \- Paymob Documentation, https\://developers.paymob.com/paymob-docs/intention-apis/create-intention 2\. Paymob Payments Api \| APIs.io APIs, https\://apis.io/apis/paymob/paymob-payments-api/ 3\. maheraladdin \- GitHub, https\://github.com/maheraladdin 4\. Paymob Developer Portal, https\://developers.paymob.com/ 5\. Webhook Testing Tool \- Paymob Developer Portal, https\://developers.paymob.com/paymob-docs/developers/webhook-callbacks-and-hmac/webhook-testing-tool 6\. Transaction Inquiry \- Paymob Developer Portal, https\://developers.paymob.com/paymob-docs/developers/transaction-inquiry-apis/transaction-inquiry 7\. Payout Callbacks \- Paymob Developer Portal, https\://developers.paymob.com/paymob-docs/developers/payouts-apis/payout-callbacks 8\. Create Subscription plan \- Paymob Developer Portal, https\://developers.paymob.com/paymob-docs/developers/subscription/create-subscription-plan 9\. Card Token Inquiry \- Paymob Developer Portal, https\://developers.paymob.com/paymob-docs/developers/transaction-inquiry-apis/card-token-inquiry 10\. By Order ID or Reference \- Paymob Developer Portal, https\://developers.paymob.com/paymob-docs/developers/transaction-inquiry-apis/transaction-inquiry/by-order-id-or-reference 11\. HMAC Transaction Callback \- Paymob Documentation, https\://developers.paymob.com/paymob-docs/developers/webhook-callbacks-and-hmac/hmac/hmac-transaction-callback 12\. Subscription Callback and HMAC Calculation, https\://developers.paymob.com/paymob-docs/developers/subscription/hmac-calculation-for-subscription-callback 13\. HMAC Card Token Callback \- Paymob Developer Portal, https\://developers.paymob.com/paymob-docs/developers/webhook-callbacks-and-hmac/hmac/hmac-for-card-tokens 14\. Crate stripe \- Rust \- Docs.rs, https\://docs.rs/stripe-rust 15\. List Subscription Details \- Paymob Developer Portal, https\://developers.paymob.com/paymob-docs/developers/subscription/subscription-actions/list-subscription-details 16\. Overview \- Paymob Documentation, https\://developers.paymob.com/paymob-docs/developers/quicklink-apis/overview 17\. Topup Inquiry \- Paymob Documentation, https\://developers.paymob.com/paymob-docs/developers/payouts-apis/inquires/topup-inquiry 18\. Changelog \| Paymob API Documentation, https\://developers.paymob.com/changelog/paymob-solutions-s-a-e/pak 19\. Topup Request – accept balance \- Paymob Documentation, https\://developers.paymob.com/paymob-docs/developers/payouts-apis/topup/topup-request-accept-balance 20\. Vodafone Cashin \- Paymob Developer Portal, https\://developers.paymob.com/paymob-docs/developers/payouts-apis/cashin-api/vodafone-cashin 21\. User Budget Inquiry \- Paymob Developer Portal, https\://developers.paymob.com/paymob-docs/developers/payouts-apis/inquires/user-budget-inquiry 22\. Refund \- Paymob Documentation, https\://developers.paymob.com/paymob-docs/developers/manage-payment-apis 23\. Update Subscription Plan \- Paymob Developer Portal, https\://developers.paymob.com/paymob-docs/developers/subscription/plan-actions/update-subscription-plan 24\. Void \- Paymob Documentation, https\://developers.paymob.com/paymob-docs/developers/manage-payment-apis/void 25\. The missing .NET SDK for Paymob — Egypt's leading payment, https\://github.com/SENESO/Paymob.Net?utm\_source=lanfrica.com\&utm\_medium=referral 26\. Paymob Capture API — OpenAPI & Docs \- APIs.io, https\://apis.io/apis/paymob/paymob-capture-api/ 27\. ahmedShokrr/paymob-springboot-integration \- GitHub, https\://github.com/ahmedShokrr/paymob-springboot-integration 28\. شرح بوابة الدفع Paymob في فلاتر (Paymob In Flutter) \- عرب فلاتر, https\://arabflutter.com/paymob-in-flutter/ 29\. Paymob Payment Links API — OpenAPI & Docs \- APIs.io, https\://apis.io/apis/paymob/paymob-payment-links-api/ 30\. Paymob Transactions Api \- APIs, https\://apis.apievangelist.com/store/paymob-transactions-api/ 31\. Paymob Orders Api \- API Evangelist APIs, https\://apis.apievangelist.com/store/paymob-orders-api/ 32\. Refresh Token \- Paymob Documentation \- Paymob Developer Portal, https\://developers.paymob.com/paymob-docs/developers/payouts-apis/auth/refresh-token 33\. Retrieve Partner HMAC Secret \- Paymob Developer Portal, https\://developers.paymob.com/paymob-docs/developers/partner-onboarding-apis-1/auth/retrieve-partner-hmac-secret 34\. Affordability Widget \- Paymob Documentation, https\://developers.paymob.com/paymob-docs/developers/checkout-experiences/affordability-widget 35\. Authorization & Capture (Auth/Cap) \- Paymob Developer Portal, https\://developers.paymob.com/paymob-docs/payments-and-features/core-features/auth-cap 36\. New Dashboard \- Paymob Documentation, https\://developers.paymob.com/paymob-docs/getting-started/new-dashboard 37\. Create Card Token \- Paymob Developer Portal, https\://developers.paymob.com/paymob-docs/developers/pay-with-saved-cards/create-card-token 38\. Last Transaction Subscription \- Paymob Developer Portal, https\://developers.paymob.com/paymob-docs/developers/subscription/subscription-actions/last-transaction-subscription 39\. Change Subscription Primary Card \- Paymob Developer Portal, https\://developers.paymob.com/paymob-docs/developers/subscription/subscription-actions/change-subscription-primary-card 40\. Suspend Subscription Plan \- Paymob Documentation, https\://developers.paymob.com/paymob-docs/developers/subscription/plan-actions/suspend-subscription-plan 41\. Subscription actions \- Paymob Documentation, https\://developers.paymob.com/paymob-docs/developers/subscription/subscription-actions 42\. Split Features \- Paymob Developer Portal, https\://developers.paymob.com/paymob-docs/payments-and-features/core-features/split-features 43\. Dashboard \- Paymob Documentation, https\://developers.paymob.com/paymob-docs/payouts/dashboard 44\. Convenience Fee \- Paymob Documentation, https\://developers.paymob.com/paymob-docs/payments-and-features/core-features/convenience-fee 45\. Paymob Disbursement Api \- API Evangelist APIs, https\://apis.apievangelist.com/store/paymob-disbursement-api/ 46\. JS 401 loop error while generating a payment token \- Stack Overflow, https\://stackoverflow.com/questions/74894373/js-401-loop-error-while-generating-a-payment-token 47\. paymob/src/config/paymob.php at master \- GitHub, https\://github.com/baselrabia/paymob/blob/master/src/config/paymob.php 48\. Transaction callbacks \- Paymob Documentation, https\://developers.paymob.com/paymob-docs/developers/transaction-callbacks 49\. Paymob Transactions API — OpenAPI & Docs \- APIs.io, https\://apis.io/apis/paymob/paymob-transactions-api/
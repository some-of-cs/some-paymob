# User Story `US-2.1.0`: v1 Payment Intention Create & Update API (POST & PUT /v1/intention/)

- **Module**: `module-2` ([Payment Intentions, Checkout Experiences & Legacy Accept v2 Flow](./README.md))
- **Story Branch**: `feat/us-2.1.0-intention-create-update`
- **Field Profile**: `software` (`engineering,security,testing`)
- **Story Decomposition Score ($S_{\text{story}}$)**: `2.55` $\to$ **`4` Parallel Implementation Units (`unit-1..4`)**

---

## 1. Spec Kit Specifications

### 1.1 User Story Narrative
> **As a** E-Commerce Checkout Engineer integrating Paymob v1 Unified Intention API,  
> **I want** an ergonomic `paymob.intentions().create(params)` and `.update(params)` service with builder-time validation of billing phone numbers, line-item completeness, and Test/Live integration parity,  
> **So that** common 400 Bad Request (`billing_data.phone_number` / `items.name`) and 404 Not Found (`Integration ID/Name does not exist` due to Test/Live mismatch) errors are prevented before network dispatch.

This User Story belongs to **Module 2 (Payment Intentions, Checkout Experiences & Legacy Accept v2 Flow)** of [`some-paymob`](https://github.com/some-of-cs/some-paymob) as specified in [`docs/Paymob Rust SDK Architecture Research.md`](../../Paymob%20Rust%20SDK%20Architecture%20Research.md). It is decomposed into `4` strictly disjoint, 100% parallel Implementation Units (`unit-1..4`) that compile and verify independently inside isolated Git worktrees without inter-unit blocking.

#### 1.1.1 Preconditions
- Module 1 (`feat/module-1-core-microkernel`) merged with `PaymobClient`, Regime 1 `AuthStrategy::SecretKeyToken`, and `MinorUnitAmount`.
- Paymob v1 Intention specification ([Create Intention](https://developers.paymob.com/paymob-docs/intention-apis/create-intention)) and [Changelog v0.6.3](https://developers.paymob.com/changelog/paymob-solutions-s-a-e/pak) path rules loaded.

#### 1.1.2 Postconditions
- `paymob.intentions().create(params)` dispatches `POST /v1/intention/` with `Authorization: Token <secret_key>` and deserializes HTTP 201 `IntentionResponse` (`id`, `intention_order_id`, `client_secret: SecretString`, `payment_keys`).
- `paymob.intentions().update(params)` dispatches `PUT /v1/intention/` with updated intention parameters.
- Builder validation rejects missing `billing_data.phone_number`, incomplete `IntentionItem` (`name`/`amount`), and Test/Live mismatches before network I/O.

### 1.2 Acceptance Criteria (Gherkin Scenarios)

```gherkin
Feature: US-2.1.0 — v1 Payment Intention Create & Update API (POST & PUT /v1/intention/)

  Scenario: AC-1 — Create Payment Intention Happy Path (POST /v1/intention/)
    Given valid `CreateIntentionParams` with `amount: 100_000` (1,000.00 EGP), `currency: Currency::EGP`, `payment_methods: vec![IntegrationId(4097558), MethodName("card")]`, and `BillingData` with `phone_number: "+201116491564"`
    When `paymob.intentions().create(params).await` is executed
    Then an HTTP `POST /v1/intention/` request is sent with `Authorization: Token <secret_key>` and returns `IntentionResponse` with `intention_order_id`, redacted `client_secret`, and `payment_keys`

  Scenario: AC-2 — Builder-Time Rejection of Missing Billing Phone Number or Item Fields
    Given a `BillingDataBuilder` omitting `phone_number` or an `IntentionItem` with an empty `name`
    When `.build()` is called on `BillingDataBuilder` or `CreateIntentionParamsBuilder`
    Then `.build()` returns `Err(PaymobError::ValidationError)` locally without sending a network request

  Scenario: AC-3 — Environment Parity Guard Between Secret Key and Integration IDs
    Given a `Test` secret key (`egy_sk_test_...`) paired with a known `Live` integration configuration
    When intention creation or response validation runs
    Then the SDK flags `PaymobError::EnvironmentMismatch` with a clear diagnostic referencing the Merchant Dashboard Payment Integrations tab

  Scenario: AC-4 — Secret Redaction, Zero Float & Cyclomatic Complexity Compliance
    Given all public types and functions implemented across unit-1..4 of US-2.1.0
    When formatted via Debug/Display and analyzed by Gate G2 and Gate G-Complexity
    Then zero raw secrets, API keys, tokens, or PANs appear in Debug output (all emit "[REDACTED]")
    And every monetary value uses integer minor units (u64) with Cyclomatic Complexity CC <= 6 and nesting depth <= 2
```

### 1.3 Test Cases & Traceability Matrix

| Test Case ID | Mapped AC | Owning Unit | Test Level (Unit / Integration / Property / Security) | Description & Input Vector | Expected Result & Pass Threshold |
| :--- | :---: | :---: | :---: | :--- | :--- |
| `TC-2.1.1` | `AC-1` | `unit-1` | Unit + Doc-Test | Validate `BillingData` & `BillingDataBuilder` (enforcing non-empty `phone_number` at `.build()` time and redacting PII in `Debug`), `IntentionCustomer`, and `IntentionItem` (enforcing non-empty `name` and `amount` in minor units) in `src/resources/intentions/billing.rs` (positive, boundary, and malformed inputs) | 100% deterministic assertion pass; $\ge 90\%$ line & $\ge 85\%$ branch coverage |
| `TC-2.1.2` | `AC-2` | `unit-2` | Unit + Doc-Test | Validate `PaymentMethodInput` untagged enum (`IntegrationId(u64)` | `MethodName(String)`), `CreateIntentionParams` & `UpdateIntentionParams` builders supporting `amount`, `currency`, `payment_methods`, `items`, `billing_data`, `customer`, `extras`, `special_reference`, `expiration`, `notification_url`, `redirection_url`, `pre_selected_plan`, and `card_tokens` in `src/resources/intentions/params.rs` (positive, boundary, and malformed inputs) | 100% deterministic assertion pass; $\ge 90\%$ line & $\ge 85\%$ branch coverage |
| `TC-2.1.3` | `AC-3` | `unit-3` | Unit + Doc-Test | Validate `IntentionResponse` (`id: String` `pi_*`, `intention_order_id: u64`, `client_secret: SecretString` `egy_csk_*`, `payment_keys: Vec<IntentionPaymentKey>`, `intention_detail`, `payment_methods: Vec<ConfiguredPaymentMethod>`, `special_reference`, `extras`, `confirmed`, `status`, `created`, `card_detail`, `card_tokens`, `object`) in `src/resources/intentions/response.rs` (positive, boundary, and malformed inputs) | 100% deterministic assertion pass; $\ge 90\%$ line & $\ge 85\%$ branch coverage |
| `TC-2.1.4` | `AC-3` | `unit-4` | Integration / Wire | Validate `IntentionsService` (`paymob.intentions().create(params)` `POST /v1/intention/` and `paymob.intentions().update(params)` `PUT /v1/intention/`) using Regime 1 `Authorization: Token <secret_key>` with pre-flight Test/Live parity validation in `src/resources/intentions/service.rs` (positive, boundary, and malformed inputs) | 100% deterministic assertion pass; $\ge 90\%$ line & $\ge 85\%$ branch coverage |
| `TC-2.1.5` | `AC-4` | `unit-1..4` | Security / Property | Verify `[REDACTED]` `Debug` output, zero `f32`/`f64` floats, and `CC <= 6` across all units | 0 secret leaks in logs/panics; 0 Clippy warnings; all doctests pass |

---

## 2. Technical Implementation Plan

### 2.1 Domain Invariants & Storage Schema
- **Domain Invariants**:
  - **3 Mandatory Builder Invariants**: (1) Test/Live mode parity between `SecretKey` and `payment_methods`; (2) every `IntentionItem` in `items` has non-empty `name` and `amount`; (3) `billing_data.phone_number` is mandatory whenever `billing_data` is provided.
  - **Untagged PaymentMethodInput Serialization**: `PaymentMethodInput::IntegrationId(u64)` serializes as a JSON integer (`4097558`) while `PaymentMethodInput::MethodName(String)` serializes as a JSON string (`"card"`).
  - **Secret Client Token Protection**: `IntentionResponse::client_secret` (`egy_csk_*`) is stored in `SecretString` so single-use checkout secrets never leak in logs.
- **Rust Type Definitions & Wire Protocol Schema**:

```rust
#![forbid(unsafe_code)]
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PaymentMethodInput {
    IntegrationId(u64),
    MethodName(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateIntentionParams {
    pub amount: u64,
    pub currency: String,
    pub payment_methods: Vec<PaymentMethodInput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub items: Option<Vec<IntentionItem>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub billing_data: Option<BillingData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub special_reference: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notification_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirection_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pre_selected_plan: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IntentionResponse {
    pub id: String,
    pub intention_order_id: u64,
    pub client_secret: SecretString,
    pub payment_keys: Vec<IntentionPaymentKey>,
    pub confirmed: bool,
    pub status: String,
}
```

### 2.2 Sequence Diagram

```mermaid
sequenceDiagram
    autonumber
    actor Caller as Rust Application Caller
    participant U1 as unit-1 (src/resources/intentions/billing.rs)
    participant U2 as unit-2 (src/resources/intentions/params.rs)
    participant UK as unit-4 (src/resources/intentions/service.rs)
    participant Paymob as Paymob Gateway / Verifier

    Caller->>U1: Construct validated params / domain types
    U1->>U1: Enforce builder invariants, bounds & redaction rules
    Caller->>UK: Invoke service / engine entrypoint
    UK->>U2: Resolve auth regime / canonical payload encoding
    U2-->>UK: Return verified auth header/token or canonical digest input
    UK->>Paymob: Execute TLS 1.3 HTTP call or constant-time HMAC-SHA512 check
    Paymob-->>UK: Return wire payload / verification status
    UK-->>Caller: Return strongly-typed Result<T, PaymobError>
```

---

## 3. Expected Folder Architecture at the Project

All `4` Implementation Units in `US-2.1.0` own **100% disjoint files** so they execute concurrently in isolated `.worktrees/` with zero merge conflicts:

```text
some-paymob/
├── Cargo.toml                                  # Seeded on Module/Story base branch
├── src/
│   ├── lib.rs                                  # Seeded on Module base branch
│   ├── src/resources/intentions/billing.rs     # Owned exclusively by unit-1 (feat/us-2.1.0/unit-1-billing-and-items)
│   ├── src/resources/intentions/params.rs      # Owned exclusively by unit-2 (feat/us-2.1.0/unit-2-intention-params)
│   ├── src/resources/intentions/response.rs    # Owned exclusively by unit-3 (feat/us-2.1.0/unit-3-intention-response)
│   ├── src/resources/intentions/service.rs     # Owned exclusively by unit-4 (feat/us-2.1.0/unit-4-intentions-service)
└── tests/
    └── intention_create_update_integration.rs         # Executed by story-leader after unit-1..4 merge
```

---

## 4. Implementation Units in Detail & Specialist Agent Assignment

### 4.1 Story Decomposition Score ($S_{\text{story}}$) & Dynamic Unit Count ($K$)
- **$D_1$ (35% Functional Surface)**: `3` — 4 distinct domain components: `BillingData` + `IntentionItem` validated models, `CreateIntentionParams` + `UpdateIntentionParams` builders, `IntentionResponse` deserializer, and `IntentionsService`
- **$D_2$ (25% Artifact Volume)**: `2` — ~620 production LOC across `src/resources/intentions/`
- **$D_3$ (20% Logic Complexity)**: `3` — Builder-time validation of Test/Live integration parity, mandatory `phone_number` when `billing_data` is present, mandatory `name` + `amount` on every `IntentionItem`, untagged `PaymentMethodInput` integer/string serialization, and `/v1/intention/` trailing-slash enforcement
- **$D_4$ (20% Orthogonal Boundaries)**: `2` — 4 independent files under `src/resources/intentions/` (`billing.rs`, `params.rs`, `response.rs`, `service.rs`)
- **Calculated Score**: $S_{\text{story}} = 0.35(3) + 0.25(2) + 0.20(3) + 0.20(2) = \mathbf{2.55}$ $\to$ **`4` Parallel Units**

### 4.2 Detailed Unit Specifications (`unit-1..4`)

- **`unit-1` (`feat/us-2.1.0/unit-1-billing-and-items`)**:
  - **Deliverable Scope**: `BillingData` & `BillingDataBuilder` (enforcing non-empty `phone_number` at `.build()` time and redacting PII in `Debug`), `IntentionCustomer`, and `IntentionItem` (enforcing non-empty `name` and `amount` in minor units)
  - **Owned Files**: `src/resources/intentions/billing.rs`
  - **Public Contract / Exports**: Public types, builders, and methods defined in `src/resources/intentions/billing.rs` re-exported via parent `mod.rs`
  - **Unit Verification & Target Complexity**: Colocated `#[cfg(test)] mod tests` + runnable rustdoc examples (`TC-2.1.1`), Max Cyclomatic Complexity $CC \le 6$ (cap $\le 10$, nesting $\le 2$)
- **`unit-2` (`feat/us-2.1.0/unit-2-intention-params`)**:
  - **Deliverable Scope**: `PaymentMethodInput` untagged enum (`IntegrationId(u64)` | `MethodName(String)`), `CreateIntentionParams` & `UpdateIntentionParams` builders supporting `amount`, `currency`, `payment_methods`, `items`, `billing_data`, `customer`, `extras`, `special_reference`, `expiration`, `notification_url`, `redirection_url`, `pre_selected_plan`, and `card_tokens`
  - **Owned Files**: `src/resources/intentions/params.rs`
  - **Public Contract / Exports**: Public types, builders, and methods defined in `src/resources/intentions/params.rs` re-exported via parent `mod.rs`
  - **Unit Verification & Target Complexity**: Colocated `#[cfg(test)] mod tests` + runnable rustdoc examples (`TC-2.1.2`), Max Cyclomatic Complexity $CC \le 6$ (cap $\le 10$, nesting $\le 2$)
- **`unit-3` (`feat/us-2.1.0/unit-3-intention-response`)**:
  - **Deliverable Scope**: `IntentionResponse` (`id: String` `pi_*`, `intention_order_id: u64`, `client_secret: SecretString` `egy_csk_*`, `payment_keys: Vec<IntentionPaymentKey>`, `intention_detail`, `payment_methods: Vec<ConfiguredPaymentMethod>`, `special_reference`, `extras`, `confirmed`, `status`, `created`, `card_detail`, `card_tokens`, `object`)
  - **Owned Files**: `src/resources/intentions/response.rs`
  - **Public Contract / Exports**: Public types, builders, and methods defined in `src/resources/intentions/response.rs` re-exported via parent `mod.rs`
  - **Unit Verification & Target Complexity**: Colocated `#[cfg(test)] mod tests` + runnable rustdoc examples (`TC-2.1.3`), Max Cyclomatic Complexity $CC \le 6$ (cap $\le 10$, nesting $\le 2$)
- **`unit-4` (`feat/us-2.1.0/unit-4-intentions-service`)**:
  - **Deliverable Scope**: `IntentionsService` (`paymob.intentions().create(params)` `POST /v1/intention/` and `paymob.intentions().update(params)` `PUT /v1/intention/`) using Regime 1 `Authorization: Token <secret_key>` with pre-flight Test/Live parity validation
  - **Owned Files**: `src/resources/intentions/service.rs`
  - **Public Contract / Exports**: Public types, builders, and methods defined in `src/resources/intentions/service.rs` re-exported via parent `mod.rs`
  - **Unit Verification & Target Complexity**: Colocated `#[cfg(test)] mod tests` + runnable rustdoc examples (`TC-2.1.4`), Max Cyclomatic Complexity $CC \le 6$ (cap $\le 10$, nesting $\le 2$)

### 4.3 Best-Fit Specialist Agents per Unit (`msitarzewski/agency-catalog` + Core Roster)

| Unit ID | Branch Name | Primary Implementer Agent(s) (`agency-catalog`) | Reviewing Council Agent(s) | Mandatory Skills Enforced |
| :--- | :--- | :--- | :--- | :--- |
| `unit-1` | `feat/us-2.1.0/unit-1-billing-and-items` | `backend-architect` | `code-reviewer`, `security-engineer`, `api-tester` | `code-review-council`, `security-audit`, `cyclomatic-complexity` |
| `unit-2` | `feat/us-2.1.0/unit-2-intention-params` | `backend-architect` | `code-reviewer`, `security-engineer`, `api-tester` | `code-review-council`, `security-audit`, `cyclomatic-complexity` |
| `unit-3` | `feat/us-2.1.0/unit-3-intention-response` | `backend-architect` | `code-reviewer`, `security-engineer`, `api-tester` | `code-review-council`, `security-audit`, `cyclomatic-complexity` |
| `unit-4` | `feat/us-2.1.0/unit-4-intentions-service` | `api-tester` | `code-reviewer`, `security-engineer`, `api-tester` | `code-review-council`, `security-audit`, `cyclomatic-complexity` |
| **Story Remediation** | `patch/us-2.1.0-intention-create-update` | `patch-implementer` + `backend-architect` | `code-reviewer-council-president` | Full 6-Gate Re-Verification |

### 4.4 Parallel Execution & Zero-Blocking Contract Seeding Plan
1. **Base Contract Seeding**: Commit `src/resources/intentions/mod.rs` and shared `IntentionItem`/`BillingData` type stubs on `feat/us-2.1.0-intention-create-update` before branching `unit-1..4`.
2. **Simultaneous Worktree Spawning**: All `4` units are provisioned in `.worktrees/feat-us-2.1.0-unit-1..4` and spawned simultaneously in Wave 2.
3. **Ordered Cascading Merge Sequence**: `unit-1` $\to$ `unit-2` $\to$ `unit-3` $\to$ `unit-4` into `feat/us-2.1.0-intention-create-update` via `gh pr merge <PR> --merge`.

---

## 5. Security Gateway (Powered by `security-audit` Skill)

### 5.1 Trust Boundaries & Security Actors
- **Security Actors**: Merchant backend services (`PaymobClient` callers), customer browsers/mobile apps (redirected via Unified Checkout / Pixel / Legacy Iframe), Paymob Acquiring & Payouts servers, and untrusted external webhook senders.
- **Trust Boundaries**:
  1. **Caller Input Boundary**: Untrusted builder inputs (phone numbers, amounts, frequencies, proof attachments, integration IDs) crossing into SDK request serializers.
  2. **Network Ingress / Deserialization Boundary**: Raw JSON/HTTP responses and incoming webhook payloads crossing into typed Rust domain models.
  3. **Credential & Telemetry Boundary**: Secret keys (`sk_*`), API keys, JWT/OAuth2 bearer tokens, saved card tokens, and HMAC secrets crossing into memory caches, HTTP headers, or diagnostic logs.

### 5.2 Threat Modeling & Abuse Matrix (STRIDE / OWASP ASVS)

| Threat ID | STRIDE Category | ASVS / CWE Ref | Attack Vector / Abuse Scenario | Impact | Required Mitigation & Code/Deliverable Control |
| :--- | :---: | :---: | :--- | :---: | :--- |
| `TM-1` | **S**poofing | ASVS V2 / CWE-287 | Wrong auth scheme (`Bearer` vs `Token`), expired 60-min JWT reuse, or forged webhook signature | Critical | Explicit `AuthStrategy` per endpoint, single-flight JWT/OAuth2 refresh, and constant-time `Hmac<Sha512>` + `subtle::ConstantTimeEq` verification |
| `TM-2` | **T**ampering | ASVS V5 / CWE-20 | Floating-point rounding manipulation, 100x currency unit errors, or tampered webhook query/body fields | Critical | `MinorUnitAmount(u64)` integer minor units (zero `f32`/`f64`), builder-time field validation, and fail-closed 20-key/8-key/body-HMAC verification |
| `TM-3` | **R**epudiation | ASVS V7 / CWE-778 | Duplicate transaction fulfillment on retried webhooks or unlogged state mutations | High | `IdempotentWebhookGuard` extracting `(obj.id, order.id)` and `(paymob_request_id, subscription_data.id)` + correlation logging |
| `TM-4` | **I**nformation Disclosure | ASVS V8 / CWE-200 | Secret key (`sk_*`), `client_secret`, JWT `auth_token`, or PAN/CVV leaked in `Debug` logs or panic traces | Critical | `secrecy::SecretString` + `ZeroizeOnDrop` on all credentials/tokens and custom `[REDACTED]` `Debug` implementations |
| `TM-5` | **D**enial of Service | ASVS V11 / CWE-400 | Thundering-herd token refresh storms on 1-hour JWT expiry or oversized (>2.8 MB) topup proof payloads | High | Lock-free `ArcSwapOption` + single-flight `tokio::sync::Mutex<()>` refresh guard, bounded timeouts, and `MAX_TOPUP_PROOF_BYTES` check |
| `TM-6` | **E**levation of Privilege | ASVS V4 / CWE-285 | Cross-merchant IDOR in Partner Onboarding (`with_merchant`) or mixing Test and Live integration IDs | Critical | Immutable `MerchantScopedClient` per `merchant_id` and strict `EnvironmentMode` (`Test` vs `Live`) parity enforcement |

### 5.3 Cryptography & Global Data Protection Controls (Worldwide Legal & Regulatory Compliance)
1. **Cryptographic Standards**:
   - **In Transit**: TLS 1.3 (`reqwest` with `rustls-tls`) enforced for all Accept Acquiring and Payouts connections.
   - **Signatures & Constant-Time MACs**: `HMAC-SHA512` (`hmac` + `sha2`) verified exclusively via branchless constant-time comparison (`subtle::ConstantTimeEq::ct_eq`); zero `SHA-1`/`MD5` or early-exit byte comparisons.
   - **Memory Hygiene**: All secret keys, API keys, JWTs, OAuth2 refresh tokens, card tokens, and HMAC secrets use `secrecy::SecretString` and `zeroize::ZeroizeOnDrop`.
2. **Global Multi-Jurisdictional Privacy & Financial Compliance**:
   - **PCI-DSS v4.0**: Raw PANs and CVVs are never stored or logged; card tokenization uses `masked_pan` (`xxxx-xxxx-xxxx-2346`) for display and `SecretString` for tokens; frontend checkout helpers accept only `PublicKey` (`pk_*`).
   - **MENA & Regional Central Bank Regulations (CBE Egypt, SAMA Saudi Arabia, CBUAE UAE, CBO Oman, SBP Pakistan)**: Regional host isolation via `PaymobRegion` ensures transaction and disbursement payloads remain routed to the designated sovereign regional gateway.
   - **GDPR / UK GDPR / CCPA / Egypt PDPL (Law No. 151 of 2020) / KSA PDPL**: Strict PII minimization and automatic `[REDACTED]` scrubbing of customer emails, phone numbers (`msisdn`), and bank account numbers in diagnostic traces.

### 5.4 Automated Security Verification Checklist (`security-audit` Skill)
- [ ] Applicable security playbooks reviewed (`WEB-PROTOCOL-AND-AUTH.md`, `MEMORY-SAFETY-AND-BINARY.md`, `SUPPLY-CHAIN-AND-RELEASE.md`).
- [ ] `#![forbid(unsafe_code)]` enforced at the crate root; all untrusted inputs validated for bounds, non-empty prefixes, and encoding prior to network dispatch.
- [ ] Zero secrets, API keys, JWTs, card tokens, or raw PII emitted in `Debug` formatting, logs, or error messages.
- [ ] Zero `f32`/`f64` floating-point types used for monetary amounts or fee calculations.

### 5.5 Security Gateway (Gate G2) Sign-Off Checklist
- [ ] **0 Critical / High / Medium** vulnerabilities in `security-audit` scan.
- [ ] All STRIDE / ASVS threat mitigations (`TM-1..TM-6`) implemented and covered by security/negative tests in Section 1.3 (`TC-2.1.1..5`).
- [ ] Regional host partitioning, PCI-DSS token redaction, and `ZeroizeOnDrop` controls verified.
- [ ] Independent Security Reviewer agent sign-off posted to the GitHub PR conversation.

---

## 6. Validation Gates & Acceptance Sign-Off

Every Unit PR (`feat/us-2.1.0-intention-create-update/unit-1..4`) and the parent Story PR (`feat/us-2.1.0-intention-create-update`) MUST pass all 6 Quality Gates and post the evidence directly to the GitHub PR conversation before `gh pr merge`:

| Gate | Gate Name | Pass Criteria for `US-2.1.0` | Verification Command / Evidence | Status |
| :--- | :--- | :--- | :--- | :---: |
| **Gate G0** | **Build, Lint & Format** | 0 errors, 0 warnings, 100% `rustfmt` & `clippy` compliance | `CARGO_BUILD_JOBS=1 cargo fmt --check && CARGO_BUILD_JOBS=1 cargo clippy --all-targets --all-features -- -D warnings` | `[ ]` |
| **Gate G1** | **Tests, Coverage & Traceability** | 100% of `AC-1..4` and `TC-2.1.1..5` passing ($\ge 90\%$ line, $\ge 85\%$ branch coverage) | `CARGO_BUILD_JOBS=1 cargo test --all-features` | `[ ]` |
| **Gate G2** | **Security Gateway (`security-audit`)** | All Section 5 STRIDE, constant-time crypto, and `[REDACTED]` checks pass (0 findings) | `security-audit` report on PR | `[ ]` |
| **Gate G-Complexity** | **Cyclomatic Complexity** | Every function $CC \le 6$ target ($CC \le 10$ ceiling, $CC > 15$ blocker, nesting $\le 2$) | `cyclomatic-complexity` table on PR | `[ ]` |
| **Gate G-Docs** | **Documentation & Examples** | 100% public symbols documented + runnable doc-tests + this spec synced | `CARGO_BUILD_JOBS=1 cargo test --doc --all-features` | `[ ]` |
| **Gate G-Review** | **Council President Sign-Off** | Independent Reviewing Council posts `GATE G-REVIEW APPROVED` on GitHub PR | `gh pr comment <PR>` | `[ ]` |

### Final Acceptance Sign-Off Block
- **Story Leader Verification**: All `4` units (`unit-1..4`) merged via cascading `gh pr merge`, story integration suite green, and zero unaddressed findings (or remediated via dedicated `patch-implementer` PRs).
- **Reviewing Council Verdict**: `PENDING` $\to$ `GATE G-REVIEW APPROVED`

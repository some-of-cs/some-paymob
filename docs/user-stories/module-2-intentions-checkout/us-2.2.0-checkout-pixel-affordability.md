# User Story `US-2.2.0`: Unified Checkout URL, Embedded Pixel JS Config & Affordability Widget Builders

- **Module**: `module-2` ([Payment Intentions, Checkout Experiences & Legacy Accept v2 Flow](./README.md))
- **Story Branch**: `feat/us-2.2.0-checkout-pixel-affordability`
- **Field Profile**: `software` (`engineering,security,testing`)
- **Story Decomposition Score ($S_{\text{story}}$)**: `2.00` $\to$ **`3` Parallel Implementation Units (`unit-1..3`)**

---

## 1. Spec Kit Specifications

### 1.1 User Story Narrative
> **As a** Full Stack Product Engineer building web and mobile checkout flows,  
> **I want** type-safe builders for Paymob Unified Checkout redirect URLs (`paymob.checkout().unified_url(...)`), embedded Pixel JS configurations (`pixel_config`), and bank installment Affordability Widgets (`affordability_widget`),  
> **So that** frontend redirects and embedded Apple Pay / Google Pay / Card components receive properly encoded `pk_*` public keys and `client_secret` tokens without ever exposing server-side `sk_*` secret keys.

This User Story belongs to **Module 2 (Payment Intentions, Checkout Experiences & Legacy Accept v2 Flow)** of [`some-paymob`](https://github.com/some-of-cs/some-paymob) as specified in [`docs/Paymob Rust SDK Architecture Research.md`](../../Paymob%20Rust%20SDK%20Architecture%20Research.md). It is decomposed into `3` strictly disjoint, 100% parallel Implementation Units (`unit-1..3`) that compile and verify independently inside isolated Git worktrees without inter-unit blocking.

#### 1.1.1 Preconditions
- `PaymobClient` configured with a valid `PublicKey` (`pk_*` / `egy_pk_*`) and `PaymobRegion`.
- A `client_secret` (`egy_csk_*`) obtained from `US-2.1.0` (`POST /v1/intention/`) and [Affordability Widget](https://developers.paymob.com/paymob-docs/developers/checkout-experiences/affordability-widget) specifications.

#### 1.1.2 Postconditions
- `paymob.checkout().unified_url(&client_secret)` returns a fully qualified, URL-encoded Unified Checkout redirect URL for the active `PaymobRegion`.
- `paymob.checkout().pixel_config(...)` and `affordability_widget(...)` produce serializable frontend configuration structs using only `PublicKey` (`pk_*`).

### 1.2 Acceptance Criteria (Gherkin Scenarios)

```gherkin
Feature: US-2.2.0 — Unified Checkout URL, Embedded Pixel JS Config & Affordability Widget Builders

  Scenario: AC-1 — Regional Unified Checkout Redirect URL Construction
    Given a `PaymobClient` in `PaymobRegion::Egypt` with public key `"egy_pk_test_ABC"` and `client_secret` `"egy_csk_test_XYZ"`
    When `paymob.checkout().unified_url(&intention.client_secret)` is called
    Then it returns `Ok("https://accept.paymob.com/unifiedcheckout/?publicKey=egy_pk_test_ABC&clientSecret=egy_csk_test_XYZ")`

  Scenario: AC-2 — Embedded Pixel JS & Affordability Widget Configuration
    Given a merchant configuring embedded Cards, Apple Pay, and Google Pay or bank installment plans
    When `pixel_config` and `affordability_widget` builders are invoked
    Then strongly-typed configuration structs are generated and the selected installment plan ID wires cleanly into `CreateIntentionParams::pre_selected_plan`

  Scenario: AC-3 — Missing or Invalid PublicKey Rejection
    Given a `PaymobClient` initialized without a `public_key`
    When `paymob.checkout().unified_url(...)` is called
    Then it fails closed with `Err(PaymobError::ValidationError)` rather than emitting a broken checkout URL

  Scenario: AC-4 — Secret Redaction, Zero Float & Cyclomatic Complexity Compliance
    Given all public types and functions implemented across unit-1..3 of US-2.2.0
    When formatted via Debug/Display and analyzed by Gate G2 and Gate G-Complexity
    Then zero raw secrets, API keys, tokens, or PANs appear in Debug output (all emit "[REDACTED]")
    And every monetary value uses integer minor units (u64) with Cyclomatic Complexity CC <= 6 and nesting depth <= 2
```

### 1.3 Test Cases & Traceability Matrix

| Test Case ID | Mapped AC | Owning Unit | Test Level (Unit / Integration / Property / Security) | Description & Input Vector | Expected Result & Pass Threshold |
| :--- | :---: | :---: | :---: | :--- | :--- |
| `TC-2.2.1` | `AC-1` | `unit-1` | Unit + Doc-Test | Validate `CheckoutService::unified_url(&client_secret)` building `{checkout_host}/?publicKey={pk}&clientSecret={client_secret}` with URL-safe percent-encoding and compile/runtime `PublicKey` (`pk_*`) verification in `src/resources/checkout/unified.rs` (positive, boundary, and malformed inputs) | 100% deterministic assertion pass; $\ge 90\%$ line & $\ge 85\%$ branch coverage |
| `TC-2.2.2` | `AC-2` | `unit-2` | Unit + Doc-Test | Validate `PixelConfig` & `PixelConfigBuilder` (`paymob.checkout().pixel_config(...)`) generating typed JSON configuration for Paymob's embedded Pixel JS SDK (Cards, Apple Pay, Google Pay, domain verification, and Apple Pay certificate settings) in `src/resources/checkout/pixel.rs` (positive, boundary, and malformed inputs) | 100% deterministic assertion pass; $\ge 90\%$ line & $\ge 85\%$ branch coverage |
| `TC-2.2.3` | `AC-3` | `unit-3` | Unit + Doc-Test | Validate `AffordabilityWidgetConfig` (`paymob.checkout().affordability_widget(...)`) for bank installment plans and helper methods wiring selected installment plan IDs into `CreateIntentionParams::pre_selected_plan` in `src/resources/checkout/affordability.rs` (positive, boundary, and malformed inputs) | 100% deterministic assertion pass; $\ge 90\%$ line & $\ge 85\%$ branch coverage |
| `TC-2.2.4` | `AC-4` | `unit-1..3` | Security / Property | Verify `[REDACTED]` `Debug` output, zero `f32`/`f64` floats, and `CC <= 6` across all units | 0 secret leaks in logs/panics; 0 Clippy warnings; all doctests pass |

---

## 2. Technical Implementation Plan

### 2.1 Domain Invariants & Storage Schema
- **Domain Invariants**:
  - **PublicKey-Only Frontend Surface**: Checkout URLs, Pixel configs, and Affordability Widget configs NEVER read or expose `SecretKey` (`sk_*`) or `ApiKey`.
  - **Strict URL Query Percent-Encoding**: Both `publicKey` and `clientSecret` parameters are percent-encoded to prevent parameter injection.
- **Rust Type Definitions & Wire Protocol Schema**:

```rust
#![forbid(unsafe_code)]
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PixelConfig {
    pub public_key: String,
    pub client_secret: String,
    pub payment_methods: Vec<String>,
    pub show_save_card: bool,
    pub apple_pay_merchant_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AffordabilityWidgetConfig {
    pub public_key: String,
    pub amount_cents: u64,
    pub currency: String,
    pub pre_selected_plan: Option<u64>,
}
```

### 2.2 Sequence Diagram

```mermaid
sequenceDiagram
    autonumber
    actor Caller as Rust Application Caller
    participant U1 as unit-1 (src/resources/checkout/unified.rs)
    participant U2 as unit-2 (src/resources/checkout/pixel.rs)
    participant UK as unit-3 (src/resources/checkout/affordability.rs)
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

All `3` Implementation Units in `US-2.2.0` own **100% disjoint files** so they execute concurrently in isolated `.worktrees/` with zero merge conflicts:

```text
some-paymob/
├── Cargo.toml                                  # Seeded on Module/Story base branch
├── src/
│   ├── lib.rs                                  # Seeded on Module base branch
│   ├── src/resources/checkout/unified.rs       # Owned exclusively by unit-1 (feat/us-2.2.0/unit-1-unified-checkout-url)
│   ├── src/resources/checkout/pixel.rs         # Owned exclusively by unit-2 (feat/us-2.2.0/unit-2-pixel-config)
│   ├── src/resources/checkout/affordability.rs # Owned exclusively by unit-3 (feat/us-2.2.0/unit-3-affordability-widget)
└── tests/
    └── checkout_pixel_affordability_integration.rs         # Executed by story-leader after unit-1..3 merge
```

---

## 4. Implementation Units in Detail & Specialist Agent Assignment

### 4.1 Story Decomposition Score ($S_{\text{story}}$) & Dynamic Unit Count ($K$)
- **$D_1$ (35% Functional Surface)**: `2` — 3 client-facing checkout builders: `unified_url`, `pixel_config`, and `affordability_widget`
- **$D_2$ (25% Artifact Volume)**: `2` — ~380 production LOC across `src/resources/checkout/`
- **$D_3$ (20% Logic Complexity)**: `2` — Strict `PublicKey` (`pk_*`) enforcement preventing `SecretKey` exposure in frontend URLs/configs, URL query encoding, and installment plan wiring into `CreateIntentionParams::pre_selected_plan`
- **$D_4$ (20% Orthogonal Boundaries)**: `2` — 3 independent files under `src/resources/checkout/` (`unified.rs`, `pixel.rs`, `affordability.rs`)
- **Calculated Score**: $S_{\text{story}} = 0.35(2) + 0.25(2) + 0.20(2) + 0.20(2) = \mathbf{2.00}$ $\to$ **`3` Parallel Units**

### 4.2 Detailed Unit Specifications (`unit-1..3`)

- **`unit-1` (`feat/us-2.2.0/unit-1-unified-checkout-url`)**:
  - **Deliverable Scope**: `CheckoutService::unified_url(&client_secret)` building `{checkout_host}/?publicKey={pk}&clientSecret={client_secret}` with URL-safe percent-encoding and compile/runtime `PublicKey` (`pk_*`) verification
  - **Owned Files**: `src/resources/checkout/unified.rs`
  - **Public Contract / Exports**: Public types, builders, and methods defined in `src/resources/checkout/unified.rs` re-exported via parent `mod.rs`
  - **Unit Verification & Target Complexity**: Colocated `#[cfg(test)] mod tests` + runnable rustdoc examples (`TC-2.2.1`), Max Cyclomatic Complexity $CC \le 6$ (cap $\le 10$, nesting $\le 2$)
- **`unit-2` (`feat/us-2.2.0/unit-2-pixel-config`)**:
  - **Deliverable Scope**: `PixelConfig` & `PixelConfigBuilder` (`paymob.checkout().pixel_config(...)`) generating typed JSON configuration for Paymob's embedded Pixel JS SDK (Cards, Apple Pay, Google Pay, domain verification, and Apple Pay certificate settings)
  - **Owned Files**: `src/resources/checkout/pixel.rs`
  - **Public Contract / Exports**: Public types, builders, and methods defined in `src/resources/checkout/pixel.rs` re-exported via parent `mod.rs`
  - **Unit Verification & Target Complexity**: Colocated `#[cfg(test)] mod tests` + runnable rustdoc examples (`TC-2.2.2`), Max Cyclomatic Complexity $CC \le 6$ (cap $\le 10$, nesting $\le 2$)
- **`unit-3` (`feat/us-2.2.0/unit-3-affordability-widget`)**:
  - **Deliverable Scope**: `AffordabilityWidgetConfig` (`paymob.checkout().affordability_widget(...)`) for bank installment plans and helper methods wiring selected installment plan IDs into `CreateIntentionParams::pre_selected_plan`
  - **Owned Files**: `src/resources/checkout/affordability.rs`
  - **Public Contract / Exports**: Public types, builders, and methods defined in `src/resources/checkout/affordability.rs` re-exported via parent `mod.rs`
  - **Unit Verification & Target Complexity**: Colocated `#[cfg(test)] mod tests` + runnable rustdoc examples (`TC-2.2.3`), Max Cyclomatic Complexity $CC \le 6$ (cap $\le 10$, nesting $\le 2$)

### 4.3 Best-Fit Specialist Agents per Unit (`msitarzewski/agency-catalog` + Core Roster)

| Unit ID | Branch Name | Primary Implementer Agent(s) (`agency-catalog`) | Reviewing Council Agent(s) | Mandatory Skills Enforced |
| :--- | :--- | :--- | :--- | :--- |
| `unit-1` | `feat/us-2.2.0/unit-1-unified-checkout-url` | `backend-architect` | `code-reviewer`, `security-engineer`, `api-tester` | `code-review-council`, `security-audit`, `cyclomatic-complexity` |
| `unit-2` | `feat/us-2.2.0/unit-2-pixel-config` | `backend-architect` | `code-reviewer`, `security-engineer`, `api-tester` | `code-review-council`, `security-audit`, `cyclomatic-complexity` |
| `unit-3` | `feat/us-2.2.0/unit-3-affordability-widget` | `backend-architect` | `code-reviewer`, `security-engineer`, `api-tester` | `code-review-council`, `security-audit`, `cyclomatic-complexity` |
| **Story Remediation** | `patch/us-2.2.0-checkout-pixel-affordability` | `patch-implementer` + `backend-architect` | `code-reviewer-council-president` | Full 6-Gate Re-Verification |

### 4.4 Parallel Execution & Zero-Blocking Contract Seeding Plan
1. **Base Contract Seeding**: Commit `src/resources/checkout/mod.rs` and `CheckoutService` facade stub on `feat/us-2.2.0-checkout-pixel-affordability` before branching `unit-1..3`.
2. **Simultaneous Worktree Spawning**: All `3` units are provisioned in `.worktrees/feat-us-2.2.0-unit-1..3` and spawned simultaneously in Wave 2.
3. **Ordered Cascading Merge Sequence**: `unit-1` $\to$ `unit-2` $\to$ `unit-3` into `feat/us-2.2.0-checkout-pixel-affordability` via `gh pr merge <PR> --merge`.

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
- [ ] All STRIDE / ASVS threat mitigations (`TM-1..TM-6`) implemented and covered by security/negative tests in Section 1.3 (`TC-2.2.1..4`).
- [ ] Regional host partitioning, PCI-DSS token redaction, and `ZeroizeOnDrop` controls verified.
- [ ] Independent Security Reviewer agent sign-off posted to the GitHub PR conversation.

---

## 6. Validation Gates & Acceptance Sign-Off

Every Unit PR (`feat/us-2.2.0-checkout-pixel-affordability/unit-1..3`) and the parent Story PR (`feat/us-2.2.0-checkout-pixel-affordability`) MUST pass all 6 Quality Gates and post the evidence directly to the GitHub PR conversation before `gh pr merge`:

| Gate | Gate Name | Pass Criteria for `US-2.2.0` | Verification Command / Evidence | Status |
| :--- | :--- | :--- | :--- | :---: |
| **Gate G0** | **Build, Lint & Format** | 0 errors, 0 warnings, 100% `rustfmt` & `clippy` compliance | `CARGO_BUILD_JOBS=1 cargo fmt --check && CARGO_BUILD_JOBS=1 cargo clippy --all-targets --all-features -- -D warnings` | `[ ]` |
| **Gate G1** | **Tests, Coverage & Traceability** | 100% of `AC-1..4` and `TC-2.2.1..4` passing ($\ge 90\%$ line, $\ge 85\%$ branch coverage) | `CARGO_BUILD_JOBS=1 cargo test --all-features` | `[ ]` |
| **Gate G2** | **Security Gateway (`security-audit`)** | All Section 5 STRIDE, constant-time crypto, and `[REDACTED]` checks pass (0 findings) | `security-audit` report on PR | `[ ]` |
| **Gate G-Complexity** | **Cyclomatic Complexity** | Every function $CC \le 6$ target ($CC \le 10$ ceiling, $CC > 15$ blocker, nesting $\le 2$) | `cyclomatic-complexity` table on PR | `[ ]` |
| **Gate G-Docs** | **Documentation & Examples** | 100% public symbols documented + runnable doc-tests + this spec synced | `CARGO_BUILD_JOBS=1 cargo test --doc --all-features` | `[ ]` |
| **Gate G-Review** | **Council President Sign-Off** | Independent Reviewing Council posts `GATE G-REVIEW APPROVED` on GitHub PR | `gh pr comment <PR>` | `[ ]` |

### Final Acceptance Sign-Off Block
- **Story Leader Verification**: All `3` units (`unit-1..3`) merged via cascading `gh pr merge`, story integration suite green, and zero unaddressed findings (or remediated via dedicated `patch-implementer` PRs).
- **Reviewing Council Verdict**: `PENDING` $\to$ `GATE G-REVIEW APPROVED`

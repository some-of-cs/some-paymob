# User Story `US-6.2.0`: Sub-Merchant Registration, Onboarding Flow Schema, Step Submission, Inquiry & with_merchant Scoping

- **Module**: `module-6` ([Partner Merchant Onboarding APIs & Multi-Tenant Client Scoping](./README.md))
- **Story Branch**: `feat/us-6.2.0-merchant-onboarding-flow`
- **Field Profile**: `software` (`engineering,security,testing`)
- **Story Decomposition Score ($S_{\text{story}}$)**: `2.35` $\to$ **`4` Parallel Implementation Units (`unit-1..4`)**

---

## 1. Spec Kit Specifications

### 1.1 User Story Narrative
> **As a** Multi-Tenant SaaS Engineer building white-label merchant onboarding and payment routing,  
> **I want** complete `paymob.onboarding().flow()` methods (`register_merchant`, `get_schema`, `submit_step`, `merchant_inquiry`) and a `paymob.with_merchant(merchant_id)` scoped client view,  
> **So that** our SaaS backend can onboard sub-merchants through Paymob's KYC schema steps and immediately execute intentions and inquiries on behalf of any onboarded `merchant_id` with strict tenant isolation.

This User Story belongs to **Module 6 (Partner Merchant Onboarding APIs & Multi-Tenant Client Scoping)** of [`some-paymob`](https://github.com/some-of-cs/some-paymob) as specified in [`docs/Paymob Rust SDK Architecture Research.md`](../../Paymob%20Rust%20SDK%20Architecture%20Research.md). It is decomposed into `4` strictly disjoint, 100% parallel Implementation Units (`unit-1..4`) that compile and verify independently inside isolated Git worktrees without inter-unit blocking.

#### 1.1.1 Preconditions
- Feature flag `onboarding` enabled and `US-6.1.0` Partner API Key authentication available.
- Modules 2 and 3 merged so `MerchantScopedClient` can delegate `.intentions()`, `.inquiries()`, and `.manage()`.

#### 1.1.2 Postconditions
- `paymob.onboarding().flow()` provides `register_merchant`, `get_schema` (`GET /api/onboarding/flow/schema?partner=...&resubmission=...&paymob_mid=...`), `submit_step`, and `merchant_inquiry`.
- `paymob.with_merchant(merchant_id)` returns a thread-safe `MerchantScopedClient` binding the Partner API Key + `merchant_id`.

### 1.2 Acceptance Criteria (Gherkin Scenarios)

```gherkin
Feature: US-6.2.0 — Sub-Merchant Registration, Onboarding Flow Schema, Step Submission, Inquiry & with_merchant Scoping

  Scenario: AC-1 — Dynamic Onboarding Flow Schema Discovery (GET /api/onboarding/flow/schema)
    Given `OnboardingSchemaQuery { partner: "KeyPartner".into(), resubmission: Some(true), paymob_mid: Some(123) }`
    When `paymob.onboarding().flow().get_schema(&query).await` is executed
    Then `GET /api/onboarding/flow/schema?partner=KeyPartner&resubmission=true&paymob_mid=123` is dispatched with the Partner API Key

  Scenario: AC-2 — Sub-Merchant Registration, KYC Step Submission & Status Inquiry
    Given partner onboarding parameters for a new sub-merchant
    When `register_merchant`, `submit_step`, and `merchant_inquiry(mid)` are called
    Then each step authenticates under Regime 4 `PartnerApiKey` and returns the merchant onboarding state

  Scenario: AC-3 — Multi-Tenant Sub-Merchant Scoped Client (with_merchant)
    Given an onboarded sub-merchant `merchant_id: 987654`
    When `let scoped = paymob.with_merchant(987654); scoped.intentions().create(params).await` is executed
    Then the request is authenticated with the Partner API Key + `merchant_id: 987654` without mutating the parent `PaymobClient`'s default tenant state

  Scenario: AC-4 — Secret Redaction, Zero Float & Cyclomatic Complexity Compliance
    Given all public types and functions implemented across unit-1..4 of US-6.2.0
    When formatted via Debug/Display and analyzed by Gate G2 and Gate G-Complexity
    Then zero raw secrets, API keys, tokens, or PANs appear in Debug output (all emit "[REDACTED]")
    And every monetary value uses integer minor units (u64) with Cyclomatic Complexity CC <= 6 and nesting depth <= 2
```

### 1.3 Test Cases & Traceability Matrix

| Test Case ID | Mapped AC | Owning Unit | Test Level (Unit / Integration / Property / Security) | Description & Input Vector | Expected Result & Pass Threshold |
| :--- | :---: | :---: | :---: | :--- | :--- |
| `TC-6.2.1` | `AC-1` | `unit-1` | Unit + Doc-Test | Validate `RegisterMerchantParams`, `RegisteredMerchantResponse`, `OnboardingSchemaQuery` (`partner: String`, `resubmission: Option<bool>`, `paymob_mid: Option<u64>`), `OnboardingFlowSchema`, `SubmitOnboardingStepParams`, and `PartnerMerchantInquiryResponse` in `src/resources/onboarding/flow_models.rs` (positive, boundary, and malformed inputs) | 100% deterministic assertion pass; $\ge 90\%$ line & $\ge 85\%$ branch coverage |
| `TC-6.2.2` | `AC-2` | `unit-2` | Unit + Doc-Test | Validate `PartnerFlowService::register_merchant(params)` and `PartnerFlowService::get_schema(query)` (`GET /api/onboarding/flow/schema?partner=...&resubmission=...&paymob_mid=...`) under Regime 4 `PartnerApiKey` in `src/resources/onboarding/schema_register.rs` (positive, boundary, and malformed inputs) | 100% deterministic assertion pass; $\ge 90\%$ line & $\ge 85\%$ branch coverage |
| `TC-6.2.3` | `AC-3` | `unit-3` | Unit + Doc-Test | Validate `PartnerFlowService::submit_step(params)` and `PartnerFlowService::merchant_inquiry(mid)` checking merchant approval status and live integration IDs in `src/resources/onboarding/step_inquiry.rs` (positive, boundary, and malformed inputs) | 100% deterministic assertion pass; $\ge 90\%$ line & $\ge 85\%$ branch coverage |
| `TC-6.2.4` | `AC-3` | `unit-4` | Integration / Wire | Validate `paymob.with_merchant(merchant_id)` returning `MerchantScopedClient` that binds the Partner API Key and target `merchant_id` across scoped `.intentions()`, `.inquiries()`, and `.manage()` operations in `src/resources/onboarding/scoped_client.rs` (positive, boundary, and malformed inputs) | 100% deterministic assertion pass; $\ge 90\%$ line & $\ge 85\%$ branch coverage |
| `TC-6.2.5` | `AC-4` | `unit-1..4` | Security / Property | Verify `[REDACTED]` `Debug` output, zero `f32`/`f64` floats, and `CC <= 6` across all units | 0 secret leaks in logs/panics; 0 Clippy warnings; all doctests pass |

---

## 2. Technical Implementation Plan

### 2.1 Domain Invariants & Storage Schema
- **Domain Invariants**:
  - **Strict Multi-Tenant Isolation**: `MerchantScopedClient` is an immutable view bound to a single non-zero `merchant_id`; concurrent calls across different sub-merchants never share mutable tenant state (`ASVS V4`).
- **Rust Type Definitions & Wire Protocol Schema**:

```rust
#![forbid(unsafe_code)]
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
pub struct OnboardingSchemaQuery {
    pub partner: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resubmission: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paymob_mid: Option<u64>,
}

#[derive(Clone)]
pub struct MerchantScopedClient {
    inner: crate::PaymobClient,
    merchant_id: u64,
}
```

### 2.2 Sequence Diagram

```mermaid
sequenceDiagram
    autonumber
    actor Caller as Rust Application Caller
    participant U1 as unit-1 (src/resources/onboarding/flow_models.rs)
    participant U2 as unit-2 (src/resources/onboarding/schema_register.rs)
    participant UK as unit-4 (src/resources/onboarding/scoped_client.rs)
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

All `4` Implementation Units in `US-6.2.0` own **100% disjoint files** so they execute concurrently in isolated `.worktrees/` with zero merge conflicts:

```text
some-paymob/
├── Cargo.toml                                  # Seeded on Module/Story base branch
├── src/
│   ├── lib.rs                                  # Seeded on Module base branch
│   ├── src/resources/onboarding/flow_models.rs # Owned exclusively by unit-1 (feat/us-6.2.0/unit-1-onboarding-flow-models)
│   ├── src/resources/onboarding/schema_register.rs # Owned exclusively by unit-2 (feat/us-6.2.0/unit-2-register-and-schema)
│   ├── src/resources/onboarding/step_inquiry.rs # Owned exclusively by unit-3 (feat/us-6.2.0/unit-3-submit-step-and-inquiry)
│   ├── src/resources/onboarding/scoped_client.rs # Owned exclusively by unit-4 (feat/us-6.2.0/unit-4-scoped-merchant-client)
└── tests/
    └── merchant_onboarding_flow_integration.rs         # Executed by story-leader after unit-1..4 merge
```

---

## 4. Implementation Units in Detail & Specialist Agent Assignment

### 4.1 Story Decomposition Score ($S_{\text{story}}$) & Dynamic Unit Count ($K$)
- **$D_1$ (35% Functional Surface)**: `3` — 4 onboarding flow operations (`register_merchant`, `get_schema`, `submit_step`, `merchant_inquiry`) + `paymob.with_merchant(merchant_id)` multi-tenant client wrapper
- **$D_2$ (25% Artifact Volume)**: `2` — ~480 production LOC across 4 files under `src/resources/onboarding/`
- **$D_3$ (20% Logic Complexity)**: `2` — Query parameter construction `?partner=KeyPartner&resubmission=true&paymob_mid=123`, KYC step payload validation, and `MerchantScopedClient` delegation binding Partner API Key + `merchant_id`
- **$D_4$ (20% Orthogonal Boundaries)**: `2` — 4 independent files under `src/resources/onboarding/` (`flow_models.rs`, `schema_register.rs`, `step_inquiry.rs`, `scoped_client.rs`)
- **Calculated Score**: $S_{\text{story}} = 0.35(3) + 0.25(2) + 0.20(2) + 0.20(2) = \mathbf{2.35}$ $\to$ **`4` Parallel Units**

### 4.2 Detailed Unit Specifications (`unit-1..4`)

- **`unit-1` (`feat/us-6.2.0/unit-1-onboarding-flow-models`)**:
  - **Deliverable Scope**: `RegisterMerchantParams`, `RegisteredMerchantResponse`, `OnboardingSchemaQuery` (`partner: String`, `resubmission: Option<bool>`, `paymob_mid: Option<u64>`), `OnboardingFlowSchema`, `SubmitOnboardingStepParams`, and `PartnerMerchantInquiryResponse`
  - **Owned Files**: `src/resources/onboarding/flow_models.rs`
  - **Public Contract / Exports**: Public types, builders, and methods defined in `src/resources/onboarding/flow_models.rs` re-exported via parent `mod.rs`
  - **Unit Verification & Target Complexity**: Colocated `#[cfg(test)] mod tests` + runnable rustdoc examples (`TC-6.2.1`), Max Cyclomatic Complexity $CC \le 6$ (cap $\le 10$, nesting $\le 2$)
- **`unit-2` (`feat/us-6.2.0/unit-2-register-and-schema`)**:
  - **Deliverable Scope**: `PartnerFlowService::register_merchant(params)` and `PartnerFlowService::get_schema(query)` (`GET /api/onboarding/flow/schema?partner=...&resubmission=...&paymob_mid=...`) under Regime 4 `PartnerApiKey`
  - **Owned Files**: `src/resources/onboarding/schema_register.rs`
  - **Public Contract / Exports**: Public types, builders, and methods defined in `src/resources/onboarding/schema_register.rs` re-exported via parent `mod.rs`
  - **Unit Verification & Target Complexity**: Colocated `#[cfg(test)] mod tests` + runnable rustdoc examples (`TC-6.2.2`), Max Cyclomatic Complexity $CC \le 6$ (cap $\le 10$, nesting $\le 2$)
- **`unit-3` (`feat/us-6.2.0/unit-3-submit-step-and-inquiry`)**:
  - **Deliverable Scope**: `PartnerFlowService::submit_step(params)` and `PartnerFlowService::merchant_inquiry(mid)` checking merchant approval status and live integration IDs
  - **Owned Files**: `src/resources/onboarding/step_inquiry.rs`
  - **Public Contract / Exports**: Public types, builders, and methods defined in `src/resources/onboarding/step_inquiry.rs` re-exported via parent `mod.rs`
  - **Unit Verification & Target Complexity**: Colocated `#[cfg(test)] mod tests` + runnable rustdoc examples (`TC-6.2.3`), Max Cyclomatic Complexity $CC \le 6$ (cap $\le 10$, nesting $\le 2$)
- **`unit-4` (`feat/us-6.2.0/unit-4-scoped-merchant-client`)**:
  - **Deliverable Scope**: `paymob.with_merchant(merchant_id)` returning `MerchantScopedClient` that binds the Partner API Key and target `merchant_id` across scoped `.intentions()`, `.inquiries()`, and `.manage()` operations
  - **Owned Files**: `src/resources/onboarding/scoped_client.rs`
  - **Public Contract / Exports**: Public types, builders, and methods defined in `src/resources/onboarding/scoped_client.rs` re-exported via parent `mod.rs`
  - **Unit Verification & Target Complexity**: Colocated `#[cfg(test)] mod tests` + runnable rustdoc examples (`TC-6.2.4`), Max Cyclomatic Complexity $CC \le 6$ (cap $\le 10$, nesting $\le 2$)

### 4.3 Best-Fit Specialist Agents per Unit (`msitarzewski/agency-catalog` + Core Roster)

| Unit ID | Branch Name | Primary Implementer Agent(s) (`agency-catalog`) | Reviewing Council Agent(s) | Mandatory Skills Enforced |
| :--- | :--- | :--- | :--- | :--- |
| `unit-1` | `feat/us-6.2.0/unit-1-onboarding-flow-models` | `backend-architect` | `code-reviewer`, `security-engineer`, `api-tester` | `code-review-council`, `security-audit`, `cyclomatic-complexity` |
| `unit-2` | `feat/us-6.2.0/unit-2-register-and-schema` | `backend-architect` | `code-reviewer`, `security-engineer`, `api-tester` | `code-review-council`, `security-audit`, `cyclomatic-complexity` |
| `unit-3` | `feat/us-6.2.0/unit-3-submit-step-and-inquiry` | `backend-architect` | `code-reviewer`, `security-engineer`, `api-tester` | `code-review-council`, `security-audit`, `cyclomatic-complexity` |
| `unit-4` | `feat/us-6.2.0/unit-4-scoped-merchant-client` | `api-tester` | `code-reviewer`, `security-engineer`, `api-tester` | `code-review-council`, `security-audit`, `cyclomatic-complexity` |
| **Story Remediation** | `patch/us-6.2.0-merchant-onboarding-flow` | `patch-implementer` + `backend-architect` | `code-reviewer-council-president` | Full 6-Gate Re-Verification |

### 4.4 Parallel Execution & Zero-Blocking Contract Seeding Plan
1. **Base Contract Seeding**: Commit `PartnerFlowService` and `MerchantScopedClient` struct declarations in `src/resources/onboarding/mod.rs` on `feat/us-6.2.0-merchant-onboarding-flow` before branching `unit-1..4`.
2. **Simultaneous Worktree Spawning**: All `4` units are provisioned in `.worktrees/feat-us-6.2.0-unit-1..4` and spawned simultaneously in Wave 2.
3. **Ordered Cascading Merge Sequence**: `unit-1` $\to$ `unit-2` $\to$ `unit-3` $\to$ `unit-4` into `feat/us-6.2.0-merchant-onboarding-flow` via `gh pr merge <PR> --merge`.

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
- [ ] All STRIDE / ASVS threat mitigations (`TM-1..TM-6`) implemented and covered by security/negative tests in Section 1.3 (`TC-6.2.1..5`).
- [ ] Regional host partitioning, PCI-DSS token redaction, and `ZeroizeOnDrop` controls verified.
- [ ] Independent Security Reviewer agent sign-off posted to the GitHub PR conversation.

---

## 6. Validation Gates & Acceptance Sign-Off

Every Unit PR (`feat/us-6.2.0-merchant-onboarding-flow/unit-1..4`) and the parent Story PR (`feat/us-6.2.0-merchant-onboarding-flow`) MUST pass all 6 Quality Gates and post the evidence directly to the GitHub PR conversation before `gh pr merge`:

| Gate | Gate Name | Pass Criteria for `US-6.2.0` | Verification Command / Evidence | Status |
| :--- | :--- | :--- | :--- | :---: |
| **Gate G0** | **Build, Lint & Format** | 0 errors, 0 warnings, 100% `rustfmt` & `clippy` compliance | `CARGO_BUILD_JOBS=1 cargo fmt --check && CARGO_BUILD_JOBS=1 cargo clippy --all-targets --all-features -- -D warnings` | `[ ]` |
| **Gate G1** | **Tests, Coverage & Traceability** | 100% of `AC-1..4` and `TC-6.2.1..5` passing ($\ge 90\%$ line, $\ge 85\%$ branch coverage) | `CARGO_BUILD_JOBS=1 cargo test --all-features` | `[ ]` |
| **Gate G2** | **Security Gateway (`security-audit`)** | All Section 5 STRIDE, constant-time crypto, and `[REDACTED]` checks pass (0 findings) | `security-audit` report on PR | `[ ]` |
| **Gate G-Complexity** | **Cyclomatic Complexity** | Every function $CC \le 6$ target ($CC \le 10$ ceiling, $CC > 15$ blocker, nesting $\le 2$) | `cyclomatic-complexity` table on PR | `[ ]` |
| **Gate G-Docs** | **Documentation & Examples** | 100% public symbols documented + runnable doc-tests + this spec synced | `CARGO_BUILD_JOBS=1 cargo test --doc --all-features` | `[ ]` |
| **Gate G-Review** | **Council President Sign-Off** | Independent Reviewing Council posts `GATE G-REVIEW APPROVED` on GitHub PR | `gh pr comment <PR>` | `[ ]` |

### Final Acceptance Sign-Off Block
- **Story Leader Verification**: All `4` units (`unit-1..4`) merged via cascading `gh pr merge`, story integration suite green, and zero unaddressed findings (or remediated via dedicated `patch-implementer` PRs).
- **Reviewing Council Verdict**: `PENDING` $\to$ `GATE G-REVIEW APPROVED`

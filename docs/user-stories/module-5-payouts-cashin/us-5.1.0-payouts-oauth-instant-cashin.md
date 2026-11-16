# User Story `US-5.1.0`: Payouts OAuth 2.0 Token Facade & Instant Cashin Disbursements (7 Issuers + Aman Cancel)

- **Module**: `module-5` ([Paymob Send — Payouts OAuth2, Instant/Bulk Cashin, Inquiries & Topups](./README.md))
- **Story Branch**: `feat/us-5.1.0-payouts-oauth-instant-cashin`
- **Field Profile**: `software` (`engineering,security,testing`)
- **Story Decomposition Score ($S_{\text{story}}$)**: `2.55` $\to$ **`4` Parallel Implementation Units (`unit-1..4`)**

---

## 1. Spec Kit Specifications

### 1.1 User Story Narrative
> **As a** Marketplace Treasury & Payouts Engineer disbursing funds to drivers, sellers, and freelancers across Egypt, KSA, and UAE,  
> **I want** an ergonomic `paymob.payouts()` service covering OAuth2 token lifecycle (`auth()`) and instant disbursements (`cashin()`) across Vodafone Cash, Etisalat Cash, Orange Cash, Bank Wallets, Bank Cards, Instant Bank Transfers, Egypt Post, and Aman cancellation,  
> **So that** Instant Cashin payouts execute reliably against Paymob's Payouts host topology with automatic 60-minute OAuth2 refresh and zero PAN/MSISDN leakage in logs.

This User Story belongs to **Module 5 (Paymob Send — Payouts OAuth2, Instant/Bulk Cashin, Inquiries & Topups)** of [`some-paymob`](https://github.com/some-of-cs/some-paymob) as specified in [`docs/Paymob Rust SDK Architecture Research.md`](../../Paymob%20Rust%20SDK%20Architecture%20Research.md). It is decomposed into `4` strictly disjoint, 100% parallel Implementation Units (`unit-1..4`) that compile and verify independently inside isolated Git worktrees without inter-unit blocking.

#### 1.1.1 Preconditions
- Feature flag `payouts` enabled and `PaymobRegion` Payouts host resolved (`https://payouts.paymobsolutions.com/`, `https://payouts.paymob.sa/`, or `https://payouts-uae.paymobsolutions.com/`).
- Paymob Payouts specifications ([Vodafone Cashin](https://developers.paymob.com/paymob-docs/developers/payouts-apis/cashin-api/vodafone-cashin), [Refresh Token](https://developers.paymob.com/paymob-docs/developers/payouts-apis/auth/refresh-token), and [Paymob Disbursement API](https://apis.apievangelist.com/store/paymob-disbursement-api/)) loaded.

#### 1.1.2 Postconditions
- `paymob.payouts().auth().generate_token()` and `.refresh_token()` manage OAuth 2.0 tokens against `POST /api/secure/o/token/`.
- `paymob.payouts().cashin()` executes instant disbursements (`vodafone`, `etisalat`, `orange`, `bank_wallet`, `bank_card`, `bank_instant`, `egyptian_post`) on `POST /api/secure/disburse/` and cancels Aman transactions via `POST /api/secure/transaction/aman/cancel/`.

### 1.2 Acceptance Criteria (Gherkin Scenarios)

```gherkin
Feature: US-5.1.0 — Payouts OAuth 2.0 Token Facade & Instant Cashin Disbursements (7 Issuers + Aman Cancel)

  Scenario: AC-1 — Payouts OAuth2 Password & Refresh Token Grants (POST /api/secure/o/token/)
    Given configured Payouts `client_id`, `client_secret`, `username`, and `password`
    When `paymob.payouts().auth().generate_token().await` and `.refresh_token(&token.refresh_token).await` are called
    Then `POST /api/secure/o/token/` sends HTTP Basic Auth + form-urlencoded payload and returns `PayoutsTokenResponse` (mapping `{"error": "invalid_grant"}` to `PaymobError::AuthenticationError`)

  Scenario: AC-2 — Instant Mobile Wallet Cashin (Vodafone, Etisalat, Orange, Bank Wallet)
    Given a Vodafone Cashin request with `msisdn: "01023456789"`, `amount: 112`, and `client_reference_id`
    When `paymob.payouts().cashin().vodafone(params).await` is executed
    Then `POST /api/secure/disburse/` is called with `issuer: "vodafone"` and returns `DisbursementResponse` (`transaction_id`, `disbursement_status`, `status_code`)

  Scenario: AC-3 — Bank Card, Instant Bank, Egypt Post Cashin & Aman Cancellation
    Given a `BankCardCashinParams` with `bank_transaction_type: BankTransactionType::Salary` or an Aman cancellation request
    When `bank_card(params)` or `cancel_aman(params)` is invoked
    Then `POST /api/secure/disburse/` or `POST /api/secure/transaction/aman/cancel/` executes with redacted `bank_card_number` in `Debug` logs

  Scenario: AC-4 — Secret Redaction, Zero Float & Cyclomatic Complexity Compliance
    Given all public types and functions implemented across unit-1..4 of US-5.1.0
    When formatted via Debug/Display and analyzed by Gate G2 and Gate G-Complexity
    Then zero raw secrets, API keys, tokens, or PANs appear in Debug output (all emit "[REDACTED]")
    And every monetary value uses integer minor units (u64) with Cyclomatic Complexity CC <= 6 and nesting depth <= 2
```

### 1.3 Test Cases & Traceability Matrix

| Test Case ID | Mapped AC | Owning Unit | Test Level (Unit / Integration / Property / Security) | Description & Input Vector | Expected Result & Pass Threshold |
| :--- | :---: | :---: | :---: | :--- | :--- |
| `TC-5.1.1` | `AC-1` | `unit-1` | Security / Negative | Validate `PayoutsAuthService` (`payouts().auth().generate_token()`, `.refresh_token()`) wrapping `POST /api/secure/o/token/` (Basic Auth `{client_id}:{client_secret}` + form grants), returning `PayoutsTokenResponse` (`access_token: SecretString`, `refresh_token: SecretString`, `expires_in: 3600`, `scope`, `token_type`), and mapping `{"error": "invalid_grant"}` to `PaymobError::AuthenticationError` in `src/resources/payouts/auth.rs` (positive, boundary, and malformed inputs) | 100% deterministic assertion pass; $\ge 90\%$ line & $\ge 85\%$ branch coverage |
| `TC-5.1.2` | `AC-2` | `unit-2` | Unit + Doc-Test | Validate `DisburseIssuer` enum (`Vodafone`, `Etisalat`, `Orange`, `BankWallet`, `BankCard`, `InstantBank`, `EgyptianPost` via static lookup slice `CC <= 3`), `BankTransactionType` (`Salary`, `CreditCard`, `PrepaidCard`, `CashTransfer`), `DisbursementResponse` (`transaction_id`, `msisdn`, `issuer`, `amount`, `full_name`, `disbursement_status`, `status_code`, `status_description`, `aman_cashing_details`, `created_at`, `updated_at`), and `AmanCashingDetails` in `src/resources/payouts/models.rs` (positive, boundary, and malformed inputs) | 100% deterministic assertion pass; $\ge 90\%$ line & $\ge 85\%$ branch coverage |
| `TC-5.1.3` | `AC-3` | `unit-3` | Unit + Doc-Test | Validate `PayoutsCashinService` mobile & bank wallet methods (`vodafone(params)`, `etisalat(params)`, `orange(params)`, `bank_wallet(params)`) dispatching `POST /api/secure/disburse/` with validated `msisdn`, `amount`, `client_reference_id`, and `customer_bears_fees` in `src/resources/payouts/wallet_cashin.rs` (positive, boundary, and malformed inputs) | 100% deterministic assertion pass; $\ge 90\%$ line & $\ge 85\%$ branch coverage |
| `TC-5.1.4` | `AC-3` | `unit-4` | Integration / Wire | Validate `PayoutsCashinService` bank & cash methods (`bank_card(params)` with redacted `bank_card_number`, `bank_code`, `bank_transaction_type`; `bank_instant(params)`; `egyptian_post(params)`; and `cancel_aman(params)` on `POST /api/secure/transaction/aman/cancel/`) in `src/resources/payouts/bank_cashin.rs` (positive, boundary, and malformed inputs) | 100% deterministic assertion pass; $\ge 90\%$ line & $\ge 85\%$ branch coverage |
| `TC-5.1.5` | `AC-4` | `unit-1..4` | Security / Property | Verify `[REDACTED]` `Debug` output, zero `f32`/`f64` floats, and `CC <= 6` across all units | 0 secret leaks in logs/panics; 0 Clippy warnings; all doctests pass |

---

## 2. Technical Implementation Plan

### 2.1 Domain Invariants & Storage Schema
- **Domain Invariants**:
  - **Static Lookup Table for Issuers & Bank Transaction Types**: `DisburseIssuer` (7 variants) and `BankTransactionType` (4 variants) map to wire strings via static lookup slices (`CC <= 3`).
  - **PII & Card Number Redaction**: `bank_card_number` and `msisdn` are masked/redacted in `Debug` formatting.
- **Rust Type Definitions & Wire Protocol Schema**:

```rust
#![forbid(unsafe_code)]
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisburseIssuer {
    Vodafone,
    Etisalat,
    Orange,
    BankWallet,
    BankCard,
    InstantBank,
    EgyptianPost,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BankTransactionType {
    Salary,
    CreditCard,
    PrepaidCard,
    CashTransfer,
}
```

### 2.2 Sequence Diagram

```mermaid
sequenceDiagram
    autonumber
    actor Caller as Rust Application Caller
    participant U1 as unit-1 (src/resources/payouts/auth.rs)
    participant U2 as unit-2 (src/resources/payouts/models.rs)
    participant UK as unit-4 (src/resources/payouts/bank_cashin.rs)
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

All `4` Implementation Units in `US-5.1.0` own **100% disjoint files** so they execute concurrently in isolated `.worktrees/` with zero merge conflicts:

```text
some-paymob/
├── Cargo.toml                                  # Seeded on Module/Story base branch
├── src/
│   ├── lib.rs                                  # Seeded on Module base branch
│   ├── src/resources/payouts/auth.rs           # Owned exclusively by unit-1 (feat/us-5.1.0/unit-1-payouts-auth-facade)
│   ├── src/resources/payouts/models.rs         # Owned exclusively by unit-2 (feat/us-5.1.0/unit-2-disburse-models)
│   ├── src/resources/payouts/wallet_cashin.rs  # Owned exclusively by unit-3 (feat/us-5.1.0/unit-3-mobile-wallet-cashin)
│   ├── src/resources/payouts/bank_cashin.rs    # Owned exclusively by unit-4 (feat/us-5.1.0/unit-4-bank-post-aman-cashin)
└── tests/
    └── payouts_oauth_instant_cashin_integration.rs         # Executed by story-leader after unit-1..4 merge
```

---

## 4. Implementation Units in Detail & Specialist Agent Assignment

### 4.1 Story Decomposition Score ($S_{\text{story}}$) & Dynamic Unit Count ($K$)
- **$D_1$ (35% Functional Surface)**: `3` — 4 functional slices covering 10 operations: OAuth2 `generate_token` & `refresh_token`, Disbursement models/enums, Mobile/Bank Wallet Cashin (`vodafone`, `etisalat`, `orange`, `bank_wallet`), and Bank/Post/Aman Cashin (`bank_card`, `bank_instant`, `egyptian_post`, `cancel_aman`)
- **$D_2$ (25% Artifact Volume)**: `2` — ~620 production LOC across 4 files under `src/resources/payouts/`
- **$D_3$ (20% Logic Complexity)**: `3` — Regime 3 OAuth2 Basic Auth + form grant integration, MSISDN & bank account validation, `BankTransactionType` lookup table (`CC <= 3`), and strict trailing-slash enforcement on `/api/secure/disburse/`
- **$D_4$ (20% Orthogonal Boundaries)**: `2` — 4 independent files under `src/resources/payouts/` (`auth.rs`, `models.rs`, `wallet_cashin.rs`, `bank_cashin.rs`)
- **Calculated Score**: $S_{\text{story}} = 0.35(3) + 0.25(2) + 0.20(3) + 0.20(2) = \mathbf{2.55}$ $\to$ **`4` Parallel Units**

### 4.2 Detailed Unit Specifications (`unit-1..4`)

- **`unit-1` (`feat/us-5.1.0/unit-1-payouts-auth-facade`)**:
  - **Deliverable Scope**: `PayoutsAuthService` (`payouts().auth().generate_token()`, `.refresh_token()`) wrapping `POST /api/secure/o/token/` (Basic Auth `{client_id}:{client_secret}` + form grants), returning `PayoutsTokenResponse` (`access_token: SecretString`, `refresh_token: SecretString`, `expires_in: 3600`, `scope`, `token_type`), and mapping `{"error": "invalid_grant"}` to `PaymobError::AuthenticationError`
  - **Owned Files**: `src/resources/payouts/auth.rs`
  - **Public Contract / Exports**: Public types, builders, and methods defined in `src/resources/payouts/auth.rs` re-exported via parent `mod.rs`
  - **Unit Verification & Target Complexity**: Colocated `#[cfg(test)] mod tests` + runnable rustdoc examples (`TC-5.1.1`), Max Cyclomatic Complexity $CC \le 6$ (cap $\le 10$, nesting $\le 2$)
- **`unit-2` (`feat/us-5.1.0/unit-2-disburse-models`)**:
  - **Deliverable Scope**: `DisburseIssuer` enum (`Vodafone`, `Etisalat`, `Orange`, `BankWallet`, `BankCard`, `InstantBank`, `EgyptianPost` via static lookup slice `CC <= 3`), `BankTransactionType` (`Salary`, `CreditCard`, `PrepaidCard`, `CashTransfer`), `DisbursementResponse` (`transaction_id`, `msisdn`, `issuer`, `amount`, `full_name`, `disbursement_status`, `status_code`, `status_description`, `aman_cashing_details`, `created_at`, `updated_at`), and `AmanCashingDetails`
  - **Owned Files**: `src/resources/payouts/models.rs`
  - **Public Contract / Exports**: Public types, builders, and methods defined in `src/resources/payouts/models.rs` re-exported via parent `mod.rs`
  - **Unit Verification & Target Complexity**: Colocated `#[cfg(test)] mod tests` + runnable rustdoc examples (`TC-5.1.2`), Max Cyclomatic Complexity $CC \le 6$ (cap $\le 10$, nesting $\le 2$)
- **`unit-3` (`feat/us-5.1.0/unit-3-mobile-wallet-cashin`)**:
  - **Deliverable Scope**: `PayoutsCashinService` mobile & bank wallet methods (`vodafone(params)`, `etisalat(params)`, `orange(params)`, `bank_wallet(params)`) dispatching `POST /api/secure/disburse/` with validated `msisdn`, `amount`, `client_reference_id`, and `customer_bears_fees`
  - **Owned Files**: `src/resources/payouts/wallet_cashin.rs`
  - **Public Contract / Exports**: Public types, builders, and methods defined in `src/resources/payouts/wallet_cashin.rs` re-exported via parent `mod.rs`
  - **Unit Verification & Target Complexity**: Colocated `#[cfg(test)] mod tests` + runnable rustdoc examples (`TC-5.1.3`), Max Cyclomatic Complexity $CC \le 6$ (cap $\le 10$, nesting $\le 2$)
- **`unit-4` (`feat/us-5.1.0/unit-4-bank-post-aman-cashin`)**:
  - **Deliverable Scope**: `PayoutsCashinService` bank & cash methods (`bank_card(params)` with redacted `bank_card_number`, `bank_code`, `bank_transaction_type`; `bank_instant(params)`; `egyptian_post(params)`; and `cancel_aman(params)` on `POST /api/secure/transaction/aman/cancel/`)
  - **Owned Files**: `src/resources/payouts/bank_cashin.rs`
  - **Public Contract / Exports**: Public types, builders, and methods defined in `src/resources/payouts/bank_cashin.rs` re-exported via parent `mod.rs`
  - **Unit Verification & Target Complexity**: Colocated `#[cfg(test)] mod tests` + runnable rustdoc examples (`TC-5.1.4`), Max Cyclomatic Complexity $CC \le 6$ (cap $\le 10$, nesting $\le 2$)

### 4.3 Best-Fit Specialist Agents per Unit (`msitarzewski/agency-catalog` + Core Roster)

| Unit ID | Branch Name | Primary Implementer Agent(s) (`agency-catalog`) | Reviewing Council Agent(s) | Mandatory Skills Enforced |
| :--- | :--- | :--- | :--- | :--- |
| `unit-1` | `feat/us-5.1.0/unit-1-payouts-auth-facade` | `security-engineer` | `code-reviewer`, `security-engineer`, `api-tester` | `code-review-council`, `security-audit`, `cyclomatic-complexity` |
| `unit-2` | `feat/us-5.1.0/unit-2-disburse-models` | `backend-architect` | `code-reviewer`, `security-engineer`, `api-tester` | `code-review-council`, `security-audit`, `cyclomatic-complexity` |
| `unit-3` | `feat/us-5.1.0/unit-3-mobile-wallet-cashin` | `backend-architect` | `code-reviewer`, `security-engineer`, `api-tester` | `code-review-council`, `security-audit`, `cyclomatic-complexity` |
| `unit-4` | `feat/us-5.1.0/unit-4-bank-post-aman-cashin` | `api-tester` | `code-reviewer`, `security-engineer`, `api-tester` | `code-review-council`, `security-audit`, `cyclomatic-complexity` |
| **Story Remediation** | `patch/us-5.1.0-payouts-oauth-instant-cashin` | `patch-implementer` + `backend-architect` | `code-reviewer-council-president` | Full 6-Gate Re-Verification |

### 4.4 Parallel Execution & Zero-Blocking Contract Seeding Plan
1. **Base Contract Seeding**: Commit `src/resources/payouts/mod.rs` with `PayoutsService`, `PayoutsAuthService`, and `PayoutsCashinService` struct stubs on `feat/us-5.1.0-payouts-oauth-instant-cashin` before branching `unit-1..4`.
2. **Simultaneous Worktree Spawning**: All `4` units are provisioned in `.worktrees/feat-us-5.1.0-unit-1..4` and spawned simultaneously in Wave 2.
3. **Ordered Cascading Merge Sequence**: `unit-1` $\to$ `unit-2` $\to$ `unit-3` $\to$ `unit-4` into `feat/us-5.1.0-payouts-oauth-instant-cashin` via `gh pr merge <PR> --merge`.

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
- [ ] All STRIDE / ASVS threat mitigations (`TM-1..TM-6`) implemented and covered by security/negative tests in Section 1.3 (`TC-5.1.1..5`).
- [ ] Regional host partitioning, PCI-DSS token redaction, and `ZeroizeOnDrop` controls verified.
- [ ] Independent Security Reviewer agent sign-off posted to the GitHub PR conversation.

---

## 6. Validation Gates & Acceptance Sign-Off

Every Unit PR (`feat/us-5.1.0-payouts-oauth-instant-cashin/unit-1..4`) and the parent Story PR (`feat/us-5.1.0-payouts-oauth-instant-cashin`) MUST pass all 6 Quality Gates and post the evidence directly to the GitHub PR conversation before `gh pr merge`:

| Gate | Gate Name | Pass Criteria for `US-5.1.0` | Verification Command / Evidence | Status |
| :--- | :--- | :--- | :--- | :---: |
| **Gate G0** | **Build, Lint & Format** | 0 errors, 0 warnings, 100% `rustfmt` & `clippy` compliance | `CARGO_BUILD_JOBS=1 cargo fmt --check && CARGO_BUILD_JOBS=1 cargo clippy --all-targets --all-features -- -D warnings` | `[ ]` |
| **Gate G1** | **Tests, Coverage & Traceability** | 100% of `AC-1..4` and `TC-5.1.1..5` passing ($\ge 90\%$ line, $\ge 85\%$ branch coverage) | `CARGO_BUILD_JOBS=1 cargo test --all-features` | `[ ]` |
| **Gate G2** | **Security Gateway (`security-audit`)** | All Section 5 STRIDE, constant-time crypto, and `[REDACTED]` checks pass (0 findings) | `security-audit` report on PR | `[ ]` |
| **Gate G-Complexity** | **Cyclomatic Complexity** | Every function $CC \le 6$ target ($CC \le 10$ ceiling, $CC > 15$ blocker, nesting $\le 2$) | `cyclomatic-complexity` table on PR | `[ ]` |
| **Gate G-Docs** | **Documentation & Examples** | 100% public symbols documented + runnable doc-tests + this spec synced | `CARGO_BUILD_JOBS=1 cargo test --doc --all-features` | `[ ]` |
| **Gate G-Review** | **Council President Sign-Off** | Independent Reviewing Council posts `GATE G-REVIEW APPROVED` on GitHub PR | `gh pr comment <PR>` | `[ ]` |

### Final Acceptance Sign-Off Block
- **Story Leader Verification**: All `4` units (`unit-1..4`) merged via cascading `gh pr merge`, story integration suite green, and zero unaddressed findings (or remediated via dedicated `patch-implementer` PRs).
- **Reviewing Council Verdict**: `PENDING` $\to$ `GATE G-REVIEW APPROVED`

# User Story `US-6.1.0`: Partner Authentication, Partner API Key Provisioning & Partner HMAC Secret Retrieval

- **Module**: `module-6` ([Partner Merchant Onboarding APIs & Multi-Tenant Client Scoping](./README.md))
- **Story Branch**: `feat/us-6.1.0-partner-auth-hmac`
- **Field Profile**: `software` (`engineering,security,testing`)
- **Story Decomposition Score ($S_{\text{story}}$)**: `2.00` $\to$ **`3` Parallel Implementation Units (`unit-1..3`)**

---

## 1. Spec Kit Specifications

### 1.1 User Story Narrative
> **As a** SaaS Platform Architect onboarding sub-merchants onto Paymob,  
> **I want** a strongly-typed `paymob.onboarding().auth()` service covering Partner Login, Partner API Key creation, and `GET /api/auth/hmac_secret/get_hmac`,  
> **So that** platforms can provision partner credentials and retrieve sub-merchant HMAC secrets programmatically with automatic memory zeroization.

This User Story belongs to **Module 6 (Partner Merchant Onboarding APIs & Multi-Tenant Client Scoping)** of [`some-paymob`](https://github.com/some-of-cs/some-paymob) as specified in [`docs/Paymob Rust SDK Architecture Research.md`](../../Paymob%20Rust%20SDK%20Architecture%20Research.md). It is decomposed into `3` strictly disjoint, 100% parallel Implementation Units (`unit-1..3`) that compile and verify independently inside isolated Git worktrees without inter-unit blocking.

#### 1.1.1 Preconditions
- Feature flag `onboarding` (or `partner-onboarding` / `full`) enabled.
- Paymob Partner Onboarding Auth specifications ([Retrieve Partner HMAC Secret](https://developers.paymob.com/paymob-docs/developers/partner-onboarding-apis-1/auth/retrieve-partner-hmac-secret)) loaded.

#### 1.1.2 Postconditions
- `paymob.onboarding().auth().login(creds)` exchanges partner credentials for a `PartnerAuthTokenResponse` (`SecretString`).
- `paymob.onboarding().auth().create_api_key(params)` provisions a `PartnerApiKeyResponse` (`SecretString`).
- `paymob.onboarding().auth().retrieve_hmac_secret()` calls `GET /api/auth/hmac_secret/get_hmac` and returns `PartnerHmacEnvelope` (`code: 201`, `body.hmac_secret: SecretString`).

### 1.2 Acceptance Criteria (Gherkin Scenarios)

```gherkin
Feature: US-6.1.0 — Partner Authentication, Partner API Key Provisioning & Partner HMAC Secret Retrieval

  Scenario: AC-1 — Retrieve Partner HMAC Secret (GET /api/auth/hmac_secret/get_hmac)
    Given a valid Partner Bearer `auth_token`
    When `paymob.onboarding().auth().retrieve_hmac_secret().await` is executed
    Then `GET /api/auth/hmac_secret/get_hmac` returns HTTP 201 `{ "label": null, "status": "Created", "code": 201, "body": { "hmac_secret": "..." } }` with `hmac_secret` wrapped in `SecretString`

  Scenario: AC-2 — Partner Login & Partner API Key Provisioning
    Given valid `PartnerLoginCredentials`
    When `login(creds)` and `create_api_key(params)` are executed
    Then both the Partner Bearer token and Partner API Key are cached in `ZeroizeOnDrop` containers

  Scenario: AC-3 — Zero Secret Leakage in Debug & Error Traces
    Given a `PartnerHmacEnvelope` and `PartnerLoginCredentials`
    When formatted with `{:?}`
    Then passwords, tokens, and `hmac_secret` values output `"[REDACTED]"`

  Scenario: AC-4 — Secret Redaction, Zero Float & Cyclomatic Complexity Compliance
    Given all public types and functions implemented across unit-1..3 of US-6.1.0
    When formatted via Debug/Display and analyzed by Gate G2 and Gate G-Complexity
    Then zero raw secrets, API keys, tokens, or PANs appear in Debug output (all emit "[REDACTED]")
    And every monetary value uses integer minor units (u64) with Cyclomatic Complexity CC <= 6 and nesting depth <= 2
```

### 1.3 Test Cases & Traceability Matrix

| Test Case ID | Mapped AC | Owning Unit | Test Level (Unit / Integration / Property / Security) | Description & Input Vector | Expected Result & Pass Threshold |
| :--- | :---: | :---: | :---: | :--- | :--- |
| `TC-6.1.1` | `AC-1` | `unit-1` | Security / Negative | Validate `PartnerLoginCredentials` (redacted `password`), `PartnerAuthTokenResponse` (`token: SecretString`), `CreatePartnerApiKeyParams`, `PartnerApiKeyResponse` (`api_key: SecretString`), and `PartnerHmacEnvelope` (`label`, `status: "Created"`, `code: 201`, `body: PartnerHmacBody { hmac_secret: SecretString }`) in `src/resources/onboarding/auth_models.rs` (positive, boundary, and malformed inputs) | 100% deterministic assertion pass; $\ge 90\%$ line & $\ge 85\%$ branch coverage |
| `TC-6.1.2` | `AC-2` | `unit-2` | Unit + Doc-Test | Validate `PartnerAuthService::login(creds)` and `PartnerAuthService::create_api_key(params)` under Regime 4 Partner Authentication in `src/resources/onboarding/login_apikey.rs` (positive, boundary, and malformed inputs) | 100% deterministic assertion pass; $\ge 90\%$ line & $\ge 85\%$ branch coverage |
| `TC-6.1.3` | `AC-3` | `unit-3` | Integration / Wire | Validate `PartnerAuthService::retrieve_hmac_secret()` (`GET /api/auth/hmac_secret/get_hmac` with `Authorization: Bearer <partner_auth_token>`) returning `PartnerHmacEnvelope` in `src/resources/onboarding/hmac_secret.rs` (positive, boundary, and malformed inputs) | 100% deterministic assertion pass; $\ge 90\%$ line & $\ge 85\%$ branch coverage |
| `TC-6.1.4` | `AC-4` | `unit-1..3` | Security / Property | Verify `[REDACTED]` `Debug` output, zero `f32`/`f64` floats, and `CC <= 6` across all units | 0 secret leaks in logs/panics; 0 Clippy warnings; all doctests pass |

---

## 2. Technical Implementation Plan

### 2.1 Domain Invariants & Storage Schema
- **Domain Invariants**:
  - **ZeroizeOnDrop Partner Secrets**: Partner passwords, Partner Bearer tokens, Partner API Keys, and retrieved sub-merchant HMAC secrets are wrapped in `SecretString` with `ZeroizeOnDrop`.
- **Rust Type Definitions & Wire Protocol Schema**:

```rust
#![forbid(unsafe_code)]
use secrecy::SecretString;
use serde::Deserialize;

#[derive(Clone, Deserialize)]
pub struct PartnerHmacBody {
    pub hmac_secret: SecretString,
}

#[derive(Clone, Deserialize)]
pub struct PartnerHmacEnvelope {
    pub label: Option<String>,
    pub status: String,
    pub code: u16,
    pub body: PartnerHmacBody,
}
```

### 2.2 Sequence Diagram

```mermaid
sequenceDiagram
    autonumber
    actor Caller as Rust Application Caller
    participant U1 as unit-1 (src/resources/onboarding/auth_models.rs)
    participant U2 as unit-2 (src/resources/onboarding/login_apikey.rs)
    participant UK as unit-3 (src/resources/onboarding/hmac_secret.rs)
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

All `3` Implementation Units in `US-6.1.0` own **100% disjoint files** so they execute concurrently in isolated `.worktrees/` with zero merge conflicts:

```text
some-paymob/
├── Cargo.toml                                  # Seeded on Module/Story base branch
├── src/
│   ├── lib.rs                                  # Seeded on Module base branch
│   ├── src/resources/onboarding/auth_models.rs # Owned exclusively by unit-1 (feat/us-6.1.0/unit-1-partner-auth-models)
│   ├── src/resources/onboarding/login_apikey.rs # Owned exclusively by unit-2 (feat/us-6.1.0/unit-2-partner-login-apikey)
│   ├── src/resources/onboarding/hmac_secret.rs # Owned exclusively by unit-3 (feat/us-6.1.0/unit-3-retrieve-partner-hmac)
└── tests/
    └── partner_auth_hmac_integration.rs         # Executed by story-leader after unit-1..3 merge
```

---

## 4. Implementation Units in Detail & Specialist Agent Assignment

### 4.1 Story Decomposition Score ($S_{\text{story}}$) & Dynamic Unit Count ($K$)
- **$D_1$ (35% Functional Surface)**: `2` — 3 Partner Auth operations: `login(creds)`, `create_api_key(...)`, and `retrieve_hmac_secret()` (`GET /api/auth/hmac_secret/get_hmac`)
- **$D_2$ (25% Artifact Volume)**: `2` — ~360 production LOC across 3 files under `src/resources/onboarding/`
- **$D_3$ (20% Logic Complexity)**: `2` — Regime 4 Partner Bearer token exchange, wrapping `hmac_secret` and `api_key` in `secrecy::SecretString` with `ZeroizeOnDrop`
- **$D_4$ (20% Orthogonal Boundaries)**: `2` — 3 independent files under `src/resources/onboarding/` (`auth_models.rs`, `login_apikey.rs`, `hmac_secret.rs`)
- **Calculated Score**: $S_{\text{story}} = 0.35(2) + 0.25(2) + 0.20(2) + 0.20(2) = \mathbf{2.00}$ $\to$ **`3` Parallel Units**

### 4.2 Detailed Unit Specifications (`unit-1..3`)

- **`unit-1` (`feat/us-6.1.0/unit-1-partner-auth-models`)**:
  - **Deliverable Scope**: `PartnerLoginCredentials` (redacted `password`), `PartnerAuthTokenResponse` (`token: SecretString`), `CreatePartnerApiKeyParams`, `PartnerApiKeyResponse` (`api_key: SecretString`), and `PartnerHmacEnvelope` (`label`, `status: "Created"`, `code: 201`, `body: PartnerHmacBody { hmac_secret: SecretString }`)
  - **Owned Files**: `src/resources/onboarding/auth_models.rs`
  - **Public Contract / Exports**: Public types, builders, and methods defined in `src/resources/onboarding/auth_models.rs` re-exported via parent `mod.rs`
  - **Unit Verification & Target Complexity**: Colocated `#[cfg(test)] mod tests` + runnable rustdoc examples (`TC-6.1.1`), Max Cyclomatic Complexity $CC \le 6$ (cap $\le 10$, nesting $\le 2$)
- **`unit-2` (`feat/us-6.1.0/unit-2-partner-login-apikey`)**:
  - **Deliverable Scope**: `PartnerAuthService::login(creds)` and `PartnerAuthService::create_api_key(params)` under Regime 4 Partner Authentication
  - **Owned Files**: `src/resources/onboarding/login_apikey.rs`
  - **Public Contract / Exports**: Public types, builders, and methods defined in `src/resources/onboarding/login_apikey.rs` re-exported via parent `mod.rs`
  - **Unit Verification & Target Complexity**: Colocated `#[cfg(test)] mod tests` + runnable rustdoc examples (`TC-6.1.2`), Max Cyclomatic Complexity $CC \le 6$ (cap $\le 10$, nesting $\le 2$)
- **`unit-3` (`feat/us-6.1.0/unit-3-retrieve-partner-hmac`)**:
  - **Deliverable Scope**: `PartnerAuthService::retrieve_hmac_secret()` (`GET /api/auth/hmac_secret/get_hmac` with `Authorization: Bearer <partner_auth_token>`) returning `PartnerHmacEnvelope`
  - **Owned Files**: `src/resources/onboarding/hmac_secret.rs`
  - **Public Contract / Exports**: Public types, builders, and methods defined in `src/resources/onboarding/hmac_secret.rs` re-exported via parent `mod.rs`
  - **Unit Verification & Target Complexity**: Colocated `#[cfg(test)] mod tests` + runnable rustdoc examples (`TC-6.1.3`), Max Cyclomatic Complexity $CC \le 6$ (cap $\le 10$, nesting $\le 2$)

### 4.3 Best-Fit Specialist Agents per Unit (`msitarzewski/agency-catalog` + Core Roster)

| Unit ID | Branch Name | Primary Implementer Agent(s) (`agency-catalog`) | Reviewing Council Agent(s) | Mandatory Skills Enforced |
| :--- | :--- | :--- | :--- | :--- |
| `unit-1` | `feat/us-6.1.0/unit-1-partner-auth-models` | `security-engineer` | `code-reviewer`, `security-engineer`, `api-tester` | `code-review-council`, `security-audit`, `cyclomatic-complexity` |
| `unit-2` | `feat/us-6.1.0/unit-2-partner-login-apikey` | `backend-architect` | `code-reviewer`, `security-engineer`, `api-tester` | `code-review-council`, `security-audit`, `cyclomatic-complexity` |
| `unit-3` | `feat/us-6.1.0/unit-3-retrieve-partner-hmac` | `api-tester` | `code-reviewer`, `security-engineer`, `api-tester` | `code-review-council`, `security-audit`, `cyclomatic-complexity` |
| **Story Remediation** | `patch/us-6.1.0-partner-auth-hmac` | `patch-implementer` + `backend-architect` | `code-reviewer-council-president` | Full 6-Gate Re-Verification |

### 4.4 Parallel Execution & Zero-Blocking Contract Seeding Plan
1. **Base Contract Seeding**: Commit `src/resources/onboarding/mod.rs` and `PartnerAuthService` struct stub on `feat/us-6.1.0-partner-auth-hmac` before branching `unit-1..3`.
2. **Simultaneous Worktree Spawning**: All `3` units are provisioned in `.worktrees/feat-us-6.1.0-unit-1..3` and spawned simultaneously in Wave 2.
3. **Ordered Cascading Merge Sequence**: `unit-1` $\to$ `unit-2` $\to$ `unit-3` into `feat/us-6.1.0-partner-auth-hmac` via `gh pr merge <PR> --merge`.

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
- [ ] All STRIDE / ASVS threat mitigations (`TM-1..TM-6`) implemented and covered by security/negative tests in Section 1.3 (`TC-6.1.1..4`).
- [ ] Regional host partitioning, PCI-DSS token redaction, and `ZeroizeOnDrop` controls verified.
- [ ] Independent Security Reviewer agent sign-off posted to the GitHub PR conversation.

---

## 6. Validation Gates & Acceptance Sign-Off

Every Unit PR (`feat/us-6.1.0-partner-auth-hmac/unit-1..3`) and the parent Story PR (`feat/us-6.1.0-partner-auth-hmac`) MUST pass all 6 Quality Gates and post the evidence directly to the GitHub PR conversation before `gh pr merge`:

| Gate | Gate Name | Pass Criteria for `US-6.1.0` | Verification Command / Evidence | Status |
| :--- | :--- | :--- | :--- | :---: |
| **Gate G0** | **Build, Lint & Format** | 0 errors, 0 warnings, 100% `rustfmt` & `clippy` compliance | `CARGO_BUILD_JOBS=1 cargo fmt --check && CARGO_BUILD_JOBS=1 cargo clippy --all-targets --all-features -- -D warnings` | `[ ]` |
| **Gate G1** | **Tests, Coverage & Traceability** | 100% of `AC-1..4` and `TC-6.1.1..4` passing ($\ge 90\%$ line, $\ge 85\%$ branch coverage) | `CARGO_BUILD_JOBS=1 cargo test --all-features` | `[ ]` |
| **Gate G2** | **Security Gateway (`security-audit`)** | All Section 5 STRIDE, constant-time crypto, and `[REDACTED]` checks pass (0 findings) | `security-audit` report on PR | `[ ]` |
| **Gate G-Complexity** | **Cyclomatic Complexity** | Every function $CC \le 6$ target ($CC \le 10$ ceiling, $CC > 15$ blocker, nesting $\le 2$) | `cyclomatic-complexity` table on PR | `[ ]` |
| **Gate G-Docs** | **Documentation & Examples** | 100% public symbols documented + runnable doc-tests + this spec synced | `CARGO_BUILD_JOBS=1 cargo test --doc --all-features` | `[ ]` |
| **Gate G-Review** | **Council President Sign-Off** | Independent Reviewing Council posts `GATE G-REVIEW APPROVED` on GitHub PR | `gh pr comment <PR>` | `[ ]` |

### Final Acceptance Sign-Off Block
- **Story Leader Verification**: All `3` units (`unit-1..3`) merged via cascading `gh pr merge`, story integration suite green, and zero unaddressed findings (or remediated via dedicated `patch-implementer` PRs).
- **Reviewing Council Verdict**: `PENDING` $\to$ `GATE G-REVIEW APPROVED`

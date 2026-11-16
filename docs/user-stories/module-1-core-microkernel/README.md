# Module `1`: Core Microkernel, Multi-Region Routing & 4-Regime Auth Engine (`feat/module-1-core-microkernel`)

- **Module Branch**: `feat/module-1-core-microkernel`
- **Base Branch**: `main`
- **Field Profile**: `software` (`engineering,security,testing`)
- **Cargo Feature Flag(s)**: `core` (implicit, always enabled), `rustls-tls` (default)
- **User Stories**: `3` Stories (`US-1.1.0` .. `US-1.3.0`) | **Total Parallel Units**: `13` Units
- **Merge Order Position to `main`**: `1st (Foundation Module — merges to `main` first; zero upstream module prerequisites; required by Modules 2–8)`

## 1. Module Overview & User Story / Implementation Unit Index

Implements the foundational `some-paymob` microkernel (`src/core/`): multi-region dual-host URL routing (`PaymobRegion` across Egypt, Saudi Arabia, UAE, Oman, Pakistan, and Custom mock hosts for both Accept Acquiring and Payouts Disbursement), compile-time and builder-time credential isolation (`SecretKey`, `PublicKey`, `ApiKey`, `HmacSecret` wrapped in `secrecy::SecretString` with `ZeroizeOnDrop` and `[REDACTED]` `Debug` formatting), the lock-free 4-regime authentication state machine (`AuthManager` backed by `ArcSwapOption` and a single-flight `tokio::sync::Mutex<()>` refresh guard), resilient `reqwest` HTTP transport with exponential backoff and trailing-slash normalization, structured `PaymobError` diagnostics, and zero-float `MinorUnitAmount(u64)` money primitives.

| Story ID | Title & Spec Link | $S_{\text{story}}$ Score | Parallel Units ($K$) | Owned Directory / Paths |
| :--- | :--- | :---: | :---: | :--- |
| `US-1.1.0` | [`us-1.1.0-region-router-config.md`](./us-1.1.0-region-router-config.md) — Multi-Region Dual-Host Router, Credential Newtypes & ClientConfig | `2.55` | `4` | `src/core/region.rs`, `src/core/credentials.rs`, `src/core/config.rs`, `src/core/client.rs` |
| `US-1.2.0` | [`us-1.2.0-multi-regime-auth.md`](./us-1.2.0-multi-regime-auth.md) — Zero-Race 4-Regime Authentication State Machine & Single-Flight Token Cache | `2.95` | `5` | `src/core/auth/strategy.rs`, `src/core/auth/cache.rs`, `src/core/auth/accept_jwt.rs`, `src/core/auth/payouts_oauth.rs`, `src/core/auth/partner.rs` |
| `US-1.3.0` | [`us-1.3.0-http-error-primitives.md`](./us-1.3.0-http-error-primitives.md) — HTTP Transport Pipeline, PaymobError Hierarchy, MinorUnitAmount & Prelude | `2.35` | `4` | `src/core/error.rs`, `src/core/http.rs`, `src/core/types.rs`, `src/core/pagination.rs`, `src/prelude.rs` |

---

## 2. Copy-Paste Module Execution Prompt

Copy and paste the prompt block below directly into your AI agent session to execute **Module `1`** end-to-end using the `some-divide-and-conquer` multi-agent workflow:

```text
Execute Module 1 (Core Microkernel, Multi-Region Routing & 4-Regime Auth Engine) on https://github.com/some-of-cs/some-paymob (base: main) using the some-divide-and-conquer plugin in full parallel mode.

### 1. Architecture, Scope & Feature/Deliverable Contract
- Module branch: `feat/module-1-core-microkernel` (base: `main`).
- Feature flags / Deliverable boundaries: `core` (implicit, always enabled), `rustls-tls` (default); ensure standalone `core` and default feature builds (`cargo check`, `cargo check --no-default-features`, `cargo check --all-features`) remain 100% green.
- Specifications to implement 100% (every Acceptance Criterion `AC-*` and Test Case `TC-*`):
  1. `docs/user-stories/module-1-core-microkernel/us-1.1.0-region-router-config.md`
  2. `docs/user-stories/module-1-core-microkernel/us-1.2.0-multi-regime-auth.md`
  3. `docs/user-stories/module-1-core-microkernel/us-1.3.0-http-error-primitives.md`

### 2. Agent Roster, Roles & Skills (40 Total Agents)
- **Shared Infrastructure Agents (3)**:
  - `git-workflow-master` (1): Exclusive owner of `.worktrees/`, branches, PR creation, and ordered cascading merges.
  - `github-projects-kanban` (1): Syncs `.agents/checkpoints/module-1-core-microkernel/checkpoint.json` and PR conversation reports.
  - `quota-sentinel` (1): Monitors rate limits and flushes state on HTTP 429 / 1% remaining quota.
- **Tier 1 — Module Level (2 Agents)**:
  - `module-leader` (1) on `feat/module-1-core-microkernel` (3-minute watchdog `*/3 * * * *`). NEVER spawns Unit Implementers directly and NEVER edits code/deliverables directly.
  - Independent `code-review-council` + `code-reviewer-council-president` (1) for the Module PR.
- **Tier 2 — Story Level (9 Agents = 3 Story Leaders + 3 Integration Verifiers + 3 Story Review Councils)**:
  - 3 `story-leader` agents (`US-1.1.0`..`US-1.3.0`, 1-minute watchdog `* * * * *`). NEVER edits code/deliverables directly.
  - 3 integration/API tester agents (`testing-api-tester`) for story-level verification.
  - 3 independent `code-review-council` subagents (1 per Story PR).
- **Tier 3 — Unit Level (26 Agents = 13 Unit Implementers + 13 Independent Unit Review Councils)**:
  - **US-1.1.0 (4 Units + 4 Reviewers)**:
    - Unit 1 (`feat/us-1.1.0/unit-1-region-router` -> `src/core/region.rs`): `PaymobRegion` (`Egypt`, `SaudiArabia`, `Uae`, `Oman`, `Pakistan`, `Custom`), `RegionalEndpoints` resolver (Accept Acquiring, Unified Checkout, Payouts Prod, Payouts Staging), and endpoint trailing-slash policy normalizer (`/v1/intention/` vs `/api/secure/disburse/`) | Agent: `backend-architect`
    - Unit 2 (`feat/us-1.1.0/unit-2-credential-types` -> `src/core/credentials.rs`): `SecretKey`, `PublicKey`, `ApiKey`, `HmacSecret`, `PayoutsCredentials`, and `PartnerCredentials` newtypes wrapping `secrecy::SecretString` with `ZeroizeOnDrop`, `[REDACTED]` `Debug` impls, `EnvironmentMode` (`Test` | `Live`), and static lookup table prefix parser (`CC <= 3`) | Agent: `security-engineer`
    - Unit 3 (`feat/us-1.1.0/unit-3-client-config` -> `src/core/config.rs`): `ClientConfig` and `ClientConfigBuilder` validating key-prefix environment parity, rejecting `pk_*` in `secret_key`, configuring timeouts/retries, and exposing the legacy-v2 capture `Bearer` auth toggle | Agent: `backend-architect`
    - Unit 4 (`feat/us-1.1.0/unit-4-paymob-client` -> `src/core/client.rs`): `PaymobClient` (`Arc<PaymobCore>`), cheap `Clone`, compile-time `Send + Sync` assertions, regional URL builders, and feature-gated service accessor methods | Agent: `backend-architect`
  - **US-1.2.0 (5 Units + 5 Reviewers)**:
    - Unit 1 (`feat/us-1.2.0/unit-1-auth-strategy` -> `src/core/auth/strategy.rs`): `AuthStrategy` enum (`SecretKeyToken`, `AcceptJwtBearer`, `AcceptJwtBody`, `PayoutsOAuth2`, `PartnerBearer`, `PartnerApiKey`, `PublicKeyOnly`), `EndpointAuthSpec`, and Regime 1 `Authorization: Token <secret_key>` header injector | Agent: `security-engineer`
    - Unit 2 (`feat/us-1.2.0/unit-2-lockfree-token-cache` -> `src/core/auth/cache.rs`): `CachedToken` with 3600s TTL and 60s proactive refresh margin, lock-free `ArcSwapOption<CachedToken>` read fast-path, `tokio::sync::Mutex<()>` single-flight refresh lock, and `ZeroizeOnDrop` token scrubbing | Agent: `backend-architect`
    - Unit 3 (`feat/us-1.2.0/unit-3-accept-jwt-provider` -> `src/core/auth/accept_jwt.rs`): Regime 2 Accept JWT provider (`POST /api/auth/tokens` with `{"api_key": "..."}`), `Authorization: Bearer <auth_token>` header attachment, JSON body `"auth_token"` field injector, and automatic single-flight retry on HTTP 401 `{"detail": "incorrect credentials"}` | Agent: `backend-architect`
    - Unit 4 (`feat/us-1.2.0/unit-4-payouts-oauth2-provider` -> `src/core/auth/payouts_oauth.rs`): Regime 3 Payouts OAuth 2.0 state machine (`POST /api/secure/o/token/` with HTTP Basic Auth `{client_id}:{client_secret}` and `application/x-www-form-urlencoded` `grant_type=password` initial grant + `grant_type=refresh_token` renewal) | Agent: `security-engineer`
    - Unit 5 (`feat/us-1.2.0/unit-5-partner-delegated-auth` -> `src/core/auth/partner.rs`): Regime 4 Partner Delegated authentication context (`PartnerBearer` header, `PartnerApiKey` header/query injector, and sub-merchant `merchant_id` delegation binding) | Agent: `backend-architect`
  - **US-1.3.0 (4 Units + 4 Reviewers)**:
    - Unit 1 (`feat/us-1.3.0/unit-1-error-hierarchy` -> `src/core/error.rs`): `PaymobError` enum (`ApiError`, `AuthenticationError`, `EnvironmentMismatch`, `RefundExceedsPermissibleAmount`, `RateLimited`, `WebhookError`, `ValidationError`, `TransportError`), multi-shape Paymob error JSON parser (`detail`, `message`, nested field maps), and PII/secret-redacted `Display`/`Debug` | Agent: `backend-architect`
    - Unit 2 (`feat/us-1.3.0/unit-2-http-transport` -> `src/core/http.rs`): `HttpClient` wrapping `reqwest::Client` (TLS 1.3), exponential backoff with full jitter on HTTP `429` / `502` / `503` / `504`, `Retry-After` header parsing, request timeout enforcement, and correlation request ID logging | Agent: `backend-architect`
    - Unit 3 (`feat/us-1.3.0/unit-3-money-currency-types` -> `src/core/types.rs`): `MinorUnitAmount(u64)` newtype (piasters/halalas/fils/paisas with checked `checked_add`/`checked_sub`, zero `f32`/`f64` floats), `Currency` enum (`EGP`, `SAR`, `AED`, `OMR`, `PKR`, `USD`, `EUR`, `Unknown(String)` via static lookup slice `CC <= 3`), and non-empty prefixed ID validators | Agent: `backend-architect`
    - Unit 4 (`feat/us-1.3.0/unit-4-pagination-prelude` -> `src/core/pagination.rs, src/prelude.rs`): `PaginatedResponse<T>` (`count`, `next`, `previous`, `results`), `PageQuery` builder (`?page=N`), and `some_paymob::prelude::*` exporting core client, config, region, money, and error types | Agent: `backend-architect`
- **On-Demand Remediation Agent**: `patch-implementer` (spawned by any Story Leader or Module Leader whenever a Review Council, CodeScene, or CodeRabbit check flags any issue).
- **Skills Loaded**: `divide-and-conquer-orchestrator`, `preflight-git-gh`, `git-workflow-master`, `github-projects-kanban`, `quota-sentinel`, `security-audit`, `code-review-council`, `code-reviewer-council-president`, `cyclomatic-complexity`, `patch-implementer`.

### 3. Mandatory Anti-Regression Rules (Hard Invariants)
1. **Zero Shared-Index (`mod.rs` / `lib.rs`) Clobbering Across Stories & Units**: In Wave 1, `module-leader` MUST pre-scaffold all module index files (`src/lib.rs`, `mod.rs`, `Cargo.toml`) and empty stub files for all `13` units on `feat/module-1-core-microkernel` BEFORE branching `feat/us-1.1.0-region-router-config`..`feat/us-1.3.0-http-error-primitives`. Story and Unit branches MUST NOT delete sibling declarations.
2. **Never Self-Review or Merge Before Independent Subagent Approval**: Every Unit PR, Story PR, Patch PR, and Module PR MUST receive a structured Implementation Report comment AND an independent `code-review-council` subagent review (`event="COMMENT"` when using a single GitHub account to avoid self-approval API errors). If ANY gate or automated PR comment (CodeScene / CodeRabbit) flags an issue, iterate on the Unit branch or spawn `patch-implementer` at the Story/Module tier and re-run the Reviewer subagent until `Gate G-Review: Approved` with 0 issues.
3. **Plain UTF-8 Commits Only**: When committing files via GitHub API / MCP tools (`GITHUB_COMMIT_MULTIPLE_FILES`), ALWAYS pass plain-text UTF-8 strings with `encoding: "utf-8"` (never pre-encode Base64, preventing binary corruption).
4. **Static Lookup Tables for Multi-Branch Mapping (`CC <= 6`, Nesting `<= 2`)**: Any enum or dispatcher with >5 variants mapping to/from strings MUST use a static `const KNOWN_*: &[(&str, Self)]` lookup table or declarative map so cyclomatic complexity stays `CC <= 3` (never write a 10+ arm `match`/`switch` that fails `G-Complexity`).
5. **Security, Bounds & Secret Hygiene (`G2` & `G-Law`)**: Enforce domain bounds during deserialization, require non-empty suffixes on prefixed IDs, redact all secrets/tokens/PII (`[REDACTED]`) in `Debug`/logs, zeroize intermediate credential buffers (`ZeroizeOnDrop`), verify all webhooks in constant time (`subtle::ConstantTimeEq`), and use checked integer math for monetary values (`MinorUnitAmount(u64)`, zero `f32`/`f64` floats).
6. **Complete Documentation, Runnable Doc-Tests & Compile-Fail Guards (`G-Docs` & `G1`)**: Every public symbol/interface MUST include doc comments, runnable doc-tests, and negative/compile-time guards where applicable.
7. **Memory-Safe Verification Execution**: Run build, lint, format, test, and doc-test commands sequentially (e.g., `CARGO_BUILD_JOBS=1` in memory-constrained sandboxes) so linking never OOMs.

### 4. Step-by-Step Execution & Strict Merge-Order Constraint into `main`
- **Step 1 (Gate 0 & Wave 1 Scaffolding)**: Run `preflight-git-gh`, start `quota-sentinel`, create `feat/module-1-core-microkernel` from `main`, pre-scaffold index files + `13` empty unit stub files, and spawn all `3` `story-leader` subagents in parallel.
- **Step 2 (Wave 2 Parallel Unit Loop)**: Each `story-leader` spawns its `K` Unit Implementers in parallel. Each Unit Implementer implements its owned file + unit tests + doc-tests, verifies build/lint/format, opens its Unit PR, posts its Implementation Report comment, and loops with its dedicated Unit Review Council subagent until `APPROVED`.
- **Step 3 (Wave 3 Ordered Cascading Unit Merges & Story Review Loop)**: Merge Unit PRs `1 -> 2 -> ... -> K` one by one per story (rebasing/updating each next Unit PR onto the updated story branch). Then open each Story PR (`US-1.1.0`..`US-1.3.0`) into `feat/module-1-core-microkernel`, post the Story Implementation Report, run the independent Story Review Council subagent, and spawn `patch-implementer` if any issue is flagged until all `3` Story PRs are `APPROVED` and merged sequentially into `feat/module-1-core-microkernel`.
- **Step 4 (Wave 4 Module PR, Whole-Module Audit & Strict `main` Merge Order)**:
  - Open the Module `1` PR (`feat/module-1-core-microkernel` -> `main`), post the Module Implementation Report, and run the independent Module `1` Review Council subagent (+ `patch-implementer` loop if needed) until `GATE G-REVIEW APPROVED` with 0 issues.
  - **STRICT MERGE ORDER CONSTRAINT TO `main` (`Module 1 -> Module 7 -> Module 2 -> Module 3 -> Module 4 -> Module 5 -> Module 6 -> Module 8`)**: Module `1` MUST be merged into `main` in position **`1st (Foundation Module — merges to `main` first; zero upstream module prerequisites; required by Modules 2–8)`**—strictly AFTER `None (Base `main` branch)` have merged into `main` and BEFORE `Module 7, Module 2, Module 3, Module 4, Module 5, Module 6, Module 8`. Before merging the approved Module `1` PR into `main`, sync/rebase `feat/module-1-core-microkernel` onto the latest `main` branch so shared manifests (`Cargo.toml`) and top-level exports (`src/lib.rs`, `src/prelude.rs`) preserve all previously merged modules alongside Module `1`, re-run the full verification suite (`cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --all-features`, `cargo test --doc`), and then merge into `main`.
```

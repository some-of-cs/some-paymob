# Module `6`: Partner Merchant Onboarding APIs & Multi-Tenant Client Scoping (`feat/module-6-partner-onboarding`)

- **Module Branch**: `feat/module-6-partner-onboarding`
- **Base Branch**: `main`
- **Field Profile**: `software` (`engineering,security,testing`)
- **Cargo Feature Flag(s)**: `onboarding` (alias `partner-onboarding`)
- **User Stories**: `2` Stories (`US-6.1.0` .. `US-6.2.0`) | **Total Parallel Units**: `7` Units
- **Merge Order Position to `main`**: `7th (Merges to `main` after Modules 1, 7, 2, 3, 4, and 5; before Module 8)`

## 1. Module Overview & User Story / Implementation Unit Index

Implements Paymob's 7 Partner Onboarding APIs (`src/resources/onboarding/`) and multi-tenant sub-merchant client scoping (`paymob.with_merchant(merchant_id)`): Partner Login (`onboarding().auth().login`), Partner API Key creation (`onboarding().auth().create_api_key`), and Partner HMAC Secret retrieval (`GET /api/auth/hmac_secret/get_hmac`); Sub-Merchant Registration (`register_merchant`), dynamic Onboarding Flow Schema discovery (`GET /api/onboarding/flow/schema?partner=...&resubmission=...&paymob_mid=...`), KYC Step Submission (`submit_step`), Partner Merchant Inquiry (`merchant_inquiry`), and the `MerchantScopedClient` wrapper that processes intentions, inquiries, and refunds on behalf of an onboarded sub-merchant using the Partner API Key + `merchant_id`.

| Story ID | Title & Spec Link | $S_{\text{story}}$ Score | Parallel Units ($K$) | Owned Directory / Paths |
| :--- | :--- | :---: | :---: | :--- |
| `US-6.1.0` | [`us-6.1.0-partner-auth-hmac.md`](./us-6.1.0-partner-auth-hmac.md) — Partner Authentication, Partner API Key Provisioning & Partner HMAC Secret Retrieval | `2.00` | `3` | `src/resources/onboarding/auth_models.rs`, `src/resources/onboarding/login_apikey.rs`, `src/resources/onboarding/hmac_secret.rs` |
| `US-6.2.0` | [`us-6.2.0-merchant-onboarding-flow.md`](./us-6.2.0-merchant-onboarding-flow.md) — Sub-Merchant Registration, Onboarding Flow Schema, Step Submission, Inquiry & with_merchant Scoping | `2.35` | `4` | `src/resources/onboarding/flow_models.rs`, `src/resources/onboarding/schema_register.rs`, `src/resources/onboarding/step_inquiry.rs`, `src/resources/onboarding/scoped_client.rs` |

---

## 2. Copy-Paste Module Execution Prompt

Copy and paste the prompt block below directly into your AI agent session to execute **Module `6`** end-to-end using the `some-divide-and-conquer` multi-agent workflow:

```text
Execute Module 6 (Partner Merchant Onboarding APIs & Multi-Tenant Client Scoping) on https://github.com/some-of-cs/some-paymob (base: main) using the some-divide-and-conquer plugin in full parallel mode.

### 1. Architecture, Scope & Feature/Deliverable Contract
- Module branch: `feat/module-6-partner-onboarding` (base: `main`).
- Feature flags / Deliverable boundaries: `onboarding` (alias `partner-onboarding`); ensure standalone `core` and default feature builds (`cargo check`, `cargo check --no-default-features`, `cargo check --all-features`) remain 100% green.
- Specifications to implement 100% (every Acceptance Criterion `AC-*` and Test Case `TC-*`):
  1. `docs/user-stories/module-6-partner-onboarding/us-6.1.0-partner-auth-hmac.md`
  2. `docs/user-stories/module-6-partner-onboarding/us-6.2.0-merchant-onboarding-flow.md`

### 2. Agent Roster, Roles & Skills (25 Total Agents)
- **Shared Infrastructure Agents (3)**:
  - `git-workflow-master` (1): Exclusive owner of `.worktrees/`, branches, PR creation, and ordered cascading merges.
  - `github-projects-kanban` (1): Syncs `.agents/checkpoints/module-6-partner-onboarding/checkpoint.json` and PR conversation reports.
  - `quota-sentinel` (1): Monitors rate limits and flushes state on HTTP 429 / 1% remaining quota.
- **Tier 1 — Module Level (2 Agents)**:
  - `module-leader` (1) on `feat/module-6-partner-onboarding` (3-minute watchdog `*/3 * * * *`). NEVER spawns Unit Implementers directly and NEVER edits code/deliverables directly.
  - Independent `code-review-council` + `code-reviewer-council-president` (1) for the Module PR.
- **Tier 2 — Story Level (6 Agents = 2 Story Leaders + 2 Integration Verifiers + 2 Story Review Councils)**:
  - 2 `story-leader` agents (`US-6.1.0`..`US-6.2.0`, 1-minute watchdog `* * * * *`). NEVER edits code/deliverables directly.
  - 2 integration/API tester agents (`testing-api-tester`) for story-level verification.
  - 2 independent `code-review-council` subagents (1 per Story PR).
- **Tier 3 — Unit Level (14 Agents = 7 Unit Implementers + 7 Independent Unit Review Councils)**:
  - **US-6.1.0 (3 Units + 3 Reviewers)**:
    - Unit 1 (`feat/us-6.1.0/unit-1-partner-auth-models` -> `src/resources/onboarding/auth_models.rs`): `PartnerLoginCredentials` (redacted `password`), `PartnerAuthTokenResponse` (`token: SecretString`), `CreatePartnerApiKeyParams`, `PartnerApiKeyResponse` (`api_key: SecretString`), and `PartnerHmacEnvelope` (`label`, `status: "Created"`, `code: 201`, `body: PartnerHmacBody { hmac_secret: SecretString }`) | Agent: `security-engineer`
    - Unit 2 (`feat/us-6.1.0/unit-2-partner-login-apikey` -> `src/resources/onboarding/login_apikey.rs`): `PartnerAuthService::login(creds)` and `PartnerAuthService::create_api_key(params)` under Regime 4 Partner Authentication | Agent: `backend-architect`
    - Unit 3 (`feat/us-6.1.0/unit-3-retrieve-partner-hmac` -> `src/resources/onboarding/hmac_secret.rs`): `PartnerAuthService::retrieve_hmac_secret()` (`GET /api/auth/hmac_secret/get_hmac` with `Authorization: Bearer <partner_auth_token>`) returning `PartnerHmacEnvelope` | Agent: `api-tester`
  - **US-6.2.0 (4 Units + 4 Reviewers)**:
    - Unit 1 (`feat/us-6.2.0/unit-1-onboarding-flow-models` -> `src/resources/onboarding/flow_models.rs`): `RegisterMerchantParams`, `RegisteredMerchantResponse`, `OnboardingSchemaQuery` (`partner: String`, `resubmission: Option<bool>`, `paymob_mid: Option<u64>`), `OnboardingFlowSchema`, `SubmitOnboardingStepParams`, and `PartnerMerchantInquiryResponse` | Agent: `backend-architect`
    - Unit 2 (`feat/us-6.2.0/unit-2-register-and-schema` -> `src/resources/onboarding/schema_register.rs`): `PartnerFlowService::register_merchant(params)` and `PartnerFlowService::get_schema(query)` (`GET /api/onboarding/flow/schema?partner=...&resubmission=...&paymob_mid=...`) under Regime 4 `PartnerApiKey` | Agent: `backend-architect`
    - Unit 3 (`feat/us-6.2.0/unit-3-submit-step-and-inquiry` -> `src/resources/onboarding/step_inquiry.rs`): `PartnerFlowService::submit_step(params)` and `PartnerFlowService::merchant_inquiry(mid)` checking merchant approval status and live integration IDs | Agent: `backend-architect`
    - Unit 4 (`feat/us-6.2.0/unit-4-scoped-merchant-client` -> `src/resources/onboarding/scoped_client.rs`): `paymob.with_merchant(merchant_id)` returning `MerchantScopedClient` that binds the Partner API Key and target `merchant_id` across scoped `.intentions()`, `.inquiries()`, and `.manage()` operations | Agent: `api-tester`
- **On-Demand Remediation Agent**: `patch-implementer` (spawned by any Story Leader or Module Leader whenever a Review Council, CodeScene, or CodeRabbit check flags any issue).
- **Skills Loaded**: `divide-and-conquer-orchestrator`, `preflight-git-gh`, `git-workflow-master`, `github-projects-kanban`, `quota-sentinel`, `security-audit`, `code-review-council`, `code-reviewer-council-president`, `cyclomatic-complexity`, `patch-implementer`.

### 3. Mandatory Anti-Regression Rules (Hard Invariants)
1. **Zero Shared-Index (`mod.rs` / `lib.rs`) Clobbering Across Stories & Units**: In Wave 1, `module-leader` MUST pre-scaffold all module index files (`src/lib.rs`, `mod.rs`, `Cargo.toml`) and empty stub files for all `7` units on `feat/module-6-partner-onboarding` BEFORE branching `feat/us-6.1.0-partner-auth-hmac`..`feat/us-6.2.0-merchant-onboarding-flow`. Story and Unit branches MUST NOT delete sibling declarations.
2. **Never Self-Review or Merge Before Independent Subagent Approval**: Every Unit PR, Story PR, Patch PR, and Module PR MUST receive a structured Implementation Report comment AND an independent `code-review-council` subagent review (`event="COMMENT"` when using a single GitHub account to avoid self-approval API errors). If ANY gate or automated PR comment (CodeScene / CodeRabbit) flags an issue, iterate on the Unit branch or spawn `patch-implementer` at the Story/Module tier and re-run the Reviewer subagent until `Gate G-Review: Approved` with 0 issues.
3. **Plain UTF-8 Commits Only**: When committing files via GitHub API / MCP tools (`GITHUB_COMMIT_MULTIPLE_FILES`), ALWAYS pass plain-text UTF-8 strings with `encoding: "utf-8"` (never pre-encode Base64, preventing binary corruption).
4. **Static Lookup Tables for Multi-Branch Mapping (`CC <= 6`, Nesting `<= 2`)**: Any enum or dispatcher with >5 variants mapping to/from strings MUST use a static `const KNOWN_*: &[(&str, Self)]` lookup table or declarative map so cyclomatic complexity stays `CC <= 3` (never write a 10+ arm `match`/`switch` that fails `G-Complexity`).
5. **Security, Bounds & Secret Hygiene (`G2` & `G-Law`)**: Enforce domain bounds during deserialization, require non-empty suffixes on prefixed IDs, redact all secrets/tokens/PII (`[REDACTED]`) in `Debug`/logs, zeroize intermediate credential buffers (`ZeroizeOnDrop`), verify all webhooks in constant time (`subtle::ConstantTimeEq`), and use checked integer math for monetary values (`MinorUnitAmount(u64)`, zero `f32`/`f64` floats).
6. **Complete Documentation, Runnable Doc-Tests & Compile-Fail Guards (`G-Docs` & `G1`)**: Every public symbol/interface MUST include doc comments, runnable doc-tests, and negative/compile-time guards where applicable.
7. **Memory-Safe Verification Execution**: Run build, lint, format, test, and doc-test commands sequentially (e.g., `CARGO_BUILD_JOBS=1` in memory-constrained sandboxes) so linking never OOMs.

### 4. Step-by-Step Execution & Strict Merge-Order Constraint into `main`
- **Step 1 (Gate 0 & Wave 1 Scaffolding)**: Run `preflight-git-gh`, start `quota-sentinel`, create `feat/module-6-partner-onboarding` from `main`, pre-scaffold index files + `7` empty unit stub files, and spawn all `2` `story-leader` subagents in parallel.
- **Step 2 (Wave 2 Parallel Unit Loop)**: Each `story-leader` spawns its `K` Unit Implementers in parallel. Each Unit Implementer implements its owned file + unit tests + doc-tests, verifies build/lint/format, opens its Unit PR, posts its Implementation Report comment, and loops with its dedicated Unit Review Council subagent until `APPROVED`.
- **Step 3 (Wave 3 Ordered Cascading Unit Merges & Story Review Loop)**: Merge Unit PRs `1 -> 2 -> ... -> K` one by one per story (rebasing/updating each next Unit PR onto the updated story branch). Then open each Story PR (`US-6.1.0`..`US-6.2.0`) into `feat/module-6-partner-onboarding`, post the Story Implementation Report, run the independent Story Review Council subagent, and spawn `patch-implementer` if any issue is flagged until all `2` Story PRs are `APPROVED` and merged sequentially into `feat/module-6-partner-onboarding`.
- **Step 4 (Wave 4 Module PR, Whole-Module Audit & Strict `main` Merge Order)**:
  - Open the Module `6` PR (`feat/module-6-partner-onboarding` -> `main`), post the Module Implementation Report, and run the independent Module `6` Review Council subagent (+ `patch-implementer` loop if needed) until `GATE G-REVIEW APPROVED` with 0 issues.
  - **STRICT MERGE ORDER CONSTRAINT TO `main` (`Module 1 -> Module 7 -> Module 2 -> Module 3 -> Module 4 -> Module 5 -> Module 6 -> Module 8`)**: Module `6` MUST be merged into `main` in position **`7th (Merges to `main` after Modules 1, 7, 2, 3, 4, and 5; before Module 8)`**—strictly AFTER `Module 1 (`feat/module-1-core-microkernel`), Module 2 (`feat/module-2-intentions-checkout`), Module 3 (`feat/module-3-manage-inquiries-splits`)` have merged into `main` and BEFORE `Module 8`. Before merging the approved Module `6` PR into `main`, sync/rebase `feat/module-6-partner-onboarding` onto the latest `main` branch so shared manifests (`Cargo.toml`) and top-level exports (`src/lib.rs`, `src/prelude.rs`) preserve all previously merged modules alongside Module `6`, re-run the full verification suite (`cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --all-features`, `cargo test --doc`), and then merge into `main`.
```

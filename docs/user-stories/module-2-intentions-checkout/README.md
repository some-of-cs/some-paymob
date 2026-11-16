# Module `2`: Payment Intentions, Checkout Experiences & Legacy Accept v2 Flow (`feat/module-2-intentions-checkout`)

- **Module Branch**: `feat/module-2-intentions-checkout`
- **Base Branch**: `main`
- **Field Profile**: `software` (`engineering,security,testing`)
- **Cargo Feature Flag(s)**: `intentions` (default enabled), `legacy-v2` (opt-in)
- **User Stories**: `3` Stories (`US-2.1.0` .. `US-2.3.0`) | **Total Parallel Units**: `10` Units
- **Merge Order Position to `main`**: `3rd (Merges to `main` after Module 1 and Module 7; before Module 3, Module 4, Module 5, Module 6, and Module 8)`

## 1. Module Overview & User Story / Implementation Unit Index

Implements Paymob's primary payment initialization layer (`src/resources/intentions/`, `src/resources/checkout/`) and classic migration layer (`src/resources/legacy/`): `POST /v1/intention/` and `PUT /v1/intention/` under Regime 1 (`Authorization: Token <secret_key>`) with builder-time enforcement of Environment Parity, `IntentionItem` completeness (`name` + `amount`), and `BillingData` mandatory `phone_number`; local PCI-compliant builders for Unified Checkout redirect URLs (`unified_url`), embedded Pixel JS components (`pixel_config`), and bank installment Affordability Widgets (`affordability_widget`) using `PublicKey` (`pk_*`); plus the opt-in Legacy Accept v2 3-step flow (`POST /api/auth/tokens` -> `POST /api/ecommerce/orders` -> `POST /api/acceptance/payment_keys` -> `iframe_url`).

| Story ID | Title & Spec Link | $S_{\text{story}}$ Score | Parallel Units ($K$) | Owned Directory / Paths |
| :--- | :--- | :---: | :---: | :--- |
| `US-2.1.0` | [`us-2.1.0-intention-create-update.md`](./us-2.1.0-intention-create-update.md) — v1 Payment Intention Create & Update API (POST & PUT /v1/intention/) | `2.55` | `4` | `src/resources/intentions/billing.rs`, `src/resources/intentions/params.rs`, `src/resources/intentions/response.rs`, `src/resources/intentions/service.rs` |
| `US-2.2.0` | [`us-2.2.0-checkout-pixel-affordability.md`](./us-2.2.0-checkout-pixel-affordability.md) — Unified Checkout URL, Embedded Pixel JS Config & Affordability Widget Builders | `2.00` | `3` | `src/resources/checkout/unified.rs`, `src/resources/checkout/pixel.rs`, `src/resources/checkout/affordability.rs` |
| `US-2.3.0` | [`us-2.3.0-legacy-v2-checkout.md`](./us-2.3.0-legacy-v2-checkout.md) — Legacy Accept v2 3-Step Checkout Flow (Auth Token -> Order -> Payment Key -> Iframe) | `2.00` | `3` | `src/resources/legacy/orders.rs`, `src/resources/legacy/payment_keys.rs`, `src/resources/legacy/service.rs` |

---

## 2. Copy-Paste Module Execution Prompt

Copy and paste the prompt block below directly into your AI agent session to execute **Module `2`** end-to-end using the `some-divide-and-conquer` multi-agent workflow:

```text
Execute Module 2 (Payment Intentions, Checkout Experiences & Legacy Accept v2 Flow) on https://github.com/some-of-cs/some-paymob (base: main) using the some-divide-and-conquer plugin in full parallel mode.

### 1. Architecture, Scope & Feature/Deliverable Contract
- Module branch: `feat/module-2-intentions-checkout` (base: `main`).
- Feature flags / Deliverable boundaries: `intentions` (default enabled), `legacy-v2` (opt-in); ensure standalone `core` and default feature builds (`cargo check`, `cargo check --no-default-features`, `cargo check --all-features`) remain 100% green.
- Specifications to implement 100% (every Acceptance Criterion `AC-*` and Test Case `TC-*`):
  1. `docs/user-stories/module-2-intentions-checkout/us-2.1.0-intention-create-update.md`
  2. `docs/user-stories/module-2-intentions-checkout/us-2.2.0-checkout-pixel-affordability.md`
  3. `docs/user-stories/module-2-intentions-checkout/us-2.3.0-legacy-v2-checkout.md`

### 2. Agent Roster, Roles & Skills (34 Total Agents)
- **Shared Infrastructure Agents (3)**:
  - `git-workflow-master` (1): Exclusive owner of `.worktrees/`, branches, PR creation, and ordered cascading merges.
  - `github-projects-kanban` (1): Syncs `.agents/checkpoints/module-2-intentions-checkout/checkpoint.json` and PR conversation reports.
  - `quota-sentinel` (1): Monitors rate limits and flushes state on HTTP 429 / 1% remaining quota.
- **Tier 1 — Module Level (2 Agents)**:
  - `module-leader` (1) on `feat/module-2-intentions-checkout` (3-minute watchdog `*/3 * * * *`). NEVER spawns Unit Implementers directly and NEVER edits code/deliverables directly.
  - Independent `code-review-council` + `code-reviewer-council-president` (1) for the Module PR.
- **Tier 2 — Story Level (9 Agents = 3 Story Leaders + 3 Integration Verifiers + 3 Story Review Councils)**:
  - 3 `story-leader` agents (`US-2.1.0`..`US-2.3.0`, 1-minute watchdog `* * * * *`). NEVER edits code/deliverables directly.
  - 3 integration/API tester agents (`testing-api-tester`) for story-level verification.
  - 3 independent `code-review-council` subagents (1 per Story PR).
- **Tier 3 — Unit Level (20 Agents = 10 Unit Implementers + 10 Independent Unit Review Councils)**:
  - **US-2.1.0 (4 Units + 4 Reviewers)**:
    - Unit 1 (`feat/us-2.1.0/unit-1-billing-and-items` -> `src/resources/intentions/billing.rs`): `BillingData` & `BillingDataBuilder` (enforcing non-empty `phone_number` at `.build()` time and redacting PII in `Debug`), `IntentionCustomer`, and `IntentionItem` (enforcing non-empty `name` and `amount` in minor units) | Agent: `backend-architect`
    - Unit 2 (`feat/us-2.1.0/unit-2-intention-params` -> `src/resources/intentions/params.rs`): `PaymentMethodInput` untagged enum (`IntegrationId(u64)` | `MethodName(String)`), `CreateIntentionParams` & `UpdateIntentionParams` builders supporting `amount`, `currency`, `payment_methods`, `items`, `billing_data`, `customer`, `extras`, `special_reference`, `expiration`, `notification_url`, `redirection_url`, `pre_selected_plan`, and `card_tokens` | Agent: `backend-architect`
    - Unit 3 (`feat/us-2.1.0/unit-3-intention-response` -> `src/resources/intentions/response.rs`): `IntentionResponse` (`id: String` `pi_*`, `intention_order_id: u64`, `client_secret: SecretString` `egy_csk_*`, `payment_keys: Vec<IntentionPaymentKey>`, `intention_detail`, `payment_methods: Vec<ConfiguredPaymentMethod>`, `special_reference`, `extras`, `confirmed`, `status`, `created`, `card_detail`, `card_tokens`, `object`) | Agent: `backend-architect`
    - Unit 4 (`feat/us-2.1.0/unit-4-intentions-service` -> `src/resources/intentions/service.rs`): `IntentionsService` (`paymob.intentions().create(params)` `POST /v1/intention/` and `paymob.intentions().update(params)` `PUT /v1/intention/`) using Regime 1 `Authorization: Token <secret_key>` with pre-flight Test/Live parity validation | Agent: `api-tester`
  - **US-2.2.0 (3 Units + 3 Reviewers)**:
    - Unit 1 (`feat/us-2.2.0/unit-1-unified-checkout-url` -> `src/resources/checkout/unified.rs`): `CheckoutService::unified_url(&client_secret)` building `{checkout_host}/?publicKey={pk}&clientSecret={client_secret}` with URL-safe percent-encoding and compile/runtime `PublicKey` (`pk_*`) verification | Agent: `backend-architect`
    - Unit 2 (`feat/us-2.2.0/unit-2-pixel-config` -> `src/resources/checkout/pixel.rs`): `PixelConfig` & `PixelConfigBuilder` (`paymob.checkout().pixel_config(...)`) generating typed JSON configuration for Paymob's embedded Pixel JS SDK (Cards, Apple Pay, Google Pay, domain verification, and Apple Pay certificate settings) | Agent: `backend-architect`
    - Unit 3 (`feat/us-2.2.0/unit-3-affordability-widget` -> `src/resources/checkout/affordability.rs`): `AffordabilityWidgetConfig` (`paymob.checkout().affordability_widget(...)`) for bank installment plans and helper methods wiring selected installment plan IDs into `CreateIntentionParams::pre_selected_plan` | Agent: `backend-architect`
  - **US-2.3.0 (3 Units + 3 Reviewers)**:
    - Unit 1 (`feat/us-2.3.0/unit-1-legacy-orders` -> `src/resources/legacy/orders.rs`): `CreateLegacyOrderParams` (`amount_cents`, `currency`, `merchant_order_id`, `items`, `delivery_needed`), `LegacyOrder` response model, and `POST /api/ecommerce/orders` using Regime 2 JSON body `"auth_token"` | Agent: `backend-architect`
    - Unit 2 (`feat/us-2.3.0/unit-2-legacy-payment-keys` -> `src/resources/legacy/payment_keys.rs`): `CreatePaymentKeyParams` (`order_id`, `amount_cents`, `currency`, `integration_id`, `billing_data`, `expiration`, `lock_order_when_paid`), `PaymentKeyResponse` (`token: SecretString`), and `POST /api/acceptance/payment_keys` | Agent: `backend-architect`
    - Unit 3 (`feat/us-2.3.0/unit-3-legacy-checkout-facade` -> `src/resources/legacy/service.rs`): `LegacyV2Service` (`generate_auth_token`, `create_order`, `create_payment_key`, `iframe_url(iframe_id, payment_token)`, and one-call `create_checkout(params)` composite orchestrator) | Agent: `api-tester`
- **On-Demand Remediation Agent**: `patch-implementer` (spawned by any Story Leader or Module Leader whenever a Review Council, CodeScene, or CodeRabbit check flags any issue).
- **Skills Loaded**: `divide-and-conquer-orchestrator`, `preflight-git-gh`, `git-workflow-master`, `github-projects-kanban`, `quota-sentinel`, `security-audit`, `code-review-council`, `code-reviewer-council-president`, `cyclomatic-complexity`, `patch-implementer`.

### 3. Mandatory Anti-Regression Rules (Hard Invariants)
1. **Zero Shared-Index (`mod.rs` / `lib.rs`) Clobbering Across Stories & Units**: In Wave 1, `module-leader` MUST pre-scaffold all module index files (`src/lib.rs`, `mod.rs`, `Cargo.toml`) and empty stub files for all `10` units on `feat/module-2-intentions-checkout` BEFORE branching `feat/us-2.1.0-intention-create-update`..`feat/us-2.3.0-legacy-v2-checkout`. Story and Unit branches MUST NOT delete sibling declarations.
2. **Never Self-Review or Merge Before Independent Subagent Approval**: Every Unit PR, Story PR, Patch PR, and Module PR MUST receive a structured Implementation Report comment AND an independent `code-review-council` subagent review (`event="COMMENT"` when using a single GitHub account to avoid self-approval API errors). If ANY gate or automated PR comment (CodeScene / CodeRabbit) flags an issue, iterate on the Unit branch or spawn `patch-implementer` at the Story/Module tier and re-run the Reviewer subagent until `Gate G-Review: Approved` with 0 issues.
3. **Plain UTF-8 Commits Only**: When committing files via GitHub API / MCP tools (`GITHUB_COMMIT_MULTIPLE_FILES`), ALWAYS pass plain-text UTF-8 strings with `encoding: "utf-8"` (never pre-encode Base64, preventing binary corruption).
4. **Static Lookup Tables for Multi-Branch Mapping (`CC <= 6`, Nesting `<= 2`)**: Any enum or dispatcher with >5 variants mapping to/from strings MUST use a static `const KNOWN_*: &[(&str, Self)]` lookup table or declarative map so cyclomatic complexity stays `CC <= 3` (never write a 10+ arm `match`/`switch` that fails `G-Complexity`).
5. **Security, Bounds & Secret Hygiene (`G2` & `G-Law`)**: Enforce domain bounds during deserialization, require non-empty suffixes on prefixed IDs, redact all secrets/tokens/PII (`[REDACTED]`) in `Debug`/logs, zeroize intermediate credential buffers (`ZeroizeOnDrop`), verify all webhooks in constant time (`subtle::ConstantTimeEq`), and use checked integer math for monetary values (`MinorUnitAmount(u64)`, zero `f32`/`f64` floats).
6. **Complete Documentation, Runnable Doc-Tests & Compile-Fail Guards (`G-Docs` & `G1`)**: Every public symbol/interface MUST include doc comments, runnable doc-tests, and negative/compile-time guards where applicable.
7. **Memory-Safe Verification Execution**: Run build, lint, format, test, and doc-test commands sequentially (e.g., `CARGO_BUILD_JOBS=1` in memory-constrained sandboxes) so linking never OOMs.

### 4. Step-by-Step Execution & Strict Merge-Order Constraint into `main`
- **Step 1 (Gate 0 & Wave 1 Scaffolding)**: Run `preflight-git-gh`, start `quota-sentinel`, create `feat/module-2-intentions-checkout` from `main`, pre-scaffold index files + `10` empty unit stub files, and spawn all `3` `story-leader` subagents in parallel.
- **Step 2 (Wave 2 Parallel Unit Loop)**: Each `story-leader` spawns its `K` Unit Implementers in parallel. Each Unit Implementer implements its owned file + unit tests + doc-tests, verifies build/lint/format, opens its Unit PR, posts its Implementation Report comment, and loops with its dedicated Unit Review Council subagent until `APPROVED`.
- **Step 3 (Wave 3 Ordered Cascading Unit Merges & Story Review Loop)**: Merge Unit PRs `1 -> 2 -> ... -> K` one by one per story (rebasing/updating each next Unit PR onto the updated story branch). Then open each Story PR (`US-2.1.0`..`US-2.3.0`) into `feat/module-2-intentions-checkout`, post the Story Implementation Report, run the independent Story Review Council subagent, and spawn `patch-implementer` if any issue is flagged until all `3` Story PRs are `APPROVED` and merged sequentially into `feat/module-2-intentions-checkout`.
- **Step 4 (Wave 4 Module PR, Whole-Module Audit & Strict `main` Merge Order)**:
  - Open the Module `2` PR (`feat/module-2-intentions-checkout` -> `main`), post the Module Implementation Report, and run the independent Module `2` Review Council subagent (+ `patch-implementer` loop if needed) until `GATE G-REVIEW APPROVED` with 0 issues.
  - **STRICT MERGE ORDER CONSTRAINT TO `main` (`Module 1 -> Module 7 -> Module 2 -> Module 3 -> Module 4 -> Module 5 -> Module 6 -> Module 8`)**: Module `2` MUST be merged into `main` in position **`3rd (Merges to `main` after Module 1 and Module 7; before Module 3, Module 4, Module 5, Module 6, and Module 8)`**—strictly AFTER `Module 1 (`feat/module-1-core-microkernel`), Module 7 (`feat/module-7-webhooks-engine`)` have merged into `main` and BEFORE `Module 3, Module 4, Module 6, Module 8`. Before merging the approved Module `2` PR into `main`, sync/rebase `feat/module-2-intentions-checkout` onto the latest `main` branch so shared manifests (`Cargo.toml`) and top-level exports (`src/lib.rs`, `src/prelude.rs`) preserve all previously merged modules alongside Module `2`, re-run the full verification suite (`cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --all-features`, `cargo test --doc`), and then merge into `main`.
```

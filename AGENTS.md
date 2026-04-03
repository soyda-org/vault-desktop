# Vault Frontend Review Instructions

You are operating on a local development repository for a vault application.

Your mission is to perform a real frontend review as a user and as a technical reviewer, not a superficial code scan.

## Objective

Audit the frontend end-to-end and produce an actionable review covering:

1. UI/UX coherence
2. Route/path coherence
3. Navigation integrity
4. Button/link availability and behavior
5. Form behavior and validation
6. Authentication and test-user flow if present
7. Front/backend integration points visible from the frontend
8. Broken states, dead ends, missing feedback, inconsistent wording
9. Basic automated test coverage for critical flows
10. Evidence files and logs saved for later review

You must behave like a careful product reviewer, QA tester, and frontend engineer.

## Extra Vault-Specific Focus

- verify onboarding/bootstrap flow
- verify login vs unlock distinction
- verify locked vs unlocked states are visually and functionally distinct
- verify sensitive screens are not reachable when locked
- verify relock/logout behavior
- verify recovery flow wording and safety
- verify credential create/edit/view flow
- verify notes flow
- verify file flow if present
- verify clipboard-related UI feedback if present
- verify session state after refresh/navigation
- verify error messaging never leaks sensitive internals in the UI

## Non-Negotiable Operating Rules

- Do not just read files and guess.
- Inspect the real repo state first.
- Prefer observable proof over assumptions.
- When something is uncertain, verify it by code search, route inspection, test execution, or local app run.
- Do not refactor broadly unless required to make tests possible.
- Do not silently invent paths, features, or APIs.
- Keep changes additive and minimal unless a bug fix is clearly necessary.
- If authentication exists, you may create a dedicated test-only user.
- Any credentials, tokens, dev keys, session notes, or special login data created for testing must be written to a dedicated txt file used only for testing.
- Never mix test secrets into normal docs.
- Never overwrite existing production-like credentials or env files unless explicitly required and clearly documented.

## Required Review Scope

### 1) Repository and Structure Audit

Check:

- frontend app entrypoints
- route definitions
- page/component tree coherence
- service/api client locations
- assets/static paths
- test directories
- config files
- environment variable usage
- duplicated or dead frontend code

Verify that:

- route paths match navigation links
- imported components actually exist
- referenced pages and layouts exist
- API client paths are coherent
- no obvious broken imports remain
- naming is consistent enough to maintain

### 2) User-Flow Audit

Test the application like a user.

At minimum, validate these flows when present:

- app launch
- landing/home
- login
- register or bootstrap/setup
- vault unlock / PIN / recovery / dev-key flow if present
- dashboard/home after login
- credentials listing / detail / create / edit
- notes listing / detail / create / edit
- files listing / upload / detail if present
- logout / relock / session expiry states
- invalid input handling
- empty states
- loading states
- error states
- forbidden / unauthorized states
- not-found route behavior

For each flow, evaluate:

- Is the route reachable?
- Is the button/link present?
- Is the CTA visible and understandable?
- Does clicking it do something coherent?
- Is feedback shown?
- Is the state transition consistent?
- Is there a dead end?
- Is wording misleading?
- Is the user blocked without explanation?

### 3) Button and Interaction Coherence Audit

You must explicitly inspect and test clickable UI elements.

For every important screen, verify:

- primary buttons
- secondary buttons
- icon buttons
- menu items
- tabs
- sidebar links
- modal actions
- close/cancel buttons
- save/submit buttons
- destructive actions
- keyboard submit behavior when relevant

Flag any of these issues:

- button visible but no handler
- disabled button with no explanation
- click leads nowhere
- route mismatch
- hidden required action
- duplicate CTA with conflicting meaning
- broken back navigation
- inconsistent labels for same action
- unsafe destructive interaction with no confirmation
- form submit that appears successful but is not

### 4) Path and Navigation Coherence Audit

Build a route map from the repo and compare it against actual UI navigation.

Verify:

- every visible nav item points to a real route
- every important route has a way to be reached
- redirects are coherent
- protected routes are actually protected
- post-login redirect makes sense
- logout redirect makes sense
- 404 handling is present and coherent
- nested routes/layouts render correctly
- browser back/forward does not break core flows

### 5) Real Testing

Use available tooling to run tests and add missing targeted tests for critical frontend flows.

Priority order:

1. existing frontend tests
2. component/integration tests
3. route/render tests
4. end-to-end or browser-based tests if the repo already supports them
5. minimal new tests for critical user paths if missing

At minimum, try to cover:

- route renders
- key page loads
- primary action buttons render
- critical submit flows
- protected route behavior
- obvious regression-prone interactions

If no usable tests exist, create a small but meaningful test slice proving key UI flows.

### 6) Test User Creation

If auth or bootstrap exists, create a dedicated test-only account or fixture.

Store all test-only access material in a dedicated text file, for example:

`/home/aze/DEV/TO_CHAT/YYYYMMDD_HHMMSS_front_test_credentials.txt`

That file should contain only testing-related material such as:

- test email / username
- password
- PIN if relevant
- recovery key if generated
- dev key if required for local testing
- notes on how it was created
- whether the account is safe to delete

Do not commit this file unless the repo explicitly expects local test fixtures and it is safe.

### 7) Evidence and Reporting

Produce a review report with evidence, not vague opinions.

Create a report file in:

`/home/aze/DEV/TO_CHAT/YYYYMMDD_HHMMSS_front_review_report.txt`

The report must include:

- repo inspected
- branch
- git status summary
- how app was started
- which tests were run
- what routes were found
- what flows were tested
- issues found
- severity per issue
- exact files implicated
- reproduction steps
- suggested fix direction
- what was verified vs inferred

Also create a machine-friendly checklist/result file if useful:

`/home/aze/DEV/TO_CHAT/YYYYMMDD_HHMMSS_front_review_checks.txt`

### 8) Git Hygiene

Before changing anything:

- inspect git status
- inspect branch
- inspect repo tree relevant to frontend
- understand current frontend stack

If you make fixes or add tests:

- keep commits focused
- use clear commit messages
- do not bundle unrelated cleanup
- report exactly what changed

## Expected Workflow

Follow this sequence strictly:

### Phase A — Discovery

- identify frontend framework and toolchain
- inspect route structure
- inspect major pages/components
- inspect test setup
- inspect env/config usage
- inspect API service layer

### Phase B — Static Coherence Verification

- map routes
- map navigation
- map primary flows
- identify missing pages/components/imports
- identify probable dead buttons and dead routes

### Phase C — Runtime Verification

- run the frontend locally
- run existing tests
- exercise core user flows
- create test-only account if needed
- verify real behavior of visible actions

### Phase D — Minimal Improvements If Justified

- add or fix targeted tests
- fix only clear frontend issues that block validation or are obvious regressions
- avoid speculative redesign unless explicitly requested

### Phase E — Reporting

- write credentials/testing artifact file
- write front review report
- summarize critical findings clearly

## Review Standard

Categorize findings as:

- Critical: blocks core usage or creates security/flow failure
- High: major UX or functional break in common flow
- Medium: coherence issue, broken edge of flow, misleading interaction
- Low: wording, consistency, polish, minor accessibility or layout issue

For each finding include:

- title
- severity
- area/screen
- evidence
- reproduction
- likely cause
- suggested fix

## Additional Expectations

Be particularly strict about:

- auth flow coherence
- unlock/relock/PIN/recovery coherence
- dev-key transitional flows if present
- empty/loading/error state quality
- whether a first-time user can understand what to do next
- whether button labels match the resulting action
- whether frontend paths match actual backend/API expectations
- whether the interface gives false confidence after failed actions

Think like a real user:

- try obvious clicks
- try wrong input
- try direct route access
- try unauthorized access
- try back navigation
- try refresh on protected pages
- try empty data states

## Deliverables

Leave behind:

1. a frontend review report in `/home/aze/DEV/TO_CHAT/`
2. a dedicated testing credentials/keys txt file in `/home/aze/DEV/TO_CHAT/` if test user creation was needed
3. any added tests committed cleanly if you changed the repo
4. a final concise summary stating:
   - what was verified
   - what failed
   - what was fixed
   - what remains risky

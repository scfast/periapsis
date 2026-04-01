# Testing Strategy

Periapsis now has an in-repo regression strategy designed to make dependency, policy, and vulnerability response work safer to ship. The goal is to catch behavior changes before they merge and to keep policy governance reviewable over time.

## Goals

- Prevent regressions in CLI behavior, policy evaluation, and dependency-scope handling.
- Keep tests self-contained in this repository with no live registry or SaaS dependency.
- Make policy behavior explicit for common governance modes:
  - permissive-only / open license defaults
  - weak copyleft allowed
  - all dependencies versus runtime-only dependencies
  - expiring exceptions and follow-up approvals
- Turn the suite into a required PR gate through GitHub Actions branch protection.

## Test Layers

### 1. Core policy unit tests

File: `test/policy.test.mjs`

Covers pure library logic such as:

- SPDX expression parsing
- category mapping
- dependency-type parsing
- exception range matching
- active versus expired policy records

These are the fastest tests and should grow whenever policy logic changes.

### 2. CLI workflow tests

Files:

- `test/cli.test.mjs`
- `test/commands.test.mjs`

Covers command behavior and file-writing flows such as:

- `licenses allow add`
- `exceptions add`
- `init`
- `policy migrate`
- policy-driven dependency-type defaults

These protect user-facing commands from accidental flag or file-format regressions.

### 3. Fixture-driven regression gate tests

File: `test/regression-gate.test.mjs`

These tests model governed dependency scenarios end to end using temporary fixture projects:

- strict runtime-only policy should ignore disallowed dev dependencies
- all-dependency policy should fail on the same dev dependency
- standard policy should allow weak copyleft
- expired exceptions should fail
- active follow-up exceptions should pass

This is the highest-value layer for future updates to license logic, policy schemas, or dependency traversal.

## NPM Scripts

Use the following scripts locally and in CI:

- `npm test`: full Node test suite
- `npm run test:unit`: core policy engine tests
- `npm run test:cli`: CLI and fixture-driven regression tests
- `npm run policy:check`: run Periapsis against this repository and write `sbom-violations.json`
- `npm run test:ci`: CI entrypoint, currently equivalent to `npm test`

## CI Gate

The GitHub Action should run on `pull_request` and enforce two checks:

1. `test-suite`
   Runs the full automated test suite.

2. `policy-gate`
   Runs Periapsis against the repository itself and uploads `sbom-violations.json`.

Recommended branch protection:

1. Require status checks to pass before merging.
2. Mark `test-suite` as required.
3. Mark `policy-gate` as required.
4. Optionally require the branch to be up to date before merging.

## Dependency Separation

Periapsis runtime code should stay in `dependencies`. Any future tooling used only for verification should stay in `devDependencies` so the shipping package remains small and auditable.

Suggested future additions, if wanted:

- coverage reporting
- linting
- JSON schema fixture validation
- scheduled policy-audit workflow for upcoming exception expirations

Those can be added later without changing the runtime surface area of the CLI.

## Policy Maintenance Rules

When updating dependencies or handling a vulnerability:

1. Change the dependency.
2. Run `npm test`.
3. Run `npm run policy:check`.
4. If policy changes are required, update only the governed files in `policy/`.
5. Prefer adding follow-up license or exception records instead of mutating history in place.

That keeps remediation work auditable and lowers the risk of silently loosening policy.

# Periapsis

Periapsis is a modular governance platform for Node.js projects. It enforces structured, auditable policy across multiple risk domains, failing CI when dependencies or vulnerabilities are not covered by active policy.

Currently Periapsis ships two governance domains: **license governance** (SBOM generation and license compliance gating) and **vulnerability governance** (Dependabot alert SLA tracking and PR pressure). Both domains share a common `policy/` directory, a consistent exception model, and the same `periapsis <domain> <command>` CLI shape.

## Quick Start

Initialize license governance policy:

```sh
npx periapsis license init --preset strict
```

Initialize vulnerability governance policy:

```sh
npx periapsis vulnerability init
```

When working on the `periapsis` repository itself, prefer `node ./bin/periapsis.mjs ...` or `npm run policy:check` so you are exercising the checked-out CLI rather than any previously published copy.

## License Governance

### Install / Run

```sh
npm install
npx periapsis license check --violations-out sbom-violations.json
```

`init` asks which dependency types should be checked by default unless provided via flags:

```sh
npx periapsis license init --preset strict
```

### Policy Files

Periapsis uses governed policy metadata files under `policy/`:

- `policy/policy.json`
- `policy/licenses.json`
- `policy/exceptions.json`

How they work together:

- `policy/policy.json`: global behavior and category fallback policy.
- `policy/licenses.json`: explicit license allow records with audit metadata and expiration.
- `policy/exceptions.json`: package-level overrides when a dependency cannot be covered by license policy alone.

Load behavior:

- Periapsis prefers `policy/` files.
- If `policy/policy.json` is missing, it can temporarily fall back to legacy `allowedConfig.json` (with warning).
- Use `periapsis license policy migrate` to move legacy config into governed policy files.

Validation behavior:

- All `policy/*.json` files are schema-validated on load.
- `licenses allow add` and `license exceptions add` validate the full policy bundle before writing.
- Invalid files fail fast with field-level schema error messages.

#### `policy/policy.json`

```json
{
  "allowedCategories": [
    "Permissive Licenses",
    "Weak Copyleft Licenses"
  ],
  "failOnUnknownLicense": true,
  "timezone": "America/Edmonton",
  "dependencyTypes": [
    "dependencies",
    "devDependencies",
    "peerDependencies",
    "optionalDependencies",
    "bundledDependencies"
  ]
}
```

`dependencyTypes` controls which package groups are checked by default:

- `dependencies`: runtime production packages
- `devDependencies`: development/test/build packages
- `peerDependencies`: host-provided/shared dependencies
- `optionalDependencies`: non-critical optional packages
- `bundledDependencies`: dependencies bundled with the package tarball

#### `policy/licenses.json`

```json
[
  {
    "identifier": "MIT",
    "category": "Permissive Licenses",
    "fullName": "MIT License",
    "notes": "Default permissive license.",
    "rationale": "Permissive, low legal risk for SaaS distribution.",
    "approvedBy": ["security"],
    "approvedAt": "2026-02-13T18:00:00Z",
    "expiresAt": null,
    "evidenceRef": "JIRA-1234"
  }
]
```

#### `policy/exceptions.json`

```json
[
  {
    "package": "@pdftron/pdfjs-express-viewer",
    "scope": { "type": "exact", "version": "8.7.5" },
    "detectedLicenses": ["SEE LICENSE IN LICENSE"],
    "reason": "Commercial dependency required for PDF rendering.",
    "notes": "Revisit annually.",
    "approvedBy": ["legal", "security"],
    "approvedAt": "2026-02-13T18:00:00Z",
    "expiresAt": "2026-08-13T00:00:00Z",
    "evidenceRef": "JIRA-5678"
  }
]
```

Practical authoring rules:

- Keep `package` as package name only (for example `caniuse-lite`), and encode version logic in `scope`.
- Prefer `scope.type = "exact"` for least risk; use `range` carefully; avoid `any` unless necessary.
- Use non-empty `evidenceRef` values that link to a ticket, issue, or approval artifact.
- Do not delete old records to "update" policy; add follow-up records so history stays audit-friendly.

### License Categories

Periapsis uses three license policy categories:

Disclaimer: This section provides operational guidance for engineering policy decisions and is not legal advice. Consult qualified legal counsel for binding interpretation.

#### `Permissive Licenses`

Examples:

- `MIT`
- `BSD`
- `Apache-2.0`

These generally allow:

- Commercial use
- Modification
- Distribution

With minimal obligations, usually attribution.

Typical risk level for most SMEs: Low.

#### `Weak Copyleft Licenses`

Examples:

- `LGPL`

These typically require:

- Sharing modifications to the licensed component
- Following specific distribution rules

Typical risk level: Moderate, depending on usage and distribution model.

#### `Strong Copyleft Licenses`

Examples:

- `GPL`
- `AGPL`

These may require:

- Distribution of source code when software is distributed
- Sharing modifications
- Careful handling to avoid proprietary code exposure

Typical risk level: High in some commercial contexts.

### Interactive Governance Workflows

#### Add an exception

```sh
npx periapsis license exceptions add
```

Prompts include:

- package
- scope (`exact`, `range`, `any`)
- detected license identifiers / expression
- reason (required, multiline)
- notes (optional)
- approvedBy (required, comma-separated)
- approvedAt (default now)
- expiresAt (`ISO datetime` or `never`)
- evidenceRef (required)

If same package+scope exists, Periapsis prompts to add a follow-up record (recommended) or edit the latest record.

#### Add an allowed license

```sh
npx periapsis license allow add
```

Prompts include:

- SPDX identifier (warns if unknown to local SPDX catalog)
- fullName (optional, auto-filled when known)
- notes
- approvedBy
- approvedAt
- expiresAt (`ISO datetime` or `never`)
- category (`Permissive Licenses`, `Weak Copyleft Licenses`, `Strong Copyleft Licenses`, or `Uncategorized / Needs Review`)
- rationale
- evidenceRef

If identifier already exists, Periapsis appends a follow-up record.

#### Non-interactive examples

Add allowed license without prompts:

```sh
npx periapsis license allow add \
  --non-interactive \
  --identifier MIT \
  --approved-by security,legal \
  --category "Permissive Licenses" \
  --rationale "Approved baseline license" \
  --evidence-ref JIRA-1234
```

Add exception without prompts:

```sh
npx periapsis license exceptions add \
  --non-interactive \
  --package caniuse-lite \
  --scope-type exact \
  --version 1.0.30001767 \
  --reason "Reviewed and accepted by security" \
  --approved-by security \
  --expires-at 2027-02-13T00:00:00.000Z \
  --evidence-ref JIRA-5678
```

Run checker against only production dependencies:

```sh
npx periapsis license check --production-only
```

Run checker against a custom dependency set:

```sh
npx periapsis license check --dep-types dependencies,peerDependencies
```

### Expiration and Follow-up Behavior

A policy record is active when:

- `expiresAt` is `null`, or
- `expiresAt` is later than current time (UTC comparison)

Evaluation rules:

- If an active explicit license record exists for an SPDX identifier, that license is allowed (record category is metadata and does not gate the decision).
- If no explicit license record exists, SPDX category fallback uses `policy.allowedCategories`.
- SPDX expressions are parsed structurally (for example `MIT OR Apache-2.0`) before evaluating allow rules.
- If only expired records match and no active follow-up exists, this is a violation.
- Exceptions support `exact`, `range` (semver), and `any` scopes.
- If a violation is covered by an active exception, gate passes for that package.
- If only expired exception records match and no active follow-up exists, gate fails.

Violation messages include expired record details and remediation commands.

### Troubleshooting Large Violation Sets

When you get a large burst of violations, use this order to reduce noise quickly:

1. Confirm you are running the expected CLI version.
2. Confirm policy files are being read from the expected repo/path.
3. Group by `Type` in the output and fix one class at a time.

Quick checks:

- If many rows show `license-not-allowed`, add explicit records via `periapsis license allow add` for the most common licenses first (`MIT`, `Apache-2.0`, `ISC`, `BSD-3-Clause`).
- If many rows show `expired-license-policy` or `expired-exception`, add follow-up records instead of editing/deleting old records.
- If one package appears repeatedly blocked across versions, prefer a targeted exception with `scope.type = "range"` or `exact`.
- If unknown license expressions are noisy and expected, decide whether to keep strict mode or set `failOnUnknownLicense` to `false` in `policy/policy.json`.
- If a command fails with schema validation errors, fix the specific field path reported, then rerun.
- If violations are mostly from test/build tooling, start with `--production-only`, then expand scope incrementally.

Recommended triage workflow:

1. Run `npx periapsis license check --violations-out sbom-violations.json`.
2. Count by license in `sbom-licenses.json` and prioritize highest-frequency licenses.
3. Add 1-3 high-impact explicit license records.
4. Re-run and verify violation count drops.
5. Add narrowly scoped exceptions only for true outliers.

Team process tips:

- Treat `licenses.json` as strategic policy (broad impact) and `exceptions.json` as tactical policy (narrow impact).
- Require CODEOWNERS/legal-security review for policy edits.
- Add expirations intentionally, then renew with follow-up records before they expire.

## Vulnerability Governance

Periapsis tracks Dependabot alerts against SLA policy and optionally pressures PRs when breaches exist. Data source is the GitHub Dependabot API; a `GITHUB_TOKEN` with access to Dependabot alerts is required.

### Initialize

```sh
npx periapsis vulnerability init
```

Creates in `policy/`:

- `vulnerability-policy.json` — SLA days, rollout mode, PR check config, exception rules
- `vulnerability-exceptions.json` — accepted breach exceptions
- `vulnerability-owners.json` — alert ownership assignments
- `vulnerability-notifications.json` — notification channel config

Also writes three GitHub Actions workflow files under `.github/workflows/`:

- `periapsis-vulnerability-daily.yml` — scheduled check + notify
- `periapsis-vulnerability-pr-check.yml` — PR gate
- `periapsis-vulnerability-exception-request.yml` — workflow-dispatch driven exception creation

### Policy Structure

Default `policy/vulnerability-policy.json`:

```json
{
  "version": 1,
  "rollout": {
    "enabled": true,
    "gracePeriodUntil": null,
    "mode": "observe"
  },
  "slaDays": {
    "critical": 3,
    "high": 30,
    "medium": 60,
    "low": 100
  },
  "warningThresholdDays": {
    "critical": 1,
    "high": 7,
    "medium": 14,
    "low": 30
  },
  "prCheck": {
    "enabled": true,
    "failOnBreach": true,
    "advisoryOnly": true,
    "minimumSeverity": "high"
  },
  "exceptions": {
    "requireApproval": true,
    "maxDurationDays": 90,
    "allowPackageScope": true,
    "allowRepoWideScope": true,
    "allowOrgWideScope": false
  }
}
```

`slaDays` defines the maximum number of days an open alert at each severity level can remain unresolved before it is considered breached. `warningThresholdDays` controls how early the approaching-due warning state begins.

`prCheck.advisoryOnly`: when `true`, the PR check posts a summary comment but does not fail the check run. Set to `false` to enforce a hard gate. `prCheck.minimumSeverity` controls the lowest severity level that triggers PR pressure.

### Rollout Modes

`rollout.mode` controls how the vulnerability gate behaves:

- `observe`: evaluate alerts and report results; never fail CI or pressure PRs.
- `notify`: evaluate alerts and send Slack/owner notifications on breach; CI does not fail.
- `pressure`: evaluate alerts; post advisory PR comments when breaches exist; CI does not fail (equivalent to `advisoryOnly: true` on PRs).
- `enforce`: evaluate alerts; fail CI on breach (`process.exitCode = 1`); PR check respects `prCheck.failOnBreach` and `prCheck.advisoryOnly`.

Start with `observe` to understand your current alert state before moving to `enforce`. Use `rollout.gracePeriodUntil` (ISO datetime) to defer failure for pre-existing alerts during a transition.

### Advisory PR Pressure

When `prCheck.enabled` is `true` and `prCheck.advisoryOnly` is `true`, every PR receives a markdown comment summarizing any SLA-breached alerts at or above `minimumSeverity`. The PR check run itself does not fail. This lets teams adopt visibility incrementally before enabling hard enforcement.

To switch to hard enforcement, set both `prCheck.advisoryOnly: false` and `rollout.mode: "enforce"`.

### Adding Exceptions

Exceptions accept a specific alert, a package, a repo-wide severity, or an entire ecosystem. All exceptions require an expiry date; indefinite exceptions are not allowed.

Exception types: `alert`, `package`, `repo_severity`, `ecosystem`.

Non-interactive example (package-scoped exception):

```sh
npx periapsis vulnerability exceptions add \
  --non-interactive \
  --repo owner/my-repo \
  --type package \
  --package lodash \
  --ecosystem npm \
  --severities high,critical \
  --reason "Upstream fix not yet available; mitigated by WAF rule." \
  --accepted-until 2026-09-01T00:00:00Z \
  --approved-by security \
  --evidence-ref JIRA-9999
```

Non-interactive example (alert-scoped exception):

```sh
npx periapsis vulnerability exceptions add \
  --non-interactive \
  --repo owner/my-repo \
  --type alert \
  --alert-number 42 \
  --severities critical \
  --reason "False positive confirmed by security team." \
  --accepted-until 2026-07-01T00:00:00Z \
  --approved-by security \
  --evidence-ref JIRA-8888
```

Exception IDs are auto-generated in the format `VEX-<year>-<sequence>` (for example `VEX-2026-001`).

### Running Checks

Evaluate current Dependabot alert SLA status:

```sh
npx periapsis vulnerability check
npx periapsis vulnerability check --report   # also write JSON report files
```

Run PR check (posts markdown summary, exits non-zero if `advisoryOnly: false` and breaches exist):

```sh
npx periapsis vulnerability pr-check
```

Send owner/Slack notifications for breached alerts:

```sh
npx periapsis vulnerability notify
```

Generate vulnerability report files:

```sh
npx periapsis vulnerability report
```

Validate policy and exception files against schema:

```sh
npx periapsis vulnerability validate
```

### Required Environment Variables

- `GITHUB_TOKEN` (required for `check`, `pr-check`, `notify`, `report`): needs read access to Dependabot alerts.

  The generated workflows use `${{ secrets.PERIAPSIS_GITHUB_TOKEN || secrets.GITHUB_TOKEN }}`. This means:
  - If `PERIAPSIS_GITHUB_TOKEN` is set as a repository or organisation secret, it is used.
  - Otherwise the built-in `GITHUB_TOKEN` is used as a fallback.

  **Why a dedicated secret?** The built-in `GITHUB_TOKEN` in GitHub Actions has `security-events: read` in the workflow permissions block, but this maps to code scanning access — not Dependabot alerts. On many organisations the built-in token returns `403 Resource not accessible by integration` when calling the Dependabot alerts API. A dedicated fine-grained PAT with the correct permission avoids this.

  | Context | How to get a token |
  | --- | --- |
  | GitHub Actions (recommended) | Create a fine-grained PAT with **Dependabot alerts: Read**. Store it as a repo/org secret named `PERIAPSIS_GITHUB_TOKEN`. |
  | GitHub Actions (fallback) | Built-in `GITHUB_TOKEN` with `security-events: read` — works on some org configurations, not all. |
  | Local / CLI | Fine-grained PAT with **Dependabot alerts: Read**. Set as `GITHUB_TOKEN` env var. |
  | Classic PAT | `repo` scope covers it, though broader than needed. |

  Fine-grained PAT setup: resource owner → your org, repository access → the target repo, repository permissions → **Dependabot alerts: Read**. If your org requires approval for fine-grained PATs, approve it under org Settings → Personal access tokens.

- `PERIAPSIS_SLACK_WEBHOOK` (optional): Slack incoming webhook URL used by `notify` to post breach summaries. `VULN_SLA_SLACK_WEBHOOK` is also accepted as an alias.

  To get a webhook URL:
  1. Go to [api.slack.com/apps](https://api.slack.com/apps) → **Create New App** → **From scratch**
  2. Under **Features** → **Incoming Webhooks** → toggle on → **Add New Webhook to Workspace**
  3. Pick the channel to post to and authorise
  4. Copy the webhook URL (`https://hooks.slack.com/services/T.../B.../...`)
  5. Store it as `PERIAPSIS_SLACK_WEBHOOK` in your repo secrets

  `notify` is a no-op when the webhook is not set and when no alerts are breached or approaching SLA — no noise on clean days.

  Test locally before publishing:

  ```sh
  cd /path/to/target-repo
  GITHUB_TOKEN=your_pat \
  PERIAPSIS_SLACK_WEBHOOK=https://hooks.slack.com/services/your/webhook/url \
  node /path/to/periapsis/bin/periapsis.mjs vulnerability notify
  ```

Pass `--repo owner/repo` to override the repository detected from the local git remote.

## Command Reference

The preferred CLI form is `periapsis <domain> <subcommand>`. Legacy top-level aliases still work and will print a deprecation hint pointing to the preferred form.

### License domain

```
periapsis license check [--violations-out <file>] [--production-only] [--dep-types <csv>]
periapsis license init --preset <strict|standard|permissive> [--policy-dir policy] [--force]
periapsis license exceptions add [--policy-dir policy]
periapsis license allow add [--policy-dir policy]
periapsis license policy migrate [--from allowedConfig.json] [--policy-dir policy] [--force]
```

Non-interactive flags for `license exceptions add`:

```
--non-interactive
--package <name>
--scope-type <exact|range|any>
--version <value>           (required when --scope-type=exact)
--range <value>             (required when --scope-type=range)
--detected-licenses <csv>
--reason <text>
--notes <text>
--approved-by <csv>
--approved-at <iso>
--expires-at <iso|never>
--evidence-ref <value>
--edit-existing
```

Non-interactive flags for `license allow add`:

```
--non-interactive
--identifier <spdx>
--full-name <name>
--notes <text>
--approved-by <csv>
--approved-at <iso>
--expires-at <iso|never>
--category <name>
--rationale <text>
--evidence-ref <value>
```

### Vulnerability domain

```
periapsis vulnerability init [--policy-dir policy] [--force]
periapsis vulnerability check [--report] [--repo owner/repo]
periapsis vulnerability pr-check [--repo owner/repo]
periapsis vulnerability notify [--repo owner/repo]
periapsis vulnerability report [--repo owner/repo]
periapsis vulnerability validate [--policy-dir policy]
periapsis vulnerability exceptions add --non-interactive ...
```

Non-interactive flags for `vulnerability exceptions add`:

```
--non-interactive
--repo <owner/repo>
--type <alert|package|repo_severity|ecosystem>
--alert-number <n>          (required when --type=alert)
--package <name>            (required when --type=package)
--ecosystem <name>          (required when --type=package or --type=ecosystem)
--dependency-scope <prod|dev|unknown>
--severities <csv>
--reason <text>
--accepted-until <iso>
--approved-by <csv>
--evidence-ref <value>
--created-by <name>
```

### Legacy aliases (still supported)

```
periapsis init              -> periapsis license init
periapsis exceptions add    -> periapsis license exceptions add
periapsis licenses allow add -> periapsis license allow add
periapsis policy migrate    -> periapsis license policy migrate
periapsis                   -> periapsis license check
```

## Exception Storage

Each domain owns its own exception file:

- `policy/exceptions.json` — license exceptions (package-level overrides)
- `policy/vulnerability-exceptions.json` — vulnerability SLA exceptions (VEX records)

Keep these files in version control and protect them with CODEOWNERS review. Do not delete old records; append follow-up records so decision history is preserved.

## GitHub Actions

### License gate

```yaml
- uses: actions/checkout@v4
- uses: actions/setup-node@v4
  with:
    node-version: 20
    cache: npm
- run: npm ci
- run: npx periapsis license check --violations-out sbom-violations.json
```

### Vulnerability daily check

```yaml
- uses: actions/checkout@v4
- name: Install periapsis
  run: npm install -g periapsis
- name: Run vulnerability governance check
  run: periapsis vulnerability check --report
  env:
    GITHUB_TOKEN: ${{ secrets.PERIAPSIS_GITHUB_TOKEN || secrets.GITHUB_TOKEN }}
- name: Upload vulnerability report
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: vulnerability-report
    path: policy/reports/
    retention-days: 90
- name: Send vulnerability notifications
  run: periapsis vulnerability notify
  env:
    GITHUB_TOKEN: ${{ secrets.PERIAPSIS_GITHUB_TOKEN || secrets.GITHUB_TOKEN }}
    PERIAPSIS_SLACK_WEBHOOK: ${{ secrets.PERIAPSIS_SLACK_WEBHOOK }}
- name: Read breach count from report
  id: report
  run: |
    REPORT=$(ls policy/reports/vulnerability-report-*.json 2>/dev/null | sort | tail -n1)
    if [ -z "$REPORT" ]; then
      echo "breached=0" >> $GITHUB_OUTPUT
    else
      BREACHED=$(node -e "const r=JSON.parse(require('fs').readFileSync('$REPORT','utf8')); process.stdout.write(String(r.summary.breached))")
      echo "breached=$BREACHED" >> $GITHUB_OUTPUT
      echo "md=${REPORT%.json}.md" >> $GITHUB_OUTPUT
    fi
- name: Send breach notification email
  if: steps.report.outputs.breached != '0'
  uses: dawidd6/action-send-mail@v3
  with:
    server_address: ${{ secrets.PERIAPSIS_SMTP_HOST }}
    server_port: ${{ secrets.PERIAPSIS_SMTP_PORT || 587 }}
    username: ${{ secrets.PERIAPSIS_SMTP_USER }}
    password: ${{ secrets.PERIAPSIS_SMTP_PASSWORD }}
    subject: "[${{ github.repository }}] ${{ steps.report.outputs.breached }} vulnerability SLA breach(es) detected"
    to: ${{ secrets.PERIAPSIS_EMAIL_TO }}
    from: ${{ secrets.PERIAPSIS_EMAIL_FROM || secrets.PERIAPSIS_SMTP_USER }}
    body: file://${{ steps.report.outputs.md }}
```

The email step only fires when the report contains at least one breached alert. The markdown report (written by `periapsis vulnerability check --report`) is used as the email body.

Required secrets for email:

| Secret | Description |
| --- | --- |
| `PERIAPSIS_SMTP_HOST` | SMTP server hostname |
| `PERIAPSIS_SMTP_PORT` | SMTP port (optional, defaults to 587) |
| `PERIAPSIS_SMTP_USER` | SMTP username |
| `PERIAPSIS_SMTP_PASSWORD` | SMTP password or app password |
| `PERIAPSIS_EMAIL_TO` | Recipient address(es), comma-separated |
| `PERIAPSIS_EMAIL_FROM` | Sender address (optional, defaults to SMTP username) |

### Vulnerability PR check

```yaml
- uses: actions/checkout@v4
- name: Install periapsis
  run: npm install -g periapsis
- name: Run vulnerability PR check
  run: periapsis vulnerability pr-check
  env:
    GITHUB_TOKEN: ${{ secrets.PERIAPSIS_GITHUB_TOKEN || secrets.GITHUB_TOKEN }}
```

`periapsis vulnerability init` writes all three workflow files automatically.

If you add an inline `node -e` follow-up check in GitHub Actions, wrap the JavaScript in single quotes. Backticks inside a double-quoted shell string are treated as command substitution by `bash`.

When license violations exist, Periapsis exits non-zero and prints a deterministic markdown summary suitable for Actions logs.

## Testing

### Unit and integration tests

Run the regression suite:

```sh
npm test
```

This covers all domains including legacy alias behaviour. Legacy aliases are tested in `test/aliases.test.mjs` — do not remove that file or modify the routing block in `bin/periapsis.mjs` without updating the alias tests.

Run the repository policy gate locally:

```sh
npm run policy:check
```

### Testing against another repository

To exercise the CLI against a real repo before publishing:

```sh
# From the periapsis directory — build a local tarball
npm pack
cp periapsis-*.tgz /path/to/target-repo/periapsis-local.tgz

# From the target repo
cd /path/to/target-repo
GITHUB_TOKEN=your_pat node /path/to/periapsis/bin/periapsis.mjs vulnerability check
GITHUB_TOKEN=your_pat node /path/to/periapsis/bin/periapsis.mjs vulnerability check --report
GITHUB_TOKEN=your_pat node /path/to/periapsis/bin/periapsis.mjs vulnerability pr-check
node /path/to/periapsis/bin/periapsis.mjs vulnerability validate
```

### Testing GitHub Actions workflows locally with `act`

Install [`act`](https://github.com/nektos/act) to run the generated workflows without pushing to GitHub. The generated workflows use `npx periapsis`, which pulls from npm. For local dev testing, use the `-local` variant workflows described below.

**Setup (once per periapsis build):**

```sh
cd /path/to/periapsis
npm pack
cp periapsis-*.tgz /path/to/target-repo/periapsis-local.tgz
```

Add to the target repo's `.gitignore`:

```
periapsis-local.tgz
.github/workflows/*-local.yml
policy/reports/
```

**Create local workflow variants** in `.github/workflows/` that install from the tarball instead of `npx`:

```yaml
- name: Install local periapsis
  run: npm install -g ./periapsis-local.tgz
# then use `periapsis` instead of `npx periapsis` in subsequent steps
```

**Daily check workflow:**

```sh
act workflow_dispatch \
  -W .github/workflows/periapsis-vulnerability-daily-local.yml \
  --secret GITHUB_TOKEN=your_pat \
  --bind
```

**Exception request workflow** (omit the `create-pull-request` step from the local variant):

```sh
act workflow_dispatch \
  -W .github/workflows/periapsis-vulnerability-exception-request-local.yml \
  --secret GITHUB_TOKEN=your_pat \
  --bind \
  --input repo=owner/repo \
  --input alertNumber=1 \
  --input exceptionType=alert \
  --input severities=medium \
  --input reason="Testing exception workflow" \
  --input acceptedUntil=2026-09-01 \
  --input approvedBy=approver@example.com \
  --input evidenceRef=JIRA-0000
```

**PR check workflow:**

```sh
act workflow_dispatch \
  -W .github/workflows/periapsis-vulnerability-pr-check-local.yml \
  --secret GITHUB_TOKEN=your_pat \
  --bind
```

Use `--bind` so that gitignored files (including `periapsis-local.tgz`) are available inside the container. Rerun `npm pack && cp` after every periapsis code change — the container uses the tarball, not the source files directly.

**Fine-grained PAT requirements for local workflow testing:**

| Permission | Required for |
| --- | --- |
| Dependabot alerts: Read | `check`, `pr-check`, `notify`, `report` |
| Contents: Read and Write | Exception request PR branch push |
| Pull requests: Read and Write | Exception request PR creation |

Store this PAT as a repository secret named `PERIAPSIS_GITHUB_TOKEN`. The generated workflows prefer this secret over the built-in `GITHUB_TOKEN` because the built-in token does not reliably grant Dependabot alerts access across all GitHub organisation configurations.

Set the PAT resource owner to the target organisation, and ensure the specific repository is included in the PAT's repository access list.

## Governance Recommendations

Protect all policy changes with CODEOWNERS review:

```txt
/policy/* @security-team @legal-team
```

Use expiring entries plus follow-up records to preserve decision history without overwriting prior approvals.

For vulnerability governance, start with `rollout.mode: "observe"` to establish a baseline, then move through `notify` and `pressure` before enabling `enforce`. Set `rollout.gracePeriodUntil` to a future date to give teams time to remediate pre-existing alerts before CI starts failing.

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
  },
  "triage": {
    "mode": "recommend",
    "notify": ["slack", "email"],
    "apply": {
      "minimumConfidence": "high",
      "minimumConfidenceSingleStep": "medium",
      "allowedReachability": ["not_reachable", "potentially_reachable"],
      "approvedBy": ["periapsis-triage"],
      "workflow": "periapsis-vulnerability-exception-request.yml",
      "ref": null
    },
    "automation": {
      "minimumSeverity": "high",
      "scopes": ["runtime", "development"],
      "maxTriagesPerRun": 10,
      "retriageAfterDays": 30,
      "skipAlerts": []
    }
  }
}
```

The `triage` block is optional (older policy files use these defaults); see [AI-Assisted Triage](#ai-assisted-triage).

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

#### Severity adjustments

An alert-scoped exception can carry `adjustedSeverity` (CLI: `--adjusted-severity`) to re-rate an alert instead of waiving a breach. While it is active, SLA evaluation uses the adjusted severity, so the due date becomes `created_at + slaDays[adjustedSeverity]`, and reports show `medium (adjusted from high by VEX-2026-004)`.

- Only downgrades are allowed: `adjustedSeverity` must be lower than every entry in `--severities`.
- It matches only while Dependabot still reports one of `--severities`; if the advisory is re-rated, the adjustment stops applying.
- It never acts as a breach waiver. When `acceptedUntil` passes, the alert reverts to its Dependabot severity.

Severity adjustments are what triage `apply` mode requests (see below), but they can also be added by hand.

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

### AI-Assisted Triage

Dependabot severity comes from the advisory's generic CVSS score, not from how *your* code uses the package. `periapsis vulnerability triage` challenges that label: it gathers evidence from the repository and asks an LLM to re-assess the risk in context. Run it for one alert (`--alert <n>`), or let it work through the open-alert backlog on a schedule (`--pending`, see [Automated triage](#automated-triage)).

```sh
export GITHUB_TOKEN=...                 # Dependabot alerts: Read
export ANTHROPIC_API_KEY=...            # or OPENAI_API_KEY / GEMINI_API_KEY
npx periapsis vulnerability triage --alert 42
```

What it does:

1. Fetches Dependabot alert `#42` (advisory text, CVSS, CWEs, vulnerable range, patched version, dependency scope).
2. Collects repository evidence locally:
   - dependency chains from `package-lock.json` (npm), so transitive packages are traced to the top-level dependency that pulls them in;
   - manifest lines that reference the package;
   - every source file that imports the package (or its top-level parent), with line-numbered excerpts of the import and of the lines that use the imported names.
3. Sends one structured request to the configured model and validates the JSON response.
4. Prints a markdown summary (also appended to `$GITHUB_STEP_SUMMARY` in Actions) and writes `policy/triage/alert-<n>.json` and `.md`.

The result contains `recommendedSeverity` (critical/high/medium/low), `severityChange` versus Dependabot (`downgrade`/`upgrade`/`unchanged`), `reachability` (`reachable`, `potentially_reachable`, `not_reachable`, `unknown`), `confidence`, a rationale, cited evidence (`file:line`), exploit preconditions and recommended actions.

The model's output is advisory: triage itself never edits policy files. What happens next is controlled by `triage` in `vulnerability-policy.json`.

#### Recommend and apply modes

| `triage.mode` | Behaviour |
| --- | --- |
| `recommend` (default) | Sends the result to the configured channels. For a downgrade, the message includes the exact severity adjustment and expiry to request, and a ready-to-run `exceptions add` command. A developer decides and acts. |
| `apply` | When every gate below passes, requests the severity adjustment through a pull request; the adjustment takes effect once someone reviews and merges it. Single-alert runs dispatch the **Periapsis Vulnerability Exception Request** workflow; `--pending` runs add all of the run's adjustments to one PR (see [Automated triage](#automated-triage)). When a gate fails, it falls back to `recommend` and the message lists why. Re-triaging an alert whose active adjustment is no longer supported (rated higher, or now `reachable`) is reported as a **regression**; adjustments are never removed or renewed automatically. |

Override the mode for a single run with `--mode recommend|apply` (or the `mode` input on the triage workflow).

Apply gates (all must pass):

- the recommendation is a **downgrade** (upgrades and unchanged ratings are always sent as recommendations, and upgrades are flagged as needing attention);
- `result.confidence` is at least `triage.apply.minimumConfidenceSingleStep` (default `medium`) for a one-level downgrade such as high → medium, or `triage.apply.minimumConfidence` (default `high`) for larger drops;
- `result.reachability` is in `triage.apply.allowedReachability` (default `not_reachable`, `potentially_reachable`);
- the alert is open and has no active severity adjustment already;
- the adjusted SLA has not already elapsed.

What `apply` requests:

| Exception field | Value |
| --- | --- |
| `type` / `alertNumber` | `alert` / the triaged alert |
| `severities` | the Dependabot severity |
| `adjustedSeverity` | the recommended severity |
| `acceptedUntil` | `min(alert created_at + slaDays[adjustedSeverity], now + exceptions.maxDurationDays)` |
| `reason` | provider/model, severity change, reachability, confidence and the model's summary |
| `evidenceRef` | link to the triage workflow run (job summary + `vulnerability-triage-<n>` artifact); `policy/triage/alert-<n>.md` when run locally |
| `approvedBy` | `triage.apply.approvedBy` (default `periapsis-triage`); the human approval is the PR review |

`triage.apply.workflow` names the workflow to dispatch and `triage.apply.ref` the branch to run it on (default: the branch the triage ran on, else the repository default branch).

#### Notifications

`triage.notify` lists the channels for triage results (default `["slack", "email"]`; `[]` disables them, as does `--no-notify` for one run):

- `slack`: posted by the CLI to `PERIAPSIS_SLACK_WEBHOOK` (skipped with a log line when unset).
- `email`: sent by the triage workflow's SMTP step using the same `PERIAPSIS_SMTP_*` / `PERIAPSIS_EMAIL_*` secrets as the daily check; the body is the triage markdown. In GitHub Actions the CLI writes `email`, `subject`, `report` and `status` step outputs for that step.

To act on a recommendation by hand, run the Exception Request workflow or the command included in the message.

#### Automated triage

`periapsis vulnerability triage --pending` works through open alerts without repeating work. The generated triage workflow runs it daily (and when dispatched without an alert number).

Each run:

1. Fetches all open alerts. Fixed or dismissed alerts drop out here, and are removed from the ledger, at no LLM cost.
2. Keeps alerts that match `triage.automation`: `minimumSeverity` (default `high`), `scopes` (`runtime`, `development`), and not listed in `skipAlerts`.
3. Groups them by package and makes **one LLM call per package** covering all its advisories, since they share the same code evidence.
4. Skips packages whose previous verdicts still hold, using the **triage ledger** (`policy/triage/ledger.json`). A package is re-triaged when an alert is new, when its fingerprint changed, or when its verdict is older than `retriageAfterDays` (default 30). The fingerprint covers the advisory text, severity and `updated_at`, the installed versions and dependency chains, the code evidence, the model, and the prompt version.
5. Ranks what is due (never triaged, then changed, then expired; within each, highest severity, then closest to SLA breach) and triages at most `maxTriagesPerRun` packages (default 10). The rest are queued for later runs.
6. Writes per-alert reports and a run digest (`policy/triage/digest.md`, also the job summary). It sends one Slack digest, and email if configured, only when something notable happened: new or changed verdicts, applied adjustments, regressions or errors.
7. In `apply` mode, writes every approved adjustment to `policy/vulnerability-exceptions.json`. The workflow then opens **a single pull request** for the run. Opening one PR per alert would conflict on that file.

Manual `--alert` runs are recorded in the ledger too, so the schedule won't repeat them. Preview a run with `--pending --dry-run`; it needs no LLM key and writes nothing.

In GitHub Actions the ledger is stored as the `periapsis-triage-ledger` workflow artifact. Each run restores the newest copy and uploads the updated one, and runs are serialised with a concurrency group. If the artifact is missing (first run, or no run for 90 days), triage starts fresh, and the per-run cap bounds the cost.

#### LLM configuration

| Variable / flag | Purpose |
| --- | --- |
| `PERIAPSIS_LLM_PROVIDER` / `--provider` | `anthropic` (alias `claude`), `openai`, or `gemini` (alias `google`). Optional when a provider-specific key below is set. |
| `PERIAPSIS_LLM_API_KEY` | API key for the selected provider. Requires a provider to be set. |
| `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY` / `GOOGLE_API_KEY` | Provider-specific fallbacks. If no provider is set, the first one found (in this order) is used. |
| `PERIAPSIS_LLM_MODEL` / `--model` | Model override. Defaults: `claude-opus-5-5`, `gpt-5`, `gemini-2.5-pro`. |

API keys are read only from the environment, never from CLI flags.

Other flags: `--pending`, `--ledger <file>`, `--mode recommend|apply`, `--no-notify`, `--repo owner/repo`, `--max-files <n>` (default 20) and `--max-chars <n>` (default 60000) to bound how much code is sent, and `--dry-run` to print the exact prompt without calling a model (no LLM key needed).

#### Data sent to the provider

Triage sends the advisory text plus code excerpts from your repository to a third-party LLM API. Before enabling it, make sure that is acceptable under your organisation's data-handling policy, and use `--dry-run` to inspect exactly what would be sent. To limit exposure:

- only git-tracked source and manifest files are considered (falls back to a directory walk outside git);
- `node_modules`, build output, vendored directories and likely-secret files (`.env*`, `*.pem`, `*.key`, `.npmrc`, credentials files, SSH keys) are always excluded;
- only excerpts around import and usage sites are sent, capped by `--max-files` / `--max-chars`.

#### Limitations

- Evidence gathering is static and text-based: it follows imported names within a file, but not values passed across files or into a parent package's internals. When evidence is thin, the model is instructed to answer `unknown` / low confidence rather than guess.
- Dependency chains are computed for npm only; other ecosystems still get manifest and usage-site evidence.
- LLM output can be wrong. Treat the recommendation as a starting point for review, not a decision.

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

- `PERIAPSIS_LLM_PROVIDER`, `PERIAPSIS_LLM_API_KEY`, `PERIAPSIS_LLM_MODEL` (optional, `triage` only): see [AI-Assisted Triage](#ai-assisted-triage).

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
periapsis vulnerability init [--policy-dir policy] [--force | --workflows-only]
periapsis vulnerability check [--report] [--repo owner/repo]
periapsis vulnerability pr-check [--repo owner/repo]
periapsis vulnerability notify [--repo owner/repo]
periapsis vulnerability report [--repo owner/repo]
periapsis vulnerability validate [--policy-dir policy]
periapsis vulnerability triage (--alert <n> | --pending) [--ledger <file>] [--repo owner/repo] [--mode recommend|apply] [--no-notify] [--provider <name>] [--model <id>] [--max-files <n>] [--max-chars <n>] [--dry-run]
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
--adjusted-severity <severity>  (alert type only; must be lower than --severities)
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

### Vulnerability triage

`periapsis-vulnerability-triage.yml` runs daily and from **Actions → Periapsis Vulnerability Triage → Run workflow**, with an optional alert number and an optional `mode` override (`policy`, `recommend`, `apply`).

- **Without an alert number**, it runs `triage --pending`: restores the ledger artifact, triages what is due, saves the ledger, and in `apply` mode validates the policy and opens one PR with the run's adjustments.
- **With an alert number**, it triages that alert, and in `apply` mode dispatches the exception request workflow.

Both write the job summary, upload per-alert reports as `vulnerability-triage-<run id>`, post to Slack, and email when SMTP is configured. Change the `cron` line to adjust the schedule.

Setup:

| Name | Kind | Purpose |
| --- | --- | --- |
| `PERIAPSIS_LLM_API_KEY` | secret | LLM API key (or `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` / `GEMINI_API_KEY`, which are also passed through) |
| `PERIAPSIS_LLM_PROVIDER` | variable | `anthropic`, `openai` or `gemini` |
| `PERIAPSIS_LLM_MODEL` | variable (optional) | model override |
| `PERIAPSIS_SLACK_WEBHOOK` | secret (optional) | Slack notifications |
| `PERIAPSIS_SMTP_HOST`, `PERIAPSIS_SMTP_PORT`, `PERIAPSIS_SMTP_USER`, `PERIAPSIS_SMTP_PASSWORD`, `PERIAPSIS_EMAIL_TO`, `PERIAPSIS_EMAIL_FROM` | secrets (optional) | email; the step is skipped when `PERIAPSIS_SMTP_HOST` is unset |

Permissions: `actions: write` (restore the ledger artifact, dispatch single-alert exception requests), and `contents: write` + `pull-requests: write` (open the batch adjustment PR). If you set `PERIAPSIS_GITHUB_TOKEN`, the CLI uses it instead of the built-in token, so for single-alert `apply` it also needs **Actions: Read and write** in addition to **Dependabot alerts: Read**. The ledger restore and the batch PR always use the built-in token.

PRs are opened with the built-in token: enable **Settings → Actions → General → Allow GitHub Actions to create and approve pull requests** (also at the organization level, if set there). As with manually requested exceptions, PR checks may not run on these PRs automatically.

### Updating generated workflows

`periapsis vulnerability init --workflows-only` rewrites the four workflow files from the installed version's templates without touching `policy/`. Run it after upgrading Periapsis: triage `apply` mode needs the current exception request workflow (it adds the `adjustedSeverity` input and a per-run PR branch), and dispatching to an older copy fails with `Unexpected inputs provided`.

`periapsis vulnerability init` writes all four workflow files automatically.

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

# Periapsis

License compliance gate for Node.js dependencies. Periapsis reads `package-lock.json` + installed `node_modules`, writes an SBOM, and fails CI when dependency licenses are not covered by active policy.

## Install / Run

```sh
npm install
npx periapsis --violations-out sbom-violations.json
```

Initialize governed policy files:

```sh
npx periapsis init --preset strict
```

`init` now asks which dependency types should be checked by default (unless provided via flags).

## Commands

- `periapsis`: run SBOM + license gate
- `periapsis init --preset <strict|standard|permissive> [--policy-dir policy] [--force]`
- `periapsis exceptions add [--policy-dir policy]` (interactive)
- `periapsis licenses allow add [--policy-dir policy]` (interactive)
- `periapsis policy migrate [--from allowedConfig.json] [--policy-dir policy] [--force]`

Automation mode:

- `periapsis exceptions add --non-interactive ...`
- `periapsis licenses allow add --non-interactive ...`
- `periapsis --dep-types dependencies,peerDependencies`
- `periapsis --production-only` (same as `--dep-types dependencies`)

## Policy Files

Periapsis now uses governed policy metadata files under `policy/`:

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
- Use `periapsis policy migrate` to move legacy config into governed policy files.

Validation behavior:

- All `policy/*.json` files are schema-validated on load.
- `licenses add` and `exceptions add` validate the full policy bundle before writing.
- Invalid files fail fast with field-level schema error messages.

### `policy/policy.json`

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

### `policy/licenses.json`

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

### `policy/exceptions.json`

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
- Do not delete old records to “update” policy; add follow-up records so history stays audit-friendly.

## License Categories

Periapsis uses three license policy categories:

Disclaimer: This section provides operational guidance for engineering policy decisions and is not legal advice. Consult qualified legal counsel for binding interpretation.

### `Permissive Licenses`

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

### `Weak Copyleft Licenses`

Examples:

- `LGPL`

These typically require:

- Sharing modifications to the licensed component
- Following specific distribution rules

Typical risk level: Moderate, depending on usage and distribution model.

### `Strong Copyleft Licenses`

Examples:

- `GPL`
- `AGPL`

These may require:

- Distribution of source code when software is distributed
- Sharing modifications
- Careful handling to avoid proprietary code exposure

Typical risk level: High in some commercial contexts.

## Interactive Governance Workflows

### Add an exception

```sh
npx periapsis exceptions add
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

### Add an allowed license

```sh
npx periapsis licenses allow add
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

### Non-interactive examples

Add allowed license without prompts:

```sh
npx periapsis licenses allow add \
  --non-interactive \
  --identifier MIT \
  --approved-by security,legal \
  --category "Permissive Licenses" \
  --rationale "Approved baseline license" \
  --evidence-ref JIRA-1234
```

Add exception without prompts:

```sh
npx periapsis exceptions add \
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
npx periapsis --production-only
```

Run checker against a custom dependency set:

```sh
npx periapsis --dep-types dependencies,peerDependencies
```

## Expiration and Follow-up Behavior

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

## CI / GitHub Actions

Example:

```yaml
- uses: actions/checkout@v4
- uses: actions/setup-node@v4
  with:
    node-version: 20
    cache: npm
- run: npm ci
- run: npx periapsis --violations-out sbom-violations.json
```

When violations exist, Periapsis exits non-zero and prints deterministic markdown summary suitable for Actions logs.

## Troubleshooting Large Violation Sets

When you get a large burst of violations, use this order to reduce noise quickly:

1. Confirm you are running the expected CLI version.
2. Confirm policy files are being read from the expected repo/path.
3. Group by `Type` in the output and fix one class at a time.

Quick checks:

- If many rows show `license-not-allowed`, add explicit records via `periapsis licenses allow add` for the most common licenses first (`MIT`, `Apache-2.0`, `ISC`, `BSD-3-Clause`).
- If many rows show `expired-license-policy` or `expired-exception`, add follow-up records instead of editing/deleting old records.
- If one package appears repeatedly blocked across versions, prefer a targeted exception with `scope.type = "range"` or `exact`.
- If unknown license expressions are noisy and expected, decide whether to keep strict mode or set `failOnUnknownLicense` to `false` in `policy/policy.json`.
- If a command fails with schema validation errors, fix the specific field path reported, then rerun.
- If violations are mostly from test/build tooling, start with `--production-only`, then expand scope incrementally.

Recommended triage workflow:

1. Run `npx periapsis --violations-out sbom-violations.json`.
2. Count by license in `sbom-licenses.json` and prioritize highest-frequency licenses.
3. Add 1-3 high-impact explicit license records.
4. Re-run and verify violation count drops.
5. Add narrowly scoped exceptions only for true outliers.

Team process tips:

- Treat `licenses.json` as strategic policy (broad impact) and `exceptions.json` as tactical policy (narrow impact).
- Require CODEOWNERS/legal-security review for policy edits.
- Add expirations intentionally, then renew with follow-up records before they expire.

## Governance Recommendation

Protect policy changes with CODEOWNERS review:

```txt
/policy/* @security-team @legal-team
```

Use expiring entries plus follow-up records to preserve decision history without overwriting prior approvals.

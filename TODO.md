# TODO

## Test Coverage

- Add schema validation tests in `test/policy.test.mjs`:
  - Invalid `date-time` rejection for `validateExceptionRecordSchema` and `validateLicenseRecordSchema` (e.g. `"not-a-date"`, `"2025-13-01T00:00:00Z"`)
  - `formatSchemaErrors` output when ajv returns errors (currently untested)
- Update SPDX reference json for this quarter for any new identifiers added to the standard
- Add tests for `periapsis vulnerability init` (verify file layout, force flag, existing-file guard)
- Add tests for `validateVulnerabilityConfigBundle` with a full valid bundle

## Governance Platform

- Consider global `periapsis report` aggregation across all domains
- Consider global `periapsis validate` aggregation across all domains
- Decide when to migrate license exceptions from `policy/exceptions.json` to `policy/license-exceptions.json`
- Design shared evidence reference conventions across domains
- Design CODEOWNERS guidance for domain-specific policy files

## Vulnerability Governance

- Consider `periapsis vulnerability assign` to sync `policy/vulnerability-owners.json` with Dependabot alert assignees
- Consider organization-wide scanning from a central governance repository
- Consider Slack weekly digest grouping by repo owner/team
- Consider support for multiple vulnerability sources beyond Dependabot (Snyk, Trivy, GitHub code scanning)
- Consider severity-specific enforcement (e.g. enforce only breached critical alerts)
- Consider exception renewal workflows before expiration
- Consider historical trend reporting
- Add interactive mode for `periapsis vulnerability exceptions add`

## Reporting

- Add HTML report output
- Add long-term JSON report retention
- Add SLA compliance trend charts
- Add repo/team scorecards
- Add executive summary output
- Add audit export bundle

## Notifications

- Add Microsoft Teams support
- Add email notification support
- Add notification suppression windows
- Add per-owner notification frequency
- Add escalation chains for breached critical alerts

## Policy and Exceptions

- Add stronger validation for maximum exception durations by severity
- Add stronger approval requirements for broad (repo-wide, ecosystem-wide) exceptions
- Add policy templates for strict, standard, and permissive vulnerability governance
- Add risk acceptance language templates
- Add exception renewal rather than edit-in-place behaviour

## Future Domains

- Secret scanning governance
- Code scanning governance
- Infrastructure policy/drift governance
- Evidence collection governance
- AI usage governance

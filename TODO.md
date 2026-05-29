# TODO

## Test Coverage

- Add schema validation tests in `test/policy.test.mjs`:
  - Invalid `date-time` rejection for `validateExceptionRecordSchema` and `validateLicenseRecordSchema` (e.g. `"not-a-date"`, `"2025-13-01T00:00:00Z"`)
  - `formatSchemaErrors` output when ajv returns errors (currently untested)
- Update SPXD reference json for this quarter for any new references added to the standard

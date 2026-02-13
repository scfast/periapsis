import test from 'node:test';
import assert from 'node:assert/strict';
import {
  DEPENDENCY_TYPE_NAMES,
  OTHER_CATEGORY_NAME,
  categoryOrThrow,
  evaluateCompliance,
  filterSbomByDependencyTypes,
  licenseTokens,
  mapLegacyCategory,
  matchExceptionScope,
  parseDependencyTypesCsv,
  validatePolicyBundleOrThrow
} from '../lib/periapsis-core.mjs';

function emptySpdx() {
  return { byIdentifier: new Map(), fullNames: new Map() };
}

test('mapLegacyCategory maps A/B/C to renamed labels', () => {
  assert.equal(mapLegacyCategory('A'), 'Permissive Licenses');
  assert.equal(mapLegacyCategory('b'), 'Weak Copyleft Licenses');
  assert.equal(mapLegacyCategory('C'), 'Strong Copyleft Licenses');
});

test('categoryOrThrow allows Uncategorized fallback category', () => {
  assert.equal(categoryOrThrow(OTHER_CATEGORY_NAME), OTHER_CATEGORY_NAME);
});

test('matchExceptionScope supports exact/range/any', () => {
  assert.equal(matchExceptionScope('1.2.3', { type: 'exact', version: '1.2.3' }), true);
  assert.equal(matchExceptionScope('1.2.4', { type: 'exact', version: '1.2.3' }), false);
  assert.equal(matchExceptionScope('1.5.0', { type: 'range', range: '^1.2.0' }), true);
  assert.equal(matchExceptionScope('2.0.0', { type: 'range', range: '^1.2.0' }), false);
  assert.equal(matchExceptionScope('99.99.99', { type: 'any' }), true);
});

test('licenseTokens parses SPDX expressions', () => {
  const tokens = licenseTokens('(MIT OR Apache-2.0) AND BSD-3-Clause');
  assert.deepEqual(tokens.sort(), ['Apache-2.0', 'BSD-3-Clause', 'MIT']);
});

test('validatePolicyBundleOrThrow rejects invalid settings', () => {
  assert.throws(() =>
    validatePolicyBundleOrThrow({
      settings: { allowedCategories: ['Not A Real Category'] },
      licenses: [],
      exceptions: []
    })
  );
});

test('parseDependencyTypesCsv parses and validates values', () => {
  const types = parseDependencyTypesCsv('dependencies, devDependencies');
  assert.deepEqual(types, ['dependencies', 'devDependencies']);
  assert.throws(() => parseDependencyTypesCsv('invalidType'));
});

test('filterSbomByDependencyTypes filters by any matching type', () => {
  const sbom = [
    { name: 'a', version: '1.0.0', dependencyTypes: ['dependencies'] },
    { name: 'b', version: '1.0.0', dependencyTypes: ['devDependencies'] },
    { name: 'c', version: '1.0.0', dependencyTypes: ['peerDependencies', 'dependencies'] }
  ];
  const filtered = filterSbomByDependencyTypes(sbom, ['dependencies']);
  assert.deepEqual(
    filtered.map((x) => x.name).sort(),
    ['a', 'c']
  );
  const all = filterSbomByDependencyTypes(sbom, DEPENDENCY_TYPE_NAMES);
  assert.equal(all.length, 3);
});

test('active follow-up license record is selected after older one expires', () => {
  const sbom = [
    { name: 'pkg-a', version: '1.0.0', license: 'MIT', path: 'node_modules/pkg-a' }
  ];
  const policy = {
    type: 'new',
    settings: {
      allowedCategories: ['Permissive Licenses'],
      failOnUnknownLicense: true,
      timezone: 'UTC'
    },
    licenses: [
      {
        identifier: 'MIT',
        category: 'Permissive Licenses',
        rationale: 'legacy',
        approvedBy: ['security'],
        approvedAt: '2025-01-01T00:00:00Z',
        expiresAt: '2025-06-01T00:00:00Z',
        evidenceRef: 'JIRA-1'
      },
      {
        identifier: 'MIT',
        category: 'Permissive Licenses',
        rationale: 'follow-up',
        approvedBy: ['security'],
        approvedAt: '2025-07-01T00:00:00Z',
        expiresAt: null,
        evidenceRef: 'JIRA-2'
      }
    ],
    exceptions: []
  };

  const out = evaluateCompliance(sbom, policy, emptySpdx(), new Date('2026-01-01T00:00:00Z'));
  assert.equal(out.violations.length, 0);
});

test('expired license policy without active follow-up is a violation', () => {
  const sbom = [
    { name: 'pkg-a', version: '1.0.0', license: 'MIT', path: 'node_modules/pkg-a' }
  ];
  const policy = {
    type: 'new',
    settings: {
      allowedCategories: ['Permissive Licenses'],
      failOnUnknownLicense: true,
      timezone: 'UTC'
    },
    licenses: [
      {
        identifier: 'MIT',
        category: 'Permissive Licenses',
        rationale: 'temporary',
        approvedBy: ['security'],
        approvedAt: '2025-01-01T00:00:00Z',
        expiresAt: '2025-03-01T00:00:00Z',
        evidenceRef: 'JIRA-3'
      }
    ],
    exceptions: []
  };

  const out = evaluateCompliance(sbom, policy, emptySpdx(), new Date('2026-01-01T00:00:00Z'));
  assert.equal(out.violations.length, 1);
  assert.equal(out.violations[0].reasonType, 'expired-license-policy');
});

test('active exception range suppresses violation', () => {
  const sbom = [
    { name: 'pkg-a', version: '1.4.0', license: 'Custom-License', path: 'node_modules/pkg-a' }
  ];
  const policy = {
    type: 'new',
    settings: {
      allowedCategories: ['Permissive Licenses'],
      failOnUnknownLicense: true,
      timezone: 'UTC'
    },
    licenses: [],
    exceptions: [
      {
        package: 'pkg-a',
        scope: { type: 'range', range: '^1.2.0' },
        detectedLicenses: ['Custom-License'],
        reason: 'business approved',
        notes: null,
        approvedBy: ['legal'],
        approvedAt: '2026-01-01T00:00:00Z',
        expiresAt: '2026-12-31T00:00:00Z',
        evidenceRef: 'JIRA-5'
      }
    ]
  };

  const out = evaluateCompliance(sbom, policy, emptySpdx(), new Date('2026-06-01T00:00:00Z'));
  assert.equal(out.violations.length, 0);
});

test('expired exception without active follow-up reports expired-exception', () => {
  const sbom = [
    { name: 'pkg-a', version: '1.4.0', license: 'Custom-License', path: 'node_modules/pkg-a' }
  ];
  const policy = {
    type: 'new',
    settings: {
      allowedCategories: ['Permissive Licenses'],
      failOnUnknownLicense: true,
      timezone: 'UTC'
    },
    licenses: [],
    exceptions: [
      {
        package: 'pkg-a',
        scope: { type: 'range', range: '^1.2.0' },
        detectedLicenses: ['Custom-License'],
        reason: 'business approved',
        notes: null,
        approvedBy: ['legal'],
        approvedAt: '2025-01-01T00:00:00Z',
        expiresAt: '2025-12-31T00:00:00Z',
        evidenceRef: 'JIRA-7'
      }
    ]
  };

  const out = evaluateCompliance(sbom, policy, emptySpdx(), new Date('2026-06-01T00:00:00Z'));
  assert.equal(out.violations.length, 1);
  assert.equal(out.violations[0].reasonType, 'expired-exception');
});

test('exception package field tolerates package@version format', () => {
  const sbom = [
    { name: 'caniuse-lite', version: '1.0.30001767', license: 'CC-BY-4.0', path: 'node_modules/caniuse-lite' }
  ];
  const policy = {
    type: 'new',
    settings: {
      allowedCategories: ['Permissive Licenses'],
      failOnUnknownLicense: true,
      timezone: 'UTC'
    },
    licenses: [],
    exceptions: [
      {
        package: 'caniuse-lite@1.0.30001767',
        scope: { type: 'exact', version: '1.0.30001767' },
        detectedLicenses: ['CC-BY-4.0'],
        reason: 'Reviewed and accepted by security',
        notes: null,
        approvedBy: ['Shane Fast'],
        approvedAt: '2026-02-13T20:39:18.677Z',
        expiresAt: '2027-02-13T00:00:00.000Z',
        evidenceRef: 'N/A'
      }
    ]
  };

  const out = evaluateCompliance(sbom, policy, emptySpdx(), new Date('2026-02-14T00:00:00Z'));
  assert.equal(out.violations.length, 0);
});

test('spdx category allowlist permits license without explicit record', () => {
  const sbom = [{ name: 'pkg-a', version: '1.0.0', license: 'MIT', path: 'node_modules/pkg-a' }];
  const policy = {
    type: 'new',
    settings: {
      allowedCategories: ['Permissive Licenses'],
      failOnUnknownLicense: true,
      timezone: 'UTC'
    },
    licenses: [],
    exceptions: []
  };
  const spdx = {
    byIdentifier: new Map([['MIT', 'Permissive Licenses']]),
    fullNames: new Map()
  };

  const out = evaluateCompliance(sbom, policy, spdx, new Date('2026-01-01T00:00:00Z'));
  assert.equal(out.violations.length, 0);
});

test('active explicit license record bypasses category gating', () => {
  const sbom = [{ name: 'pkg-a', version: '1.0.0', license: 'MIT', path: 'node_modules/pkg-a' }];
  const policy = {
    type: 'new',
    settings: {
      allowedCategories: ['Strong Copyleft Licenses'],
      failOnUnknownLicense: true,
      timezone: 'UTC'
    },
    licenses: [
      {
        identifier: 'MIT',
        category: 'Permissive Licenses',
        rationale: 'explicit approved license',
        approvedBy: ['security'],
        approvedAt: '2026-01-01T00:00:00Z',
        expiresAt: null,
        evidenceRef: 'JIRA-12'
      }
    ],
    exceptions: []
  };
  const spdx = {
    byIdentifier: new Map([['MIT', 'Permissive Licenses']]),
    fullNames: new Map()
  };

  const out = evaluateCompliance(sbom, policy, spdx, new Date('2026-02-01T00:00:00Z'));
  assert.equal(out.violations.length, 0);
});

test('explicit expired license record overrides category baseline until follow-up exists', () => {
  const sbom = [{ name: 'pkg-a', version: '1.0.0', license: 'MIT', path: 'node_modules/pkg-a' }];
  const policy = {
    type: 'new',
    settings: {
      allowedCategories: ['Permissive Licenses'],
      failOnUnknownLicense: true,
      timezone: 'UTC'
    },
    licenses: [
      {
        identifier: 'MIT',
        category: 'Permissive Licenses',
        rationale: 'temporary approval',
        approvedBy: ['security'],
        approvedAt: '2025-01-01T00:00:00Z',
        expiresAt: '2025-06-01T00:00:00Z',
        evidenceRef: 'JIRA-11'
      }
    ],
    exceptions: []
  };
  const spdx = {
    byIdentifier: new Map([['MIT', 'Permissive Licenses']]),
    fullNames: new Map()
  };

  const out = evaluateCompliance(sbom, policy, spdx, new Date('2026-01-01T00:00:00Z'));
  assert.equal(out.violations.length, 1);
  assert.equal(out.violations[0].reasonType, 'expired-license-policy');
});

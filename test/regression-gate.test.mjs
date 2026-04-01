import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import { createFixtureProject, runCli } from '../testing/helpers.mjs';

function readViolations(root) {
  return JSON.parse(fs.readFileSync(path.join(root, 'violations.json'), 'utf8'));
}

test('runtime-only strict policy ignores disallowed dev dependency', async () => {
  const cwd = createFixtureProject({
    prefix: 'periapsis-runtime-only-',
    packageJson: {
      name: 'runtime-only-app',
      version: '1.0.0',
      dependencies: { runtimeok: '1.0.0' },
      devDependencies: { buildgpl: '1.0.0' }
    },
    lockPackages: {
      'node_modules/runtimeok': { version: '1.0.0', license: 'MIT' },
      'node_modules/buildgpl': { version: '1.0.0', license: 'GPL-3.0', dev: true }
    },
    policy: {
      settings: {
        allowedCategories: ['Permissive Licenses'],
        failOnUnknownLicense: true,
        timezone: 'UTC',
        dependencyTypes: ['dependencies']
      }
    }
  });

  await runCli(cwd, ['--violations-out', 'violations.json', '--quiet']);

  assert.deepEqual(readViolations(cwd), []);
});

test('all-dependency policy blocks disallowed dev dependency regressions', async () => {
  const cwd = createFixtureProject({
    prefix: 'periapsis-all-deps-',
    packageJson: {
      name: 'all-deps-app',
      version: '1.0.0',
      dependencies: { runtimeok: '1.0.0' },
      devDependencies: { buildgpl: '1.0.0' }
    },
    lockPackages: {
      'node_modules/runtimeok': { version: '1.0.0', license: 'MIT' },
      'node_modules/buildgpl': { version: '1.0.0', license: 'GPL-3.0', dev: true }
    },
    policy: {
      settings: {
        allowedCategories: ['Permissive Licenses'],
        failOnUnknownLicense: true,
        timezone: 'UTC',
        dependencyTypes: ['dependencies', 'devDependencies']
      }
    }
  });

  await runCli(cwd, ['--violations-out', 'violations.json'], {
    expectFail: true
  });

  const violations = readViolations(cwd);
  assert.equal(violations.length, 1);
  assert.equal(violations[0].name, 'buildgpl');
  assert.equal(violations[0].reasonType, 'license-not-allowed');
});

test('standard policy allows weak copyleft licenses', async () => {
  const cwd = createFixtureProject({
    prefix: 'periapsis-weak-copyleft-',
    packageJson: {
      name: 'weak-copyleft-app',
      version: '1.0.0',
      dependencies: { liblgpl: '1.0.0' }
    },
    lockPackages: {
      'node_modules/liblgpl': { version: '1.0.0', license: 'LGPL-2.1-only' }
    },
    policy: {
      settings: {
        allowedCategories: ['Permissive Licenses', 'Weak Copyleft Licenses'],
        failOnUnknownLicense: true,
        timezone: 'UTC',
        dependencyTypes: ['dependencies']
      }
    }
  });

  await runCli(cwd, ['--violations-out', 'violations.json', '--quiet']);

  assert.deepEqual(readViolations(cwd), []);
});

test('expired exception is surfaced as a policy regression', async () => {
  const cwd = createFixtureProject({
    prefix: 'periapsis-expired-exception-',
    packageJson: {
      name: 'expired-exception-app',
      version: '1.0.0',
      dependencies: { vendorpkg: '1.4.0' }
    },
    lockPackages: {
      'node_modules/vendorpkg': { version: '1.4.0', license: 'LicenseRef-Vendor' }
    },
    policy: {
      settings: {
        allowedCategories: ['Permissive Licenses'],
        failOnUnknownLicense: true,
        timezone: 'UTC',
        dependencyTypes: ['dependencies']
      },
      exceptions: [
        {
          package: 'vendorpkg',
          scope: { type: 'range', range: '^1.2.0' },
          detectedLicenses: ['LicenseRef-Vendor'],
          reason: 'Temporary approval',
          notes: null,
          approvedBy: ['legal'],
          approvedAt: '2025-01-01T00:00:00Z',
          expiresAt: '2025-12-31T00:00:00Z',
          evidenceRef: 'JIRA-EX-1'
        }
      ]
    }
  });

  await runCli(cwd, ['--violations-out', 'violations.json'], {
    expectFail: true
  });

  const violations = readViolations(cwd);
  assert.equal(violations[0].reasonType, 'expired-exception');
});

test('active follow-up exception keeps previously-expired package compliant', async () => {
  const cwd = createFixtureProject({
    prefix: 'periapsis-followup-exception-',
    packageJson: {
      name: 'followup-exception-app',
      version: '1.0.0',
      dependencies: { vendorpkg: '1.4.0' }
    },
    lockPackages: {
      'node_modules/vendorpkg': { version: '1.4.0', license: 'LicenseRef-Vendor' }
    },
    policy: {
      settings: {
        allowedCategories: ['Permissive Licenses'],
        failOnUnknownLicense: true,
        timezone: 'UTC',
        dependencyTypes: ['dependencies']
      },
      exceptions: [
        {
          package: 'vendorpkg',
          scope: { type: 'range', range: '^1.2.0' },
          detectedLicenses: ['LicenseRef-Vendor'],
          reason: 'Temporary approval',
          notes: null,
          approvedBy: ['legal'],
          approvedAt: '2025-01-01T00:00:00Z',
          expiresAt: '2025-12-31T00:00:00Z',
          evidenceRef: 'JIRA-EX-1'
        },
        {
          package: 'vendorpkg',
          scope: { type: 'range', range: '^1.2.0' },
          detectedLicenses: ['LicenseRef-Vendor'],
          reason: 'Renewed approval',
          notes: null,
          approvedBy: ['legal', 'security'],
          approvedAt: '2026-01-15T00:00:00Z',
          expiresAt: '2026-12-31T00:00:00Z',
          evidenceRef: 'JIRA-EX-2'
        }
      ]
    }
  });

  await runCli(cwd, ['--violations-out', 'violations.json', '--quiet']);

  assert.deepEqual(readViolations(cwd), []);
});

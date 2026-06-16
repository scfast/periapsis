import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import { createTempDir, runCli, writePolicyBundle, writeJson } from '../testing/helpers.mjs';

function setupProject(cwd) {
  writePolicyBundle(cwd, {
    settings: {
      allowedCategories: ['Permissive Licenses'],
      failOnUnknownLicense: true,
      timezone: 'UTC',
      dependencyTypes: ['dependencies']
    },
    licenses: [
      {
        identifier: 'MIT',
        category: 'Permissive Licenses',
        rationale: 'baseline',
        approvedBy: ['security'],
        approvedAt: '2026-01-01T00:00:00.000Z',
        expiresAt: null,
        evidenceRef: 'JIRA-1'
      }
    ],
    exceptions: []
  });

  writeJson(path.join(cwd, 'package.json'), {
    name: 'test-app',
    version: '1.0.0',
    dependencies: { 'some-pkg': '1.0.0' }
  });

  writeJson(path.join(cwd, 'package-lock.json'), {
    name: 'test-app',
    version: '1.0.0',
    lockfileVersion: 3,
    packages: {
      '': {
        name: 'test-app',
        version: '1.0.0',
        dependencies: { 'some-pkg': '1.0.0' }
      },
      'node_modules/some-pkg': {
        version: '1.0.0',
        license: 'MIT'
      }
    }
  });

  fs.mkdirSync(path.join(cwd, 'node_modules', 'some-pkg'), { recursive: true });
}

test('periapsis (no args) runs as license check', async () => {
  const cwd = createTempDir('periapsis-alias-');
  setupProject(cwd);
  await runCli(cwd, ['--quiet']);
});

test('periapsis license check runs license compliance', async () => {
  const cwd = createTempDir('periapsis-alias-');
  setupProject(cwd);
  await runCli(cwd, ['license', 'check', '--quiet']);
});

test('periapsis exceptions add prints backwards compat hint and writes to exceptions.json', async () => {
  const cwd = createTempDir('periapsis-alias-');
  writePolicyBundle(cwd);

  const output = await runCli(cwd, [
    'exceptions',
    'add',
    '--non-interactive',
    '--package',
    'test-pkg',
    '--scope-type',
    'any',
    '--reason',
    'testing',
    '--approved-by',
    'security',
    '--expires-at',
    '2027-01-01T00:00:00.000Z',
    '--evidence-ref',
    'JIRA-1'
  ]);

  assert.match(output, /backwards compatibility/);
  const exceptions = JSON.parse(
    fs.readFileSync(path.join(cwd, 'policy', 'exceptions.json'), 'utf8')
  );
  assert.equal(exceptions.length, 1);
});

test('periapsis exceptions add does not create vulnerability-exceptions.json', async () => {
  const cwd = createTempDir('periapsis-alias-');
  writePolicyBundle(cwd);

  await runCli(cwd, [
    'exceptions',
    'add',
    '--non-interactive',
    '--package',
    'test-pkg',
    '--scope-type',
    'any',
    '--reason',
    'testing',
    '--approved-by',
    'security',
    '--expires-at',
    '2027-01-01T00:00:00.000Z',
    '--evidence-ref',
    'JIRA-1'
  ]);

  assert.equal(
    fs.existsSync(path.join(cwd, 'policy', 'vulnerability-exceptions.json')),
    false
  );
});

test('periapsis license exceptions add works without hint', async () => {
  const cwd = createTempDir('periapsis-alias-');
  writePolicyBundle(cwd);

  const output = await runCli(cwd, [
    'license',
    'exceptions',
    'add',
    '--non-interactive',
    '--package',
    'test-pkg',
    '--scope-type',
    'any',
    '--reason',
    'testing',
    '--approved-by',
    'security',
    '--expires-at',
    '2027-01-01T00:00:00.000Z',
    '--evidence-ref',
    'JIRA-1'
  ]);

  assert.ok(!output.includes('backwards compatibility'));
  const exceptions = JSON.parse(
    fs.readFileSync(path.join(cwd, 'policy', 'exceptions.json'), 'utf8')
  );
  assert.equal(exceptions.length, 1);
});

test('periapsis licenses allow add prints backwards compat hint', async () => {
  const cwd = createTempDir('periapsis-alias-');
  writePolicyBundle(cwd);

  const output = await runCli(cwd, [
    'licenses',
    'allow',
    'add',
    '--non-interactive',
    '--identifier',
    'MIT',
    '--approved-by',
    'security',
    '--category',
    'Permissive Licenses',
    '--rationale',
    'test',
    '--evidence-ref',
    'JIRA-2'
  ]);

  assert.match(output, /backwards compatibility/);
  const licenses = JSON.parse(
    fs.readFileSync(path.join(cwd, 'policy', 'licenses.json'), 'utf8')
  );
  assert.equal(licenses.length, 1);
});

test('periapsis license allow add works without hint', async () => {
  const cwd = createTempDir('periapsis-alias-');
  writePolicyBundle(cwd);

  const output = await runCli(cwd, [
    'license',
    'allow',
    'add',
    '--non-interactive',
    '--identifier',
    'MIT',
    '--approved-by',
    'security',
    '--category',
    'Permissive Licenses',
    '--rationale',
    'test',
    '--evidence-ref',
    'JIRA-2'
  ]);

  assert.ok(!output.includes('backwards compatibility'));
  const licenses = JSON.parse(
    fs.readFileSync(path.join(cwd, 'policy', 'licenses.json'), 'utf8')
  );
  assert.equal(licenses.length, 1);
});

test('periapsis policy migrate prints backwards compat hint', async () => {
  const cwd = createTempDir('periapsis-alias-');
  writePolicyBundle(cwd);

  writeJson(path.join(cwd, 'allowedConfig.json'), {
    allowedLicenses: ['MIT'],
    allowedCategories: [],
    exceptions: []
  });

  const output = await runCli(cwd, [
    'policy',
    'migrate',
    '--from',
    'allowedConfig.json',
    '--force'
  ]);

  assert.match(output, /backwards compatibility/);
  assert.equal(fs.existsSync(path.join(cwd, 'policy', 'policy.json')), true);
});

test('periapsis license policy migrate works without hint', async () => {
  const cwd = createTempDir('periapsis-alias-');
  writePolicyBundle(cwd);

  writeJson(path.join(cwd, 'allowedConfig.json'), {
    allowedLicenses: ['MIT'],
    allowedCategories: [],
    exceptions: []
  });

  const output = await runCli(cwd, [
    'license',
    'policy',
    'migrate',
    '--from',
    'allowedConfig.json',
    '--force'
  ]);

  assert.ok(!output.includes('backwards compatibility'));
});

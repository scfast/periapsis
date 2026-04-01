import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import { createTempDir, runCli, writeJson, writePolicyBundle } from '../testing/helpers.mjs';

test('init writes strict runtime-only policy when requested', async () => {
  const cwd = createTempDir('periapsis-init-');

  await runCli(cwd, ['init', '--preset', 'strict', '--production-only']);

  const policy = JSON.parse(fs.readFileSync(path.join(cwd, 'policy', 'policy.json'), 'utf8'));
  assert.deepEqual(policy.allowedCategories, ['Permissive Licenses']);
  assert.deepEqual(policy.dependencyTypes, ['dependencies']);
});

test('init writes standard policy with explicit dependency types', async () => {
  const cwd = createTempDir('periapsis-init-deps-');

  await runCli(cwd, [
    'init',
    '--preset',
    'standard',
    '--dep-types',
    'dependencies,peerDependencies'
  ]);

  const policy = JSON.parse(fs.readFileSync(path.join(cwd, 'policy', 'policy.json'), 'utf8'));
  assert.deepEqual(policy.allowedCategories, [
    'Permissive Licenses',
    'Weak Copyleft Licenses'
  ]);
  assert.deepEqual(policy.dependencyTypes, ['dependencies', 'peerDependencies']);
});

test('policy migrate converts legacy config to governed policy files', async () => {
  const cwd = createTempDir('periapsis-migrate-');
  writeJson(path.join(cwd, 'allowedConfig.json'), {
    allowedLicenses: ['MIT'],
    allowedCategories: ['B'],
    exceptions: ['left-pad@1.3.0', 'uuid']
  });

  await runCli(cwd, ['policy', 'migrate', '--from', 'allowedConfig.json']);

  const policy = JSON.parse(fs.readFileSync(path.join(cwd, 'policy', 'policy.json'), 'utf8'));
  const licenses = JSON.parse(fs.readFileSync(path.join(cwd, 'policy', 'licenses.json'), 'utf8'));
  const exceptions = JSON.parse(fs.readFileSync(path.join(cwd, 'policy', 'exceptions.json'), 'utf8'));

  assert.deepEqual(policy.allowedCategories, ['Weak Copyleft Licenses']);
  assert.equal(licenses.length, 1);
  assert.equal(licenses[0].identifier, 'MIT');
  assert.equal(exceptions.length, 2);
  assert.deepEqual(exceptions[0].scope, { type: 'exact', version: '1.3.0' });
  assert.deepEqual(exceptions[1].scope, { type: 'any' });
});

test('checker honors policy dependencyTypes when no CLI override is provided', async () => {
  const cwd = createTempDir('periapsis-policy-scope-');
  writePolicyBundle(cwd, {
    settings: {
      allowedCategories: ['Permissive Licenses'],
      failOnUnknownLicense: true,
      timezone: 'UTC',
      dependencyTypes: ['dependencies']
    },
    licenses: [],
    exceptions: []
  });
  writeJson(path.join(cwd, 'package.json'), {
    name: 'scope-app',
    version: '1.0.0',
    dependencies: { a: '1.0.0' },
    devDependencies: { b: '1.0.0' }
  });
  writeJson(path.join(cwd, 'package-lock.json'), {
    name: 'scope-app',
    version: '1.0.0',
    lockfileVersion: 3,
    packages: {
      '': {
        name: 'scope-app',
        version: '1.0.0',
        dependencies: { a: '1.0.0' },
        devDependencies: { b: '1.0.0' }
      },
      'node_modules/a': { version: '1.0.0', license: 'MIT' },
      'node_modules/b': { version: '1.0.0', license: 'GPL-3.0', dev: true }
    }
  });
  fs.mkdirSync(path.join(cwd, 'node_modules', 'a'), { recursive: true });
  fs.mkdirSync(path.join(cwd, 'node_modules', 'b'), { recursive: true });

  await runCli(cwd, ['--quiet']);

  const sbom = JSON.parse(fs.readFileSync(path.join(cwd, 'sbom-licenses.json'), 'utf8'));
  assert.deepEqual(sbom.map((entry) => entry.name), ['a']);
});

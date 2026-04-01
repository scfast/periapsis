import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import { createTempDir, runCli, writePolicyBundle } from '../testing/helpers.mjs';

function setupTempProject() {
  const dir = createTempDir('periapsis-test-');
  writePolicyBundle(dir);
  return dir;
}

test('licenses allow add supports non-interactive mode', async () => {
  const cwd = setupTempProject();
  await runCli(cwd, [
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
    'Approved baseline license',
    '--evidence-ref',
    'JIRA-200'
  ]);

  const licenses = JSON.parse(fs.readFileSync(path.join(cwd, 'policy', 'licenses.json'), 'utf8'));
  assert.equal(licenses.length, 1);
  assert.equal(licenses[0].identifier, 'MIT');
  assert.equal(licenses[0].approvedBy[0], 'security');
});

test('exceptions add supports non-interactive mode', async () => {
  const cwd = setupTempProject();
  await runCli(cwd, [
    'exceptions',
    'add',
    '--non-interactive',
    '--package',
    'caniuse-lite',
    '--scope-type',
    'exact',
    '--version',
    '1.0.30001767',
    '--reason',
    'Reviewed and approved',
    '--approved-by',
    'security',
    '--expires-at',
    '2027-02-13T00:00:00.000Z',
    '--evidence-ref',
    'JIRA-201'
  ]);

  const exceptions = JSON.parse(fs.readFileSync(path.join(cwd, 'policy', 'exceptions.json'), 'utf8'));
  assert.equal(exceptions.length, 1);
  assert.equal(exceptions[0].package, 'caniuse-lite');
  assert.equal(exceptions[0].scope.type, 'exact');
});

test('non-interactive mode enforces required fields', async () => {
  const cwd = setupTempProject();
  const output = await runCli(
    cwd,
    ['licenses', 'allow', 'add', '--non-interactive', '--identifier', 'MIT'],
    { expectFail: true }
  );

  assert.match(output, /--approved-by is required/);
});

test('checker respects --dep-types filter', async () => {
  const cwd = setupTempProject();
  fs.writeFileSync(
    path.join(cwd, 'package.json'),
    JSON.stringify(
      {
        name: 'app',
        version: '1.0.0',
        dependencies: { a: '1.0.0' },
        devDependencies: { b: '1.0.0' }
      },
      null,
      2
    ) + '\n'
  );
  fs.writeFileSync(
    path.join(cwd, 'package-lock.json'),
    JSON.stringify(
      {
        name: 'app',
        lockfileVersion: 3,
        packages: {
          '': {
            name: 'app',
            version: '1.0.0',
            dependencies: { a: '1.0.0' },
            devDependencies: { b: '1.0.0' }
          },
          'node_modules/a': { version: '1.0.0', license: 'MIT' },
          'node_modules/b': { version: '1.0.0', license: 'GPL-3.0', dev: true }
        }
      },
      null,
      2
    ) + '\n'
  );
  fs.mkdirSync(path.join(cwd, 'node_modules', 'a'), { recursive: true });
  fs.mkdirSync(path.join(cwd, 'node_modules', 'b'), { recursive: true });

  await runCli(cwd, [
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
    'Approved baseline license',
    '--evidence-ref',
    'JIRA-300'
  ]);

  await runCli(cwd, ['--dep-types', 'dependencies', '--quiet']);
  const failOutput = await runCli(cwd, ['--dep-types', 'devDependencies'], {
    expectFail: true
  });
  assert.match(failOutput, /license-not-allowed/);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { execFileSync } from 'child_process';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const BIN = path.resolve(__dirname, '..', 'bin', 'periapsis.mjs');

function setupTempProject() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'periapsis-test-'));
  fs.mkdirSync(path.join(dir, 'policy'), { recursive: true });
  fs.writeFileSync(
    path.join(dir, 'policy', 'policy.json'),
    JSON.stringify(
      {
        allowedCategories: ['Permissive Licenses'],
        failOnUnknownLicense: true,
        timezone: 'UTC',
        dependencyTypes: ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies', 'bundledDependencies']
      },
      null,
      2
    ) + '\n'
  );
  fs.writeFileSync(path.join(dir, 'policy', 'licenses.json'), '[]\n');
  fs.writeFileSync(path.join(dir, 'policy', 'exceptions.json'), '[]\n');
  return dir;
}

function runCli(cwd, args, { expectFail = false } = {}) {
  try {
    const out = execFileSync('node', [BIN, ...args], {
      cwd,
      encoding: 'utf8'
    });
    if (expectFail) {
      assert.fail(`Expected command to fail: ${args.join(' ')}`);
    }
    return out;
  } catch (err) {
    if (!expectFail) throw err;
    return `${err.stdout || ''}${err.stderr || ''}`;
  }
}

test('licenses allow add supports non-interactive mode', () => {
  const cwd = setupTempProject();
  runCli(cwd, [
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

test('exceptions add supports non-interactive mode', () => {
  const cwd = setupTempProject();
  runCli(cwd, [
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

test('non-interactive mode enforces required fields', () => {
  const cwd = setupTempProject();
  const output = runCli(
    cwd,
    ['licenses', 'allow', 'add', '--non-interactive', '--identifier', 'MIT'],
    { expectFail: true }
  );

  assert.match(output, /--approved-by is required/);
});

test('checker respects --dep-types filter', () => {
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

  runCli(cwd, [
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

  runCli(cwd, ['--dep-types', 'dependencies', '--quiet']);
  const failOutput = runCli(cwd, ['--dep-types', 'devDependencies'], {
    expectFail: true
  });
  assert.match(failOutput, /license-not-allowed/);
});

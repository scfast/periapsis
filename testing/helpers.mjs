import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { main } from '../bin/periapsis.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const REPO_ROOT = path.resolve(__dirname, '..');
export const BIN = path.join(REPO_ROOT, 'bin', 'periapsis.mjs');

export function createTempDir(prefix = 'periapsis-test-') {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

export function writeJson(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

export function writePolicyBundle(
  root,
  {
    settings = {
      allowedCategories: ['Permissive Licenses'],
      failOnUnknownLicense: true,
      timezone: 'UTC',
      dependencyTypes: [
        'dependencies',
        'devDependencies',
        'peerDependencies',
        'optionalDependencies',
        'bundledDependencies'
      ]
    },
    licenses = [],
    exceptions = []
  } = {}
) {
  writeJson(path.join(root, 'policy', 'policy.json'), settings);
  writeJson(path.join(root, 'policy', 'licenses.json'), licenses);
  writeJson(path.join(root, 'policy', 'exceptions.json'), exceptions);
}

export function writeProject(root, { packageJson, lockPackages }) {
  writeJson(path.join(root, 'package.json'), packageJson);
  writeJson(path.join(root, 'package-lock.json'), {
    name: packageJson.name || 'fixture-app',
    version: packageJson.version || '1.0.0',
    lockfileVersion: 3,
    packages: {
      '': {
        name: packageJson.name || 'fixture-app',
        version: packageJson.version || '1.0.0',
        dependencies: packageJson.dependencies || {},
        devDependencies: packageJson.devDependencies || {},
        peerDependencies: packageJson.peerDependencies || {},
        optionalDependencies: packageJson.optionalDependencies || {},
        bundledDependencies: packageJson.bundledDependencies || packageJson.bundleDependencies || []
      },
      ...lockPackages
    }
  });

  for (const pkgPath of Object.keys(lockPackages)) {
    if (!pkgPath.startsWith('node_modules/')) continue;
    fs.mkdirSync(path.join(root, pkgPath), { recursive: true });
  }
}

export function createFixtureProject({
  packageJson,
  lockPackages,
  policy,
  prefix
}) {
  const root = createTempDir(prefix);
  writePolicyBundle(root, policy);
  writeProject(root, { packageJson, lockPackages });
  return root;
}

export async function runCli(cwd, args, { expectFail = false } = {}) {
  const originalCwd = process.cwd();
  const originalExitCode = process.exitCode;
  const captured = [];
  const originalLog = console.log;
  const originalWarn = console.warn;
  const originalError = console.error;

  console.log = (...parts) => captured.push(`${parts.join(' ')}\n`);
  console.warn = (...parts) => captured.push(`${parts.join(' ')}\n`);
  console.error = (...parts) => captured.push(`${parts.join(' ')}\n`);

  try {
    process.chdir(cwd);
    process.exitCode = 0;

    await main(args);

    const output = captured.join('');
    if (!expectFail && process.exitCode && process.exitCode !== 0) {
      throw new Error(output || `Command failed with exit code ${process.exitCode}`);
    }
    if (expectFail && process.exitCode !== 1) {
      throw new Error(`Expected command to fail: ${args.join(' ')}`);
    }
    return output;
  } catch (err) {
    const output = `${captured.join('')}${err.message ? `${err.message}\n` : ''}`;
    if (!expectFail) throw err;
    return output;
  } finally {
    process.chdir(originalCwd);
    process.exitCode = originalExitCode;
    console.log = originalLog;
    console.warn = originalWarn;
    console.error = originalError;
  }
}

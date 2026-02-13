import fs from 'fs';
import path from 'path';
import semver from 'semver';
import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import parseSpdxExpression from 'spdx-expression-parse';

export const CATEGORY_NAMES = [
  'Permissive Licenses',
  'Weak Copyleft Licenses',
  'Strong Copyleft Licenses'
];
export const OTHER_CATEGORY_NAME = 'Uncategorized / Needs Review';
const ALL_CATEGORY_NAMES = [...CATEGORY_NAMES, OTHER_CATEGORY_NAME];
export const DEPENDENCY_TYPE_NAMES = [
  'dependencies',
  'devDependencies',
  'peerDependencies',
  'optionalDependencies',
  'bundledDependencies'
];

const LEGACY_TO_NEW_CATEGORY = {
  A: 'Permissive Licenses',
  B: 'Weak Copyleft Licenses',
  C: 'Strong Copyleft Licenses'
};

const SCOPE_ORDER = {
  exact: 0,
  range: 1,
  any: 2
};

const ajv = new Ajv({ allErrors: true, strict: false });
addFormats(ajv);

const policySettingsSchema = {
  type: 'object',
  additionalProperties: false,
  required: ['allowedCategories'],
  properties: {
    allowedCategories: {
      type: 'array',
      items: { type: 'string', enum: ALL_CATEGORY_NAMES },
      uniqueItems: true
    },
    failOnUnknownLicense: { type: 'boolean' },
    timezone: { type: 'string', minLength: 1 },
    dependencyTypes: {
      type: 'array',
      items: { type: 'string', enum: DEPENDENCY_TYPE_NAMES },
      uniqueItems: true,
      minItems: 1
    }
  }
};

const commonPolicyRecordSchema = {
  type: 'object',
  required: ['approvedBy', 'approvedAt', 'expiresAt', 'evidenceRef'],
  properties: {
    approvedBy: {
      type: 'array',
      minItems: 1,
      items: { type: 'string', minLength: 1 }
    },
    approvedAt: { type: 'string', format: 'date-time' },
    expiresAt: {
      anyOf: [{ type: 'null' }, { type: 'string', format: 'date-time' }]
    },
    evidenceRef: { type: 'string', minLength: 1 }
  }
};

const licenseRecordSchema = {
  type: 'object',
  additionalProperties: true,
  required: ['identifier', 'category', 'rationale', 'approvedBy', 'approvedAt', 'expiresAt', 'evidenceRef'],
  properties: {
    identifier: { type: 'string', minLength: 1 },
    category: { type: 'string', enum: ALL_CATEGORY_NAMES },
    fullName: { anyOf: [{ type: 'null' }, { type: 'string' }] },
    notes: { anyOf: [{ type: 'null' }, { type: 'string' }] },
    rationale: { type: 'string', minLength: 1 },
    ...commonPolicyRecordSchema.properties
  }
};

const exceptionRecordSchema = {
  type: 'object',
  additionalProperties: true,
  required: ['package', 'scope', 'reason', 'approvedBy', 'approvedAt', 'expiresAt', 'evidenceRef'],
  properties: {
    package: { type: 'string', minLength: 1 },
    scope: {
      type: 'object',
      additionalProperties: false,
      required: ['type'],
      properties: {
        type: { type: 'string', enum: ['exact', 'range', 'any'] },
        version: { type: 'string' },
        range: { type: 'string' }
      },
      allOf: [
        {
          if: { properties: { type: { const: 'exact' } } },
          then: { required: ['version'] }
        },
        {
          if: { properties: { type: { const: 'range' } } },
          then: { required: ['range'] }
        }
      ]
    },
    detectedLicenses: {
      type: 'array',
      items: { type: 'string', minLength: 1 }
    },
    reason: { type: 'string', minLength: 1 },
    notes: { anyOf: [{ type: 'null' }, { type: 'string' }] },
    ...commonPolicyRecordSchema.properties
  }
};

const validatePolicySettingsSchema = ajv.compile(policySettingsSchema);
const validateLicenseRecordSchema = ajv.compile(licenseRecordSchema);
const validateExceptionRecordSchema = ajv.compile(exceptionRecordSchema);

export function mapLegacyCategory(input) {
  if (!input) return null;
  const raw = String(input).trim();
  if (!raw) return null;
  const upper = raw.toUpperCase();
  if (LEGACY_TO_NEW_CATEGORY[upper]) return LEGACY_TO_NEW_CATEGORY[upper];
  const direct = CATEGORY_NAMES.find((name) => name.toLowerCase() === raw.toLowerCase());
  return direct || null;
}

export function categoryOrThrow(input) {
  if (String(input || '').trim() === OTHER_CATEGORY_NAME) {
    return OTHER_CATEGORY_NAME;
  }
  const mapped = mapLegacyCategory(input);
  if (!mapped) {
    throw new Error(
      `Invalid category "${input}". Expected one of: ${CATEGORY_NAMES.join(', ')}, ${OTHER_CATEGORY_NAME}`
    );
  }
  return mapped;
}

export function loadJson(filePath, description) {
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (err) {
    throw new Error(`Failed to read ${description} at ${filePath}: ${err.message}`);
  }
}

export function writeJson(filePath, data) {
  fs.writeFileSync(filePath, `${JSON.stringify(data, null, 2)}\n`);
}

export function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') {
      args.help = true;
      continue;
    }
    if (arg.startsWith('--')) {
      const key = arg.slice(2);
      const next = argv[i + 1];
      if (next && !next.startsWith('--')) {
        args[key] = next;
        i += 1;
      } else {
        args[key] = true;
      }
      continue;
    }
    args._.push(arg);
  }
  return args;
}

export function extractLicense(pkgJson) {
  if (!pkgJson) return null;
  const lic = pkgJson.license || pkgJson.licenses;
  if (!lic) return null;
  if (typeof lic === 'string') return lic;
  if (Array.isArray(lic)) {
    return lic
      .map((entry) => (typeof entry === 'string' ? entry : entry?.type || entry?.name))
      .filter(Boolean)
      .join(' OR ');
  }
  if (typeof lic === 'object') return lic.type || lic.name || null;
  return null;
}

export function licenseTokens(license) {
  if (!license) return ['UNKNOWN'];
  const raw = String(license).trim();
  if (!raw) return ['UNKNOWN'];

  try {
    const ast = parseSpdxExpression(raw);
    const tokens = new Set();
    const walk = (node) => {
      if (!node) return;
      if (typeof node === 'string') {
        tokens.add(node);
        return;
      }
      if (node.license) {
        tokens.add(String(node.license));
        return;
      }
      if (node.left) walk(node.left);
      if (node.right) walk(node.right);
    };
    walk(ast);
    if (tokens.size > 0) return [...tokens];
  } catch {
    // Fall back to permissive token extraction for non-standard expressions.
  }

  return license
    .split(/\s*(?:\(|\)|\+|\/|\s+OR\s+|\s+AND\s+|,|;|\||\s+with\s+)/i)
    .map((t) => t.trim())
    .filter(Boolean);
}

function formatSchemaErrors(errors = []) {
  if (!Array.isArray(errors) || errors.length === 0) return 'Unknown schema error';
  return errors
    .map((err) => {
      const loc = err.instancePath || '(root)';
      return `${loc} ${err.message}`;
    })
    .join('; ');
}

export function loadSpdxCatalog(spdxPath) {
  if (!fs.existsSync(spdxPath)) {
    return { byIdentifier: new Map(), fullNames: new Map() };
  }
  const list = loadJson(spdxPath, 'SPDX licenses');
  const byIdentifier = new Map();
  const fullNames = new Map();
  if (!Array.isArray(list)) {
    return { byIdentifier, fullNames };
  }
  for (const entry of list) {
    if (!entry) continue;
    const identifier = entry.identifier ? String(entry.identifier).trim() : '';
    if (!identifier) continue;
    const mappedCategory = mapLegacyCategory(entry.defaultCategory);
    if (mappedCategory) byIdentifier.set(identifier, mappedCategory);
    if (entry.fullName) fullNames.set(identifier, String(entry.fullName));
  }
  return { byIdentifier, fullNames };
}

function resolveDepPath(packages, parentKey, depName) {
  const nested = parentKey
    ? path.posix.join(parentKey, 'node_modules', depName)
    : `node_modules/${depName}`;
  if (packages[nested]) return nested;
  const top = `node_modules/${depName}`;
  if (packages[top]) return top;
  return null;
}

function dependencyNameFromPath(key) {
  const parts = String(key || '').split('node_modules/').filter(Boolean);
  return parts.length > 0 ? parts[parts.length - 1] : null;
}

function detectDependencyTypes({ key, meta, rootPackageJson }) {
  const types = new Set();
  if (meta?.dev) types.add('devDependencies');
  if (meta?.optional) types.add('optionalDependencies');
  if (meta?.peer) types.add('peerDependencies');
  if (meta?.inBundle) types.add('bundledDependencies');

  const depName = dependencyNameFromPath(key);
  if (depName && rootPackageJson) {
    if (rootPackageJson.dependencies?.[depName] !== undefined) types.add('dependencies');
    if (rootPackageJson.devDependencies?.[depName] !== undefined) types.add('devDependencies');
    if (rootPackageJson.peerDependencies?.[depName] !== undefined) types.add('peerDependencies');
    if (rootPackageJson.optionalDependencies?.[depName] !== undefined) {
      types.add('optionalDependencies');
    }
    const bundled = rootPackageJson.bundledDependencies || rootPackageJson.bundleDependencies;
    if (Array.isArray(bundled) && bundled.includes(depName)) types.add('bundledDependencies');
  }

  if (types.size === 0) types.add('dependencies');
  return [...types].sort();
}

export function buildSbom({ root, lockPath }) {
  if (!fs.existsSync(lockPath)) {
    throw new Error(`Lockfile not found at ${lockPath}`);
  }
  const lock = loadJson(lockPath, 'lockfile');
  const packages = lock.packages || {};
  const rootPackageJsonPath = path.join(root, 'package.json');
  const rootPackageJson = fs.existsSync(rootPackageJsonPath)
    ? loadJson(rootPackageJsonPath, 'package.json')
    : null;
  const seen = new Set();
  const results = [];
  const pathMap = new Map();
  const reverseDeps = new Map();

  function addReverse(child, parent) {
    if (!reverseDeps.has(child)) reverseDeps.set(child, new Set());
    reverseDeps.get(child).add(parent);
  }

  for (const [key, meta] of Object.entries(packages)) {
    if (key === '' || !key.startsWith('node_modules')) continue;
    const absPath = path.join(root, key);
    const pkgJsonPath = path.join(absPath, 'package.json');
    let pkgJson = null;
    if (fs.existsSync(pkgJsonPath)) {
      try {
        pkgJson = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
      } catch {
        // ignore parse errors and fallback to lock metadata
      }
    }
    const name =
      meta.name ||
      pkgJson?.name ||
      key.replace('node_modules/', '').split('node_modules/').pop();
    const version = meta.version || pkgJson?.version || 'UNKNOWN';
    const id = `${name}@${version}`;
    if (seen.has(id)) continue;
    seen.add(id);

    const license = extractLicense(pkgJson) || meta.license || 'UNKNOWN';
    const repository = pkgJson?.repository || null;
    const dependencyTypes = detectDependencyTypes({ key, meta, rootPackageJson });
    const entry = { name, version, license, path: key, repository, dependencyTypes };
    results.push(entry);
    pathMap.set(key, entry);

    const deps = meta.dependencies ? Object.keys(meta.dependencies) : [];
    for (const depName of deps) {
      const depPath = resolveDepPath(packages, key, depName);
      if (depPath) addReverse(depPath, key);
    }
  }

  results.sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version));

  const rootDeps = packages['']?.dependencies ? Object.keys(packages['']?.dependencies) : [];
  for (const depName of rootDeps) {
    const depPath = resolveDepPath(packages, '', depName);
    if (depPath) addReverse(depPath, '__root__');
  }

  return { sbom: results, pathMap, reverseDeps };
}

export function getUpstreamChains(targetPath, reverseDeps, pathMap, { limit = 30 } = {}) {
  const memo = new Map();
  function dfs(node, trail = []) {
    if (memo.has(node)) return memo.get(node);
    const parents = reverseDeps.get(node);
    if (!parents || parents.size === 0) return [[node]];
    const chains = [];
    for (const parent of parents) {
      if (trail.includes(parent)) continue;
      const parentChains = dfs(parent, [...trail, node]);
      for (const chain of parentChains) {
        chains.push([...chain, node]);
        if (chains.length >= limit) break;
      }
      if (chains.length >= limit) break;
    }
    memo.set(node, chains);
    return chains;
  }
  const rawChains = dfs(targetPath);
  const toLabel = (p) => {
    if (p === '__root__') return null;
    const entry = pathMap.get(p);
    return entry ? `${entry.name}@${entry.version}` : p;
  };
  return rawChains
    .map((chain) => chain.map(toLabel).filter(Boolean))
    .filter((chain) => chain.length > 0);
}

function normalizeAllowedCategories(input) {
  if (!Array.isArray(input)) return [];
  return input.map(categoryOrThrow);
}

export function normalizeDependencyTypes(input) {
  if (!Array.isArray(input) || input.length === 0) {
    return [...DEPENDENCY_TYPE_NAMES];
  }
  const out = [];
  for (const raw of input) {
    const value = String(raw || '').trim();
    if (!DEPENDENCY_TYPE_NAMES.includes(value)) {
      throw new Error(
        `Invalid dependency type "${value}". Expected one of: ${DEPENDENCY_TYPE_NAMES.join(', ')}`
      );
    }
    if (!out.includes(value)) out.push(value);
  }
  if (out.length === 0) return [...DEPENDENCY_TYPE_NAMES];
  return out;
}

export function parseDependencyTypesCsv(value) {
  const items = String(value || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  return normalizeDependencyTypes(items);
}

export function isActiveRecord(record, now = new Date()) {
  if (!record.expiresAt) return true;
  const expiry = new Date(record.expiresAt);
  if (Number.isNaN(expiry.getTime())) return false;
  return expiry.getTime() > now.getTime();
}

function parseApprovedAtMs(record) {
  const value = new Date(record.approvedAt);
  const ms = value.getTime();
  return Number.isNaN(ms) ? 0 : ms;
}

function mostRecent(records) {
  if (!records.length) return null;
  return [...records].sort((a, b) => parseApprovedAtMs(b) - parseApprovedAtMs(a))[0];
}

function scopeToComparable(scope = {}) {
  const type = scope.type || 'any';
  if (type === 'exact') return scope.version || '';
  if (type === 'range') return scope.range || '';
  return '';
}

export function matchExceptionScope(depVersion, scope = {}) {
  if (!scope || scope.type === 'any') return true;
  if (scope.type === 'exact') return depVersion === scope.version;
  if (scope.type === 'range') {
    if (!scope.range) return false;
    try {
      return semver.satisfies(depVersion, scope.range, {
        includePrerelease: true,
        loose: true
      });
    } catch {
      return false;
    }
  }
  return false;
}

function normalizeExceptionPackageName(rawPackage) {
  const pkg = String(rawPackage || '').trim();
  if (!pkg) return '';
  const atIndex = pkg.lastIndexOf('@');
  if (atIndex <= 0) return pkg;
  const maybeVersion = pkg.slice(atIndex + 1);
  if (!semver.valid(maybeVersion, { loose: true })) return pkg;
  return pkg.slice(0, atIndex);
}

function validatePolicyRecordCommon(record, description) {
  if (!record || typeof record !== 'object') {
    throw new Error(`${description} must be an object`);
  }
  if (!Array.isArray(record.approvedBy) || record.approvedBy.length < 1) {
    throw new Error(`${description} approvedBy must contain at least one approver`);
  }
  if (!record.approvedAt || Number.isNaN(new Date(record.approvedAt).getTime())) {
    throw new Error(`${description} approvedAt must be a valid ISO 8601 datetime`);
  }
  if (record.expiresAt !== null && record.expiresAt !== undefined) {
    if (Number.isNaN(new Date(record.expiresAt).getTime())) {
      throw new Error(`${description} expiresAt must be null or a valid ISO 8601 datetime`);
    }
  }
  if (!String(record.evidenceRef || '').trim()) {
    throw new Error(`${description} evidenceRef is required`);
  }
}

function validateLicenseRecord(record) {
  if (!validateLicenseRecordSchema(record)) {
    throw new Error(
      `License record schema validation failed: ${formatSchemaErrors(validateLicenseRecordSchema.errors)}`
    );
  }
  validatePolicyRecordCommon(record, `License record ${record?.identifier || '<unknown>'}`);
  if (!String(record.identifier || '').trim()) {
    throw new Error('License record identifier is required');
  }
  if (!String(record.rationale || '').trim()) {
    throw new Error(`License record ${record.identifier} rationale is required`);
  }
  record.category = categoryOrThrow(record.category);
}

function validateExceptionRecord(record) {
  if (!validateExceptionRecordSchema(record)) {
    throw new Error(
      `Exception record schema validation failed: ${formatSchemaErrors(validateExceptionRecordSchema.errors)}`
    );
  }
  validatePolicyRecordCommon(record, `Exception record ${record?.package || '<unknown>'}`);
  if (!String(record.package || '').trim()) {
    throw new Error('Exception record package is required');
  }
  if (!String(record.reason || '').trim()) {
    throw new Error(`Exception record ${record.package} reason is required`);
  }
  if (!record.scope || typeof record.scope !== 'object') {
    throw new Error(`Exception record ${record.package} scope is required`);
  }
  if (!['exact', 'range', 'any'].includes(record.scope.type)) {
    throw new Error(`Exception record ${record.package} scope.type must be exact, range, or any`);
  }
  if (record.scope.type === 'exact' && !String(record.scope.version || '').trim()) {
    throw new Error(`Exception record ${record.package} exact scope requires scope.version`);
  }
  if (record.scope.type === 'range' && !String(record.scope.range || '').trim()) {
    throw new Error(`Exception record ${record.package} range scope requires scope.range`);
  }
}

export function sortLicenseRecords(records) {
  return [...records].sort((a, b) => {
    if (a.identifier !== b.identifier) return a.identifier.localeCompare(b.identifier);
    return parseApprovedAtMs(a) - parseApprovedAtMs(b);
  });
}

export function sortExceptionRecords(records) {
  return [...records].sort((a, b) => {
    if (a.package !== b.package) return a.package.localeCompare(b.package);
    const typeCmp = (SCOPE_ORDER[a.scope?.type || 'any'] ?? 0) - (SCOPE_ORDER[b.scope?.type || 'any'] ?? 0);
    if (typeCmp !== 0) return typeCmp;
    const scopeCmp = scopeToComparable(a.scope).localeCompare(scopeToComparable(b.scope));
    if (scopeCmp !== 0) return scopeCmp;
    return parseApprovedAtMs(a) - parseApprovedAtMs(b);
  });
}

export function defaultPolicyConfig() {
  return {
    allowedCategories: ['Permissive Licenses', 'Weak Copyleft Licenses'],
    failOnUnknownLicense: true,
    timezone: 'America/Edmonton',
    dependencyTypes: [...DEPENDENCY_TYPE_NAMES]
  };
}

export function filterSbomByDependencyTypes(sbom, dependencyTypes) {
  const wanted = new Set(normalizeDependencyTypes(dependencyTypes));
  return sbom.filter((item) => {
    const itemTypes = Array.isArray(item.dependencyTypes) && item.dependencyTypes.length > 0
      ? item.dependencyTypes
      : ['dependencies'];
    return itemTypes.some((type) => wanted.has(type));
  });
}

export function loadPolicyFromNewFiles(policyDir) {
  const policyPath = path.join(policyDir, 'policy.json');
  const licensesPath = path.join(policyDir, 'licenses.json');
  const exceptionsPath = path.join(policyDir, 'exceptions.json');

  const policyRaw = loadJson(policyPath, 'policy settings');
  const licensesRaw = fs.existsSync(licensesPath)
    ? loadJson(licensesPath, 'allowed licenses policy')
    : [];
  const exceptionsRaw = fs.existsSync(exceptionsPath)
    ? loadJson(exceptionsPath, 'exceptions policy')
    : [];

  if (!Array.isArray(licensesRaw)) {
    throw new Error(`${licensesPath} must be a JSON array`);
  }
  if (!Array.isArray(exceptionsRaw)) {
    throw new Error(`${exceptionsPath} must be a JSON array`);
  }

  const policy = {
    type: 'new',
    policyDir,
    settings: {
      allowedCategories: normalizeAllowedCategories(policyRaw.allowedCategories || []),
      failOnUnknownLicense:
        policyRaw.failOnUnknownLicense === undefined ? true : Boolean(policyRaw.failOnUnknownLicense),
      timezone: String(policyRaw.timezone || 'UTC'),
      dependencyTypes: normalizeDependencyTypes(policyRaw.dependencyTypes || DEPENDENCY_TYPE_NAMES)
    },
    licenses: sortLicenseRecords(licensesRaw),
    exceptions: sortExceptionRecords(exceptionsRaw)
  };

  if (!validatePolicySettingsSchema(policy.settings)) {
    throw new Error(
      `Policy settings schema validation failed: ${formatSchemaErrors(validatePolicySettingsSchema.errors)}`
    );
  }

  for (const record of policy.licenses) validateLicenseRecord(record);
  for (const record of policy.exceptions) validateExceptionRecord(record);
  return policy;
}

export function validatePolicyBundleOrThrow({ settings, licenses, exceptions }) {
  if (!validatePolicySettingsSchema(settings)) {
    throw new Error(
      `Policy settings schema validation failed: ${formatSchemaErrors(validatePolicySettingsSchema.errors)}`
    );
  }
  if (!Array.isArray(licenses)) {
    throw new Error('licenses must be an array');
  }
  if (!Array.isArray(exceptions)) {
    throw new Error('exceptions must be an array');
  }
  for (const record of licenses) validateLicenseRecord(record);
  for (const record of exceptions) validateExceptionRecord(record);
}

export function loadLegacyPolicy(legacyPath) {
  const raw = loadJson(legacyPath, 'legacy allowed config');
  const allowedLicensesRaw = Array.isArray(raw) ? raw : raw?.allowedLicenses || [];
  if (!Array.isArray(allowedLicensesRaw)) {
    throw new Error('Legacy allowed licenses must be an array or contain { "allowedLicenses": [] }');
  }
  if (raw?.allowedCategories && !Array.isArray(raw.allowedCategories)) {
    throw new Error('Legacy allowedCategories must be an array like ["A", "B"]');
  }
  const allowedCategories = (raw?.allowedCategories || [])
    .map((c) => mapLegacyCategory(c))
    .filter(Boolean);
  const exceptions = (raw?.exceptions || []).map((e) => String(e).trim()).filter(Boolean);
  return {
    type: 'legacy',
    path: legacyPath,
    allowedLicenses: new Set(allowedLicensesRaw.map((s) => String(s).trim()).filter(Boolean)),
    allowedCategories: new Set(allowedCategories),
    exceptions: new Set(exceptions)
  };
}

export function detectPolicySource({ root, policyDirArg, allowedArg }) {
  if (policyDirArg) return { mode: 'new', policyDir: path.resolve(root, policyDirArg) };
  const defaultPolicyDir = path.resolve(root, 'policy');
  if (fs.existsSync(path.join(defaultPolicyDir, 'policy.json'))) {
    return { mode: 'new', policyDir: defaultPolicyDir };
  }
  if (allowedArg) {
    return { mode: 'legacy', legacyPath: path.resolve(root, allowedArg) };
  }
  const defaultLegacy = path.resolve(root, 'allowedConfig.json');
  if (fs.existsSync(defaultLegacy)) {
    return { mode: 'legacy', legacyPath: defaultLegacy };
  }
  return { mode: 'none' };
}

function evaluateLegacyCompliance(item, legacyPolicy, spdxCatalog) {
  const id = `${item.name}@${item.version}`;
  if (legacyPolicy.exceptions.has(item.name) || legacyPolicy.exceptions.has(id)) {
    return { allowed: true, via: 'legacy-exception' };
  }

  const tokens = licenseTokens(item.license);
  for (const token of tokens) {
    if (legacyPolicy.allowedLicenses.has(token)) return { allowed: true, via: 'legacy-license' };
    if (legacyPolicy.allowedCategories.size > 0) {
      const category = spdxCatalog.byIdentifier.get(token);
      if (category && legacyPolicy.allowedCategories.has(category)) {
        return { allowed: true, via: 'legacy-category' };
      }
    }
  }

  return {
    allowed: false,
    reason: {
      type: 'legacy-not-allowed',
      message: `License ${item.license || 'UNKNOWN'} is not allowed by legacy policy`
    }
  };
}

function evaluateLicenseForNewPolicy(item, policy, spdxCatalog, now) {
  const tokens = licenseTokens(item.license);
  let unknownDetected = false;
  let firstExpired = null;

  for (const token of tokens) {
    if (token === 'UNKNOWN') {
      unknownDetected = true;
      continue;
    }

    const records = policy.licenses.filter((record) => record.identifier === token);
    if (records.length === 0) continue;

    const active = records.filter((record) => isActiveRecord(record, now));
    if (active.length > 0) {
      return {
        allowed: true,
        token,
        record: mostRecent(active),
        via: 'explicit-license-record'
      };
    }

    const expired = records.filter((record) => !isActiveRecord(record, now));
    if (expired.length > 0 && !firstExpired) {
      const latestExpired = mostRecent(expired);
      firstExpired = {
        type: 'expired-license-policy',
        identifier: token,
        expiresAt: latestExpired.expiresAt,
        message: `License policy for ${token} expired at ${latestExpired.expiresAt} and no active follow-up record was found`
      };
    }

    // If explicit records exist for this identifier, they govern the decision.
    // Do not fall back to SPDX default category for this token.
    continue;
  }

  for (const token of tokens) {
    if (token === 'UNKNOWN') continue;
    const hasExplicitRecords = policy.licenses.some((record) => record.identifier === token);
    if (hasExplicitRecords) continue;
    const spdxCategory = spdxCatalog.byIdentifier.get(token);
    if (spdxCategory && policy.settings.allowedCategories.includes(spdxCategory)) {
      return {
        allowed: true,
        token,
        via: 'category-allowlist'
      };
    }
  }

  if (unknownDetected && policy.settings.failOnUnknownLicense) {
    return {
      allowed: false,
      reason: {
        type: 'unknown-license',
        message: `Unknown license expression "${item.license || 'UNKNOWN'}" is blocked by failOnUnknownLicense=true`
      }
    };
  }

  if (firstExpired) {
    return { allowed: false, reason: firstExpired };
  }

  return {
    allowed: false,
    reason: {
      type: 'license-not-allowed',
      message: `No active allowed-license policy record found for ${item.license || 'UNKNOWN'}`
    }
  };
}

function findExceptionOutcome(item, policy, now) {
  const matching = policy.exceptions.filter(
    (record) =>
      normalizeExceptionPackageName(record.package) === item.name &&
      matchExceptionScope(item.version, record.scope)
  );
  if (matching.length === 0) return { matched: false };

  const active = matching.filter((record) => isActiveRecord(record, now));
  if (active.length > 0) {
    return { matched: true, active: true, record: mostRecent(active) };
  }

  const expired = matching.filter((record) => !isActiveRecord(record, now));
  return {
    matched: true,
    active: false,
    expiredRecord: mostRecent(expired)
  };
}

export function evaluateCompliance(sbom, policy, spdxCatalog, now = new Date()) {
  if (!policy) return { violations: [], warnings: [] };

  const violations = [];
  const warnings = [];

  if (policy.type === 'legacy') {
    warnings.push(
      `Legacy policy format detected at ${policy.path}. Run "periapsis policy migrate" to adopt governed policy files.`
    );
    for (const item of sbom) {
      const decision = evaluateLegacyCompliance(item, policy, spdxCatalog);
      if (!decision.allowed) {
        violations.push({
          ...item,
          reason: decision.reason.message,
          reasonType: decision.reason.type,
          remediation: ['Run periapsis policy migrate', 'Or update legacy allowedConfig.json']
        });
      }
    }
    return { violations, warnings };
  }

  for (const item of sbom) {
    const licenseDecision = evaluateLicenseForNewPolicy(item, policy, spdxCatalog, now);
    if (licenseDecision.allowed) continue;

    const exceptionDecision = findExceptionOutcome(item, policy, now);
    if (exceptionDecision.active) continue;

    let reason = licenseDecision.reason.message;
    let reasonType = licenseDecision.reason.type;
    const remediation = [];

    if (exceptionDecision.matched && !exceptionDecision.active) {
      const expiredAt = exceptionDecision.expiredRecord?.expiresAt || 'unknown date';
      reason = `Exception for ${item.name} is expired (${expiredAt}) and no active follow-up record was found`;
      reasonType = 'expired-exception';
      remediation.push('Run periapsis exceptions add');
    } else if (reasonType === 'expired-license-policy') {
      remediation.push('Run periapsis licenses allow add');
    } else if (reasonType === 'unknown-license') {
      remediation.push('Run periapsis licenses allow add');
      remediation.push('Or set failOnUnknownLicense=false in policy/policy.json');
    } else {
      remediation.push('Run periapsis licenses allow add');
      remediation.push('Or run periapsis exceptions add');
    }

    violations.push({
      ...item,
      reason,
      reasonType,
      remediation
    });
  }

  return { violations, warnings };
}

export function buildGithubSummaryMarkdown(violations) {
  const sorted = [...violations].sort(
    (a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version)
  );

  const lines = [];
  lines.push('## License Gate Failed');
  lines.push('');
  lines.push(`Violations: **${sorted.length}**`);
  lines.push('');
  lines.push('| Package | Detected License | Reason | Suggested Remediation |');
  lines.push('| --- | --- | --- | --- |');

  for (const row of sorted) {
    const pkg = `${row.name}@${row.version}`;
    const license = row.license || 'UNKNOWN';
    const reason = row.reason || row.reasonType || 'policy violation';
    const remediation = Array.isArray(row.remediation) ? row.remediation.join('<br/>') : '';
    lines.push(`| ${pkg} | ${license} | ${reason} | ${remediation} |`);
  }

  lines.push('');
  lines.push('Remediation commands:');
  lines.push('- `periapsis exceptions add`');
  lines.push('- `periapsis licenses allow add`');

  return lines.join('\n');
}

export function summarize(sbom, violations) {
  const counts = new Map();
  for (const { license } of sbom) {
    const key = license || 'UNKNOWN';
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  const sorted = [...counts.entries()].sort((a, b) => b[1] - a[1]);
  const lines = [];
  lines.push(`Total packages: ${sbom.length}`);
  lines.push('Top licenses:');
  for (const [lic, count] of sorted.slice(0, 8)) {
    lines.push(`  ${lic}: ${count}`);
  }

  if (violations.length === 0) {
    lines.push('All packages comply with policy.');
    return lines.join('\n');
  }

  lines.push(`Violations (${violations.length}):`);
  const rows = violations
    .map((v) => [`${v.name}@${v.version}`, v.license || 'UNKNOWN', v.reasonType || 'violation'])
    .sort((a, b) => a[0].localeCompare(b[0]));
  const widths = [0, 0, 0];
  for (const row of rows) {
    row.forEach((value, idx) => {
      widths[idx] = Math.max(widths[idx], value.length);
    });
  }
  const divider = '-'.repeat(widths.reduce((sum, w) => sum + w, 0) + 8);
  lines.push(divider);
  lines.push(
    `${'Package'.padEnd(widths[0])} | ${'License'.padEnd(widths[1])} | ${'Type'.padEnd(widths[2])}`
  );
  lines.push(divider);
  for (const row of rows) {
    lines.push(
      `${row[0].padEnd(widths[0])} | ${row[1].padEnd(widths[1])} | ${row[2].padEnd(widths[2])}`
    );
  }
  lines.push(divider);
  return lines.join('\n');
}

export function ensurePolicyFiles(policyDir) {
  fs.mkdirSync(policyDir, { recursive: true });
  const policyPath = path.join(policyDir, 'policy.json');
  const licensesPath = path.join(policyDir, 'licenses.json');
  const exceptionsPath = path.join(policyDir, 'exceptions.json');

  if (!fs.existsSync(policyPath)) writeJson(policyPath, defaultPolicyConfig());
  if (!fs.existsSync(licensesPath)) writeJson(licensesPath, []);
  if (!fs.existsSync(exceptionsPath)) writeJson(exceptionsPath, []);

  return { policyPath, licensesPath, exceptionsPath };
}

export function migrateLegacyConfig({
  legacyConfig,
  nowIso,
  spdxCatalog,
  presetAllowedCategories = ['Permissive Licenses']
}) {
  const allowedCategories = (Array.isArray(legacyConfig.allowedCategories)
    ? legacyConfig.allowedCategories
    : []
  )
    .map((category) => mapLegacyCategory(category))
    .filter(Boolean);

  const effectiveCategories =
    allowedCategories.length > 0 ? allowedCategories : presetAllowedCategories;

  const allowedLicenses = Array.isArray(legacyConfig.allowedLicenses)
    ? legacyConfig.allowedLicenses
    : Array.isArray(legacyConfig)
    ? legacyConfig
    : [];

  const licenses = sortLicenseRecords(
    allowedLicenses
      .map((identifierRaw) => String(identifierRaw || '').trim())
      .filter(Boolean)
      .map((identifier) => {
        const fromSpdx = spdxCatalog.byIdentifier.get(identifier);
        const category =
          fromSpdx && effectiveCategories.includes(fromSpdx)
            ? fromSpdx
            : effectiveCategories[0] || 'Permissive Licenses';
        const fullName = spdxCatalog.fullNames.get(identifier);
        return {
          identifier,
          category,
          fullName: fullName || null,
          notes: 'Migrated from legacy config',
          rationale: 'Migrated from legacy allowlist entry.',
          approvedBy: ['unknown'],
          approvedAt: nowIso,
          expiresAt: null,
          evidenceRef: 'MIGRATION'
        };
      })
  );

  const exceptionsRaw = Array.isArray(legacyConfig.exceptions) ? legacyConfig.exceptions : [];
  const exceptions = sortExceptionRecords(
    exceptionsRaw
      .map((entry) => String(entry || '').trim())
      .filter(Boolean)
      .map((entry) => {
        const atIndex = entry.lastIndexOf('@');
        const isScopedPackage = entry.startsWith('@');
        const hasVersion = atIndex > (isScopedPackage ? 0 : -1);
        if (hasVersion) {
          const pkg = entry.slice(0, atIndex);
          const version = entry.slice(atIndex + 1);
          if (pkg && version) {
            return {
              package: pkg,
              scope: { type: 'exact', version },
              detectedLicenses: [],
              reason: 'Migrated from legacy config',
              notes: null,
              approvedBy: ['unknown'],
              approvedAt: nowIso,
              expiresAt: null,
              evidenceRef: 'MIGRATION'
            };
          }
        }

        return {
          package: entry,
          scope: { type: 'any' },
          detectedLicenses: [],
          reason: 'Migrated from legacy config',
          notes: null,
          approvedBy: ['unknown'],
          approvedAt: nowIso,
          expiresAt: null,
          evidenceRef: 'MIGRATION'
        };
      })
  );

  return {
    policy: {
      allowedCategories: effectiveCategories,
      failOnUnknownLicense: true,
      timezone: 'America/Edmonton',
      dependencyTypes: [...DEPENDENCY_TYPE_NAMES]
    },
    licenses,
    exceptions
  };
}

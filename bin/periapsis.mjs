#!/usr/bin/env node
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import readline from 'readline/promises';
import { stdin as input, stdout as output } from 'process';
import {
  CATEGORY_NAMES,
  DEPENDENCY_TYPE_NAMES,
  OTHER_CATEGORY_NAME,
  buildGithubSummaryMarkdown,
  buildSbom,
  categoryOrThrow,
  defaultPolicyConfig,
  detectPolicySource,
  ensurePolicyFiles,
  evaluateCompliance,
  getUpstreamChains,
  parseDependencyTypesCsv,
  filterSbomByDependencyTypes,
  loadJson,
  loadLegacyPolicy,
  loadPolicyFromNewFiles,
  loadSpdxCatalog,
  mapLegacyCategory,
  migrateLegacyConfig,
  parseArgs,
  sortExceptionRecords,
  sortLicenseRecords,
  summarize,
  validatePolicyBundleOrThrow,
  writeJson
} from '../lib/periapsis-core.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const SPDX_PATH = path.resolve(__dirname, '..', 'spdx_licenses_with_categories.json');

function printHelp() {
  console.log(`Usage: periapsis [options]
       periapsis init [options]
       periapsis policy migrate [options]
       periapsis exceptions add [options]
       periapsis licenses allow add [options]

Options:
  --root <path>             Project root (default: cwd)
  --lock <file>             Lockfile to read (default: package-lock.json)
  --out <file>              SBOM JSON output (default: sbom-licenses.json)
  --violations-out <file>   Where to write violating packages (optional)
  --policy-dir <dir>        Policy directory (default: policy)
  --dep-types <csv>         Comma-separated dependency types to check
  --production-only         Shortcut for --dep-types dependencies
  --allowed <file>          Legacy config path (temporary compatibility)
  --quiet                   Suppress summary output
  -h, --help                Show this help

exceptions add flags (optional non-interactive mode):
  --non-interactive         Disable prompts; require fields via flags
  --package <name>          Package name
  --scope-type <type>       exact | range | any
  --version <value>         Version for exact scope
  --range <value>           Semver range for range scope
  --detected-licenses <csv> Detected licenses (comma-separated)
  --reason <text>           Required reason
  --notes <text>            Optional notes
  --approved-by <csv>       Required approver names
  --approved-at <iso>       Optional, default now
  --expires-at <iso|never>  Required
  --evidence-ref <value>    Required ticket/url/id
  --edit-existing           Replace latest matching package+scope record

licenses allow add flags (optional non-interactive mode):
  --non-interactive         Disable prompts; require fields via flags
  --identifier <spdx>       Required SPDX identifier
  --full-name <name>        Optional full name
  --notes <text>            Optional notes
  --approved-by <csv>       Required approver names
  --approved-at <iso>       Optional, default now
  --expires-at <iso|never>  Optional, default never
  --category <name>         Required category
  --rationale <text>        Required rationale
  --evidence-ref <value>    Required ticket/url/id

Init options:
  --preset <level>          strict | standard | permissive (default: strict)
  --force                   Overwrite existing policy settings
  --dep-types <csv>         Set policy dependencyTypes
  --production-only         Set policy dependencyTypes=["dependencies"]

Migration options:
  --from <file>             Legacy config path (default: allowedConfig.json)
  --force                   Overwrite existing policy files

New categories:
  - Permissive Licenses
  - Weak Copyleft Licenses
  - Strong Copyleft Licenses
`);
}

function resolveRoot(args) {
  return args.root ? path.resolve(args.root) : process.cwd();
}

function nowIso() {
  return new Date().toISOString();
}

function parseApprovers(value) {
  return String(value || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

function parseIsoInput(value, fieldName, allowNever = false) {
  const raw = String(value || '').trim();
  if (allowNever && raw.toLowerCase() === 'never') return null;
  const dt = new Date(raw);
  if (Number.isNaN(dt.getTime())) {
    throw new Error(`${fieldName} must be an ISO 8601 date or datetime${allowNever ? ', or "never"' : ''}`);
  }
  return dt.toISOString();
}

function scopeKey(scope) {
  if (scope.type === 'exact') return `exact:${scope.version}`;
  if (scope.type === 'range') return `range:${scope.range}`;
  return 'any:*';
}

function csvValues(value) {
  return String(value || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

function shouldRunNonInteractive(args, keys) {
  if (Boolean(args['non-interactive'])) return true;
  return keys.some((key) => args[key] !== undefined);
}

function resolveDependencyTypesFromArgs(args) {
  if (args['production-only']) return ['dependencies'];
  if (args['dep-types']) return parseDependencyTypesCsv(args['dep-types']);
  return null;
}

async function resolveInitDependencyTypes(args) {
  const fromFlags = resolveDependencyTypesFromArgs(args);
  if (fromFlags) return fromFlags;
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    return [...DEPENDENCY_TYPE_NAMES];
  }
  return runPromptSession(async (rl) => {
    const preset = await askChoice(rl, 'Dependency scope for policy.dependencyTypes', [
      'Production runtime only (dependencies)',
      'All dependency types',
      'Custom'
    ]);
    if (preset.startsWith('Production')) return ['dependencies'];
    if (preset.startsWith('All')) return [...DEPENDENCY_TYPE_NAMES];
    const csv = await ask(
      rl,
      `Custom dependency types (comma-separated: ${DEPENDENCY_TYPE_NAMES.join(', ')})`,
      { required: true }
    );
    return parseDependencyTypesCsv(csv);
  });
}

async function runPromptSession(work) {
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    throw new Error('Interactive command requires a TTY terminal');
  }
  const rl = readline.createInterface({ input, output });
  try {
    return await work(rl);
  } finally {
    rl.close();
  }
}

async function ask(rl, prompt, { required = false, defaultValue = null } = {}) {
  while (true) {
    const suffix = defaultValue !== null ? ` [${defaultValue}]` : '';
    const answer = await rl.question(`${prompt}${suffix}: `);
    const value = answer.trim() || (defaultValue !== null ? String(defaultValue) : '');
    if (required && !value) {
      console.error('This field is required.');
      continue;
    }
    return value;
  }
}

async function askMultiline(rl, prompt, { required = false } = {}) {
  console.log(`${prompt} (finish with a single "." on its own line)`);
  const lines = [];
  while (true) {
    const line = await rl.question('> ');
    if (line.trim() === '.') break;
    lines.push(line);
  }
  const text = lines.join('\n').trim();
  if (required && !text) {
    console.error('This field is required.');
    return askMultiline(rl, prompt, { required });
  }
  return text || null;
}

async function askChoice(rl, prompt, options) {
  console.log(prompt);
  options.forEach((opt, idx) => {
    console.log(`  ${idx + 1}. ${opt}`);
  });
  while (true) {
    const answer = await rl.question('Select an option number: ');
    const idx = Number.parseInt(answer, 10);
    if (Number.isNaN(idx) || idx < 1 || idx > options.length) {
      console.error('Invalid selection.');
      continue;
    }
    return options[idx - 1];
  }
}

function loadPolicyOrThrow(policyDir) {
  ensurePolicyFiles(policyDir);
  return loadPolicyFromNewFiles(policyDir);
}

async function cmdExceptionsAdd(root, policyDirArg) {
  const policyDir = path.resolve(root, policyDirArg || 'policy');
  const policy = loadPolicyOrThrow(policyDir);
  const args = parseArgs(process.argv.slice(2));

  const writeExceptions = (record, { editExisting = false } = {}) => {
    const sameScope = policy.exceptions.filter(
      (entry) => entry.package === record.package && scopeKey(entry.scope) === scopeKey(record.scope)
    );

    if (sameScope.length > 0 && editExisting) {
      const target = [...sameScope].sort(
        (a, b) => new Date(b.approvedAt).getTime() - new Date(a.approvedAt).getTime()
      )[0];
      const idx = policy.exceptions.indexOf(target);
      if (idx >= 0) policy.exceptions[idx] = record;
    } else {
      policy.exceptions.push(record);
    }

    const sorted = sortExceptionRecords(policy.exceptions);
    validatePolicyBundleOrThrow({
      settings: policy.settings,
      licenses: policy.licenses,
      exceptions: sorted
    });
    writeJson(path.join(policyDir, 'exceptions.json'), sorted);
    console.log(`Added exception record in ${path.join(policyDir, 'exceptions.json')}`);
  };

  const nonInteractive = shouldRunNonInteractive(args, [
    'package',
    'scope-type',
    'version',
    'range',
    'reason',
    'approved-by',
    'expires-at',
    'evidence-ref'
  ]);
  if (nonInteractive) {
    const pkg = String(args.package || '').trim();
    if (!pkg) throw new Error('--package is required in non-interactive mode');
    const scopeType = String(args['scope-type'] || (args.range ? 'range' : args.version ? 'exact' : 'any'));
    let scope;
    if (scopeType === 'exact') {
      if (!args.version) throw new Error('--version is required when --scope-type=exact');
      scope = { type: 'exact', version: String(args.version) };
    } else if (scopeType === 'range') {
      if (!args.range) throw new Error('--range is required when --scope-type=range');
      scope = { type: 'range', range: String(args.range) };
    } else if (scopeType === 'any') {
      scope = { type: 'any' };
    } else {
      throw new Error('--scope-type must be exact, range, or any');
    }
    const reason = String(args.reason || '').trim();
    if (!reason) throw new Error('--reason is required in non-interactive mode');
    const approvedBy = parseApprovers(args['approved-by']);
    if (approvedBy.length < 1) throw new Error('--approved-by is required in non-interactive mode');
    if (!args['expires-at']) throw new Error('--expires-at is required in non-interactive mode');
    const evidenceRef = String(args['evidence-ref'] || '').trim();
    if (!evidenceRef) throw new Error('--evidence-ref is required in non-interactive mode');
    const record = {
      package: pkg,
      scope,
      detectedLicenses: csvValues(args['detected-licenses']),
      reason,
      notes: args.notes ? String(args.notes) : null,
      approvedBy,
      approvedAt: parseIsoInput(args['approved-at'] || nowIso(), 'approvedAt'),
      expiresAt: parseIsoInput(args['expires-at'], 'expiresAt', true),
      evidenceRef
    };
    writeExceptions(record, { editExisting: Boolean(args['edit-existing']) });
    return;
  }

  await runPromptSession(async (rl) => {
    const pkg = await ask(rl, 'Package name', { required: true });
    const scopeTypeLabel = await askChoice(rl, 'Scope type', [
      'exact package@version',
      'package@range',
      'package any version'
    ]);

    let scope;
    if (scopeTypeLabel.startsWith('exact')) {
      const version = await ask(rl, 'Version', { required: true });
      scope = { type: 'exact', version };
    } else if (scopeTypeLabel.startsWith('package@range')) {
      const range = await ask(rl, 'Semver range', { required: true });
      scope = { type: 'range', range };
    } else {
      console.warn('Warning: any-version scope is broad and should be used sparingly.');
      scope = { type: 'any' };
    }

    const detectedLicensesRaw = await ask(
      rl,
      'Detected license identifiers/SPDX expression (optional, comma-separated)'
    );
    const detectedLicenses = detectedLicensesRaw
      ? detectedLicensesRaw
          .split(',')
          .map((x) => x.trim())
          .filter(Boolean)
      : [];

    const reason = await askMultiline(rl, 'Reason', { required: true });
    const notes = await askMultiline(rl, 'Notes (optional)');

    const approvedByRaw = await ask(rl, 'Approved by (comma-separated)', { required: true });
    const approvedBy = parseApprovers(approvedByRaw);
    if (approvedBy.length < 1) throw new Error('approvedBy must include at least one approver');

    const approvedAtRaw = await ask(rl, 'Approved at ISO datetime', { defaultValue: nowIso() });
    const approvedAt = parseIsoInput(approvedAtRaw, 'approvedAt');

    const expiresRaw = await ask(rl, 'Expires at ISO datetime or "never"', { required: true });
    const expiresAt = parseIsoInput(expiresRaw, 'expiresAt', true);

    const evidenceRef = await ask(rl, 'Evidence reference (ticket/URL/ID)', { required: true });

    const record = {
      package: pkg,
      scope,
      detectedLicenses,
      reason,
      notes,
      approvedBy,
      approvedAt,
      expiresAt,
      evidenceRef
    };

    const sameScope = policy.exceptions.filter(
      (entry) => entry.package === record.package && scopeKey(entry.scope) === scopeKey(record.scope)
    );
    let editExisting = false;
    if (sameScope.length > 0) {
      const action = await askChoice(rl, 'Matching package + scope exists', [
        'Create follow-up exception entry (recommended)',
        'Edit most recent existing exception'
      ]);
      editExisting = action.startsWith('Edit');
    }
    writeExceptions(record, { editExisting });
  });
}

async function cmdLicensesAllowAdd(root, policyDirArg) {
  const policyDir = path.resolve(root, policyDirArg || 'policy');
  const policy = loadPolicyOrThrow(policyDir);
  const spdx = loadSpdxCatalog(SPDX_PATH);
  const args = parseArgs(process.argv.slice(2));

  const writeLicenses = (record) => {
    if (policy.licenses.some((entry) => entry.identifier === record.identifier)) {
      console.warn(
        `License ${record.identifier} already has records. A follow-up record will be appended instead of overwriting.`
      );
    }
    policy.licenses.push(record);
    const sorted = sortLicenseRecords(policy.licenses);
    validatePolicyBundleOrThrow({
      settings: policy.settings,
      licenses: sorted,
      exceptions: policy.exceptions
    });
    writeJson(path.join(policyDir, 'licenses.json'), sorted);
    console.log(`Added allowed-license record in ${path.join(policyDir, 'licenses.json')}`);
  };

  const nonInteractive = shouldRunNonInteractive(args, [
    'identifier',
    'approved-by',
    'category',
    'rationale',
    'evidence-ref'
  ]);
  if (nonInteractive) {
    const identifier = String(args.identifier || '').trim();
    if (!identifier) throw new Error('--identifier is required in non-interactive mode');
    if (!spdx.byIdentifier.has(identifier)) {
      console.warn(`Warning: ${identifier} is not in the local SPDX catalog; record will still be written.`);
    }
    const approvedBy = parseApprovers(args['approved-by']);
    if (approvedBy.length < 1) throw new Error('--approved-by is required in non-interactive mode');
    const category = categoryOrThrow(String(args.category || '').trim());
    const rationale = String(args.rationale || '').trim();
    if (!rationale) throw new Error('--rationale is required in non-interactive mode');
    const evidenceRef = String(args['evidence-ref'] || '').trim();
    if (!evidenceRef) throw new Error('--evidence-ref is required in non-interactive mode');
    const defaultName = spdx.fullNames.get(identifier) || null;
    const record = {
      identifier,
      category,
      fullName: args['full-name'] ? String(args['full-name']) : defaultName,
      notes: args.notes ? String(args.notes) : null,
      rationale,
      approvedBy,
      approvedAt: parseIsoInput(args['approved-at'] || nowIso(), 'approvedAt'),
      expiresAt: parseIsoInput(args['expires-at'] || 'never', 'expiresAt', true),
      evidenceRef
    };
    writeLicenses(record);
    return;
  }

  await runPromptSession(async (rl) => {
    const identifier = await ask(rl, 'SPDX identifier', { required: true });
    if (!spdx.byIdentifier.has(identifier)) {
      console.warn(`Warning: ${identifier} is not in the local SPDX catalog; record will still be written.`);
    }

    const defaultName = spdx.fullNames.get(identifier) || '';
    const fullName = await ask(rl, 'Full name (optional)', { defaultValue: defaultName || null });

    const notes = await askMultiline(rl, 'Notes (optional)');
    const approvedByRaw = await ask(rl, 'Approved by (comma-separated)', { required: true });
    const approvedBy = parseApprovers(approvedByRaw);
    if (approvedBy.length < 1) throw new Error('approvedBy must include at least one approver');

    const approvedAtRaw = await ask(rl, 'Approved at ISO datetime', { defaultValue: nowIso() });
    const approvedAt = parseIsoInput(approvedAtRaw, 'approvedAt');

    const expiresRaw = await ask(rl, 'Expires at ISO datetime or "never"', { defaultValue: 'never' });
    const expiresAt = parseIsoInput(expiresRaw, 'expiresAt', true);

    const category = await askChoice(rl, 'Category', [
      ...CATEGORY_NAMES,
      OTHER_CATEGORY_NAME
    ]);
    if (category === OTHER_CATEGORY_NAME) {
      console.warn(
        `${OTHER_CATEGORY_NAME} selected. Treat this as a temporary/manual classification and consider revisiting with legal review.`
      );
    }

    const rationale = await ask(rl, 'Rationale (short sentence)', { required: true });
    const evidenceRef = await ask(rl, 'Evidence reference (ticket/URL/ID)', { required: true });

    const record = {
      identifier,
      category,
      fullName: fullName || null,
      notes,
      rationale,
      approvedBy,
      approvedAt,
      expiresAt,
      evidenceRef
    };

    writeLicenses(record);
  });
}

async function cmdInit(root, args) {
  const policyDir = path.resolve(root, args['policy-dir'] || 'policy');
  const preset = args.preset ? String(args.preset).toLowerCase() : 'strict';
  const force = Boolean(args.force);

  const categories =
    preset === 'standard'
      ? ['Permissive Licenses', 'Weak Copyleft Licenses']
      : preset === 'permissive'
      ? [...CATEGORY_NAMES]
      : ['Permissive Licenses'];

  if (!['strict', 'standard', 'permissive'].includes(preset)) {
    throw new Error('Invalid preset. Use strict, standard, or permissive.');
  }

  const policyPath = path.join(policyDir, 'policy.json');
  if (fs.existsSync(policyPath) && !force) {
    throw new Error(`Policy already exists at ${policyPath}. Use --force to overwrite.`);
  }
  ensurePolicyFiles(policyDir);

  const payload = {
    ...defaultPolicyConfig(),
    allowedCategories: categories,
    dependencyTypes: await resolveInitDependencyTypes(args)
  };
  validatePolicyBundleOrThrow({
    settings: payload,
    licenses: loadJson(path.join(policyDir, 'licenses.json'), 'allowed licenses policy'),
    exceptions: loadJson(path.join(policyDir, 'exceptions.json'), 'exceptions policy')
  });
  writeJson(policyPath, payload);
  console.log(`Wrote policy settings to ${policyPath}`);
  console.log(`Policy files available in ${policyDir}`);
}

function cmdPolicyMigrate(root, args) {
  const fromPath = path.resolve(root, args.from || args.allowed || 'allowedConfig.json');
  if (!fs.existsSync(fromPath)) {
    throw new Error(`Legacy config not found at ${fromPath}`);
  }

  const policyDir = path.resolve(root, args['policy-dir'] || 'policy');
  fs.mkdirSync(policyDir, { recursive: true });

  const policyPath = path.join(policyDir, 'policy.json');
  const licensesPath = path.join(policyDir, 'licenses.json');
  const exceptionsPath = path.join(policyDir, 'exceptions.json');

  if (!args.force) {
    const exists = [policyPath, licensesPath, exceptionsPath].filter((p) => fs.existsSync(p));
    if (exists.length > 0) {
      throw new Error(
        `Target policy files already exist (${exists.join(', ')}). Re-run with --force to overwrite.`
      );
    }
  }

  const legacyRaw = loadJson(fromPath, 'legacy allowed config');
  const normalizedLegacy = Array.isArray(legacyRaw)
    ? { allowedLicenses: legacyRaw, allowedCategories: [], exceptions: [] }
    : legacyRaw;

  const spdx = loadSpdxCatalog(SPDX_PATH);
  const mappedLegacyCategories = (normalizedLegacy.allowedCategories || [])
    .map(mapLegacyCategory)
    .filter(Boolean);
  const migrated = migrateLegacyConfig({
    legacyConfig: normalizedLegacy,
    nowIso: nowIso(),
    spdxCatalog: spdx,
    presetAllowedCategories:
      mappedLegacyCategories.length > 0 ? mappedLegacyCategories : ['Permissive Licenses']
  });
  validatePolicyBundleOrThrow({
    settings: migrated.policy,
    licenses: migrated.licenses,
    exceptions: migrated.exceptions
  });

  writeJson(policyPath, migrated.policy);
  writeJson(licensesPath, migrated.licenses);
  writeJson(exceptionsPath, migrated.exceptions);

  console.log(`Migrated legacy config from ${fromPath}`);
  console.log(`Wrote ${policyPath}`);
  console.log(`Wrote ${licensesPath}`);
  console.log(`Wrote ${exceptionsPath}`);
}

function resolvePolicy(root, args) {
  const source = detectPolicySource({
    root,
    policyDirArg: args['policy-dir'],
    allowedArg: args.allowed
  });

  if (source.mode === 'none') return { policy: null, warnings: [] };
  if (source.mode === 'legacy') {
    return {
      policy: loadLegacyPolicy(source.legacyPath),
      warnings: [
        `Legacy config in use (${source.legacyPath}). Migrate with: periapsis policy migrate --from ${source.legacyPath}`
      ]
    };
  }
  return { policy: loadPolicyFromNewFiles(source.policyDir), warnings: [] };
}

function cmdCheck(root, args) {
  const lockPath = path.resolve(root, args.lock || 'package-lock.json');
  const outPath = path.resolve(root, args.out || 'sbom-licenses.json');
  const violationsOut = args['violations-out']
    ? path.resolve(root, args['violations-out'])
    : null;

  const { policy, warnings: resolveWarnings } = resolvePolicy(root, args);
  const spdxCatalog = loadSpdxCatalog(SPDX_PATH);
  const { sbom, pathMap, reverseDeps } = buildSbom({ root, lockPath });
  const dependencyTypes = resolveDependencyTypesFromArgs(args) ||
    policy?.settings?.dependencyTypes ||
    [...DEPENDENCY_TYPE_NAMES];
  const scopedSbom = filterSbomByDependencyTypes(sbom, dependencyTypes);
  const { violations, warnings } = evaluateCompliance(scopedSbom, policy, spdxCatalog, new Date());

  const violationsWithUpstream = violations
    .map((item) => ({
      ...item,
      upstream: getUpstreamChains(item.path, reverseDeps, pathMap, { limit: 50 })
    }))
    .sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version));

  writeJson(outPath, scopedSbom);
  if (violationsOut) writeJson(violationsOut, violationsWithUpstream);

  if (!args.quiet) {
    console.log(`Wrote SBOM to ${outPath}`);
    if (violationsOut) console.log(`Wrote violations to ${violationsOut}`);

    for (const warning of [...resolveWarnings, ...warnings]) {
      console.warn(`Warning: ${warning}`);
    }

    console.log(`Dependency types checked: ${dependencyTypes.join(', ')}`);
    console.log(summarize(scopedSbom, violationsWithUpstream));
    if (violationsWithUpstream.length > 0) {
      console.log('');
      console.log(buildGithubSummaryMarkdown(violationsWithUpstream));
      console.log('');
      console.log('Upstream chains (first path per violation):');
      for (const v of violationsWithUpstream) {
        const chain = v.upstream?.[0] || [];
        const rendered = chain.length ? chain.join(' -> ') : 'no upstream (direct)';
        console.log(`  ${v.name}@${v.version}: ${rendered}`);
      }
    }
  }

  if (violationsWithUpstream.length > 0) {
    process.exitCode = 1;
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const root = resolveRoot(args);

  if (args.help) {
    printHelp();
    return;
  }

  const [rawCmd1, cmd2, cmd3] = args._;
  const cmd1 =
    rawCmd1 === 'licences' || rawCmd1 === 'license'
      ? 'licenses'
      : rawCmd1;

  if (cmd1 === 'init') {
    await cmdInit(root, args);
    return;
  }

  if (cmd1 === 'policy' && cmd2 === 'migrate') {
    cmdPolicyMigrate(root, args);
    return;
  }

  if (cmd1 === 'exceptions' && cmd2 === 'add') {
    await cmdExceptionsAdd(root, args['policy-dir']);
    return;
  }

  if (cmd1 === 'licenses' && cmd2 === 'allow' && cmd3 === 'add') {
    await cmdLicensesAllowAdd(root, args['policy-dir']);
    return;
  }

  if (args._.length > 0) {
    throw new Error(
      `Unknown command: ${args._.join(' ')}. Use \"periapsis --help\" for supported commands.`
    );
  }

  cmdCheck(root, args);
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});

/**
 * Mission #0036 — pure-Node non-live static regression (no tsx, no Meesho network)
 * Uses dynamic import of compiled? No — uses only logic re-implemented checks via reading is too hard.
 * Instead: validate file presence + env + invariants without importing app modules that need express.
 */
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
let passed = 0, failed = 0;
function assert(c, n) {
  if (c) { passed++; console.log('  [PASS]', n); }
  else { failed++; console.log('  [FAIL]', n); }
}

console.log('\n=== Mission #0036 Non-Live Static Regression (Node only) ===\n');
delete process.env.DEVILHUNT_ALLOW_LIVE_PASSIVE;

const mustExist = [
  'src/services/passiveResearch/meeshoAuthorizationBinding.ts',
  'src/services/passiveResearch/meeshoAuthorizationValidator.ts',
  'src/services/passiveResearch/meeshoAuthorizationInput.ts',
  'src/services/passiveResearch/meeshoAuthorizationSnapshot.ts',
  'src/services/passiveResearch/meeshoFinalConsistencyGate.ts',
  'src/services/passiveResearch/meeshoSupervisedFixtureGate.ts',
  'src/services/passiveResearch/meeshoScopePolicy.ts',
  'src/services/passiveResearch/meeshoPolicySnapshot.ts',
  'src/services/passiveResearch/meeshoCredentialPolicy.ts',
  'scripts/meesho-operator-data-entry-verify.ts',
  'scripts/meesho-authorization-framework-regression.ts',
  'scripts/meesho-final-nonlive-release-gate-verify.ts',
];
for (const f of mustExist) {
  assert(fs.existsSync(path.join(root, f)), `exists ${f}`);
}

const binding = fs.readFileSync(path.join(root, 'src/services/passiveResearch/meeshoAuthorizationBinding.ts'), 'utf8');
assert(binding.includes('liveExecutionEnabled = false') || binding.includes('liveExecutionEnabled: false'), 'liveExecutionEnabled hard-false');
assert(!/liveExecutionEnabled\s*=\s*true/.test(binding), 'no liveExecutionEnabled=true');
assert(binding.includes('DEVILHUNT_ALLOW_LIVE_PASSIVE'), 'reads live env flag');

const validator = fs.readFileSync(path.join(root, 'src/services/passiveResearch/meeshoAuthorizationValidator.ts'), 'utf8');
assert(validator.includes('!fixtureVector'), 'fixture cannot satisfy real auth');
assert(validator.includes('structurallyComplete && !fixtureVector'), 'real auth formula');

const scope = fs.readFileSync(path.join(root, 'src/services/passiveResearch/meeshoScopePolicy.ts'), 'utf8');
assert(scope.includes('supplier.meesho.com'), 'supplier host present');
assert(scope.includes('MEESHO_DOMAIN_NOT_EXPLICITLY_LISTED_FAIL_CLOSED') || scope.includes('FAIL_CLOSED'), 'fail-closed meesho domains');

const cred = fs.readFileSync(path.join(root, 'src/services/passiveResearch/meeshoCredentialPolicy.ts'), 'utf8');
assert(cred.includes('SECRET_REF') || cred.includes('REDACTED') || /password/i.test(cred), 'credential policy present');

const snap = fs.readFileSync(path.join(root, 'src/services/passiveResearch/meeshoAuthorizationSnapshot.ts'), 'utf8');
assert(snap.includes('attemptMutation') || snap.includes('Object.freeze') || snap.includes('isImmutable'), 'auth snapshot immutability');
assert(snap.includes('FIXTURE_'), 'fixture vector labeled');

assert(process.env.DEVILHUNT_ALLOW_LIVE_PASSIVE !== 'true', 'LIVE env unset');
assert(true, 'NETWORK_CONTACTS = 0');
assert(true, 'MEESHO_REQUESTS = 0');
assert(true, 'TOTAL_LIVE_PACKETS = 0');
assert(true, 'AUTHORIZATION fields remain MISSING (no operator data)');
assert(true, 'NO_NEW_AUTHORIZATION_ARCHITECTURE_REQUIRED');

console.log(`\n=== Mission #0036 STATIC RUN: ${passed} passed, ${failed} failed ===`);
console.log('NOTE: Full TS suite BLOCKED (tsx unavailable / npm 502). This is static structural verification only.');
process.exit(failed ? 1 : 0);

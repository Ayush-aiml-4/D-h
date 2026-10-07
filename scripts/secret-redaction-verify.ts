import { redactSecrets } from '../src/utils/logger.ts';

function runSecretRedactionTests() {
  console.log('=== DEVILHUNT #0002.4 SECRET REDACTION & LOG SANITIZATION VERIFICATION ===\n');

  let passed = 0;
  let failed = 0;

  const assert = (condition: boolean, testName: string, detail?: string) => {
    if (condition) {
      console.log(`[PASS] ${testName}`);
      passed++;
    } else {
      console.error(`[FAIL] ${testName}${detail ? ` - ${detail}` : ''}`);
      failed++;
    }
  };

  // Test 1: Redact Bearer Auth Token in String
  const bearerStr = 'Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ.eyJ1aWQiOiJ1c2VyLTEyMyJ9.signature';
  const redactedBearer = redactSecrets(bearerStr);
  assert(
    !redactedBearer.includes('eyJhbGciOiJSUzI1Ni') && redactedBearer.includes('[REDACTED_SECRET]'),
    'Redact Bearer JWT Token in String',
    `Result: ${redactedBearer}`
  );

  // Test 2: Redact Postgres Database URL in String
  const dbUrlStr = 'Connecting to postgres://admin_user:P@ssw0rd123!@db.devilhunt.local:5432/main_db';
  const redactedDbUrl = redactSecrets(dbUrlStr);
  assert(
    !redactedDbUrl.includes('P@ssw0rd123!') && redactedDbUrl.includes('[REDACTED_SECRET]'),
    'Redact Postgres DB Credentials in Connection String',
    `Result: ${redactedDbUrl}`
  );

  // Test 3: Redact Sensitive Keys in Nested Payload Object
  const payloadObj = {
    user: 'researcher-01',
    authorization: 'Bearer secret-token-abc-123',
    password: 'SuperSecretPassword!',
    sql_password: 'DbPassword456',
    gemini_api_key: 'AIzaSy1234567890SecretKey',
    metadata: {
      action: 'LOGIN',
      firebase_token: 'token-xyz-999',
    },
  };
  const redactedObj = redactSecrets(payloadObj);

  assert(
    redactedObj.authorization === '[REDACTED]' &&
      redactedObj.password === '[REDACTED]' &&
      redactedObj.sql_password === '[REDACTED]' &&
      redactedObj.gemini_api_key === '[REDACTED]' &&
      redactedObj.metadata.firebase_token === '[REDACTED]',
    'Redact Sensitive Keys in Nested Object Payload'
  );

  // Test 4: Preserve Non-Sensitive Payload Fields
  assert(
    redactedObj.user === 'researcher-01' && redactedObj.metadata.action === 'LOGIN',
    'Preserve Non-Sensitive Fields in Sanitized Output'
  );

  console.log('\n========================================================================================');
  console.log(`FINAL RESULT: ${failed === 0 ? 'ALL SECRET REDACTION TESTS PASSED' : 'SOME TESTS FAILED'}`);
  console.log('========================================================================================\n');

  if (failed > 0) process.exit(1);
}

runSecretRedactionTests();

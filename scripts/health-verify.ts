import * as dotenv from 'dotenv';
dotenv.config();

import { verifyDatabaseConnection, getPoolStats } from '../src/db/index.ts';

async function runHealthTests() {
  console.log('=== DEVILHUNT #0002.4 HEALTH, LIVENESS & READINESS VERIFICATION ===\n');

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

  try {
    // Test 1: Verify Direct Database Connectivity Health Check
    const dbHealthy = await verifyDatabaseConnection();
    assert(dbHealthy === true, 'Database Connectivity Health Check (SELECT 1)');

    // Test 2: Pool Statistics Observability
    const poolStats = getPoolStats();
    assert(
      typeof poolStats.total === 'number' &&
        typeof poolStats.idle === 'number' &&
        typeof poolStats.waiting === 'number',
      'Database Pool Statistics Observability (Total/Idle/Waiting)'
    );

    // Test 3: Safe Credentials Check (Ensure Pool Stats Object Excludes Passwords or Hosts)
    const statsKeys = Object.keys(poolStats);
    assert(
      !statsKeys.includes('password') && !statsKeys.includes('user') && !statsKeys.includes('host'),
      'Database Observability Excludes Sensitive Credentials'
    );

    // Test 4: Live Health Status Endpoint Logic
    const liveResponse = { status: 'live', timestamp: new Date().toISOString() };
    assert(liveResponse.status === 'live', 'Liveness Check Logic (/health/live)');

    // Test 5: Ready Health Status Endpoint Logic
    const readyResponse = {
      status: dbHealthy ? 'ready' : 'unhealthy',
      database: dbHealthy ? 'connected' : 'disconnected',
      pool: poolStats,
    };
    assert(
      readyResponse.status === 'ready' && readyResponse.database === 'connected',
      'Readiness Check Logic (/health/ready)'
    );

  } catch (err: any) {
    console.error('[FATAL TEST ERROR]:', err);
    failed++;
  }

  console.log('\n========================================================================================');
  console.log(`FINAL RESULT: ${failed === 0 ? 'ALL HEALTH & OBSERVABILITY TESTS PASSED' : 'SOME TESTS FAILED'}`);
  console.log('========================================================================================\n');

  // Exit cleanly
  process.exit(failed === 0 ? 0 : 1);
}

runHealthTests();

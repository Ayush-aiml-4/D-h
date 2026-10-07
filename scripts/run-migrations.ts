import { createPool } from '../src/db/index.ts';
import pg from 'pg';
import fs from 'fs';
import path from 'path';

const { Pool } = pg;

export const createAdminPool = (): pg.Pool => {
  return new Pool({
    host: process.env.SQL_HOST,
    user: process.env.SQL_ADMIN_USER || process.env.SQL_USER,
    password: process.env.SQL_ADMIN_PASSWORD || process.env.SQL_PASSWORD,
    database: process.env.SQL_DB_NAME,
    max: 5,
    connectionTimeoutMillis: 15000,
  });
};

async function main() {
  console.log('Applying database schema migrations with admin credentials...');
  const pool = createAdminPool();
  const client = await pool.connect();

  try {
    const migrationPath = path.join(process.cwd(), 'drizzle/0000_eager_leo.sql');
    if (fs.existsSync(migrationPath)) {
      const sqlContent = fs.readFileSync(migrationPath, 'utf-8');
      const statements = sqlContent
        .split('--> statement-breakpoint')
        .map((s) => s.trim())
        .filter((s) => s.length > 0);

      for (const stmt of statements) {
        try {
          await client.query(stmt);
        } catch (err: any) {
          if (
            err.code === '42P07' || // duplicate_table / relation already exists
            err.code === '42710' || // duplicate_object (constraint/index)
            err.code === '42704'    // undefined_object
          ) {
            continue;
          }
          console.warn(`Notice during statement execution (${err.code}): ${err.message}`);
        }
      }
    } else {
      console.log('Base drizzle migration file not found, skipping base file and applying DDL schema updates...');
    }

    // Incremental schema updates for DEVILHUNT #0002.4 & #0003.1
    await client.query(`ALTER TABLE "audit_events" ADD COLUMN IF NOT EXISTS "success" boolean DEFAULT true NOT NULL;`);
    await client.query(`ALTER TABLE "audit_events" ADD COLUMN IF NOT EXISTS "request_id" text;`);
    await client.query(`CREATE INDEX IF NOT EXISTS "idx_audit_events_action" ON "audit_events" ("action");`);
    await client.query(`CREATE INDEX IF NOT EXISTS "idx_audit_events_request_id" ON "audit_events" ("request_id");`);

    // DEVILHUNT #0003.1 Program Scopes Table
    await client.query(`
      CREATE TABLE IF NOT EXISTS "program_scopes" (
        "id" text PRIMARY KEY NOT NULL,
        "program_id" text NOT NULL REFERENCES "programs"("id"),
        "target_pattern" text NOT NULL,
        "scope_type" text NOT NULL,
        "scope_status" text DEFAULT 'IN_SCOPE' NOT NULL,
        "description" text,
        "created_at" timestamp DEFAULT now() NOT NULL,
        "updated_at" timestamp DEFAULT now() NOT NULL
      );
    `);
    await client.query(`CREATE INDEX IF NOT EXISTS "idx_program_scopes_program_id" ON "program_scopes" ("program_id");`);
    await client.query(`CREATE INDEX IF NOT EXISTS "idx_program_scopes_target_pattern" ON "program_scopes" ("target_pattern");`);
    await client.query(`CREATE INDEX IF NOT EXISTS "idx_program_scopes_scope_status" ON "program_scopes" ("scope_status");`);

    // DEVILHUNT #0003.2-A Discovery Sessions Table
    await client.query(`
      CREATE TABLE IF NOT EXISTS "discovery_sessions" (
        "id" text PRIMARY KEY NOT NULL,
        "program_id" text NOT NULL REFERENCES "programs"("id"),
        "initiated_by" text NOT NULL REFERENCES "users"("uid"),
        "target_scope_id" text REFERENCES "program_scopes"("id"),
        "target" text NOT NULL,
        "operation" text DEFAULT 'AUTHORIZED_DISCOVERY' NOT NULL,
        "status" text DEFAULT 'READY' NOT NULL,
        "started_at" timestamp,
        "completed_at" timestamp,
        "request_id" text,
        "created_at" timestamp DEFAULT now() NOT NULL,
        "updated_at" timestamp DEFAULT now() NOT NULL
      );
    `);
    await client.query(`CREATE INDEX IF NOT EXISTS "idx_discovery_sessions_program_id" ON "discovery_sessions" ("program_id");`);
    await client.query(`CREATE INDEX IF NOT EXISTS "idx_discovery_sessions_initiated_by" ON "discovery_sessions" ("initiated_by");`);
    await client.query(`CREATE INDEX IF NOT EXISTS "idx_discovery_sessions_target_scope_id" ON "discovery_sessions" ("target_scope_id");`);
    await client.query(`CREATE INDEX IF NOT EXISTS "idx_discovery_sessions_status" ON "discovery_sessions" ("status");`);

    // DEVILHUNT #0003.2-A Extended Asset Table Columns
    await client.query(`ALTER TABLE "assets" ADD COLUMN IF NOT EXISTS "scope_id" text REFERENCES "program_scopes"("id");`);
    await client.query(`ALTER TABLE "assets" ADD COLUMN IF NOT EXISTS "parent_asset_id" text REFERENCES "assets"("id");`);
    await client.query(`ALTER TABLE "assets" ADD COLUMN IF NOT EXISTS "hostname" text;`);
    await client.query(`ALTER TABLE "assets" ADD COLUMN IF NOT EXISTS "url" text;`);
    await client.query(`ALTER TABLE "assets" ADD COLUMN IF NOT EXISTS "path" text;`);
    await client.query(`ALTER TABLE "assets" ADD COLUMN IF NOT EXISTS "http_method" text;`);
    await client.query(`ALTER TABLE "assets" ADD COLUMN IF NOT EXISTS "discovery_source" text;`);
    await client.query(`ALTER TABLE "assets" ADD COLUMN IF NOT EXISTS "confidence" integer DEFAULT 100 NOT NULL;`);
    await client.query(`ALTER TABLE "assets" ADD COLUMN IF NOT EXISTS "first_seen_at" timestamp DEFAULT now() NOT NULL;`);
    await client.query(`ALTER TABLE "assets" ADD COLUMN IF NOT EXISTS "last_seen_at" timestamp DEFAULT now() NOT NULL;`);

    await client.query(`CREATE INDEX IF NOT EXISTS "idx_assets_scope_id" ON "assets" ("scope_id");`);
    await client.query(`CREATE INDEX IF NOT EXISTS "idx_assets_parent_asset_id" ON "assets" ("parent_asset_id");`);
    await client.query(`CREATE INDEX IF NOT EXISTS "idx_assets_hostname" ON "assets" ("hostname");`);
    await client.query(`CREATE INDEX IF NOT EXISTS "idx_assets_url" ON "assets" ("url");`);
    await client.query(`CREATE INDEX IF NOT EXISTS "idx_assets_type" ON "assets" ("type");`);
    await client.query(`CREATE INDEX IF NOT EXISTS "idx_assets_status" ON "assets" ("status");`);

    // Unique index on program_id, domain, path, and http_method to enforce duplicate asset prevention
    await client.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS "idx_assets_unique_identity"
      ON "assets" ("program_id", "domain", COALESCE("path", '/'), COALESCE("http_method", 'GET'));
    `);

    console.log('Migration execution completed successfully.');
  } catch (err) {
    console.error('Migration failed:', err);
    process.exit(1);
  } finally {
    client.release();
    await pool.end();
  }
}

main();

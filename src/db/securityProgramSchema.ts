/**
 * Optional Drizzle table definitions for Security Program ops.
 * NOT auto-migrated. In-memory repository remains the active store until SQL is available
 * and an explicit migration is run.
 *
 * Does not invent program assets or reward amounts.
 */
import { pgTable, text, timestamp, index, jsonb } from 'drizzle-orm/pg-core';

/** Serialized ProgramConfig JSON (pending fields remain null/empty arrays) */
export const securityProgramConfig = pgTable('security_program_config', {
  id: text('id').primaryKey().default('default'),
  configJson: text('config_json').notNull(),
  updatedAt: timestamp('updated_at').notNull().defaultNow(),
});

export const securityProgramReports = pgTable(
  'security_program_reports',
  {
    id: text('id').primaryKey(),
    researcher: text('researcher').notNull(),
    asset: text('asset').notNull(),
    scopeResult: text('scope_result').notNull(),
    validity: text('validity').notNull(),
    severity: text('severity'),
    bountyStatus: text('bounty_status').notNull(),
    payloadJson: text('payload_json').notNull(),
    createdAt: timestamp('created_at').notNull().defaultNow(),
    updatedAt: timestamp('updated_at').notNull().defaultNow(),
  },
  (t) => ({
    scopeIdx: index('idx_sp_reports_scope').on(t.scopeResult),
    validityIdx: index('idx_sp_reports_validity').on(t.validity),
  })
);

export const securityProgramScopeDecisions = pgTable('security_program_scope_decisions', {
  id: text('id').primaryKey(),
  reportId: text('report_id'),
  result: text('result').notNull(),
  reason: text('reason').notNull(),
  normalizedJson: text('normalized_json').notNull(),
  createdAt: timestamp('created_at').notNull().defaultNow(),
});

export const securityProgramConfigChanges = pgTable('security_program_config_changes', {
  id: text('id').primaryKey(),
  changedField: text('changed_field').notNull(),
  previousValue: text('previous_value'),
  newValue: text('new_value'),
  source: text('source').notNull(),
  reason: text('reason').notNull(),
  launchImpact: text('launch_impact'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
});

export const securityProgramAuditEvents = pgTable(
  'security_program_audit_events',
  {
    id: text('id').primaryKey(),
    action: text('action').notNull(),
    detail: text('detail'),
    actorRef: text('actor_ref'),
    createdAt: timestamp('created_at').notNull().defaultNow(),
  },
  (t) => ({
    actionIdx: index('idx_sp_audit_action').on(t.action),
  })
);

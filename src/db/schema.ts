import { relations } from 'drizzle-orm';
import { integer, boolean, pgTable, serial, text, timestamp, index } from 'drizzle-orm/pg-core';

// 1. Users Table
export const users = pgTable(
  'users',
  {
    id: serial('id').primaryKey(),
    uid: text('uid').notNull().unique(), // Firebase Auth / Test User UID
    name: text('name').notNull(),
    email: text('email').notNull().unique(),
    role: text('role').notNull().default('RESEARCHER'), // RESEARCHER | ADMIN
    avatar: text('avatar'),
    createdAt: timestamp('created_at').notNull().defaultNow(),
    updatedAt: timestamp('updated_at').notNull().defaultNow(),
  },
  (table) => ({
    uidIdx: index('idx_users_uid').on(table.uid),
    emailIdx: index('idx_users_email').on(table.email),
  })
);

// 2. Programs Table
export const programs = pgTable(
  'programs',
  {
    id: text('id').primaryKey(),
    name: text('name').notNull(),
    description: text('description').notNull(),
    status: text('status').notNull().default('ACTIVE'), // ACTIVE | INACTIVE | ARCHIVED
    rewardCeiling: text('reward_ceiling').notNull(),
    rulesLoaded: boolean('rules_loaded').notNull().default(true),
    policyEnforced: boolean('policy_enforced').notNull().default(true),
    createdAt: timestamp('created_at').notNull().defaultNow(),
    updatedAt: timestamp('updated_at').notNull().defaultNow(),
  },
  (table) => ({
    statusIdx: index('idx_programs_status').on(table.status),
  })
);

// 3. Program Assets / Targets Table
export const assets = pgTable(
  'assets',
  {
    id: text('id').primaryKey(),
    programId: text('program_id')
      .notNull()
      .references(() => programs.id),
    scopeId: text('scope_id'),
    parentAssetId: text('parent_asset_id'),
    domain: text('domain').notNull(),
    type: text('type').notNull(), // Web | API | Infrastructure | Mobile
    hostname: text('hostname'),
    url: text('url'),
    path: text('path'),
    httpMethod: text('http_method'),
    status: text('status').notNull().default('IN_SCOPE'),
    scopeStatus: text('scope_status').notNull().default('In Scope'),
    technology: text('technology'),
    endpointCount: integer('endpoint_count').notNull().default(1),
    discoverySource: text('discovery_source'),
    confidence: integer('confidence'),
    firstSeenAt: timestamp('first_seen_at'),
    lastSeenAt: timestamp('last_seen_at'),
    createdAt: timestamp('created_at').notNull().defaultNow(),
    updatedAt: timestamp('updated_at').notNull().defaultNow(),
  },
  (table) => ({
    programIdIdx: index('idx_assets_program_id').on(table.programId),
    domainIdx: index('idx_assets_domain').on(table.domain),
  })
);

// 3.5. Program Scopes Table
export const programScopes = pgTable(
  'program_scopes',
  {
    id: text('id').primaryKey(),
    programId: text('program_id')
      .notNull()
      .references(() => programs.id),
    targetPattern: text('target_pattern').notNull(),
    scopeType: text('scope_type').notNull().default('EXACT_DOMAIN'), // EXACT_DOMAIN | SUBDOMAIN | URL | IP_RANGE
    scopeStatus: text('scope_status').notNull().default('IN_SCOPE'), // IN_SCOPE | OUT_OF_SCOPE | REVIEW_REQUIRED | DISABLED
    description: text('description'),
    createdAt: timestamp('created_at').notNull().defaultNow(),
    updatedAt: timestamp('updated_at').notNull().defaultNow(),
  },
  (table) => ({
    programIdIdx: index('idx_program_scopes_program_id').on(table.programId),
    targetPatternIdx: index('idx_program_scopes_target_pattern').on(table.targetPattern),
    scopeStatusIdx: index('idx_program_scopes_scope_status').on(table.scopeStatus),
  })
);

// 3.6. Discovery Sessions Table
export const discoverySessions = pgTable(
  'discovery_sessions',
  {
    id: text('id').primaryKey(),
    programId: text('program_id')
      .notNull()
      .references(() => programs.id),
    initiatedBy: text('initiated_by')
      .notNull()
      .references(() => users.uid),
    targetScopeId: text('target_scope_id'),
    target: text('target').notNull(),
    operation: text('operation').notNull().default('ASSET_ENUMERATION'),
    status: text('status').notNull().default('READY'), // READY | STARTING | DISCOVERING | ANALYZING | COMPLETED | STOPPED | FAILED
    startedAt: timestamp('started_at').notNull().defaultNow(),
    completedAt: timestamp('completed_at'),
    updatedAt: timestamp('updated_at').notNull().defaultNow(),
    requestId: text('request_id'),
  },
  (table) => ({
    programIdIdx: index('idx_discovery_sessions_program_id').on(table.programId),
    initiatedByIdx: index('idx_discovery_sessions_initiated_by').on(table.initiatedBy),
    statusIdx: index('idx_discovery_sessions_status').on(table.status),
  })
);

// 4. Policy Rules Table
export const policyRules = pgTable(
  'policy_rules',
  {
    id: text('id').primaryKey(),
    programId: text('program_id')
      .notNull()
      .references(() => programs.id),
    name: text('name').notNull(),
    category: text('category').notNull(),
    allowed: boolean('allowed').notNull().default(true),
    description: text('description'),
    createdAt: timestamp('created_at').notNull().defaultNow(),
    updatedAt: timestamp('updated_at').notNull().defaultNow(),
  },
  (table) => ({
    programIdIdx: index('idx_policy_rules_program_id').on(table.programId),
  })
);

// 5. Hunts Table
export const hunts = pgTable(
  'hunts',
  {
    id: text('id').primaryKey(),
    programId: text('program_id')
      .notNull()
      .references(() => programs.id),
    assetId: text('asset_id')
      .notNull()
      .references(() => assets.id),
    researcherId: text('researcher_id')
      .notNull()
      .references(() => users.uid),
    status: text('status').notNull().default('Ready'), // Ready | Starting | Hunting | Running | Analyzing | Paused | Stopped | Completed | Complete | Blocked
    progress: integer('progress').notNull().default(0),
    scope: text('scope').notNull(),
    currentTask: text('current_task'),
    startedAt: text('started_at'),
    completedAt: text('completed_at'),
    createdAt: timestamp('created_at').notNull().defaultNow(),
    updatedAt: timestamp('updated_at').notNull().defaultNow(),
  },
  (table) => ({
    researcherIdIdx: index('idx_hunts_researcher_id').on(table.researcherId),
    programIdIdx: index('idx_hunts_program_id').on(table.programId),
    assetIdIdx: index('idx_hunts_asset_id').on(table.assetId),
    statusIdx: index('idx_hunts_status').on(table.status),
  })
);

// 6. Findings Table
export const findings = pgTable(
  'findings',
  {
    id: text('id').primaryKey(),
    huntId: text('hunt_id')
      .notNull()
      .references(() => hunts.id),
    programId: text('program_id')
      .notNull()
      .references(() => programs.id),
    assetId: text('asset_id')
      .notNull()
      .references(() => assets.id),
    title: text('title').notNull(),
    description: text('description').notNull(),
    severity: text('severity').notNull(), // Critical | High | Medium | Low
    confidence: integer('confidence').notNull().default(90),
    category: text('category').notNull(),
    status: text('status').notNull().default('Potential'), // Potential | Needs review | Under review | Validated | Verified | Rejected | Duplicate | Dismissed
    evidence: text('evidence'),
    discoveredAt: text('discovered_at'),
    reviewedAt: text('reviewed_at'),
    validatedAt: text('validated_at'),
    verifiedAt: text('verified_at'),
    createdAt: timestamp('created_at').notNull().defaultNow(),
    updatedAt: timestamp('updated_at').notNull().defaultNow(),
  },
  (table) => ({
    huntIdIdx: index('idx_findings_hunt_id').on(table.huntId),
    programIdIdx: index('idx_findings_program_id').on(table.programId),
    assetIdIdx: index('idx_findings_asset_id').on(table.assetId),
    statusIdx: index('idx_findings_status').on(table.status),
  })
);

// 7. Reports Table
export const reports = pgTable(
  'reports',
  {
    id: text('id').primaryKey(),
    findingId: text('finding_id')
      .notNull()
      .unique()
      .references(() => findings.id),
    programId: text('program_id')
      .notNull()
      .references(() => programs.id),
    researcherId: text('researcher_id')
      .notNull()
      .references(() => users.uid),
    title: text('title').notNull(),
    summary: text('summary').notNull(),
    severity: text('severity').notNull(),
    status: text('status').notNull().default('Draft'), // Draft | Ready | Submitted | Accepted | Rejected | Duplicate | Resolved
    createdAt: timestamp('created_at').notNull().defaultNow(),
    updatedAt: timestamp('updated_at').notNull().defaultNow(),
    submittedAt: text('submitted_at'),
    resolvedAt: text('resolved_at'),
  },
  (table) => ({
    findingIdIdx: index('idx_reports_finding_id').on(table.findingId),
    researcherIdIdx: index('idx_reports_researcher_id').on(table.researcherId),
    programIdIdx: index('idx_reports_program_id').on(table.programId),
    statusIdx: index('idx_reports_status').on(table.status),
  })
);

// 8. Rewards Table
export const rewards = pgTable(
  'rewards',
  {
    id: text('id').primaryKey(),
    reportId: text('report_id')
      .notNull()
      .unique()
      .references(() => reports.id),
    amount: text('amount').notNull().default('₹0'),
    numericAmount: integer('numeric_amount').notNull().default(0),
    currency: text('currency').notNull().default('INR'),
    status: text('status').notNull().default('NONE'), // NONE | POTENTIAL | PENDING | PAID
    createdAt: timestamp('created_at').notNull().defaultNow(),
    paidAt: text('paid_at'),
  },
  (table) => ({
    reportIdIdx: index('idx_rewards_report_id').on(table.reportId),
    statusIdx: index('idx_rewards_status').on(table.status),
  })
);

// 9. History Sessions Table
export const historySessions = pgTable(
  'history_sessions',
  {
    id: text('id').primaryKey(),
    huntId: text('hunt_id')
      .notNull()
      .unique()
      .references(() => hunts.id),
    programId: text('program_id')
      .notNull()
      .references(() => programs.id),
    researcherId: text('researcher_id')
      .notNull()
      .references(() => users.uid),
    targetId: text('target_id')
      .notNull()
      .references(() => assets.id),
    duration: text('duration').notNull(),
    verifiedFindingCount: integer('verified_finding_count').notNull().default(0),
    rewardAmount: text('reward_amount').notNull().default('₹0'),
    status: text('status').notNull().default('Completed'),
    createdAt: timestamp('created_at').notNull().defaultNow(),
  },
  (table) => ({
    researcherIdIdx: index('idx_history_sessions_researcher_id').on(table.researcherId),
    huntIdIdx: index('idx_history_sessions_hunt_id').on(table.huntId),
  })
);

// 10. Audit Events Table
export const auditEvents = pgTable(
  'audit_events',
  {
    id: text('id').primaryKey(),
    userId: text('user_id')
      .notNull()
      .references(() => users.uid),
    entityType: text('entity_type').notNull(), // HUNT | FINDING | REPORT | PROGRAM | REWARD | AUTH | POLICY
    entityId: text('entity_id').notNull(),
    action: text('action').notNull(),
    previousState: text('previous_state'),
    newState: text('new_state'),
    success: boolean('success').notNull().default(true),
    requestId: text('request_id'),
    metadata: text('metadata'),
    createdAt: timestamp('created_at').notNull().defaultNow(),
  },
  (table) => ({
    userIdIdx: index('idx_audit_events_user_id').on(table.userId),
    entityIdx: index('idx_audit_events_entity').on(table.entityType, table.entityId),
    createdAtIdx: index('idx_audit_events_created_at').on(table.createdAt),
    actionIdx: index('idx_audit_events_action').on(table.action),
    requestIdIdx: index('idx_audit_events_request_id').on(table.requestId),
  })
);

// Relationships
export const programsRelations = relations(programs, ({ many }) => ({
  assets: many(assets),
  policyRules: many(policyRules),
  hunts: many(hunts),
  findings: many(findings),
  reports: many(reports),
}));

export const assetsRelations = relations(assets, ({ one, many }) => ({
  program: one(programs, {
    fields: [assets.programId],
    references: [programs.id],
  }),
  hunts: many(hunts),
  findings: many(findings),
}));

export const policyRulesRelations = relations(policyRules, ({ one }) => ({
  program: one(programs, {
    fields: [policyRules.programId],
    references: [programs.id],
  }),
}));

export const huntsRelations = relations(hunts, ({ one, many }) => ({
  program: one(programs, {
    fields: [hunts.programId],
    references: [programs.id],
  }),
  asset: one(assets, {
    fields: [hunts.assetId],
    references: [assets.id],
  }),
  findings: many(findings),
  historySessions: many(historySessions),
}));

export const findingsRelations = relations(findings, ({ one }) => ({
  hunt: one(hunts, {
    fields: [findings.huntId],
    references: [hunts.id],
  }),
  program: one(programs, {
    fields: [findings.programId],
    references: [programs.id],
  }),
  asset: one(assets, {
    fields: [findings.assetId],
    references: [assets.id],
  }),
  report: one(reports, {
    fields: [findings.id],
    references: [reports.findingId],
  }),
}));

export const reportsRelations = relations(reports, ({ one }) => ({
  finding: one(findings, {
    fields: [reports.findingId],
    references: [findings.id],
  }),
  program: one(programs, {
    fields: [reports.programId],
    references: [programs.id],
  }),
  reward: one(rewards, {
    fields: [reports.id],
    references: [rewards.reportId],
  }),
}));

export const rewardsRelations = relations(rewards, ({ one }) => ({
  report: one(reports, {
    fields: [rewards.reportId],
    references: [reports.id],
  }),
}));

export const historySessionsRelations = relations(historySessions, ({ one }) => ({
  hunt: one(hunts, {
    fields: [historySessions.huntId],
    references: [hunts.id],
  }),
  program: one(programs, {
    fields: [historySessions.programId],
    references: [programs.id],
  }),
  asset: one(assets, {
    fields: [historySessions.targetId],
    references: [assets.id],
  }),
}));

'use strict';

// Idempotent schema top-ups applied at startup.
//
// db/init/*.sql is mysql's docker-entrypoint-initdb.d, which runs exactly
// once against an empty data dir — so a schema change shipped there reaches
// new deployments only, and an existing dashboard-db-data volume never sees
// it. Anything added to db/init after the first release therefore needs a
// matching entry here, written so that running it repeatedly is harmless.
//
// This is deliberately not a full migration framework: there's no version
// table and no down-migrations. Each step asks the database what it already
// has and does nothing if the answer is "that's there".

const { pool } = require('../db');

// Columns db/init adds for fresh installs, mirrored here for existing ones.
// Keep in step with db/init/*.sql — the SQL there is the source of truth for
// a new database, this list for an old one.
const COLUMNS = [
  {
    table: 'vulnerabilities',
    column: 'cve_source',
    // See db/init/004_cve_tracking.sql for why this exists.
    ddl: 'ALTER TABLE vulnerabilities ADD COLUMN cve_source VARCHAR(32) NULL AFTER cve_id',
  },
];

async function columnExists(table, column) {
  const [rows] = await pool.query(
    `SELECT 1 FROM information_schema.columns
      WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ?
      LIMIT 1`,
    [table, column]
  );
  return rows.length > 0;
}

async function ensureSchema() {
  const applied = [];
  for (const { table, column, ddl } of COLUMNS) {
    if (await columnExists(table, column)) continue;
    await pool.query(ddl);
    applied.push(`${table}.${column}`);
  }
  if (applied.length) {
    console.log(`Schema top-up applied: ${applied.join(', ')}`);
  }
  return applied;
}

module.exports = { ensureSchema };

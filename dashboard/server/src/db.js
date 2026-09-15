'use strict';

const mysql = require('mysql2/promise');

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'dashboard-db',
  port: Number(process.env.DB_PORT || 3306),
  user: process.env.DB_USER || 'dashboard',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'vuln_dashboard',
  waitForConnections: true,
  connectionLimit: 10,
});

// mysql's init scripts (and the container itself) can take a few seconds
// after `docker compose up` reports it healthy-adjacent — retry instead of
// crash-looping the app container on first boot.
async function waitForDb(retries = 30, delayMs = 2000) {
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      const conn = await pool.getConnection();
      conn.release();
      return;
    } catch (err) {
      console.log(`Waiting for database (${attempt}/${retries}): ${err.code || err.message}`);
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
  }
  throw new Error('Database never became available');
}

module.exports = { pool, waitForDb };

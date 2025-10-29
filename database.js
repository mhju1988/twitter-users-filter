const { Pool } = require('pg');
const Database = require('better-sqlite3');

// Determine which database to use based on environment
const USE_POSTGRES = process.env.DATABASE_URL || process.env.NODE_ENV === 'production';

let db;

if (USE_POSTGRES) {
  // PostgreSQL setup for production (Railway)
  const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
  });

  db = {
    // Wrapper to make PostgreSQL queries similar to SQLite API
    async query(sql, params = []) {
      const result = await pool.query(sql, params);
      return result.rows;
    },

    async get(sql, params = []) {
      const result = await pool.query(sql, params);
      return result.rows[0];
    },

    async run(sql, params = []) {
      const result = await pool.query(sql, params);
      const id = result.rows[0]?.id;
      return { changes: result.rowCount, lastID: id, id: id };
    },

    async all(sql, params = []) {
      const result = await pool.query(sql, params);
      return result.rows;
    },

    async exec(sql) {
      await pool.query(sql);
    },

    async close() {
      await pool.end();
    },

    isPostgres: true
  };
} else {
  // SQLite setup for local development
  const DATABASE_PATH = process.env.DATABASE_PATH || './speakers_listeners.db';
  const sqlite = new Database(DATABASE_PATH);
  sqlite.pragma('foreign_keys = ON');

  db = {
    // Make SQLite queries async-compatible
    async query(sql, params = []) {
      return sqlite.prepare(sql).all(...params);
    },

    async get(sql, params = []) {
      return sqlite.prepare(sql).get(...params);
    },

    async run(sql, params = []) {
      const stmt = sqlite.prepare(sql);
      const result = stmt.run(...params);
      return { changes: result.changes, lastID: result.lastInsertRowid, id: result.lastInsertRowid };
    },

    async all(sql, params = []) {
      return sqlite.prepare(sql).all(...params);
    },

    async exec(sql) {
      sqlite.exec(sql);
    },

    async close() {
      sqlite.close();
    },

    isPostgres: false
  };
}

module.exports = db;

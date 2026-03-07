const { Pool } = require('pg');

// Uses explicit configuration to fallback securely to pqcdb and ignores dummy env vars
const pool = new Pool({
  user: process.env.PGUSER && process.env.PGUSER !== 'your_postgres_user' ? process.env.PGUSER : 'sarveshalegaonkar',
  host: process.env.PGHOST || 'localhost',
  database: process.env.PGDATABASE || 'pqcdb',
  password: process.env.PGPASSWORD || '',
  port: process.env.PGPORT || 5432,
});

module.exports = {
  query: (text, params) => pool.query(text, params),
};

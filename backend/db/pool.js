const { Pool } = require('pg');

// Uses standard PG environment variables for connection
const pool = new Pool();

module.exports = {
  query: (text, params) => pool.query(text, params),
};

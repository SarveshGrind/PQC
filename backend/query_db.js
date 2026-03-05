const { Pool } = require('pg');
const pool = new Pool({
  user: 'sarveshalegaonkar',
  host: 'localhost',
  database: 'pqcdb'
});
pool.query('SELECT id, repo_url, state, error_message FROM jobs ORDER BY id DESC LIMIT 5;', (err, res) => {
  if (err) console.error(err);
  else console.log(JSON.stringify(res.rows, null, 2));
  pool.end();
});

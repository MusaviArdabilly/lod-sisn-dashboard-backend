const { Pool } = require('pg');

const pool = new Pool({
  user: process.env.PG_USERNAME,
  password: process.env.PG_PASSWORD,
  host: process.env.PG_HOST,
  port: process.env.PG_PORT || 5432,
  database: process.env.PG_DATABASE
});

module.exports = {
  query: (text, params) => pool.query(text, params)
};
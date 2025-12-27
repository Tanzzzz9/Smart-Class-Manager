// db.js
const { Pool } = require('pg');

const pool = new Pool({
  user: 'postgres',
  host: 'localhost',
  database: 'smart_curriculum',
  password: '', // 🔑 Replace with your actual PostgreSQL password
  port: 5432,
});

pool.on('connect', () => {
  console.log('Connected to PostgreSQL database');
});

pool.on('error', (err) => {
  console.error('Unexpected error on PostgreSQL client', err);
});

module.exports = pool;
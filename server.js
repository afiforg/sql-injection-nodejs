require('dotenv').config();
const express = require('express');
const { Client } = require('pg');
const Redis = require('ioredis');

const app = express();
app.use(express.json());

let db = null;
let rdb = null;

function requireEnv(key) {
  const value = process.env[key];
  if (!value) {
    console.error(`required environment variable "${key}" is not set`);
    process.exit(1);
  }
  return value;
}

function getEnv(key, defaultValue = '') {
  return process.env[key] || defaultValue;
}

async function connectWithRetry(config, maxAttempts = 10) {
  for (let i = 0; i < maxAttempts; i++) {
    try {
      const client = new Client(config);
      await client.connect();
      return client;
    } catch (err) {
      if (i === maxAttempts - 1) throw err;
      await new Promise((r) => setTimeout(r, 2000));
    }
  }
}

async function initDB() {
  const dbHost = requireEnv('DB_HOST');
  const dbPort = requireEnv('DB_PORT');
  const dbUser = requireEnv('DB_USER');
  const dbPassword = getEnv('DB_PASSWORD');
  const dbName = requireEnv('DB_NAME');

  const configWithoutDB = {
    host: dbHost,
    port: parseInt(dbPort, 10),
    user: dbUser,
    password: dbPassword
  };

  const conn = await connectWithRetry({ ...configWithoutDB, database: 'postgres' });
  try {
    await conn.query(`CREATE DATABASE ${dbName}`);
  } catch (err) {
    if (err.code !== '42P04') throw err; // ignore duplicate_database
  }
  await conn.end();

  db = await connectWithRetry({ ...configWithoutDB, database: dbName });

  const createTableSQL = `
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(255) NOT NULL UNIQUE,
      email VARCHAR(255) NOT NULL,
      password VARCHAR(255) NOT NULL
    );
  `;
  await db.query(createTableSQL);

  const insertSQL = `
    INSERT INTO users (username, email, password) VALUES
    ('admin', 'admin@example.com', 'admin123'),
    ('user1', 'user1@example.com', 'password123'),
    ('test', 'test@example.com', 'test123')
    ON CONFLICT (username) DO NOTHING;
  `;
  await db.query(insertSQL);

  console.log('Database initialized successfully');
}

function initRedis() {
  const addr = getEnv('REDIS_ADDR');
  if (!addr) {
    console.log('REDIS_ADDR not set, running without Redis');
    return;
  }
  rdb = new Redis(addr);
  rdb.ping().then(() => {
    console.log('Redis connected, search cache enabled');
  }).catch((err) => {
    console.log('Redis ping failed (%s), continuing without cache', err.message);
    rdb = null;
  });
}

// VULNERABLE: SQL Injection via query parameter
// GET /users?id=1 OR 1=1--
app.get('/users', async (req, res) => {
  const userID = req.query.id || '';

  // VULNERABLE: Direct string concatenation - SQL Injection possible
  const query = `SELECT id, username, email, password FROM users WHERE id = ${userID}`;

  try {
    const result = await db.query(query);
    const users = result.rows.map((row) => ({
      id: row.id,
      username: row.username,
      email: row.email,
      password: row.password // VULNERABLE: Exposing passwords
    }));
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// VULNERABLE: SQL Injection via POST body
// POST /users/search
// Body: {"search": "admin' OR '1'='1"}
app.post('/users/search', async (req, res) => {
  const search = (req.body && req.body.search) ? String(req.body.search) : '';

  if (rdb) {
    const cacheKey = 'sqli:search:' + search;
    try {
      const cached = await rdb.get(cacheKey);
      if (cached) {
        return res.json(JSON.parse(cached));
      }
    } catch (_) {}
  }

  // VULNERABLE: Direct string concatenation - SQL Injection possible
  const likeVal = '%' + search + '%';
  const query = `SELECT id, username, email, password FROM users WHERE username LIKE '${likeVal}' OR email LIKE '${likeVal}'`;

  try {
    const result = await db.query(query);
    const users = result.rows.map((row) => ({
      id: row.id,
      username: row.username,
      email: row.email,
      password: row.password // VULNERABLE: Exposing passwords
    }));

    if (rdb) {
      const cacheKey = 'sqli:search:' + search;
      await rdb.set(cacheKey, JSON.stringify(users), 'EX', 60);
    }

    res.json(users);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// VULNERABLE: SQL Injection via path parameter
// GET /users/name/admin' OR '1'='1
app.get('/users/name/:name', async (req, res) => {
  const name = req.params.name || '';

  // VULNERABLE: Direct string concatenation - SQL Injection possible
  const query = `SELECT id, username, email, password FROM users WHERE username = '${name}'`;

  try {
    const result = await db.query(query);
    const users = result.rows.map((row) => ({
      id: row.id,
      username: row.username,
      email: row.email,
      password: row.password // VULNERABLE: Exposing passwords
    }));
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

async function runMigrations() {
  await initDB();
  if (db) await db.end();
  console.log('Migrations completed successfully');
  process.exit(0);
}

async function main() {
  if (process.argv[2] === 'migrate') {
    await runMigrations();
    return;
  }

  await initDB();
  initRedis();

  const port = parseInt(getEnv('PORT', '8080'), 10);

  app.listen(port, () => {
    console.log('Vulnerable server starting on :%d', port);
    console.log('Test endpoints:');
    console.log('  GET  http://localhost:%d/users?id=1', port);
    console.log('  GET  http://localhost:%d/users?id=1 OR 1=1--', port);
    console.log('  POST http://localhost:%d/users/search', port);
    console.log('  GET  http://localhost:%d/users/name/admin', port);
  });
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

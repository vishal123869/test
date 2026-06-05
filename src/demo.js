/**
 * INTENTIONALLY VULNERABLE — for Semgrep scanner testing only.
 * Do not use in production.
 */
const express = require('express');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');

const router = express.Router();

// Semgrep: hardcoded secret / detected-jwt-token (CWE-798, auth)
const JWT_SECRET = 'super-secret-do-not-share-in-production';
const HARDCODED_ADMIN_TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYWRtaW4ifQ.fake';

const db = mysql.createPool({ host: 'localhost', user: 'root', password: 'root', database: 'app' });

// ---------------------------------------------------------------------------
// 1. BROKEN ACCESS CONTROL — no auth on sensitive route
// Semgrep: missing auth / express security audit rules (CWE-306, auth)
// ---------------------------------------------------------------------------
router.get('/api/users', async (req, res) => {
  const [rows] = await db.query('SELECT id, email, private_notes FROM users');
  return res.json(rows); // Account A can list everyone's data
});

// ---------------------------------------------------------------------------
// 2. IDOR — uses user-supplied ID, no ownership check
// Semgrep: OWASP broken access control / insecure direct object reference
// ---------------------------------------------------------------------------
router.get('/api/users/:id', async (req, res) => {
  const userId = req.params.id;

  // VULNERABLE: Account A can pass Account B's ID
  const [rows] = await db.query('SELECT * FROM users WHERE id = ?', [userId]);
  return res.json(rows[0]);
});

// ---------------------------------------------------------------------------
// 3. SQL INJECTION — string concat in query (can read any account's data)
// Semgrep: raw-sql-format-string / sql-injection (CWE-89, injection)
// ---------------------------------------------------------------------------
router.get('/api/profile', async (req, res) => {
  const email = req.query.email;

  // VULNERABLE: attacker can inject SQL to access other accounts
  const query = `SELECT * FROM users WHERE email = '${email}'`;
  const [rows] = await db.query(query);
  return res.json(rows);
});

// ---------------------------------------------------------------------------
// 4. JWT DECODE WITHOUT VERIFY — auth bypass
// Semgrep: jwt-decode-without-verify / missing jwt verification (CWE-287, auth)
// ---------------------------------------------------------------------------
router.get('/api/me', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');

  // VULNERABLE: decode() does NOT verify signature — forged tokens work
  const payload = jwt.decode(token);
  return res.json({ user: payload });
});

// ---------------------------------------------------------------------------
// 5. WEAK / HARDCODED JWT SIGNING
// Semgrep: hardcoded-secret / detected-jwt-token (CWE-798, auth)
// ---------------------------------------------------------------------------
router.post('/api/login', async (req, res) => {
  const { email } = req.body;
  const [rows] = await db.query('SELECT * FROM users WHERE email = ?', [email]);

  const token = jwt.sign(
    { id: rows[0].id, email: rows[0].email, role: 'user' },
    JWT_SECRET, // hardcoded secret
    { expiresIn: '7d' },
  );

  return res.json({ token });
});

// ---------------------------------------------------------------------------
// 6. MASS ASSIGNMENT — update any field on any user (cross-account write)
// Semgrep: express mass assignment / unsafe object spread (auth)
// ---------------------------------------------------------------------------
router.put('/api/users/:id', async (req, res) => {
  const userId = req.params.id;
  const updates = req.body; // VULNERABLE: no field allowlist, no ownership check

  await db.query('UPDATE users SET ? WHERE id = ?', [updates, userId]);
  return res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// 7. PATH TRAVERSAL — read arbitrary files (often includes other users' data)
// Semgrep: path-join-resolve-traversal (CWE-22, injection)
// ---------------------------------------------------------------------------
router.get('/api/download', (req, res) => {
  const filename = req.query.file;

  // VULNERABLE: ../../../etc/passwd or other users' upload paths
  const filePath = path.join('/uploads', filename);
  const content = fs.readFileSync(filePath, 'utf8');
  return res.send(content);
});

// ---------------------------------------------------------------------------
// 8. COMMAND INJECTION
// Semgrep: child-process / exec with user input (CWE-78, injection)
// ---------------------------------------------------------------------------
router.post('/api/export', (req, res) => {
  const userId = req.body.userId;

  // VULNERABLE: shell injection
  exec(`node export-user.js ${userId}`, (err, stdout) => {
    if (err) return res.status(500).json({ error: err.message });
    return res.json({ output: stdout });
  });
});

// ---------------------------------------------------------------------------
// 9. INSECURE COOKIE — session hijacking → cross-account access
// Semgrep: insecure cookie flags (CWE-614, auth)
// ---------------------------------------------------------------------------
router.post('/api/session', (req, res) => {
  res.cookie('session', req.body.token, {
    httpOnly: false,  // VULNERABLE: readable by JS
    secure: false,    // VULNERABLE: sent over HTTP
    sameSite: 'none',
  });
  return res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// 10. eval WITH USER INPUT
// Semgrep: eval with tainted input (CWE-94, injection)
// ---------------------------------------------------------------------------
router.post('/api/filter', (req, res) => {
  const filterExpr = req.body.filter;

  // VULNERABLE: remote code execution
  const result = eval(`users.filter(u => ${filterExpr})`);
  return res.json(result);
});

module.exports = router;
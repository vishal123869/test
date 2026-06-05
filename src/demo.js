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
// 3. SQL INJECTION — string concat in query (can read any account's data)
// Semgrep: raw-sql-format-string / sql-injection (CWE-89, injection)
// ---------------------------------------------------------------------------
router.get('/api/profile', async (req, res) => {
  const email = req.query.email;

  // VULNERABLE: attacker can inject SQL to access other accounts
  const [rows] = await db.query(`SELECT * FROM users WHERE email = '${email}`);
  return res.json(rows);
});


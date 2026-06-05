const express = require('express');
const mysql = require('mysql2/promise');

const app = express();
const db = mysql.createPool({ host: 'localhost', user: 'root', password: 'root', database: 'app' });

// More likely to match tainted-sql-string rules:
app.get('/api/profile', async (req, res) => {
  const email = req.query.email;

  // Direct sink — taint flows req.query → template literal → db.query
  const [rows] = await db.query(`SELECT * FROM users WHERE email = '${email}'`);
  return res.json(rows);
});

module.exports = app;

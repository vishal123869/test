const express = require('express');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');
const crypto = require('crypto');
const fs = require('fs/promises');
const path = require('path');

const router = express.Router();

const db = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  port: Number(process.env.DB_PORT || 3306),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: Number(process.env.DB_CONNECTION_LIMIT || 10),
});

const UPLOAD_ROOT = path.resolve(process.env.UPLOAD_ROOT || path.join(process.cwd(), 'uploads'));
const ALLOWED_UPDATE_FIELDS = new Set(['display_name', 'private_notes']);

function asyncHandler(handler) {
  return (req, res, next) => {
    Promise.resolve(handler(req, res, next)).catch(next);
  };
}

function getJwtSecret() {
  return process.env.JWT_SECRET;
}

function getBearerToken(req) {
  const header = req.headers.authorization;

  if (!header || !header.startsWith('Bearer ')) {
    return null;
  }

  return header.slice('Bearer '.length).trim();
}

function requireAuth(req, res, next) {
  const secret = getJwtSecret();
  const token = getBearerToken(req);

  if (!secret) {
    return res.status(500).json({ error: 'Authentication is not configured.' });
  }

  if (!token) {
    return res.status(401).json({ error: 'Missing bearer token.' });
  }

  try {
    req.user = jwt.verify(token, secret, { algorithms: ['HS256'] });
    req.token = token;
    return next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid or expired token.' });
  }
}

function requireAdmin(req, res, next) {
  if (req.user?.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access is required.' });
  }

  return next();
}

function requireSelfOrAdmin(req, res, next) {
  if (req.user?.role === 'admin' || String(req.user?.id) === String(req.params.id)) {
    return next();
  }

  return res.status(403).json({ error: 'Access denied.' });
}

function parsePositiveInteger(value) {
  const parsed = Number(value);

  if (!Number.isInteger(parsed) || parsed <= 0) {
    return null;
  }

  return parsed;
}

function isValidEmail(email) {
  return typeof email === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function buildAllowedUpdates(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return {};
  }

  return Object.fromEntries(
    Object.entries(body).filter(([key, value]) => ALLOWED_UPDATE_FIELDS.has(key) && typeof value === 'string'),
  );
}

function verifyPassword(password, salt, expectedHash) {
  return new Promise((resolve, reject) => {
    if (typeof password !== 'string' || typeof salt !== 'string' || typeof expectedHash !== 'string') {
      resolve(false);
      return;
    }

    crypto.scrypt(password, salt, 64, (error, derivedKey) => {
      if (error) {
        reject(error);
        return;
      }

      const expected = Buffer.from(expectedHash, 'hex');

      if (expected.length !== derivedKey.length) {
        resolve(false);
        return;
      }

      resolve(crypto.timingSafeEqual(expected, derivedKey));
    });
  });
}

function safeDownloadPath(filename, userId) {
  if (typeof filename !== 'string' || !filename || filename !== path.basename(filename)) {
    return null;
  }

  const userUploadRoot = path.resolve(UPLOAD_ROOT, String(userId));
  const resolvedPath = path.resolve(userUploadRoot, filename);
  const relativePath = path.relative(userUploadRoot, resolvedPath);

  if (relativePath.startsWith('..') || path.isAbsolute(relativePath)) {
    return null;
  }

  return resolvedPath;
}

router.get(
  '/api/users',
  requireAuth,
  requireAdmin,
  asyncHandler(async (req, res) => {
    const [rows] = await db.query('SELECT id, email, role, display_name FROM users ORDER BY id LIMIT 100');
    return res.json(rows);
  }),
);

router.get(
  '/api/users/:id',
  requireAuth,
  requireSelfOrAdmin,
  asyncHandler(async (req, res) => {
    const userId = parsePositiveInteger(req.params.id);

    if (!userId) {
      return res.status(400).json({ error: 'Invalid user id.' });
    }

    const [rows] = await db.query('SELECT id, email, role, display_name, private_notes FROM users WHERE id = ?', [
      userId,
    ]);

    if (!rows.length) {
      return res.status(404).json({ error: 'User not found.' });
    }

    return res.json(rows[0]);
  }),
);

router.get(
  '/api/profile',
  requireAuth,
  asyncHandler(async (req, res) => {
    const userId = parsePositiveInteger(req.user.id);

    if (!userId) {
      return res.status(401).json({ error: 'Invalid user session.' });
    }

    const [rows] = await db.query('SELECT id, email, role, display_name, private_notes FROM users WHERE id = ?', [
      userId,
    ]);

    if (!rows.length) {
      return res.status(404).json({ error: 'Profile not found.' });
    }

    return res.json(rows[0]);
  }),
);

router.get('/api/me', requireAuth, (req, res) => {
  return res.json({
    user: {
      id: req.user.id,
      email: req.user.email,
      role: req.user.role,
    },
  });
});

router.post(
  '/api/login',
  asyncHandler(async (req, res) => {
    const { email, password } = req.body || {};
    const secret = getJwtSecret();

    if (!secret) {
      return res.status(500).json({ error: 'Authentication is not configured.' });
    }

    if (!isValidEmail(email) || typeof password !== 'string') {
      return res.status(400).json({ error: 'Valid email and password are required.' });
    }

    const [rows] = await db.query(
      'SELECT id, email, role, password_hash, password_salt FROM users WHERE email = ? LIMIT 1',
      [email],
    );
    const user = rows[0];

    if (!user || !(await verifyPassword(password, user.password_salt, user.password_hash))) {
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role || 'user' },
      secret,
      { algorithm: 'HS256', expiresIn: '1h' },
    );

    return res.json({ token });
  }),
);

router.put(
  '/api/users/:id',
  requireAuth,
  requireSelfOrAdmin,
  asyncHandler(async (req, res) => {
    const userId = parsePositiveInteger(req.params.id);
    const updates = buildAllowedUpdates(req.body);

    if (!userId) {
      return res.status(400).json({ error: 'Invalid user id.' });
    }

    if (!Object.keys(updates).length) {
      return res.status(400).json({ error: 'No allowed fields were provided.' });
    }

    if (Object.hasOwn(updates, 'display_name') && Object.hasOwn(updates, 'private_notes')) {
      await db.query('UPDATE users SET display_name = ?, private_notes = ? WHERE id = ?', [
        updates.display_name,
        updates.private_notes,
        userId,
      ]);
    } else if (Object.hasOwn(updates, 'display_name')) {
      await db.query('UPDATE users SET display_name = ? WHERE id = ?', [updates.display_name, userId]);
    } else {
      await db.query('UPDATE users SET private_notes = ? WHERE id = ?', [updates.private_notes, userId]);
    }

    return res.json({ ok: true });
  }),
);

router.get(
  '/api/download',
  requireAuth,
  asyncHandler(async (req, res) => {
    const userId = parsePositiveInteger(req.user.id);
    const filePath = userId ? safeDownloadPath(req.query.file, userId) : null;

    if (!filePath) {
      return res.status(400).json({ error: 'Invalid file name.' });
    }

    await fs.access(filePath);
    return res.download(filePath);
  }),
);

router.post(
  '/api/export',
  requireAuth,
  asyncHandler(async (req, res) => {
    const userId = parsePositiveInteger(req.user.id);

    if (!userId) {
      return res.status(401).json({ error: 'Invalid user session.' });
    }

    const [rows] = await db.query('SELECT id, email, role, display_name, private_notes FROM users WHERE id = ?', [
      userId,
    ]);

    if (!rows.length) {
      return res.status(404).json({ error: 'User not found.' });
    }

    return res.json({ user: rows[0] });
  }),
);

router.post('/api/session', requireAuth, (req, res) => {
  res.cookie('session', req.token, {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    maxAge: 60 * 60 * 1000,
  });

  return res.json({ ok: true });
});

router.post(
  '/api/filter',
  requireAuth,
  requireAdmin,
  asyncHandler(async (req, res) => {
    const { field, value } = req.body || {};

    if (typeof value !== 'string') {
      return res.status(400).json({ error: 'A valid filter field and value are required.' });
    }

    const likeValue = `%${value}%`;
    let rows;

    if (field === 'email') {
      [rows] = await db.query('SELECT id, email, role, display_name FROM users WHERE email LIKE ? ORDER BY id LIMIT 100', [
        likeValue,
      ]);
    } else if (field === 'role') {
      [rows] = await db.query('SELECT id, email, role, display_name FROM users WHERE role LIKE ? ORDER BY id LIMIT 100', [
        likeValue,
      ]);
    } else if (field === 'displayName') {
      [rows] = await db.query(
        'SELECT id, email, role, display_name FROM users WHERE display_name LIKE ? ORDER BY id LIMIT 100',
        [likeValue],
      );
    } else {
      return res.status(400).json({ error: 'A valid filter field and value are required.' });
    }

    return res.json(rows);
  }),
);

module.exports = router;
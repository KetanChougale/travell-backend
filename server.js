// server.js - Postgres version for Render
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '1h';

app.use(express.json());
app.use(cors());

// Create Postgres pool using DATABASE_URL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }, // required for Render
});

// Test connection
pool.connect()
  .then(client => {
    console.log('✅ Connected to Postgres successfully');
    client.release();
  })
  .catch(err => {
    console.error('❌ Failed to connect to Postgres:', err.message);
  });

// Helper: create JWT
function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

// Middleware
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Missing or invalid token' });
  }
  const token = auth.split(' ')[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
}

function adminMiddleware(req, res, next) {
  if (!req.user) return res.status(401).json({ message: 'Not authenticated' });
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Admin only' });
  next();
}

/* ------------------ Public API ------------------ */

// Health check
app.get('/', (req, res) => res.json({ ok: true }));

// REGISTER
app.post('/api/register',
  body('name').trim().notEmpty(),
  body('address').trim().notEmpty(),
  body('email').isEmail(),
  body('password').isLength({ min: 6 }),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { name, address, email, password } = req.body;
    const pwdRegex = /^(?=.*[A-Z])(?=.*[!@#$%^&*()_\-+=[\]{};':"\\|,.<>/?`~]).{6,}$/;
    if (!pwdRegex.test(password)) {
      return res.status(400).json({ message: 'Password must have 6+ chars, one uppercase, and one special symbol' });
    }

    try {
      const { rows } = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
      if (rows.length) return res.status(409).json({ message: 'Email already registered' });

      const hash = await bcrypt.hash(password, 10);
      await pool.query(
        'INSERT INTO users (name, address, email, password_hash) VALUES ($1, $2, $3, $4)',
        [name, address, email, hash]
      );

      res.status(201).json({ message: 'User registered successfully' });
    } catch (err) {
      console.error('❌ Register error:', err);
      res.status(500).json({ message: 'Server error' });
    }
  }
);

// LOGIN
app.post('/api/login',
  body('email').isEmail(),
  body('password').notEmpty(),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { email, password } = req.body;
    try {
      const { rows } = await pool.query(
        'SELECT id, name, email, password_hash, role FROM users WHERE email = $1',
        [email]
      );
      if (!rows.length) return res.status(401).json({ message: 'Invalid email or password' });

      const user = rows[0];
      const match = await bcrypt.compare(password, user.password_hash);
      if (!match) return res.status(401).json({ message: 'Invalid email or password' });

      const token = signToken({ id: user.id, email: user.email, role: user.role || 'user' });
      res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role || 'user' } });
    } catch (err) {
      console.error('❌ Login error:', err);
      res.status(500).json({ message: 'Server error' });
    }
  }
);

// Protected user info
app.get('/api/me', authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT id, name, email, address, role, created_at FROM users WHERE id = $1',
      [req.user.id]
    );
    if (!rows.length) return res.status(404).json({ message: 'User not found' });
    res.json(rows[0]);
  } catch (err) {
    console.error('❌ Me error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// BOOK TRIP
app.post('/api/trips', authMiddleware, async (req, res) => {
  const { full_name, address, mobile, email, num_people, from_location, to_location, departure_date } = req.body;
  if (!full_name || !address || !mobile || !email || !num_people || !from_location || !to_location || !departure_date) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  try {
    await pool.query(
      `INSERT INTO trip_requests (user_id, full_name, address, mobile, email, num_people, from_location, to_location, departure_date)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
      [req.user.id, full_name, address, mobile, email, num_people, from_location, to_location, departure_date]
    );
    res.status(201).json({ message: 'Trip request saved successfully' });
  } catch (err) {
    console.error('❌ Trip request error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

/* ------------------ ADMIN API ------------------ */

// Pagination helper
function parsePagination(qsPage, qsLimit) {
  let page = parseInt(qsPage, 10);
  let limit = parseInt(qsLimit, 10);
  if (isNaN(page) || page < 1) page = 1;
  if (isNaN(limit) || limit < 1) limit = 10;
  if (limit > 200) limit = 200;
  const offset = (page - 1) * limit;
  return { page, limit, offset };
}

// GET users
app.get('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const q = (req.query.q || '').trim();
    const date = (req.query.date || '').trim();
    const { page, limit, offset } = parsePagination(req.query.page, req.query.limit);

    let where = [];
    let params = [];
    if (q) {
      where.push('(name ILIKE $' + (params.length + 1) + ' OR email ILIKE $' + (params.length + 2) + ')');
      params.push(`%${q}%`, `%${q}%`);
    }
    if (date) {
      where.push('DATE(created_at) = $' + (params.length + 1));
      params.push(date);
    }
    const whereSql = where.length ? 'WHERE ' + where.join(' AND ') : '';

    const countSql = `SELECT COUNT(*) as total FROM users ${whereSql}`;
    const countResult = await pool.query(countSql, params);
    const total = countResult.rows[0].total;

    const sql = `SELECT id, name, email, role, created_at
                 FROM users ${whereSql} ORDER BY created_at DESC LIMIT ${limit} OFFSET ${offset}`;
    const { rows } = await pool.query(sql, params);

    res.json({ users: rows, meta: { total, page, limit } });
  } catch (err) {
    console.error('❌ GET /api/admin/users error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// GET trips
app.get('/api/admin/trips', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const q = (req.query.q || '').trim();
    const date = (req.query.date || '').trim();
    const { page, limit, offset } = parsePagination(req.query.page, req.query.limit);

    let where = [];
    let params = [];
    if (q) {
      where.push('(full_name ILIKE $' + (params.length + 1) + ' OR email ILIKE $' + (params.length + 2) + ' OR mobile ILIKE $' + (params.length + 3) + ')');
      params.push(`%${q}%`, `%${q}%`, `%${q}%`);
    }
    if (date) {
      where.push('DATE(created_at) = $' + (params.length + 1));
      params.push(date);
    }
    const whereSql = where.length ? 'WHERE ' + where.join(' AND ') : '';

    const countSql = `SELECT COUNT(*) as total FROM trip_requests ${whereSql}`;
    const countResult = await pool.query(countSql, params);
    const total = countResult.rows[0].total;

    const sql = `SELECT id, user_id, full_name, address, mobile, email, num_people, from_location, to_location, departure_date, created_at
                 FROM trip_requests ${whereSql} ORDER BY created_at DESC LIMIT ${limit} OFFSET ${offset}`;
    const { rows } = await pool.query(sql, params);

    res.json({ trips: rows, meta: { total, page, limit } });
  } catch (err) {
    console.error('❌ GET /api/admin/trips error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// PUT update trip
app.put('/api/admin/trips/:id', authMiddleware, adminMiddleware, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (isNaN(id)) return res.status(400).json({ message: 'Invalid id' });

  const { full_name, mobile, email, num_people, address, from_location, to_location, departure_date } = req.body;

  try {
    const result = await pool.query(
      `UPDATE trip_requests SET full_name=$1, mobile=$2, email=$3, num_people=$4, address=$5, from_location=$6, to_location=$7, departure_date=$8 WHERE id=$9`,
      [full_name, mobile, email, num_people, address, from_location, to_location, departure_date, id]
    );
    if (result.rowCount === 0) return res.status(404).json({ message: 'Trip not found' });
    res.json({ message: 'Trip updated' });
  } catch (err) {
    console.error('❌ PUT /api/admin/trips/:id error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// DELETE trip
app.delete('/api/admin/trips/:id', authMiddleware, adminMiddleware, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (isNaN(id)) return res.status(400).json({ message: 'Invalid id' });

  try {
    const result = await pool.query('DELETE FROM trip_requests WHERE id = $1', [id]);
    if (result.rowCount === 0) return res.status(404).json({ message: 'Trip not found' });
    res.json({ message: 'Trip deleted' });
  } catch (err) {
    console.error('❌ DELETE /api/admin/trips/:id error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

/* ------------------ Start ------------------ */
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});

// create_admin.js
require('dotenv').config();
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');

const ADMIN_EMAIL = 'admin@gmail.com';
const ADMIN_PWD = 'Admin@123';
const ADMIN_NAME = 'Administrator';
const ADMIN_ADDRESS = 'Head Office';

async function run() {
  const pool = mysql.createPool({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT || 3306,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 5,
  });

  try {
    // Check if admin exists
    const [rows] = await pool.execute('SELECT id, email FROM users WHERE email = ?', [ADMIN_EMAIL]);
    const hashed = await bcrypt.hash(ADMIN_PWD, 10);

    if (rows.length) {
      // update password + role
      await pool.execute(
        'UPDATE users SET password_hash = ?, role = ?, name = ?, address = ? WHERE email = ?',
        [hashed, 'admin', ADMIN_NAME, ADMIN_ADDRESS, ADMIN_EMAIL]
      );
      console.log('Existing user updated to admin:', ADMIN_EMAIL);
    } else {
      // create admin user
      await pool.execute(
        'INSERT INTO users (name, address, email, password_hash, role) VALUES (?, ?, ?, ?, ?)',
        [ADMIN_NAME, ADMIN_ADDRESS, ADMIN_EMAIL, hashed, 'admin']
      );
      console.log('Admin user created:', ADMIN_EMAIL);
    }
    process.exit(0);
  } catch (err) {
    console.error('Error creating admin user:', err);
    process.exit(1);
  } finally {
    try { await pool.end(); } catch (e) {}
  }
}

run();

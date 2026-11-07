require('dotenv').config();
const express = require('express');
const axios = require('axios');
const path = require('path');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { randomInt, createHash } = require('crypto');
const nodemailer = require('nodemailer');

const app = express();
app.use(express.json());
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});
app.use(express.static(__dirname));

const SECRET = process.env.PAYSTACK_SECRET_KEY;
const PORT = process.env.PORT || 3000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  connectionTimeoutMillis: 5000
});

let usersTableReady = false;
function isDatabaseUnavailable(error) {
  const code = error.code || '';
  return code.startsWith('08') ||
    ['ECONNREFUSED', 'ECONNRESET', 'ENOTFOUND', 'ETIMEDOUT', 'EHOSTUNREACH', '57P03'].includes(code);
}

async function ensureUsersTable() {
  if (usersTableReady) return;
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      verified BOOLEAN NOT NULL DEFAULT FALSE,
      verification_code_hash TEXT,
      verification_code_expires_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await pool.query(`
    ALTER TABLE users
      ADD COLUMN IF NOT EXISTS verified BOOLEAN NOT NULL DEFAULT TRUE,
      ADD COLUMN IF NOT EXISTS verification_code_hash TEXT,
      ADD COLUMN IF NOT EXISTS verification_code_expires_at TIMESTAMPTZ
  `);
  usersTableReady = true;
}

app.post('/api/pay', async (req, res) => {
  const { email, amount } = req.body;
  try {
    const response = await axios.post(
      'https://api.paystack.co/transaction/initialize',
      {
        email: email,
        amount: amount * 100,
        callback_url: `${req.protocol}://${req.get('host')}/`
      },
      { headers: { Authorization: `Bearer ${SECRET}` } }
    );
    res.json(response.data.data);
  } catch (err) {
    console.log(err.response?.data || err.message);
    res.status(500).json({ error: 'Paystack failed' });
  }
});

app.get('/api/verify/:reference', async (req, res) => {
  try {
    const response = await axios.get(
      `https://api.paystack.co/transaction/verify/${req.params.reference}`,
      { headers: { Authorization: `Bearer ${SECRET}` } }
    );
    res.json(response.data.data);
  } catch (err) {
    res.status(500).json({ error: 'Verify failed' });
  }
});
// ===== LOGIN / REGISTER =====
app.post('/api/signup', async (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name || !email || !password || password.length < 6) {
    return res.status(400).json({ success: false, message: 'Name, email, and password (min 6 chars) are required' });
  }
  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
    return res.status(503).json({ success: false, message: 'Email verification is not configured' });
  }

  const normalizedEmail = email.trim().toLowerCase();
  const verificationCode = String(randomInt(100000, 1000000));
  const verificationCodeHash = createHash('sha256').update(verificationCode).digest('hex');
  try {
    await ensureUsersTable();
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO users(name,email,password_hash,verified,verification_code_hash,verification_code_expires_at)
       VALUES($1,$2,$3,FALSE,$4,NOW() + INTERVAL '10 minutes')
       ON CONFLICT(email) DO UPDATE SET
         name=EXCLUDED.name,
         password_hash=EXCLUDED.password_hash,
         verification_code_hash=EXCLUDED.verification_code_hash,
         verification_code_expires_at=EXCLUDED.verification_code_expires_at
       WHERE users.verified=FALSE
       RETURNING id,name,email,created_at`,
      [name.trim(), normalizedEmail, hash, verificationCodeHash]
    );
    if (result.rows.length === 0) {
      return res.status(409).json({ success: false, message: 'Email already used, try login' });
    }

    try {
      const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
          user: process.env.EMAIL_USER,
          pass: process.env.EMAIL_PASS
        }
      });
      await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: normalizedEmail,
        subject: 'Verify your Pets World account',
        text: `Your verification code is ${verificationCode}. It expires in 10 minutes.`,
        html: `<p>Your verification code is <strong>${verificationCode}</strong>.</p><p>It expires in 10 minutes.</p>`
      });
    } catch (emailError) {
      console.error('Signup verification email error:', emailError.message);
      return res.status(502).json({ success: false, message: 'Could not send verification email. Please try again.' });
    }

    return res.status(201).json({
      success: true,
      message: 'Verification code sent',
      user: result.rows[0]
    });
  } catch (error) {
    if (error.code === '23505') {
      return res.status(409).json({ success: false, message: 'Email already used, try login' });
    }
    console.error('Signup database error:', error.message);
    const unavailable = isDatabaseUnavailable(error);
    return res.status(unavailable ? 503 : 500).json({
      success: false,
      fallback: unavailable,
      message: unavailable ? 'Database unavailable' : 'Account creation failed'
    });
  }
});

app.post('/api/verify-email', async (req, res) => {
  const { email, code } = req.body || {};
  if (!email || !/^\d{6}$/.test(String(code || ''))) {
    return res.status(400).json({ success: false, message: 'Email and 6-digit verification code are required' });
  }
  try {
    await ensureUsersTable();
    const codeHash = createHash('sha256').update(String(code)).digest('hex');
    const result = await pool.query(
      `UPDATE users
       SET verified=TRUE, verification_code_hash=NULL, verification_code_expires_at=NULL
       WHERE email=$1 AND verified=FALSE AND verification_code_hash=$2
         AND verification_code_expires_at > NOW()
       RETURNING id,name,email`,
      [email.trim().toLowerCase(), codeHash]
    );
    if (result.rows.length === 0) {
      return res.status(400).json({ success: false, message: 'Invalid or expired verification code' });
    }
    return res.json({ success: true, message: 'Email verified', user: result.rows[0] });
  } catch (error) {
    console.error('Email verification error:', error.message);
    const unavailable = isDatabaseUnavailable(error);
    return res.status(unavailable ? 503 : 500).json({
      success: false,
      message: unavailable ? 'Database unavailable' : 'Email verification failed'
    });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ success: false, message: 'Email and password are required' });
  }
  try {
    await ensureUsersTable();
    const result = await pool.query(
      'SELECT id,name,email,password_hash,verified,created_at FROM users WHERE email=$1',
      [email.trim().toLowerCase()]
    );
    if (result.rows.length === 0) {
      return res.status(401).json({
        success: false,
        code: 'email_not_found',
        message: 'This email is not registered, please sign up'
      });
    }
    const user = result.rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      return res.status(401).json({
        success: false,
        code: 'wrong_password',
        message: 'Incorrect password, try again'
      });
    }
    if (!user.verified) {
      return res.status(403).json({
        success: false,
        code: 'not_verified',
        message: 'Please verify your email before logging in'
      });
    }
    return res.json({
      success: true,
      message: 'Login success',
      user: { id: user.id, name: user.name, email: user.email }
    });
  } catch (error) {
    console.error('Login database error:', error.message);
    const unavailable = isDatabaseUnavailable(error);
    return res.status(unavailable ? 503 : 500).json({
      success: false,
      fallback: unavailable,
      message: unavailable ? 'Database unavailable' : 'Login failed'
    });
  }
});

app.get('/login', (req,res)=>{ res.sendFile(__dirname + '/login.html'); });


if (require.main === module) {
  app.listen(PORT, '0.0.0.0', () => console.log('Running on ' + PORT))
}
module.exports = app;

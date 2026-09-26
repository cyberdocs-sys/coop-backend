const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

const app = express();
app.use(express.json());
app.use(cors());

// Configure PostgreSQL connection with SSL for Supabase
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

const JWT_SECRET = process.env.JWT_SECRET || 'cooperative_super_secret_key';

// Middleware to verify JWT Token
const authenticate = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied' });
  try {
    const verified = jwt.verify(token, JWT_SECRET);
    req.user = verified;
    next();
  } catch (err) {
    res.status(400).json({ error: 'Invalid token' });
  }
};

// 1. Member Login API
app.post('/api/auth/login', async (req, res) => {
  const { phone, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM members WHERE phone = $1', [phone]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Member not found' });

    const member = result.rows[0];
    const validPass = await bcrypt.compare(password, member.password_hash);
    if (!validPass) return res.status(400).json({ error: 'Invalid password' });

    const token = jwt.sign({ member_id: member.member_id, phone: member.phone }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, member: { id: member.member_id, name: member.full_name, member_no: member.member_no } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 2. Dashboard Balances API
app.get('/api/member/dashboard', authenticate, async (req, res) => {
  try {
    const accounts = await pool.query(
      'SELECT account_type, balance FROM accounts WHERE member_id = $1',
      [req.user.member_id]
    );
    
    let balances = { savings: 0, share_capital: 0, loan_balance: 0 };
    accounts.rows.forEach(acc => {
      if (acc.account_type === 'SAVINGS') balances.savings = acc.balance;
      if (acc.account_type === 'SHARE_CAPITAL') balances.share_capital = acc.balance;
      if (acc.account_type === 'LOAN') balances.loan_balance = acc.balance;
    });

    res.json(balances);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 3. Transactions Passbook API
app.get('/api/member/transactions', authenticate, async (req, res) => {
  try {
    const txs = await pool.query(
      `SELECT t.transaction_id, t.amount, t.type, t.reference, t.description, t.created_at, a.account_type 
       FROM transactions t 
       JOIN accounts a ON t.account_id = a.account_id 
       WHERE a.member_id = $1 
       ORDER BY t.created_at DESC LIMIT 50`,
      [req.user.member_id]
    );
    res.json(txs.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 4. Submit Loan Application
app.post('/api/loans/apply', authenticate, async (req, res) => {
  const { amount, tenor, purpose } = req.body;
  try {
    await pool.query(
      'INSERT INTO loan_applications (member_id, amount_requested, tenor_months, purpose) VALUES ($1, $2, $3, $4)',
      [req.user.member_id, amount, tenor, purpose]
    );
    res.json({ message: 'Loan application submitted successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Cooperative API running on port ${PORT}`));
    

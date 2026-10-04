const express = require('express');
const { createClient } = require('@supabase/supabase-js');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

const JWT_SECRET = process.env.JWT_SECRET || 'coop_jwt_secret_key_2026';

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access token required' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
};

// 1. MEMBER ACCOUNT ACTIVATION
app.post('/api/auth/activate', async (req, res) => {
  const { phone, password } = req.body;
  if (!phone || !password) {
    return res.status(400).json({ error: 'Phone number and password are required.' });
  }

  try {
    const { data: member, error: findErr } = await supabase
      .from('members')
      .select('*')
      .eq('phone', phone)
      .maybeSingle();

    if (findErr || !member) {
      return res.status(404).json({ error: 'Phone number not found in member registry.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    // Match directly on phone number to eliminate primary key name mismatch
    const { error: updateErr } = await supabase
      .from('members')
      .update({ password: hashedPassword, is_active: true })
      .eq('phone', phone);

    if (updateErr) {
      console.error('Supabase Update Error:', updateErr);
      return res.status(500).json({ error: `Save failed: ${updateErr.message}` });
    }

    res.json({ message: 'Account activated successfully!' });
  } catch (err) {
    console.error('Activation Server Error:', err);
    res.status(500).json({ error: `Server error: ${err.message}` });
  }
});

// 2. MEMBER & EXECUTIVE LOGIN
app.post('/api/auth/login', async (req, res) => {
  const { phone, password } = req.body;
  if (!phone || !password) {
    return res.status(400).json({ error: 'Phone number and password required.' });
  }

  try {
    const { data: member, error } = await supabase
      .from('members')
      .select('*')
      .eq('phone', phone)
      .maybeSingle();

    if (error || !member) {
      return res.status(401).json({ error: 'Invalid phone number or password.' });
    }

    if (!member.password) {
      return res.status(400).json({ error: 'Account not activated yet. Tap ACTIVATE MEMBER ACCOUNT below.' });
    }

    const validPassword = await bcrypt.compare(password, member.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid phone number or password.' });
    }

    const userRole = member.role || (member.is_admin ? 'ADMIN' : 'MEMBER');

    const token = jwt.sign(
      { id: member.id || member.phone, phone: member.phone, role: userRole },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      token,
      member: {
        id: member.id || member.phone,
        name: member.name,
        phone: member.phone,
        role: userRole,
        is_admin: userRole === 'ADMIN'
      }
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error during login.' });
  }
});

// 3. RESET PASSWORD
app.post('/api/auth/reset-password', async (req, res) => {
  const { phone, newPassword } = req.body;
  if (!phone || !newPassword) {
    return res.status(400).json({ error: 'Phone number and new password required.' });
  }

  try {
    const { data: member, error: findErr } = await supabase
      .from('members')
      .select('*')
      .eq('phone', phone)
      .maybeSingle();

    if (findErr || !member) {
      return res.status(404).json({ error: 'Registered phone number not found.' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    const { error: updateErr } = await supabase
      .from('members')
      .update({ password: hashedPassword })
      .eq('phone', phone);

    if (updateErr) {
      return res.status(500).json({ error: `Reset failed: ${updateErr.message}` });
    }

    res.json({ message: 'Password updated successfully!' });
  } catch (err) {
    res.status(500).json({ error: 'Server error during password reset.' });
  }
});

// 4. MEMBER DASHBOARD BALANCES
app.get('/api/member/dashboard', authenticateToken, async (req, res) => {
  try {
    const { data: member, error } = await supabase
      .from('members')
      .select('savings, share_capital, loan_balance')
      .eq('phone', req.user.phone)
      .maybeSingle();

    if (error || !member) {
      return res.status(404).json({ error: 'Member record not found.' });
    }

    res.json({
      savings: member.savings || 0,
      share_capital: member.share_capital || 0,
      loan_balance: member.loan_balance || 0
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error loading balances.' });
  }
});

// 5. MEMBER PASSBOOK TRANSACTIONS
app.get('/api/member/transactions', authenticateToken, async (req, res) => {
  try {
    const { data: transactions, error } = await supabase
      .from('transactions')
      .select('*')
      .eq('phone', req.user.phone)
      .order('created_at', { ascending: false });

    if (error) {
      return res.status(500).json({ error: 'Error loading transactions.' });
    }

    res.json(transactions || []);
  } catch (err) {
    res.status(500).json({ error: 'Server error loading passbook history.' });
  }
});

// 6. LOAN APPLICATION SUBMISSION
app.post('/api/loans/apply', authenticateToken, async (req, res) => {
  const { amount, tenor, purpose } = req.body;
  try {
    const { error } = await supabase
      .from('loans')
      .insert([
        {
          phone: req.user.phone,
          amount,
          tenor,
          purpose,
          status: 'PENDING'
        }
      ]);

    if (error) {
      return res.status(500).json({ error: 'Failed to submit application.' });
    }

    res.json({ message: 'Loan application submitted successfully.' });
  } catch (err) {
    res.status(500).json({ error: 'Server error submitting loan application.' });
  }
});

// 7. EXECUTIVE STATUTORY REPORTING
app.get('/api/reports/:type', authenticateToken, async (req, res) => {
  const { type } = req.params;
  if (req.user.role !== 'ADMIN') {
    return res.status(403).json({ error: 'Unauthorized executive access.' });
  }

  res.json({ status: 'success', report_type: type, generated_at: new Date() });
});

// 8. ADMIN MEMBER SEARCH
app.get('/api/admin/members/search', authenticateToken, async (req, res) => {
  const { q } = req.query;
  if (req.user.role !== 'ADMIN') {
    return res.status(403).json({ error: 'Unauthorized executive access.' });
  }

  try {
    const { data: members, error } = await supabase
      .from('members')
      .select('name, phone, savings, share_capital, loan_balance')
      .or(`name.ilike.%${q}%,phone.ilike.%${q}%`);

    if (error) return res.status(500).json({ error: 'Search failed.' });
    res.json(members || []);
  } catch (err) {
    res.status(500).json({ error: 'Server error during search.' });
  }
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`Cooperative API running on port ${PORT}`);
});
  

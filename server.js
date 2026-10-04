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

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access token required' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

// 1. ACTIVATION
app.post('/api/auth/activate', async (req, res) => {
  const { phone, password } = req.body;
  if (!phone || !password) return res.status(400).json({ error: 'Phone and password required.' });

  try {
    const { data: member, error: findErr } = await supabase
      .from('members')
      .select('*')
      .eq('phone', phone)
      .maybeSingle();

    if (findErr || !member) return res.status(404).json({ error: 'Phone number not found in register.' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const { error: updateErr } = await supabase
      .from('members')
      .update({ password: hashedPassword, is_active: true })
      .eq('phone', phone);

    if (updateErr) return res.status(500).json({ error: updateErr.message });
    res.json({ message: 'Account activated successfully!' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 2. LOGIN
app.post('/api/auth/login', async (req, res) => {
  const { phone, password } = req.body;
  try {
    const { data: member, error } = await supabase
      .from('members')
      .select('*')
      .eq('phone', phone)
      .maybeSingle();

    if (error || !member) return res.status(401).json({ error: 'Invalid credentials.' });
    if (!member.password) return res.status(400).json({ error: 'Account not activated yet.' });

    const validPassword = await bcrypt.compare(password, member.password);
    if (!validPassword) return res.status(401).json({ error: 'Invalid credentials.' });

    const userRole = member.role || 'MEMBER';
    const token = jwt.sign({ phone: member.phone, account_number: member.account_number, role: userRole }, JWT_SECRET, { expiresIn: '7d' });

    res.json({
      token,
      member: {
        name: member.name,
        phone: member.phone,
        account_number: member.account_number,
        role: userRole,
        is_admin: userRole === 'ADMIN'
      }
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error during login.' });
  }
});

// 3. MEMBER PERSONAL LEDGER DASHBOARD
app.get('/api/member/dashboard', authenticateToken, async (req, res) => {
  try {
    const { data: member, error } = await supabase
      .from('members')
      .select('share_capital, cap_mob, thrift_savings, loan_balance, edu_loan_balance, special_deposit')
      .eq('phone', req.user.phone)
      .maybeSingle();

    if (error || !member) return res.status(404).json({ error: 'Member ledger not found.' });

    res.json({
      share_capital: member.share_capital || 0,
      cap_mob: member.cap_mob || 0,
      thrift_savings: member.thrift_savings || 0,
      loan_balance: member.loan_balance || 0,
      edu_loan_balance: member.edu_loan_balance || 0,
      special_deposit: member.special_deposit || 0
    });
  } catch (err) {
    res.status(500).json({ error: 'Error fetching personal ledger.' });
  }
});

// 4. SECRETARY MEMBER POSTING
app.post('/api/admin/post-member-ledger', authenticateToken, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ error: 'Unauthorized' });
  const { account_number, ledger_type, type, amount, description } = req.body;

  try {
    const { data: member, error: findErr } = await supabase
      .from('members')
      .select('*')
      .eq('account_number', account_number)
      .maybeSingle();

    if (findErr || !member) return res.status(404).json({ error: 'Member account not found.' });

    const currentBal = Number(member[ledger_type] || 0);
    const numAmount = Number(amount);
    const newBal = (type === 'CREDIT') ? (currentBal + numAmount) : (currentBal - numAmount);

    await supabase.from('members').update({ [ledger_type]: newBal }).eq('account_number', account_number);
    await supabase.from('member_transactions').insert([{
      account_number,
      phone: member.phone,
      ledger_type,
      type,
      amount: numAmount,
      description: description || 'Secretary Ledger Post'
    }]);

    res.json({ message: 'Ledger updated successfully', new_balance: newBal });
  } catch (err) {
    res.status(500).json({ error: 'Server error updating member ledger.' });
  }
});

// 5. SECRETARY JOURNAL ENTRY (INCOME/EXPENDITURE/ASSETS)
app.post('/api/admin/post-journal', authenticateToken, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ error: 'Unauthorized' });
  const { account_category, account_head, description, debit, credit } = req.body;

  try {
    const { error } = await supabase.from('journal_entries').insert([{
      account_category,
      account_head,
      description,
      debit: Number(debit || 0),
      credit: Number(credit || 0)
    }]);

    if (error) return res.status(500).json({ error: error.message });
    res.json({ message: 'Journal entry recorded.' });
  } catch (err) {
    res.status(500).json({ error: 'Server error recording entry.' });
  }
});

// 6. MEMBER SEARCH & LEDGER REGISTRY
app.get('/api/admin/members/search', authenticateToken, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ error: 'Unauthorized' });
  const { q } = req.query;

  try {
    let query = supabase.from('members').select('*');
    if (q) query = query.or(`name.ilike.%${q}%,account_number.ilike.%${q}%,phone.ilike.%${q}%`);

    const { data: members, error } = await query;
    if (error) return res.status(500).json({ error: 'Search failed.' });
    res.json(members || []);
  } catch (err) {
    res.status(500).json({ error: 'Server error searching members.' });
  }
});

// 7. STATUTORY FINANCIAL REPORTS (TRIAL BALANCE, INCOME/EXP, APPROPRIATION, BALANCE SHEET)
app.get('/api/reports/:type', authenticateToken, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ error: 'Unauthorized' });

  try {
    const { data: members } = await supabase.from('members').select('*');
    const { data: journals } = await supabase.from('journal_entries').select('*');

    const memberTotals = (members || []).reduce((acc, m) => {
      acc.share_capital += Number(m.share_capital || 0);
      acc.cap_mob += Number(m.cap_mob || 0);
      acc.thrift_savings += Number(m.thrift_savings || 0);
      acc.loan_balance += Number(m.loan_balance || 0);
      acc.edu_loan_balance += Number(m.edu_loan_balance || 0);
      acc.special_deposit += Number(m.special_deposit || 0);
      return acc;
    }, { share_capital: 0, cap_mob: 0, thrift_savings: 0, loan_balance: 0, edu_loan_balance: 0, special_deposit: 0 });

    const journalTotals = (journals || []).reduce((acc, j) => {
      if (j.account_category === 'INCOME') acc.income += Number(j.credit || 0);
      if (j.account_category === 'EXPENDITURE') acc.expenditure += Number(j.debit || 0);
      return acc;
    }, { income: 0, expenditure: 0 });

    const netSurplus = journalTotals.income - journalTotals.expenditure;

    res.json({
      status: 'success',
      report_type: req.params.type,
      memberTotals,
      journalTotals,
      journals: journals || [],
      net_surplus: netSurplus,
      generated_at: new Date()
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to generate report.' });
  }
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`Dynamic Teachers MPCS Server live on port ${PORT}`));
                                                

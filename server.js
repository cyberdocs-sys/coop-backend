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

// 1. ACCOUNT ACTIVATION
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
      .update({ password: hashedPassword, is_active: true, updated_at: new Date() })
      .eq('phone', phone);

    if (updateErr) return res.status(500).json({ error: updateErr.message });
    res.json({ message: 'Account activated successfully!' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 2. MEMBER LOGIN
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

    const userRole = (member.role || 'MEMBER').toUpperCase();
    const token = jwt.sign(
      { phone: member.phone, member_no: member.member_no, role: userRole },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      token,
      member: {
        full_name: member.full_name,
        phone: member.phone,
        member_no: member.member_no,
        role: userRole,
        updated_at: member.updated_at,
        is_admin: userRole === 'ADMIN' || userRole === 'SECRETARY'
      }
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error during login.' });
  }
});

// 3. ACCOUNT RECOVERY / FORGOT PASSWORD
app.post('/api/auth/reset-password', async (req, res) => {
  const { phone, newPassword } = req.body;
  if (!phone || !newPassword) return res.status(400).json({ error: 'Phone and new password required.' });

  try {
    const { data: member, error: findErr } = await supabase
      .from('members')
      .select('phone')
      .eq('phone', phone)
      .maybeSingle();

    if (findErr || !member) return res.status(404).json({ error: 'Registered phone number not found.' });

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    const { error: updateErr } = await supabase
      .from('members')
      .update({ password: hashedPassword, updated_at: new Date() })
      .eq('phone', phone);

    if (updateErr) return res.status(500).json({ error: 'Failed to reset password.' });
    res.json({ message: 'Password reset successful! You can now log in.' });
  } catch (err) {
    res.status(500).json({ error: 'Server error resetting password.' });
  }
});

// 4. MEMBER PERSONAL LEDGER DASHBOARD
app.get('/api/member/dashboard', authenticateToken, async (req, res) => {
  try {
    const { data: member, error } = await supabase
      .from('members')
      .select('full_name, member_no, share_capital, cap_mob, thrift_savings, loan_balance, edu_loan_balance, special_deposit, updated_at')
      .eq('phone', req.user.phone)
      .maybeSingle();

    if (error || !member) return res.status(404).json({ error: 'Member ledger not found.' });

    res.json({
      full_name: member.full_name,
      member_no: member.member_no,
      share_capital: member.share_capital || 0,
      cap_mob: member.cap_mob || 0,
      thrift_savings: member.thrift_savings || 0,
      loan_balance: member.loan_balance || 0,
      edu_loan_balance: member.edu_loan_balance || 0,
      special_deposit: member.special_deposit || 0,
      updated_at: member.updated_at
    });
  } catch (err) {
    res.status(500).json({ error: 'Error fetching personal ledger.' });
  }
});

// 5. MEMBER 12-MONTH DEDUCTION SCHEDULE
app.get('/api/member/monthly-schedule', authenticateToken, async (req, res) => {
  try {
    const { data: records, error } = await supabase
      .from('monthly_deductions')
      .select('*')
      .eq('member_no', req.user.member_no)
      .order('id', { ascending: true });

    if (error) return res.status(500).json({ error: 'Failed to fetch schedule.' });
    res.json(records || []);
  } catch (err) {
    res.status(500).json({ error: 'Server error fetching schedule.' });
  }
});

// 6. SECRETARY 16-POINT EXECUTIVE FINANCIAL SUMMARY
app.get('/api/admin/executive-summary', authenticateToken, async (req, res) => {
  const month_year = req.query.month_year || '';

  try {
    const { data: members } = await supabase
      .from('members')
      .select('share_capital, thrift_savings, special_deposit, loan_balance, edu_loan_balance');

    let dedQuery = supabase.from('monthly_deductions').select('*');
    if (month_year) dedQuery = dedQuery.eq('month_year', month_year);
    const { data: deductions } = await dedQuery;

    const { data: journals } = await supabase.from('journal_entries').select('*');

    const memberTotals = (members || []).reduce((acc, m) => {
      acc.share_capital += Number(m.share_capital || 0);
      acc.thrift_savings += Number(m.thrift_savings || 0);
      acc.special_deposit += Number(m.special_deposit || 0);
      acc.loan_balance += Number(m.loan_balance || 0);
      acc.edu_loan_balance += Number(m.edu_loan_balance || 0);
      return acc;
    }, { share_capital: 0, thrift_savings: 0, special_deposit: 0, loan_balance: 0, edu_loan_balance: 0 });

    const deductionTotals = (deductions || []).reduce((acc, d) => {
      acc.total_paid += Number(d.total_amount || 0);
      acc.social_dues += Number(d.social_dues || 0);
      acc.loan_refund += Number(d.loan_repayment || 0);
      acc.edu_loan_refund += Number(d.edu_loan_repayment || 0);
      return acc;
    }, { total_paid: 0, social_dues: 0, loan_refund: 0, edu_loan_refund: 0 });

    const journalTotals = (journals || []).reduce((acc, j) => {
      const head = (j.account_head || '').toUpperCase();
      const credit = Number(j.credit || 0);
      const debit = Number(j.debit || 0);

      if (head.includes('REGULAR LOAN DISBURSED')) acc.loan_given += debit;
      if (head.includes('REGULAR LOAN INTEREST')) acc.loan_interest += credit;
      if (head.includes('REGULAR PENAL INTEREST')) acc.loan_penal += credit;

      if (head.includes('EDU LOAN DISBURSED')) acc.edu_given += debit;
      if (head.includes('EDU LOAN INTEREST')) acc.edu_interest += credit;
      if (head.includes('EDU PENAL INTEREST')) acc.edu_penal += credit;

      if (head.includes('REGISTRATION FEE') || head.includes('ENTRANCE FEE')) acc.registration_fees += credit;

      return acc;
    }, { loan_given: 0, loan_interest: 0, loan_penal: 0, edu_given: 0, edu_interest: 0, edu_penal: 0, registration_fees: 0 });

    res.json({
      summary_period: month_year || 'Cumulative YTD',
      1_total_paid_in: deductionTotals.total_paid,
      2_share_capital: memberTotals.share_capital,
      3_thrift_savings: memberTotals.thrift_savings,
      4_social_dues: deductionTotals.social_dues,
      5_loan_given_out: journalTotals.loan_given,
      6_loan_interest: journalTotals.loan_interest,
      7_loan_refund: deductionTotals.loan_refund,
      8_loan_balance: memberTotals.loan_balance,
      9_edu_loan_given_out: journalTotals.edu_given,
      10_edu_loan_interest: journalTotals.edu_interest,
      11_edu_loan_refund: deductionTotals.edu_loan_refund,
      12_edu_loan_balance: memberTotals.edu_loan_balance,
      13_loan_penal_interest: journalTotals.loan_penal,
      14_edu_loan_penal_interest: journalTotals.edu_penal,
      15_special_deposits: memberTotals.special_deposit,
      16_registration_fees: journalTotals.registration_fees
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to generate summary.' });
  }
});

// 7. SECRETARY MEMBER POSTING
app.post('/api/admin/post-member-ledger', authenticateToken, async (req, res) => {
  const { member_no, ledger_type, type, amount, description } = req.body;

  try {
    const { data: member, error: findErr } = await supabase
      .from('members')
      .select('*')
      .eq('member_no', member_no)
      .maybeSingle();

    if (findErr || !member) return res.status(404).json({ error: 'Member account not found.' });

    const currentBal = Number(member[ledger_type] || 0);
    const numAmount = Number(amount);
    const newBal = (type === 'CREDIT') ? (currentBal + numAmount) : (currentBal - numAmount);

    await supabase.from('members').update({ [ledger_type]: newBal, updated_at: new Date() }).eq('member_no', member_no);
    await supabase.from('member_transactions').insert([{
      member_no,
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

// 8. SECRETARY JOURNAL ENTRY
app.post('/api/admin/post-journal', authenticateToken, async (req, res) => {
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

// 9. MEMBER SEARCH & REGISTER
app.get('/api/admin/members/search', authenticateToken, async (req, res) => {
  const { q } = req.query;

  try {
    let query = supabase.from('members').select('*');
    if (q) query = query.or(`full_name.ilike.%${q}%,member_no.ilike.%${q}%,phone.ilike.%${q}%`);

    const { data: members, error } = await query.order('member_no', { ascending: true });
    if (error) return res.status(500).json({ error: 'Search failed.' });
    res.json(members || []);
  } catch (err) {
    res.status(500).json({ error: 'Server error searching members.' });
  }
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`Dynamic Teachers MPCS Server live on port ${PORT}`));

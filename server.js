const express = require('express');
const { createClient } = require('@supabase/supabase-js');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

// Safe fallback for express-rate-limit to prevent deploy crashes on Render
let rateLimit;
try {
  rateLimit = require('express-rate-limit');
} catch (e) {
  rateLimit = () => (req, res, next) => next();
}

// Enforce critical environment variables at server startup
if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_ROLE_KEY || !process.env.JWT_SECRET) {
  console.error('FATAL: Missing critical environment variables (SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, or JWT_SECRET).');
  process.exit(1);
}

const app = express();
app.use(cors());
app.use(express.json());

// Rate limiter for auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many login attempts from this IP. Please try again after 15 minutes.' }
});

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

const JWT_SECRET = process.env.JWT_SECRET;

// Middleware 1: JWT Authentication Guard
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access token required.' });

  jwt.verify(token, JWT_SECRET, (err, decodedUser) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token.' });
    req.user = decodedUser;
    next();
  });
};

// Middleware 2: Role-Based Authorization Guard (RBAC)
const requireRoles = (...roles) => {
  return (req, res, next) => {
    if (!req.user || !roles.includes((req.user.role || '').toUpperCase())) {
      return res.status(403).json({ error: 'Forbidden: Insufficient privileges.' });
    }
    next();
  };
};

// ==========================================
// 1. AUTHENTICATION & ACCOUNT MANAGEMENT
// ==========================================

// Account Activation
app.post('/api/auth/activate', authLimiter, async (req, res) => {
  const { phone, password } = req.body;
  if (!phone || !password) return res.status(400).json({ error: 'Phone and password required.' });

  try {
    const cleanPhone = phone.trim();
    const { data: member, error: findErr } = await supabase
      .from('members')
      .select('*')
      .eq('phone', cleanPhone)
      .maybeSingle();

    if (findErr || !member) return res.status(404).json({ error: 'Phone number not found in register.' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const { error: updateErr } = await supabase
      .from('members')
      .update({ password: hashedPassword, status: 'ACTIVE' })
      .eq('phone', cleanPhone);

    if (updateErr) return res.status(500).json({ error: updateErr.message });
    res.json({ message: 'Account activated successfully!' });
  } catch (err) {
    res.status(500).json({ error: 'Server error during activation.' });
  }
});

// Member Login
app.post('/api/auth/login', authLimiter, async (req, res) => {
  const { phone, password } = req.body;
  if (!phone || !password) return res.status(400).json({ error: 'Phone and password required.' });

  try {
    const { data: member, error } = await supabase
      .from('members')
      .select('*')
      .eq('phone', phone.trim())
      .maybeSingle();

    if (error || !member) return res.status(401).json({ error: 'Invalid credentials.' });
    if (!member.password) return res.status(400).json({ error: 'Account not activated yet.' });

    const validPassword = await bcrypt.compare(password, member.password);
    if (!validPassword) return res.status(401).json({ error: 'Invalid credentials.' });

    const userRole = (member.role || 'MEMBER').toUpperCase();
    const token = jwt.sign(
      { phone: member.phone, member_no: member.member_no, role: userRole },
      JWT_SECRET,
      { expiresIn: '1d' }
    );

    res.json({
      token,
      member: {
        full_name: member.full_name || 'Member',
        phone: member.phone,
        member_no: member.member_no || '-',
        role: userRole,
        is_admin: ['ADMIN', 'SECRETARY'].includes(userRole)
      }
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error during login.' });
  }
});

// Password Reset
app.post('/api/auth/reset-password', authLimiter, async (req, res) => {
  const { phone, newPassword } = req.body;
  if (!phone || !newPassword) return res.status(400).json({ error: 'Phone and new password required.' });

  try {
    const cleanPhone = phone.trim();
    const { data: member, error: findErr } = await supabase
      .from('members')
      .select('phone')
      .eq('phone', cleanPhone)
      .maybeSingle();

    if (findErr || !member) return res.status(404).json({ error: 'Registered phone number not found.' });

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    const { error: updateErr } = await supabase
      .from('members')
      .update({ password: hashedPassword })
      .eq('phone', cleanPhone);

    if (updateErr) return res.status(500).json({ error: 'Failed to reset password.' });
    res.json({ message: 'Password reset successful! You can now log in.' });
  } catch (err) {
    res.status(500).json({ error: 'Server error resetting password.' });
  }
});

// ==========================================
// 2. MEMBER PROTECTED ROUTES
// ==========================================

// Member Dashboard Balances
app.get('/api/member/dashboard', authenticateToken, async (req, res) => {
  try {
    const { data: member, error } = await supabase
      .from('members')
      .select('*')
      .eq('phone', req.user.phone)
      .maybeSingle();

    if (error || !member) return res.status(404).json({ error: 'Member ledger not found.' });

    res.json({
      full_name: member.full_name || 'Member',
      member_no: member.member_no || '-',
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

// Member 12-Month Schedule (SQL Database Filtered)
app.get('/api/member/monthly-schedule', authenticateToken, async (req, res) => {
  try {
    const targetNo = req.user.member_no;
    if (!targetNo) return res.status(400).json({ error: 'Invalid member session.' });

    const { data: records, error } = await supabase
      .from('monthly_deductions')
      .select('*')
      .eq('member_no', targetNo.trim())
      .order('payment_date', { ascending: false });

    if (error) throw error;
    res.json(records || []);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch schedule.' });
  }
});

// ==========================================
// 3. ADMIN / SECRETARY PROTECTED ROUTES
// ==========================================

// Post Monthly Remittance (Dual-Table Posting & Balance Updates)
app.post('/api/admin/post-monthly-deduction', authenticateToken, requireRoles('ADMIN', 'SECRETARY'), async (req, res) => {
  const { 
    member_no, 
    month_year,
    payment_date, 
    thrift_savings, 
    share_capital, 
    cap_mob, 
    social_dues, 
    special_deposit, 
    loan_repayment, 
    edu_loan_repayment,
    loan_interest,
    edu_interest
  } = req.body;

  if (!member_no || !payment_date) {
    return res.status(400).json({ error: 'Member No and Payment Date are required.' });
  }

  try {
    const cleanMemberNo = member_no.trim();
    const thrift = Math.max(0, Number(thrift_savings || 0));
    const shares = Math.max(0, Number(share_capital || 0));
    const dues = Math.max(0, Number(social_dues || 0));
    const loanRepay = Math.max(0, Number(loan_repayment || 0));
    const eduRepay = Math.max(0, Number(edu_loan_repayment || 0));
    const special = Math.max(0, Number(special_deposit || 0));
    const mob = Math.max(0, Number(cap_mob || 0));
    const total = thrift + shares + dues + loanRepay + eduRepay + special + mob;

    // 1. Insert into monthly_deductions
    const { error: dedErr } = await supabase.from('monthly_deductions').insert([{
      member_no: cleanMemberNo,
      month_year: month_year || 'JAN 2026',
      payment_date,
      thrift_savings: thrift,
      share_capital: shares,
      social_dues: dues,
      loan_repayment: loanRepay,
      edu_loan_repayment: eduRepay,
      special_deposit: special,
      cap_mob: mob,
      total_amount: total
    }]);
    if (dedErr) throw dedErr;

    // 2. Insert into monthly_remittances
    const { error: remErr } = await supabase.from('monthly_remittances').insert([{
      member_no: cleanMemberNo,
      payment_date,
      thrift_savings: thrift,
      share_capital: shares,
      cap_mobilization: mob,
      social_dues: dues,
      special_deposit: special,
      normal_loan_repay: loanRepay,
      edu_loan_repay: eduRepay,
      loan_interest: Math.max(0, Number(loan_interest || 0)),
      edu_interest: Math.max(0, Number(edu_interest || 0))
    }]);
    if (remErr) throw remErr;

    // 3. Fetch and update Member Balances
    const { data: member, error: memErr } = await supabase
      .from('members')
      .select('*')
      .eq('member_no', cleanMemberNo)
      .maybeSingle();

    if (memErr || !member) return res.status(404).json({ error: 'Member record not found.' });

    const newThrift = Number(member.thrift_savings || 0) + thrift;
    const newShares = Number(member.share_capital || 0) + shares;
    const newSpecial = Number(member.special_deposit || 0) + special;
    const newCapMob = Number(member.cap_mob || 0) + mob;
    const newLoanBal = Math.max(0, Number(member.loan_balance || 0) - loanRepay);
    const newEduLoanBal = Math.max(0, Number(member.edu_loan_balance || 0) - eduRepay);

    const { error: updateErr } = await supabase
      .from('members')
      .update({
        thrift_savings: newThrift,
        share_capital: newShares,
        special_deposit: newSpecial,
        cap_mob: newCapMob,
        loan_balance: newLoanBal,
        edu_loan_balance: newEduLoanBal
      })
      .eq('member_no', cleanMemberNo);

    if (updateErr) throw updateErr;

    res.json({ message: 'Remittance posted and balances updated successfully.' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to post remittance: ' + err.message });
  }
});

// Grant Loan to Member (With Balanced Double-Entry Journal Records)
app.post('/api/admin/grant-loan', authenticateToken, requireRoles('ADMIN', 'SECRETARY'), async (req, res) => {
  const { member_no, loan_type, principal_amount, disbursement_date } = req.body;
  const amount = Number(principal_amount);

  if (!member_no || !loan_type || isNaN(amount) || amount <= 0 || !disbursement_date) {
    return res.status(400).json({ error: 'Valid Member No, Loan Type, Positive Amount, and Date are required.' });
  }

  try {
    const cleanNo = member_no.trim();
    const isEdu = loan_type.toUpperCase() === 'EDU';
    const field = isEdu ? 'edu_loan_balance' : 'loan_balance';

    const { data: member, error: memErr } = await supabase
      .from('members')
      .select('member_no, full_name, loan_balance, edu_loan_balance')
      .eq('member_no', cleanNo)
      .maybeSingle();

    if (memErr || !member) {
      return res.status(404).json({ error: `Member account '${cleanNo}' not found.` });
    }

    const currentBalance = Number(member[field] || 0);
    const { error: updErr } = await supabase
      .from('members')
      .update({ [field]: currentBalance + amount })
      .eq('member_no', cleanNo);

    if (updErr) throw updErr;

    // Double-Entry Record: Asset Debit (Loan Portfolio), Asset Credit (Bank Account)
    const headName = isEdu ? 'EDU LOAN DISBURSED' : 'REGULAR LOAN DISBURSED';
    await supabase.from('journal_entries').insert([
      {
        entry_date: disbursement_date,
        category: 'ASSET',
        particulars: `${headName} - ${member.full_name || cleanNo}`,
        debit_amount: amount,
        credit_amount: 0,
        financial_year: new Date(disbursement_date).getFullYear()
      },
      {
        entry_date: disbursement_date,
        category: 'ASSET',
        particulars: `BANK DISBURSEMENT - ${cleanNo}`,
        debit_amount: 0,
        credit_amount: amount,
        financial_year: new Date(disbursement_date).getFullYear()
      }
    ]);

    res.json({ message: `₦${amount.toLocaleString()} disbursed successfully to ${cleanNo}.` });
  } catch (err) {
    res.status(500).json({ error: 'Failed to process loan disbursement.' });
  }
});

// Post Journal Entry
app.post('/api/admin/post-journal-entry', authenticateToken, requireRoles('ADMIN', 'SECRETARY'), async (req, res) => {
  const { entry_date, account_category, account_head, debit, credit } = req.body;

  if (!entry_date || !account_category || !account_head) {
    return res.status(400).json({ error: 'Entry Date, Category, and Account Head (Particulars) are required.' });
  }

  try {
    const { error } = await supabase.from('journal_entries').insert([{
      entry_date,
      category: account_category.toUpperCase(),
      particulars: account_head.trim(),
      debit_amount: Math.max(0, Number(debit || 0)),
      credit_amount: Math.max(0, Number(credit || 0)),
      financial_year: new Date(entry_date).getFullYear()
    }]);

    if (error) return res.status(500).json({ error: error.message });
    res.json({ message: 'Financial entry posted successfully to General Ledger!' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to post journal entry.' });
  }
});

// Onboard New Member
app.post('/api/admin/add-member', authenticateToken, requireRoles('ADMIN', 'SECRETARY'), async (req, res) => {
  const { member_no, full_name, phone, role, share_capital, thrift_savings } = req.body;

  if (!member_no || !full_name || !phone) {
    return res.status(400).json({ error: 'Member No, Full Name, and Phone are required.' });
  }

  try {
    const cleanNo = member_no.trim();
    const { error } = await supabase.from('members').insert([{
      member_no: cleanNo,
      full_name: full_name.trim(),
      phone: phone.trim(),
      role: (role || 'MEMBER').toLowerCase(),
      share_capital: Math.max(0, Number(share_capital || 0)),
      thrift_savings: Math.max(0, Number(thrift_savings || 0)),
      special_deposit: 0,
      cap_mob: 0,
      loan_balance: 0,
      edu_loan_balance: 0,
      status: 'ACTIVE'
    }]);

    if (error) return res.status(500).json({ error: error.message });
    res.json({ message: `Member ${full_name} (${cleanNo}) onboarded successfully!` });
  } catch (err) {
    res.status(500).json({ error: 'Failed to onboard new member.' });
  }
});

// Search Members (Sanitized Input)
app.get('/api/admin/members/search', authenticateToken, requireRoles('ADMIN', 'SECRETARY'), async (req, res) => {
  const rawQuery = (req.query.q || '').trim();
  const sanitized = rawQuery.replace(/[^a-zA-Z0-9\s]/g, '');

  try {
    let query = supabase.from('members').select('*');
    if (sanitized) {
      query = query.or(`full_name.ilike.%${sanitized}%,member_no.ilike.%${sanitized}%,phone.ilike.%${sanitized}%`);
    }
    const { data: members, error } = await query.order('member_no', { ascending: true });
    if (error) throw error;
    res.json(members || []);
  } catch (err) {
    res.status(500).json({ error: 'Search failed.' });
  }
});

// Executive Financial Summary
app.get('/api/admin/executive-summary', authenticateToken, requireRoles('ADMIN', 'SECRETARY'), async (req, res) => {
  const month_year = req.query.month_year || '';

  try {
    const { data: members } = await supabase.from('members').select('*');

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
      const head = (j.particulars || '').toUpperCase();
      const credit = Number(j.credit_amount || 0);
      const debit = Number(j.debit_amount || 0);

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
      "1_total_paid_in": deductionTotals.total_paid,
      "2_share_capital": memberTotals.share_capital,
      "3_thrift_savings": memberTotals.thrift_savings,
      "4_social_dues": deductionTotals.social_dues,
      "5_loan_given_out": journalTotals.loan_given,
      "6_loan_interest": journalTotals.loan_interest,
      "7_loan_refund": deductionTotals.loan_refund,
      "8_loan_balance": memberTotals.loan_balance,
      "9_edu_loan_given_out": journalTotals.edu_given,
      "10_edu_loan_interest": journalTotals.edu_interest,
      "11_edu_loan_refund": deductionTotals.edu_loan_refund,
      "12_edu_loan_balance": memberTotals.edu_loan_balance,
      "13_loan_penal_interest": journalTotals.loan_penal,
      "14_edu_loan_penal_interest": journalTotals.edu_penal,
      "15_special_deposits": memberTotals.special_deposit,
      "16_registration_fees": journalTotals.registration_fees
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to generate executive summary.' });
  }
});

// Statutory Financial Statements
app.get('/api/admin/financial-statements', authenticateToken, requireRoles('ADMIN', 'SECRETARY'), async (req, res) => {
  try {
    const { data: members } = await supabase.from('members').select('*');
    const { data: journals } = await supabase.from('journal_entries').select('*');
    const { data: deductions } = await supabase.from('monthly_deductions').select('*');

    const mTotals = (members || []).reduce((acc, m) => {
      acc.shares += Number(m.share_capital || 0);
      acc.thrift += Number(m.thrift_savings || 0);
      acc.capmob += Number(m.cap_mob || 0);
      acc.special += Number(m.special_deposit || 0);
      acc.regLoan += Number(m.loan_balance || 0);
      acc.eduLoan += Number(m.edu_loan_balance || 0);
      return acc;
    }, { shares: 0, thrift: 0, capmob: 0, special: 0, regLoan: 0, eduLoan: 0 });

    const headMap = {};
    let journalIncome = 0;
    let journalExpenditure = 0;

    (journals || []).forEach(j => {
      const cat = (j.category || 'GENERAL').toUpperCase();
      const head = (j.particulars || 'GENERAL').toUpperCase();
      const dr = Number(j.debit_amount || 0);
      const cr = Number(j.credit_amount || 0);

      if (!headMap[head]) headMap[head] = { category: cat, debit: 0, credit: 0 };
      headMap[head].debit += dr;
      headMap[head].credit += cr;

      if (cat === 'INCOME') journalIncome += (cr - dr);
      if (cat === 'EXPENDITURE') journalExpenditure += (dr - cr);
    });

    const totalSocialDues = (deductions || []).reduce((sum, d) => sum + Number(d.social_dues || 0), 0);
    const totalIncome = journalIncome + totalSocialDues;
    const netSurplus = totalIncome - journalExpenditure;

    const trialBalance = [
      { head: 'Regular Member Loans Portfolio', debit: mTotals.regLoan, credit: 0 },
      { head: 'Education Member Loans Portfolio', debit: mTotals.eduLoan, credit: 0 },
      { head: 'Member Share Capital', debit: 0, credit: mTotals.shares },
      { head: 'Member Thrift Savings', debit: 0, credit: mTotals.thrift },
      { head: 'Capital Mobilization Deposits', debit: 0, credit: mTotals.capmob },
      { head: 'Special Member Deposits', debit: 0, credit: mTotals.special }
    ];

    Object.keys(headMap).forEach(h => {
      trialBalance.push({ head: h, debit: headMap[h].debit, credit: headMap[h].credit });
    });

    const incomes = [
      ...Object.keys(headMap).filter(k => headMap[k].category === 'INCOME').map(k => ({ head: k, amount: headMap[k].credit - headMap[k].debit })),
      { head: 'Monthly Social Dues Collections', amount: totalSocialDues }
    ];
    const expenditures = Object.keys(headMap).filter(k => headMap[k].category === 'EXPENDITURE').map(k => ({ head: k, amount: headMap[k].debit - headMap[k].credit }));

    const assetJournals = Object.keys(headMap).filter(k => headMap[k].category === 'ASSET').map(k => ({ head: k, amount: headMap[k].debit - headMap[k].credit }));
    const liabilityJournals = Object.keys(headMap).filter(k => headMap[k].category === 'LIABILITY').map(k => ({ head: k, amount: headMap[k].credit - headMap[k].debit }));
    const equityJournals = Object.keys(headMap).filter(k => headMap[k].category === 'EQUITY').map(k => ({ head: k, amount: headMap[k].credit - headMap[k].debit }));

    const assets = [
      { head: 'Outstanding Regular Loans', amount: mTotals.regLoan },
      { head: 'Outstanding Education Loans', amount: mTotals.eduLoan },
      ...assetJournals
    ];

    const liabilities = [
      { head: 'Member Thrift Savings', amount: mTotals.thrift },
      { head: 'Capital Mobilization Fund', amount: mTotals.capmob },
      { head: 'Special Member Deposits', amount: mTotals.special },
      ...liabilityJournals
    ];

    const equity = [
      { head: 'Member Share Capital', amount: mTotals.shares },
      { head: 'Net Surplus for the Period', amount: netSurplus },
      ...equityJournals
    ];

    res.json({
      generated_at: new Date(),
      income_expenditure: { incomes, expenditures, total_income: totalIncome, total_expenditure: journalExpenditure, net_surplus: netSurplus },
      trial_balance: trialBalance,
      balance_sheet: { assets, liabilities, equity, total_assets: assets.reduce((s, a) => s + a.amount, 0), total_liabilities_and_equity: liabilities.reduce((s, l) => s + l.amount, 0) + equity.reduce((s, e) => s + e.amount, 0) }
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to generate financial statements.' });
  }
});

// Personal Ledger for Audit Printing
app.get('/api/admin/personal-ledger', authenticateToken, requireRoles('ADMIN', 'SECRETARY'), async (req, res) => {
  const { member_no, year } = req.query;
  const targetYear = year || new Date().getFullYear();

  if (!member_no) return res.status(400).json({ error: 'Member No is required.' });

  try {
    const cleanNo = member_no.trim();
    const { data: member, error: memErr } = await supabase
      .from('members')
      .select('*')
      .eq('member_no', cleanNo)
      .maybeSingle();

    if (memErr || !member) return res.status(404).json({ error: 'Member record not found.' });

    const { data: remittances, error: remErr } = await supabase
      .from('monthly_remittances')
      .select('*')
      .eq('member_no', cleanNo)
      .gte('payment_date', `${targetYear}-01-01`)
      .lte('payment_date', `${targetYear}-12-31`)
      .order('payment_date', { ascending: true });

    if (remErr) throw remErr;

    res.json({ member, year: targetYear, transactions: remittances || [] });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch personal ledger.' });
  }
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`DTMPCS Server running on port ${PORT}`));

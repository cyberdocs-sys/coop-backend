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
      .update({ password: hashedPassword, is_active: true })
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
      { phone: member.phone, member_no: member.member_no || member.acc_no, role: userRole },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      token,
      member: {
        full_name: member.full_name || member.name || 'Member',
        phone: member.phone,
        member_no: member.member_no || member.acc_no || '-',
        role: userRole,
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
      .update({ password: hashedPassword })
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
      .select('*')
      .eq('phone', req.user.phone)
      .maybeSingle();

    if (error || !member) return res.status(404).json({ error: 'Member ledger not found.' });

    res.json({
      full_name: member.full_name || member.name || 'Member',
      member_no: member.member_no || member.acc_no || '-',
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

// 5. MEMBER 12-MONTH DEDUCTION SCHEDULE
app.get('/api/member/monthly-schedule', authenticateToken, async (req, res) => {
  try {
    const targetNo = (req.user.member_no || '').trim().toLowerCase();
    const { data: records, error } = await supabase
      .from('monthly_deductions')
      .select('*')
      .order('id', { ascending: true });

    if (error) return res.status(500).json({ error: 'Failed to fetch schedule.' });

    const filtered = (records || []).filter(r => r.member_no && r.member_no.trim().toLowerCase() === targetNo);
    res.json(filtered);
  } catch (err) {
    res.status(500).json({ error: 'Server error fetching schedule.' });
  }
});

// 6. SECRETARY 16-POINT EXECUTIVE FINANCIAL SUMMARY
app.get('/api/admin/executive-summary', authenticateToken, async (req, res) => {
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

// 7. STATUTORY FINANCIAL STATEMENTS
app.get('/api/admin/financial-statements', authenticateToken, async (req, res) => {
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
      const cat = (j.account_category || 'GENERAL').toUpperCase();
      const head = (j.account_head || 'GENERAL').toUpperCase();
      const dr = Number(j.debit || 0);
      const cr = Number(j.credit || 0);

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

    const totalAssets = assets.reduce((sum, a) => sum + a.amount, 0);
    const totalLiabilities = liabilities.reduce((sum, l) => sum + l.amount, 0);
    const totalEquity = equity.reduce((sum, e) => sum + e.amount, 0);

    res.json({
      generated_at: new Date(),
      income_expenditure: { incomes, expenditures, total_income: totalIncome, total_expenditure: journalExpenditure, net_surplus: netSurplus },
      trial_balance: trialBalance,
      balance_sheet: { assets, liabilities, equity, total_assets: totalAssets, total_liabilities_and_equity: totalLiabilities + totalEquity }
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to generate financial statements.' });
  }
});

// 8. SECRETARY POST MONTHLY REMITTANCE & AUTOMATIC LEDGER SYNC
app.post('/api/admin/post-monthly-deduction', authenticateToken, async (req, res) => {
  const {
    member_no,
    month_year,
    payment_date,
    thrift_savings,
    share_capital,
    social_dues,
    loan_repayment,
    edu_loan_repayment,
    special_deposit,
    cap_mob
  } = req.body;

  if (!member_no || !month_year || !payment_date) {
    return res.status(400).json({ error: 'Member No, Month/Year, and Payment Date are required.' });
  }

  try {
    const cleanMemberNo = member_no.trim();
    const thrift = Number(thrift_savings || 0);
    const shares = Number(share_capital || 0);
    const dues = Number(social_dues || 0);
    const loanRepay = Number(loan_repayment || 0);
    const eduRepay = Number(edu_loan_repayment || 0);
    const special = Number(special_deposit || 0);
    const mob = Number(cap_mob || 0);
    const total = thrift + shares + dues + loanRepay + eduRepay + special + mob;

    // 1. Insert remittance row into monthly_deductions
    const { error: dedErr } = await supabase.from('monthly_deductions').insert([{
      member_no: cleanMemberNo,
      month_year,
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

    if (dedErr) return res.status(500).json({ error: dedErr.message });

    // 2. Fetch current member balances using member_no directly
    const { data: member, error: memErr } = await supabase
// 8. SECRETARY POST MONTHLY REMITTANCE (SAVINGS, SHARES & LEDGER ROW)
app.post('/api/admin/post-monthly-deduction', authenticateToken, async (req, res) => {
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
    const thrift = Number(thrift_savings || 0);
    const shares = Number(share_capital || 0);
    const dues = Number(social_dues || 0);
    const loanRepay = Number(loan_repayment || 0);
    const eduRepay = Number(edu_loan_repayment || 0);
    const special = Number(special_deposit || 0);
    const mob = Number(cap_mob || 0);

    // 1. Insert detailed line-by-line row into monthly_remittances for the printable ledger
    const { error: dedErr } = await supabase
      .from('monthly_remittances')
      .insert([{
        member_no: cleanMemberNo,
        payment_date,
        thrift_savings: thrift,
        share_capital: shares,
        cap_mobilization: mob,
        social_dues: dues,
        special_deposit: special,
        normal_loan_repay: loanRepay,
        edu_loan_repay: eduRepay,
        loan_interest: Number(loan_interest || 0),
        edu_interest: Number(edu_interest || 0)
      }]);

    if (dedErr) throw dedErr;

    // 2. Fetch current member balances
    const { data: member, error: memErr } = await supabase
      .from('members')
      .select('*')
      .eq('member_no', cleanMemberNo)
      .maybeSingle();

    if (memErr || !member) return res.status(404).json({ error: 'Member not found' });

    // 3. Calculate updated cumulative balances
    const newThrift = Number(member.thrift_savings || 0) + thrift;
    const newShares = Number(member.share_capital || 0) + shares;
    const newSpecial = Number(member.special_deposit || 0) + special;
    const newCapMob = Number(member.cap_mob || member.cap_mobilization || 0) + mob;
    const newLoanBal = Math.max(0, Number(member.loan_balance || member.normal_loan_bal || 0) - loanRepay);
    const newEduLoanBal = Math.max(0, Number(member.edu_loan_balance || member.edu_loan_bal || 0) - eduRepay);

    // 4. Update member master account balances
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

    if (updateErr) return res.status(500).json({ error: updateErr.message });

    res.json({ message: 'Remittance posted and saved to ledger successfully' });

  } catch (err) {
    res.status(500).json({ error: 'Failed to post remittance: ' + err.message });
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

// 10. ADMIN: ONBOARD NEW MEMBER
app.post('/api/admin/add-member', authenticateToken, async (req, res) => {
  const {
    member_no,
    full_name,
    phone,
    role,
    share_capital,
    thrift_savings,
    special_deposit,
    cap_mob,
    loan_balance,
    edu_loan_balance
  } = req.body;

  if (!member_no || !full_name || !phone) {
    return res.status(400).json({ error: 'Member No, Full Name, and Phone are required.' });
  }

  try {
    const cleanNo = member_no.trim();
    const { error } = await supabase.from('members').insert([{
      member_no: cleanNo,
      acc_no: cleanNo,
      full_name: full_name.trim(),
      phone: phone.trim(),
      role: (role || 'MEMBER').toUpperCase(),
      share_capital: Number(share_capital || 0),
      thrift_savings: Number(thrift_savings || 0),
      special_deposit: Number(special_deposit || 0),
      cap_mob: Number(cap_mob || 0),
      loan_balance: Number(loan_balance || 0),
      edu_loan_balance: Number(edu_loan_balance || 0),
      is_active: false
    }]);

    if (error) return res.status(500).json({ error: error.message });
    res.json({ message: `Member ${full_name} (${cleanNo}) onboarded successfully!` });
  } catch (err) {
    res.status(500).json({ error: 'Failed to onboard new member.' });
  }
});

// 11. ADMIN: POST INCOME & EXPENDITURE (JOURNAL ENTRY)
app.post('/api/admin/post-journal-entry', authenticateToken, async (req, res) => {
  const { entry_date, account_category, account_head, description, debit, credit } = req.body;

  if (!entry_date || !account_category || !account_head) {
    return res.status(400).json({ error: 'Entry Date, Category, and Account Head are required.' });
  }

  try {
    const { error } = await supabase.from('journal_entries').insert([{
      entry_date,
      account_category: account_category.toUpperCase(), // 'INCOME', 'EXPENDITURE', 'ASSET', 'LIABILITY', 'EQUITY'
      account_head: account_head.trim(),
      description: description || '',
      debit: Number(debit || 0),
      credit: Number(credit || 0)
    }]);

    if (error) return res.status(500).json({ error: error.message });
    res.json({ message: 'Financial entry posted successfully to General Ledger!' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to post financial journal entry.' });
  }
});

// 12. ADMIN: GRANT NEW LOAN TO MEMBER
app.post('/api/admin/grant-loan', authenticateToken, async (req, res) => {
  const { member_no, loan_type, principal_amount, disbursement_date } = req.body;

  if (!member_no || !loan_type || !principal_amount || !disbursement_date) {
    return res.status(400).json({ error: 'Member No, Loan Type, Amount, and Date are required.' });
  }

  try {
    const cleanNo = member_no.trim();
    const amount = Number(principal_amount);
    const isEdu = loan_type.toUpperCase() === 'EDU';

    // 1. Fetch current member loan balance
    const { data: member, error: memErr } = await supabase
      .from('members')
      .select('*')
      .eq('member_no', cleanNo)
      .maybeSingle();

    if (memErr || !member) {
      return res.status(404).json({ error: `Member account '${cleanNo}' not found.` });
    }

    const currentBal = isEdu ? Number(member.edu_loan_balance || 0) : Number(member.loan_balance || 0);
    const updatedBal = currentBal + amount;

    // 2. Update member outstanding balance in members register
    const updateField = isEdu ? { edu_loan_balance: updatedBal } : { loan_balance: updatedBal };
    const { error: updErr } = await supabase.from('members').update(updateField).eq('member_no', cleanNo);
    if (updErr) return res.status(500).json({ error: updErr.message });

    // 3. Post automatically to journal_entries for Statutory Reports & Executive Summary
    const headName = isEdu ? 'EDU LOAN DISBURSED' : 'REGULAR LOAN DISBURSED';
    await supabase.from('journal_entries').insert([{
      entry_date: disbursement_date,
      account_category: 'ASSET',
      account_head: headName,
      description: `Loan granted to ${member.full_name || cleanNo}`,
      debit: amount,
      credit: 0
    }]);

    res.json({ message: `${loan_type.toUpperCase()} loan of ₦${amount.toLocaleString()} granted to ${cleanNo}!` });
  } catch (err) {
    res.status(500).json({ error: 'Failed to grant loan.' });
  }
});

// GET MEMBER PERSONAL LEDGER FOR AUDIT PRINTING
app.get('/api/admin/personal-ledger', authenticateToken, async (req, res) => {
  const { member_no, year } = req.query;
  const targetYear = year || new Date().getFullYear();

  try {
    // 1. Fetch Member Info
    const { data: member, error: memErr } = await supabase
      .from('members')
      .select('*')
      .eq('member_no', member_no)
      .single();

    if (memErr || !member) {
      return res.status(404).json({ error: 'Member not found' });
    }

    // 2. Fetch All Monthly Remittances for the Selected Year
    const { data: remittances, error: remErr } = await supabase
      .from('monthly_remittances')
      .select('*')
      .eq('member_no', member_no)
      .gte('payment_date', `${targetYear}-01-01`)
      .lte('payment_date', `${targetYear}-12-31`)
      .order('payment_date', { ascending: true });

    if (remErr) throw remErr;

    res.json({
      member,
      year: targetYear,
      transactions: remittances || []
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`Dynamic Teachers MPCS Server live on port ${PORT}`));
        

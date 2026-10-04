const express = require('express');
const { createClient } = require('@supabase/supabase-js');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

// 1. Member Authentication & Role Check
app.post('/api/login', async (req, res) => {
  const { phone } = req.body;
  if (!phone) return res.status(400).json({ error: 'Phone number is required' });

  try {
    const { data: member, error } = await supabase
      .from('members')
      .select('member_no, full_name, phone, role')
      .eq('phone', phone.trim())
      .single();

    if (error || !member) {
      return res.status(401).json({ error: 'Member record not found' });
    }

    res.json({ success: true, member });
  } catch (err) {
    res.status(500).json({ error: 'Server error during login' });
  }
});

// 2. Executive Financial Aggregations (Statutory Reporting)
app.get('/api/reports/statutory', async (req, res) => {
  const userPhone = req.headers['x-user-phone'];

  // Verify Admin Access
  const { data: admin } = await supabase
    .from('members')
    .select('role')
    .eq('phone', userPhone)
    .single();

  if (!admin || admin.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied. Executive privileges required.' });
  }

  try {
    const [journals, assets, investments, appropriations] = await Promise.all([
      supabase.from('journal_entries').select('debit_amount, credit_amount'),
      supabase.from('fixed_assets').select('cost_value, current_value'),
      supabase.from('external_investments').select('principal_amount, interest_earned'),
      supabase.from('appropriation_records').select('amount')
    ]);

    res.json({
      success: true,
      data: {
        journalSummary: journals.data || [],
        fixedAssets: assets.data || [],
        investments: investments.data || [],
        appropriations: appropriations.data || []
      }
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to generate statutory financial report' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Executive accounting portal running on port ${PORT}`));

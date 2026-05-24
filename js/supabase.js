// ════════════════════════════════════════════════
//  FRANCHISEFOREST ADMIN — Supabase Client
//  Admin-only functions. Do not expose publicly.
// ════════════════════════════════════════════════

const SUPABASE_URL      = window.__ENV__?.SUPABASE_URL      || '';
const SUPABASE_ANON_KEY = window.__ENV__?.SUPABASE_ANON_KEY || '';

if (!SUPABASE_URL || !SUPABASE_ANON_KEY) {
  console.error('[Admin] Supabase config missing — ensure env vars are set on Railway');
}

const { createClient } = supabase;
const db = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);


// ── Auth helpers ─────────────────────────────────

async function signIn(email, password) {
  const { data, error } = await db.auth.signInWithPassword({ email, password });
  if (error) throw error;
  return data;
}

async function signOut() {
  await db.auth.signOut();
  location.reload();
}

async function getSession() {
  const { data } = await db.auth.getSession();
  return data.session;
}

async function getCurrentProfile() {
  const session = await getSession();
  if (!session) return null;
  const { data } = await db.from('profiles').select('*').eq('id', session.user.id).single();
  return data;
}


// ── Admin helpers ────────────────────────────────

async function adminGetAllInvestors() {
  const { data, error } = await db
    .from('profiles')
    .select('*, investments(count)')
    .order('created_at', { ascending: false });
  if (error) throw error;
  return data;
}

async function adminGetAllInvestments() {
  const { data, error } = await db
    .from('investments')
    .select('*, profiles(full_name, phone, email), units(name, location, type)')
    .order('created_at', { ascending: false });
  if (error) throw error;
  return data;
}

async function adminAddPayout(investmentId, quarter, year, amount, note = '') {
  const { data, error } = await db.from('payouts').insert({
    investment_id: investmentId,
    quarter,
    year,
    amount,
    note,
    status: 'pending'
  }).select().single();
  if (error) throw error;
  return data;
}

async function adminMarkPayoutPaid(payoutId) {
  const { data, error } = await db.from('payouts')
    .update({ status: 'paid', paid_at: new Date().toISOString() })
    .eq('id', payoutId)
    .select().single();
  if (error) throw error;
  return data;
}

async function adminAddInvestment(investorId, unitId, plan, amount, unitsCount) {
  const { data, error } = await db.from('investments').insert({
    investor_id: investorId,
    unit_id: unitId,
    plan,
    amount,
    units_count: unitsCount
  }).select().single();
  if (error) throw error;
  return data;
}

async function adminGetUnits() {
  const { data, error } = await db.from('units').select('*').order('name');
  if (error) throw error;
  return data;
}

async function adminGetAllCPs() {
  const { data, error } = await db.from('channel_partners')
    .select('*, profiles(full_name, email, phone, city)')
    .order('joined_at', { ascending: false });
  if (error) throw error;
  return data;
}

async function adminAddCP(profileId, consultantId, referredBy, rank) {
  const { data, error } = await db.from('channel_partners').insert({
    id: profileId,
    consultant_id: consultantId,
    referred_by: referredBy || null,
    rank: rank || 'channel_partner'
  }).select().single();
  if (error) throw error;
  return data;
}

async function adminAddCPCommission(cpId, type, saleAmount, commissionAmount, note) {
  const { data, error } = await db.from('cp_commissions').insert({
    cp_id: cpId, type, sale_amount: saleAmount,
    commission_amount: commissionAmount, note, status: 'pending'
  }).select().single();
  if (error) throw error;
  return data;
}

async function adminMarkCPCommissionPaid(commissionId) {
  const { data, error } = await db.from('cp_commissions')
    .update({ status: 'paid', paid_at: new Date().toISOString() })
    .eq('id', commissionId).select().single();
  if (error) throw error;
  return data;
}

async function adminGetLeads() {
  const { data, error } = await db
    .from('invest_leads')
    .select('*')
    .order('submitted_at', { ascending: false });
  if (error) throw error;
  return data;
}

async function adminUpdateLeadStatus(leadId, status) {
  const { data, error } = await db
    .from('invest_leads')
    .update({ status })
    .eq('id', leadId)
    .select().single();
  if (error) throw error;
  return data;
}

async function adminGetDashboardStats() {
  const [investors, investments, payouts] = await Promise.all([
    db.from('profiles').select('id', { count: 'exact' }),
    db.from('investments').select('amount'),
    db.from('payouts').select('amount, status')
  ]);
  const totalInvestors  = investors.count;
  const totalRaised     = investments.data.reduce((s, i) => s + Number(i.amount), 0);
  const totalPaidOut    = payouts.data.filter(p => p.status === 'paid').reduce((s, p) => s + Number(p.amount), 0);
  const pendingPayouts  = payouts.data.filter(p => p.status === 'pending').reduce((s, p) => s + Number(p.amount), 0);
  return { totalInvestors, totalRaised, totalPaidOut, pendingPayouts };
}

// Sign-up helper (used by admin to create investor accounts)
async function signUp(email, password, fullName, phone, city) {
  const { data, error } = await db.auth.signUp({
    email,
    password,
    options: { data: { full_name: fullName } }
  });
  if (error) throw error;
  if (data.user) {
    await db.from('profiles').update({ phone, city, full_name: fullName })
      .eq('id', data.user.id);
  }
  return data;
}

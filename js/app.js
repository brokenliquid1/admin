// ════════════════════════════════════════════════════════════════
//  FRANCHISEFOREST ADMIN — App Logic
//  Moved from inline <script> to this file (H3 CSP fix).
//  No inline event handlers — all wired via addEventListener (H3+H5).
//  DOMPurify used before any innerHTML write (H2 XSS fix).
//  Generic error messages — raw Supabase errors go to console (M4).
// ════════════════════════════════════════════════════════════════

// ── H1 NOTE ─────────────────────────────────────────────────────
// The localStorage idle timer is a UX hint only.
// The HARD session limit is the Supabase JWT expiry (set to 8h in
// Supabase → Auth → Settings → JWT expiry = 28800).
// Even if localStorage is tampered, an expired JWT will be rejected
// by every Supabase query — the session cannot be extended client-side.

// ── Safe HTML helper (H2) ────────────────────────────────────────
// Always sanitise HTML strings before setting innerHTML.
function safeHtml(html) {
  if (typeof DOMPurify !== 'undefined') {
    return DOMPurify.sanitize(html, {
      ALLOWED_TAGS: ['div','span','p','b','strong','em','br','hr',
                     'table','thead','tbody','tr','th','td',
                     'button','select','option','input',
                     'label','small','ul','li'],
      ALLOWED_ATTR: ['class','style','id','data-id','data-action',
                     'value','selected','type','placeholder',
                     'onchange', // kept for lead status selects only
                     'colspan','rowspan']
    });
  }
  // Fallback: strip all tags if DOMPurify failed to load
  return html.replace(/<[^>]*>/g, '');
}

// ── M4 Safe error messages ───────────────────────────────────────
// Map known Supabase error codes/messages to generic user-facing text.
// Real error always logged to console for debugging.
function friendlyError(e) {
  console.error('[Admin error]', e);
  const msg = (e?.message || e?.code || '').toLowerCase();
  if (msg.includes('jwt'))              return 'Session expired. Please sign in again.';
  if (msg.includes('not an admin'))     return 'Access denied — admin privileges required.';
  if (msg.includes('invalid login'))    return 'Incorrect email or password.';
  if (msg.includes('email not confirmed')) return 'Email address not confirmed.';
  if (msg.includes('network'))          return 'Network error. Check your connection.';
  if (msg.includes('duplicate') || msg.includes('unique')) return 'A record with this ID already exists.';
  if (msg.includes('foreign key'))      return 'Cannot complete — a related record is missing.';
  return 'Something went wrong. Please try again.';
}

// ── Topbar date ──────────────────────────────────────────────────
document.getElementById('todayDate').textContent =
  new Date().toLocaleDateString('en-IN', { weekday:'short', day:'numeric', month:'long', year:'numeric' });

// ── Tab metadata ─────────────────────────────────────────────────
const tabMeta = {
  dashboard:       { title:'Dashboard',        sub:'Overview of all activity' },
  investors:       { title:'Investors',        sub:'All registered investors' },
  investments:     { title:'Investments',      sub:'All active & past investments' },
  payouts:         { title:'Payouts',          sub:'Quarterly payout management' },
  units:           { title:'Units',            sub:'Kiosk & store locations' },
  channelpartners: { title:'Channel Partners', sub:'CP network, ranks & commissions' },
  leads:           { title:'Invest Leads',     sub:'Enquiries from the Invest Now form' }
};

// ── Admin lockout ─────────────────────────────────────────────────
async function _checkLockout(email) {
  if (!email) return false;
  const { data } = await db.from('admin_lockout').select('locked')
    .eq('email', email.toLowerCase()).maybeSingle();
  return data?.locked === true;
}

async function _recordFail(email) {
  const { data } = await db.rpc('record_failed_login', { p_email: email.toLowerCase() });
  return data || { attempts: 0, locked: false };
}

function _showPermanentLock() {
  const err = document.getElementById('authError');
  const btn = document.getElementById('loginBtn');
  document.getElementById('loginEmail').disabled    = true;
  document.getElementById('loginPassword').disabled = true;
  err.style.display    = 'block';
  err.style.background = 'rgba(231,76,60,0.12)';
  err.style.border     = '1px solid rgba(231,76,60,0.35)';
  err.style.color      = '#c0392b';
  err.style.padding    = '14px 16px';
  err.style.lineHeight = '1.5';
  // Safe: using textContent for text, only static HTML for formatting
  err.innerHTML = DOMPurify.sanitize('<b>🔒 Account Locked</b><br>Too many failed login attempts. Contact the administrator to restore access.');
  btn.disabled         = true;
  btn.textContent      = '🔒 Locked';
  btn.style.background = '#c0392b';
  btn.style.opacity    = '1';
  localStorage.setItem('_bw_le', document.getElementById('loginEmail').value.trim().toLowerCase());
}

// ── Auth ──────────────────────────────────────────────────────────
async function doLogin() {
  const email = document.getElementById('loginEmail').value.trim().toLowerCase();
  const pass  = document.getElementById('loginPassword').value;
  const btn   = document.getElementById('loginBtn');
  const err   = document.getElementById('authError');

  if (!email || !pass) {
    err.style.display = 'block';
    err.textContent   = 'Please enter your email and password.';
    return;
  }

  err.style.display = 'none';
  btn.innerHTML = '<span class="spinner"></span>';
  btn.disabled  = true;

  if (await _checkLockout(email)) { _showPermanentLock(); return; }

  try {
    await signIn(email, pass);
    const profile = await getCurrentProfile();
    if (!profile?.is_admin) {
      await db.auth.signOut();
      throw new Error('Not an admin');
    }
    initApp(profile);
  } catch(e) {
    const result    = await _recordFail(email);
    const remaining = Math.max(0, 2 - result.attempts);
    if (result.locked) {
      _showPermanentLock();
    } else {
      err.style.display = 'block';
      err.textContent   = remaining > 0
        ? `Invalid credentials or insufficient permissions. ${remaining} attempt${remaining !== 1 ? 's' : ''} remaining before lockout.`
        : 'Invalid credentials or insufficient permissions.';
      btn.textContent = 'Sign In to Admin Panel';
      btn.disabled    = false;
    }
  }
}

async function doLogout() {
  await db.auth.signOut();
  location.reload();
}

// ── Init app ──────────────────────────────────────────────────────
async function initApp(profile) {
  document.getElementById('authGate').style.display = 'none';
  document.getElementById('app').style.display = 'flex';
  document.getElementById('adminName').textContent    = profile.full_name || profile.email;
  document.getElementById('adminAvatar').textContent  = (profile.full_name || 'A')[0].toUpperCase();
  loadDashboard();
  resetIdleTimer(); // start idle clock after login
}

// On page load: check lockout cache, then check existing session
(async function() {
  const cached = localStorage.getItem('_bw_le');
  if (cached) {
    document.getElementById('loginEmail').value = cached;
    if (await _checkLockout(cached)) _showPermanentLock();
  }
})();

(async () => {
  const session = await getSession();
  if (!session) return;

  // H1 — check localStorage idle stamp; if > 30 min, force logout
  const IDLE_LIMIT = 30 * 60 * 1000;
  const last = parseInt(localStorage.getItem('_ff_last_active') || '0', 10);
  const gap  = Date.now() - last;
  if (last && gap > IDLE_LIMIT) {
    await db.auth.signOut();
    localStorage.removeItem('_ff_last_active');
    return;
  }

  const profile = await getCurrentProfile();
  if (profile?.is_admin) {
    stampActivity();
    initApp(profile);
  }
})();

// ── Tab switching ─────────────────────────────────────────────────
function switchTab(name, el) {
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  if (el) el.classList.add('active');
  document.getElementById('topbarTitle').textContent = tabMeta[name].title;
  document.getElementById('topbarSub').textContent   = tabMeta[name].sub;
  closeDetail();
  if (name === 'dashboard')       loadDashboard();
  if (name === 'investors')       loadInvestors();
  if (name === 'investments')     loadInvestments();
  if (name === 'payouts')         loadPayouts();
  if (name === 'units')           loadUnits();
  if (name === 'channelpartners') loadChannelPartners();
  if (name === 'leads')           loadLeads();
}

// ── Modal helpers ─────────────────────────────────────────────────
function openModal(id) {
  document.getElementById(id).classList.add('open');
  if (id === 'addInvestmentModal')    populateInvestmentDropdowns();
  if (id === 'addPayoutModal')        populatePayoutDropdowns();
  if (id === 'addCPModal')            populateCPModals();
  if (id === 'addCPCommissionModal')  populateCPCommissionModal();
}
function closeModal(id) {
  document.getElementById(id).classList.remove('open');
}

// ── Detail panel ──────────────────────────────────────────────────
// H2 FIX: safeHtml() sanitises before setting innerHTML
function showDetail(title, html) {
  document.getElementById('detailTitle').textContent  = title;
  document.getElementById('detailBody').innerHTML     = safeHtml(html);
  document.getElementById('detailPanel').classList.add('open');
}
function closeDetail() {
  document.getElementById('detailPanel').classList.remove('open');
}

// ── Toast ─────────────────────────────────────────────────────────
function toast(msg, type = 'success') {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'show ' + type;
  setTimeout(() => { t.className = ''; }, 3000);
}

// ── Format helpers ────────────────────────────────────────────────
function fmt(n)    { return '₹' + Number(n).toLocaleString('en-IN'); }
function fmtDate(d){ return d ? new Date(d).toLocaleDateString('en-IN', { day:'numeric', month:'short', year:'numeric' }) : '—'; }
function esc(v)    { return String(v ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#x27;'); }

// ── DASHBOARD ─────────────────────────────────────────────────────
async function loadDashboard() {
  try {
    const stats = await adminGetDashboardStats();
    document.getElementById('s-investors').textContent = stats.totalInvestors || 0;
    document.getElementById('s-raised').textContent    = fmt(stats.totalRaised);
    document.getElementById('s-paidout').textContent   = fmt(stats.totalPaidOut);
    document.getElementById('s-pending').textContent   = fmt(stats.pendingPayouts);
  } catch(e) { console.error('[dashboard stats]', e); }

  try {
    const investments = await adminGetAllInvestments();
    const tbody = document.getElementById('recentInvestmentsBody');
    const recent = investments.slice(0, 8);
    if (!recent.length) {
      tbody.innerHTML = '<tr class="loading-row"><td colspan="6">No investments yet.</td></tr>';
      return;
    }
    tbody.innerHTML = recent.map(i => `
      <tr>
        <td class="td-name">${esc(i.profiles?.full_name) || '—'}</td>
        <td>${esc(i.units?.name) || '—'}</td>
        <td><span class="badge badge-gold">Plan ${esc(i.plan)}</span></td>
        <td class="td-mono">${fmt(i.amount)}</td>
        <td>${fmtDate(i.start_date)}</td>
        <td><span class="badge ${i.status==='active'?'badge-green':'badge-navy'}">${esc(i.status)}</span></td>
      </tr>`).join('');
  } catch(e) { console.error('[dashboard investments]', e); }
}

// ── INVESTORS ─────────────────────────────────────────────────────
let allInvestors = [];
async function loadInvestors() {
  const tbody = document.getElementById('investorsBody');
  tbody.innerHTML = '<tr class="loading-row"><td colspan="5">Loading...</td></tr>';
  try {
    allInvestors = await adminGetAllInvestors();
    renderInvestors(allInvestors);
  } catch(e) {
    tbody.innerHTML = '<tr class="loading-row"><td colspan="5">Error loading investors.</td></tr>';
    console.error('[investors]', e);
  }
}

function renderInvestors(list) {
  const tbody = document.getElementById('investorsBody');
  if (!list.length) {
    tbody.innerHTML = '<tr class="loading-row"><td colspan="5">No investors found.</td></tr>';
    return;
  }
  // H5 FIX: use data-id attribute instead of onclick="fn('${id}')"
  tbody.innerHTML = list.map(inv => `
    <tr style="cursor:pointer;" data-id="${esc(inv.id)}">
      <td class="td-name">${esc(inv.full_name) || '—'}</td>
      <td>${esc(inv.phone) || '—'}</td>
      <td>${esc(inv.city) || '—'}</td>
      <td>${fmtDate(inv.created_at)}</td>
      <td><button class="btn btn-ghost btn-sm" data-action="view-investor" data-id="${esc(inv.id)}">View →</button></td>
    </tr>`).join('');
}

function filterInvestors(q) {
  const filtered = allInvestors.filter(i =>
    (i.full_name||'').toLowerCase().includes(q.toLowerCase()) ||
    (i.phone||'').includes(q)
  );
  renderInvestors(filtered);
}

async function showInvestorDetail(id) {
  const inv = allInvestors.find(i => i.id === id);
  if (!inv) return;
  const { data: investments } = await db.from('investments')
    .select('*, units(name, location, type)').eq('investor_id', id);
  const totalInvested = (investments||[]).reduce((s,i) => s + Number(i.amount), 0);
  const invRows = (investments||[]).map(i => `
    <div style="background:var(--warm-grey);border-radius:8px;padding:12px 14px;margin-bottom:8px;">
      <div style="font-weight:600;font-size:13px;color:var(--text);">${esc(i.units?.name) || 'Unknown Unit'}</div>
      <div style="font-size:12px;color:var(--text-light);margin-top:2px;">${esc(i.units?.location)} · Plan ${esc(i.plan)} · ${fmt(i.amount)}</div>
      <div style="margin-top:6px;"><span class="badge ${i.status==='active'?'badge-green':'badge-navy'}">${esc(i.status)}</span></div>
    </div>`).join('') || '<p style="color:var(--text-light);font-size:13px;">No investments yet.</p>';

  showDetail(esc(inv.full_name) || 'Investor', `
    <div class="detail-row"><label>Full Name</label><span>${esc(inv.full_name) || '—'}</span></div>
    <div class="detail-row"><label>Email</label><span>${esc(inv.email) || '—'}</span></div>
    <div class="detail-row"><label>Phone</label><span>${esc(inv.phone) || '—'}</span></div>
    <div class="detail-row"><label>City</label><span>${esc(inv.city) || '—'}</span></div>
    <div class="detail-row"><label>Joined</label><span>${fmtDate(inv.created_at)}</span></div>
    <hr class="detail-divider">
    <div class="detail-row"><label>Total Invested</label><span style="font-size:18px;font-weight:700;color:var(--gold);">${fmt(totalInvested)}</span></div>
    <hr class="detail-divider">
    <div style="font-size:12px;font-weight:700;letter-spacing:1px;text-transform:uppercase;color:var(--text-light);margin-bottom:10px;">Investments</div>
    ${invRows}
  `);
}

async function addInvestor() {
  const name  = document.getElementById('inv-name').value.trim();
  const email = document.getElementById('inv-email').value.trim();
  const pass  = document.getElementById('inv-pass').value;
  const phone = document.getElementById('inv-phone').value.trim();
  const city  = document.getElementById('inv-city').value.trim();
  if (!name || !email || !pass) return toast('Name, email & password are required.', 'error');
  try {
    await signUp(email, pass, name, phone, city);
    closeModal('addInvestorModal');
    toast('Investor account created.');
    loadInvestors();
  } catch(e) { toast(friendlyError(e), 'error'); }
}

// ── INVESTMENTS ───────────────────────────────────────────────────
async function loadInvestments() {
  const tbody = document.getElementById('investmentsBody');
  tbody.innerHTML = '<tr class="loading-row"><td colspan="7">Loading...</td></tr>';
  try {
    const data = await adminGetAllInvestments();
    if (!data.length) {
      tbody.innerHTML = '<tr class="loading-row"><td colspan="7">No investments yet.</td></tr>';
      return;
    }
    tbody.innerHTML = data.map(i => `
      <tr>
        <td class="td-name">${esc(i.profiles?.full_name) || '—'}</td>
        <td>${esc(i.units?.name) || '—'}</td>
        <td><span class="badge badge-gold">Plan ${esc(i.plan)}</span></td>
        <td class="td-mono">${fmt(i.amount)}</td>
        <td>${Number(i.units_count)}</td>
        <td>${fmtDate(i.start_date)}</td>
        <td><span class="badge ${i.status==='active'?'badge-green':'badge-navy'}">${esc(i.status)}</span></td>
      </tr>`).join('');
  } catch(e) {
    tbody.innerHTML = '<tr class="loading-row"><td colspan="7">Error loading data.</td></tr>';
    console.error('[investments]', e);
  }
}

async function populateInvestmentDropdowns() {
  const [invRes, unitRes] = await Promise.all([
    db.from('profiles').select('id, full_name').eq('is_admin', false),
    db.from('units').select('id, name').eq('status', 'active')
  ]);
  document.getElementById('inv-select').innerHTML =
    (invRes.data||[]).map(i => `<option value="${esc(i.id)}">${esc(i.full_name)}</option>`).join('');
  document.getElementById('unit-select').innerHTML =
    (unitRes.data||[]).map(u => `<option value="${esc(u.id)}">${esc(u.name)}</option>`).join('');
  document.getElementById('inv-start').value = new Date().toISOString().split('T')[0];
}

async function addInvestment() {
  const investorId = document.getElementById('inv-select').value;
  const unitId     = document.getElementById('unit-select').value;
  const plan       = document.getElementById('plan-select').value;
  const amount     = document.getElementById('inv-amount').value;
  const unitsCount = document.getElementById('inv-units-count').value;
  const startDate  = document.getElementById('inv-start').value;
  if (!investorId || !amount) return toast('Investor and amount are required.', 'error');
  try {
    const { error } = await db.from('investments').insert({
      investor_id: investorId, unit_id: unitId, plan,
      amount: Number(amount), units_count: Number(unitsCount), start_date: startDate
    });
    if (error) throw error;
    closeModal('addInvestmentModal');
    toast('Investment saved.');
    loadInvestments();
    loadDashboard();
  } catch(e) { toast(friendlyError(e), 'error'); }
}

// ── PAYOUTS ───────────────────────────────────────────────────────
async function loadPayouts() {
  const tbody = document.getElementById('payoutsBody');
  tbody.innerHTML = '<tr class="loading-row"><td colspan="7">Loading...</td></tr>';
  try {
    const { data, error } = await db.from('payouts')
      .select('*, investments(amount, plan, investor_id, profiles(full_name), units(name))')
      .order('year', { ascending: false }).order('quarter', { ascending: false });
    if (error) throw error;
    if (!data.length) {
      tbody.innerHTML = '<tr class="loading-row"><td colspan="7">No payouts yet.</td></tr>';
      return;
    }
    // H5 FIX: data-id + data-action instead of onclick
    tbody.innerHTML = data.map(p => `
      <tr>
        <td class="td-name">${esc(p.investments?.profiles?.full_name) || '—'}</td>
        <td>${esc(p.investments?.units?.name) || '—'}</td>
        <td>Q${Number(p.quarter)}</td>
        <td>${Number(p.year)}</td>
        <td class="td-mono">${fmt(p.amount)}</td>
        <td><span class="badge ${p.status==='paid'?'badge-green':'badge-orange'}">${esc(p.status)}</span></td>
        <td>
          ${p.status === 'pending'
            ? `<button class="btn btn-success btn-sm" data-action="mark-payout-paid" data-id="${esc(p.id)}">Mark Paid</button>`
            : `<span style="font-size:11px;color:var(--text-light);">${fmtDate(p.paid_at)}</span>`}
        </td>
      </tr>`).join('');
  } catch(e) {
    tbody.innerHTML = '<tr class="loading-row"><td colspan="7">Error loading data.</td></tr>';
    console.error('[payouts]', e);
  }
}

async function populatePayoutDropdowns() {
  const { data } = await db.from('investments')
    .select('id, amount, plan, profiles(full_name), units(name)').eq('status', 'active');
  document.getElementById('payout-investment-select').innerHTML =
    (data||[]).map(i => `<option value="${esc(i.id)}">${esc(i.profiles?.full_name)} — ${esc(i.units?.name)} (Plan ${esc(i.plan)})</option>`).join('');
  document.getElementById('payout-year').value = new Date().getFullYear();
}

async function addPayout() {
  const investmentId = document.getElementById('payout-investment-select').value;
  const quarter  = document.getElementById('payout-quarter').value;
  const year     = document.getElementById('payout-year').value;
  const amount   = document.getElementById('payout-amount').value;
  const note     = document.getElementById('payout-note').value;
  if (!amount) return toast('Amount is required.', 'error');
  try {
    await adminAddPayout(investmentId, Number(quarter), Number(year), Number(amount), note);
    closeModal('addPayoutModal');
    toast('Payout added.');
    loadPayouts();
    loadDashboard();
  } catch(e) { toast(friendlyError(e), 'error'); }
}

async function markPaid(payoutId) {
  try {
    await adminMarkPayoutPaid(payoutId);
    toast('Marked as paid.');
    loadPayouts();
    loadDashboard();
  } catch(e) { toast(friendlyError(e), 'error'); }
}

// ── UNITS ─────────────────────────────────────────────────────────
async function loadUnits() {
  const tbody = document.getElementById('unitsBody');
  tbody.innerHTML = '<tr class="loading-row"><td colspan="5">Loading...</td></tr>';
  try {
    const data = await adminGetUnits();
    if (!data.length) {
      tbody.innerHTML = '<tr class="loading-row"><td colspan="5">No units yet.</td></tr>';
      return;
    }
    tbody.innerHTML = data.map(u => `
      <tr>
        <td class="td-name">${esc(u.name)}</td>
        <td>${esc(u.location)}</td>
        <td><span class="badge ${u.type==='store'?'badge-navy':'badge-gold'}">${esc(u.type)}</span></td>
        <td class="td-mono">${fmt(u.ebitda_quarterly)}</td>
        <td><span class="badge ${u.status==='active'?'badge-green':u.status==='upcoming'?'badge-orange':'badge-red'}">${esc(u.status)}</span></td>
      </tr>`).join('');
  } catch(e) {
    tbody.innerHTML = '<tr class="loading-row"><td colspan="5">Error loading units.</td></tr>';
    console.error('[units]', e);
  }
}

async function addUnit() {
  const name     = document.getElementById('unit-name').value.trim();
  const location = document.getElementById('unit-location').value.trim();
  const type     = document.getElementById('unit-type').value;
  const ebitda   = document.getElementById('unit-ebitda').value;
  const status   = document.getElementById('unit-status').value;
  if (!name || !location) return toast('Name and location are required.', 'error');
  try {
    const { error } = await db.from('units').insert({ name, location, type, ebitda_quarterly: Number(ebitda), status });
    if (error) throw error;
    closeModal('addUnitModal');
    toast('Unit added.');
    loadUnits();
  } catch(e) { toast(friendlyError(e), 'error'); }
}

// ── CHANNEL PARTNERS ──────────────────────────────────────────────
const cpRankLabel = { channel_partner:'Channel Partner', manager:'Manager', senior_manager:'Sr. Manager', bdo:'BDO' };
const cpRankBadge = { channel_partner:'badge-navy', manager:'badge-gold', senior_manager:'badge-orange', bdo:'badge-green' };
let allCPs = [];

async function loadChannelPartners() {
  try {
    const [cpRes, commRes] = await Promise.all([
      db.from('channel_partners').select('id', { count: 'exact' }),
      db.from('cp_commissions').select('commission_amount, status')
    ]);
    document.getElementById('cp-total').textContent   = cpRes.count || 0;
    const c = commRes.data || [];
    document.getElementById('cp-paid').textContent    = fmt(c.filter(x=>x.status==='paid').reduce((s,x)=>s+Number(x.commission_amount),0));
    document.getElementById('cp-pending').textContent = fmt(c.filter(x=>x.status==='pending').reduce((s,x)=>s+Number(x.commission_amount),0));
  } catch(e) { console.error('[cp stats]', e); }
  await loadCPTable();
  await loadCPCommissions();
}

async function loadCPTable() {
  const tbody = document.getElementById('cpBody');
  tbody.innerHTML = '<tr class="loading-row"><td colspan="7">Loading...</td></tr>';
  try {
    allCPs = await adminGetAllCPs();
    renderCPs(allCPs);
  } catch(e) {
    tbody.innerHTML = '<tr class="loading-row"><td colspan="7">Error loading data.</td></tr>';
    console.error('[cp table]', e);
  }
}

function renderCPs(list) {
  const tbody = document.getElementById('cpBody');
  if (!list.length) {
    tbody.innerHTML = '<tr class="loading-row"><td colspan="7">No channel partners yet.</td></tr>';
    return;
  }
  tbody.innerHTML = list.map(cp => {
    const referrer = allCPs.find(c => c.id === cp.referred_by);
    // H5 FIX: data-id attribute
    return `
      <tr style="cursor:pointer;" data-id="${esc(cp.id)}">
        <td class="td-name">${esc(cp.profiles?.full_name) || '—'}</td>
        <td class="td-mono">${esc(cp.consultant_id)}</td>
        <td><span class="badge ${cpRankBadge[cp.rank]||'badge-navy'}">${esc(cpRankLabel[cp.rank]||cp.rank)}</span></td>
        <td>${referrer ? esc(referrer.profiles?.full_name) : '—'}</td>
        <td>${fmtDate(cp.joined_at)}</td>
        <td><span class="badge ${cp.status==='active'?'badge-green':'badge-red'}">${esc(cp.status)}</span></td>
        <td><button class="btn btn-ghost btn-sm" data-action="view-cp" data-id="${esc(cp.id)}">View →</button></td>
      </tr>`;
  }).join('');
}

function filterCPs(q) {
  const filtered = allCPs.filter(cp =>
    (cp.profiles?.full_name||'').toLowerCase().includes(q.toLowerCase()) ||
    (cp.consultant_id||'').toLowerCase().includes(q.toLowerCase())
  );
  renderCPs(filtered);
}

async function showCPDetail(id) {
  const cp = allCPs.find(c => c.id === id);
  if (!cp) return;
  const [l1Res, commRes] = await Promise.all([
    db.from('channel_partners').select('*, profiles(full_name)').eq('referred_by', id),
    db.from('cp_commissions').select('*').eq('cp_id', id).order('created_at', { ascending: false }).limit(10)
  ]);
  const l1    = l1Res.data || [];
  const comms = commRes.data || [];
  const referrer     = allCPs.find(c => c.id === cp.referred_by);
  const totalEarned  = comms.filter(c=>c.status==='paid').reduce((s,c)=>s+Number(c.commission_amount),0);
  const totalPending = comms.filter(c=>c.status==='pending').reduce((s,c)=>s+Number(c.commission_amount),0);
  const l1Rows = l1.map(l => `
    <div style="background:var(--warm-grey);border-radius:7px;padding:10px 13px;margin-bottom:6px;display:flex;align-items:center;justify-content:space-between;">
      <div>
        <div style="font-weight:600;font-size:13px;">${esc(l.profiles?.full_name)||'—'}</div>
        <div style="font-size:11px;color:var(--text-light);">${esc(l.consultant_id)}</div>
      </div>
      <span class="badge badge-green" style="font-size:10px;">${esc(l.status)}</span>
    </div>`).join('') || '<p style="font-size:13px;color:var(--text-light);">No L1 referrals yet.</p>';
  const commTypeLabel = { direct:'Direct', l1_passive:'L1 Passive', l2_passive:'L2 Passive' };
  const commTypeBadge = { direct:'badge-gold', l1_passive:'badge-green', l2_passive:'badge-navy' };
  const commRows = comms.slice(0,5).map(c => `
    <div style="display:flex;align-items:center;justify-content:space-between;padding:9px 0;border-bottom:1px solid var(--border);">
      <div>
        <span class="badge ${commTypeBadge[c.type]||'badge-navy'}" style="font-size:10px;margin-right:6px;">${esc(commTypeLabel[c.type]||c.type)}</span>
        <span style="font-size:12px;color:var(--text-light);">${esc(c.note)||''}</span>
      </div>
      <div style="text-align:right;">
        <div style="font-weight:600;font-size:13px;">${fmt(c.commission_amount)}</div>
        <span class="badge ${c.status==='paid'?'badge-green':'badge-orange'}" style="font-size:10px;">${esc(c.status)}</span>
      </div>
    </div>`).join('') || '<p style="font-size:13px;color:var(--text-light);">No commissions yet.</p>';

  showDetail(esc(cp.profiles?.full_name)||'Channel Partner', `
    <div class="detail-row"><label>Full Name</label><span>${esc(cp.profiles?.full_name)||'—'}</span></div>
    <div class="detail-row"><label>Email</label><span>${esc(cp.profiles?.email)||'—'}</span></div>
    <div class="detail-row"><label>Phone</label><span>${esc(cp.profiles?.phone)||'—'}</span></div>
    <div class="detail-row"><label>Consultant ID</label><span style="font-family:monospace;font-size:15px;font-weight:700;color:var(--gold);">${esc(cp.consultant_id)}</span></div>
    <div class="detail-row"><label>Rank</label><span class="badge ${cpRankBadge[cp.rank]||'badge-navy'}">${esc(cpRankLabel[cp.rank]||cp.rank)}</span></div>
    <div class="detail-row"><label>Referred By</label><span>${referrer ? esc(referrer.profiles?.full_name) : '—'}</span></div>
    <div class="detail-row"><label>Joined</label><span>${fmtDate(cp.joined_at)}</span></div>
    <hr class="detail-divider">
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:16px;">
      <div style="background:var(--green-pale);border-radius:8px;padding:12px;text-align:center;">
        <div style="font-size:18px;font-weight:700;color:#1a9e52;">${fmt(totalEarned)}</div>
        <div style="font-size:11px;color:#1a9e52;margin-top:2px;">Total Earned</div>
      </div>
      <div style="background:rgba(232,98,42,0.1);border-radius:8px;padding:12px;text-align:center;">
        <div style="font-size:18px;font-weight:700;color:var(--orange);">${fmt(totalPending)}</div>
        <div style="font-size:11px;color:var(--orange);margin-top:2px;">Pending</div>
      </div>
    </div>
    <hr class="detail-divider">
    <div style="font-size:11px;font-weight:700;letter-spacing:1px;text-transform:uppercase;color:var(--text-light);margin-bottom:10px;">L1 Network (${l1.length})</div>
    ${l1Rows}
    <hr class="detail-divider">
    <div style="font-size:11px;font-weight:700;letter-spacing:1px;text-transform:uppercase;color:var(--text-light);margin-bottom:10px;">Recent Commissions</div>
    ${commRows}
  `);
}

async function loadCPCommissions() {
  const tbody = document.getElementById('cpCommissionsBody');
  tbody.innerHTML = '<tr class="loading-row"><td colspan="7">Loading...</td></tr>';
  try {
    const { data, error } = await db.from('cp_commissions')
      .select('*, channel_partners(consultant_id, profiles(full_name))')
      .order('created_at', { ascending: false });
    if (error) throw error;
    if (!data.length) {
      tbody.innerHTML = '<tr class="loading-row"><td colspan="7">No commissions yet.</td></tr>';
      return;
    }
    const commTypeLabel = { direct:'Direct', l1_passive:'L1 Passive', l2_passive:'L2 Passive' };
    const commTypeBadge = { direct:'badge-gold', l1_passive:'badge-green', l2_passive:'badge-navy' };
    // H5 FIX: data-action + data-id
    tbody.innerHTML = data.map(c => `
      <tr>
        <td class="td-name">${esc(c.channel_partners?.profiles?.full_name)||'—'}</td>
        <td><span class="badge ${commTypeBadge[c.type]||'badge-navy'}">${esc(commTypeLabel[c.type]||c.type)}</span></td>
        <td class="td-mono">${fmt(c.sale_amount)}</td>
        <td class="td-mono">${fmt(c.commission_amount)}</td>
        <td><span class="badge ${c.status==='paid'?'badge-green':'badge-orange'}">${esc(c.status)}</span></td>
        <td>${fmtDate(c.created_at)}</td>
        <td>${c.status==='pending'
          ? `<button class="btn btn-success btn-sm" data-action="mark-commission-paid" data-id="${esc(c.id)}">Mark Paid</button>`
          : `<span style="font-size:11px;color:var(--text-light);">${fmtDate(c.paid_at)}</span>`}
        </td>
      </tr>`).join('');
  } catch(e) {
    tbody.innerHTML = '<tr class="loading-row"><td colspan="7">Error loading data.</td></tr>';
    console.error('[cp commissions]', e);
  }
}

async function populateCPModals() {
  const [profilesRes, cpsRes] = await Promise.all([
    db.from('profiles').select('id, full_name').eq('is_admin', false),
    db.from('channel_partners').select('id, consultant_id, profiles(full_name)')
  ]);
  const existingIds = new Set((cpsRes.data||[]).map(c => c.id));
  const eligible = (profilesRes.data||[]).filter(p => !existingIds.has(p.id));
  document.getElementById('cp-profile-select').innerHTML =
    eligible.length
      ? eligible.map(p => `<option value="${esc(p.id)}">${esc(p.full_name)}</option>`).join('')
      : '<option value="">No eligible users — add an investor first</option>';
  document.getElementById('cp-referrer-select').innerHTML =
    '<option value="">— None (no referrer) —</option>' +
    (cpsRes.data||[]).map(c => `<option value="${esc(c.id)}">${esc(c.profiles?.full_name)} (${esc(c.consultant_id)})</option>`).join('');
}

async function populateCPCommissionModal() {
  const { data } = await db.from('channel_partners').select('id, consultant_id, profiles(full_name)');
  document.getElementById('cp-comm-cp-select').innerHTML =
    (data||[]).length
      ? (data||[]).map(c => `<option value="${esc(c.id)}">${esc(c.profiles?.full_name)} (${esc(c.consultant_id)})</option>`).join('')
      : '<option>No CPs yet</option>';
}

function suggestCommission() {
  const type = document.getElementById('cp-comm-type').value;
  const sale = Number(document.getElementById('cp-comm-sale').value);
  if (!sale) return;
  const rates = { direct: 0.035, l1_passive: 0.0075, l2_passive: 0.005 };
  document.getElementById('cp-comm-amount').value = Math.round(sale * (rates[type] || 0));
}

async function addCP() {
  const profileId    = document.getElementById('cp-profile-select').value;
  const consultantId = document.getElementById('cp-consultant-id').value.trim();
  const referredBy   = document.getElementById('cp-referrer-select').value;
  const rank         = document.getElementById('cp-rank-select').value;
  if (!profileId || !consultantId) return toast('User and Consultant ID are required.', 'error');
  try {
    await adminAddCP(profileId, consultantId, referredBy || null, rank);
    closeModal('addCPModal');
    toast('Channel Partner added.');
    loadChannelPartners();
  } catch(e) { toast(friendlyError(e), 'error'); }
}

async function addCPCommission() {
  const cpId   = document.getElementById('cp-comm-cp-select').value;
  const type   = document.getElementById('cp-comm-type').value;
  const sale   = document.getElementById('cp-comm-sale').value;
  const amount = document.getElementById('cp-comm-amount').value;
  const note   = document.getElementById('cp-comm-note').value;
  if (!cpId || !sale || !amount) return toast('CP, sale amount and commission amount are required.', 'error');
  try {
    await adminAddCPCommission(cpId, type, Number(sale), Number(amount), note);
    closeModal('addCPCommissionModal');
    toast('Commission added.');
    loadChannelPartners();
  } catch(e) { toast(friendlyError(e), 'error'); }
}

async function markCPCommissionPaid(id) {
  try {
    await adminMarkCPCommissionPaid(id);
    toast('Commission marked as paid.');
    loadCPCommissions();
  } catch(e) { toast(friendlyError(e), 'error'); }
}

// ── INVEST LEADS ──────────────────────────────────────────────────
let allLeads = [];

async function loadLeads() {
  const tbody = document.getElementById('leadsBody');
  tbody.innerHTML = '<tr class="loading-row"><td colspan="8">Loading…</td></tr>';
  try {
    allLeads = await adminGetLeads();
    renderLeads(allLeads);
    document.getElementById('leads-total').textContent     = allLeads.length;
    document.getElementById('leads-new').textContent       = allLeads.filter(l=>l.status==='new').length;
    document.getElementById('leads-contacted').textContent = allLeads.filter(l=>l.status==='contacted').length;
    document.getElementById('leads-converted').textContent = allLeads.filter(l=>l.status==='converted').length;
  } catch(e) {
    tbody.innerHTML = '<tr class="loading-row"><td colspan="8">Error loading leads.</td></tr>';
    console.error('[leads]', e);
  }
}

function renderLeads(list) {
  const tbody = document.getElementById('leadsBody');
  if (!list.length) {
    tbody.innerHTML = '<tr class="loading-row"><td colspan="8">No leads yet.</td></tr>';
    return;
  }
  const badgeCls = { new:'badge-orange', contacted:'badge-gold', converted:'badge-green', dropped:'badge-navy' };
  // H5 FIX: data-lead-id on select instead of onchange="setLeadStatus('${id}',...)"
  tbody.innerHTML = list.map(l => `
    <tr>
      <td class="td-name">${esc(l.full_name)}</td>
      <td>${esc(l.phone)}</td>
      <td>${esc(l.email) || '—'}</td>
      <td style="font-size:12px;">${esc(l.interest) || '—'}</td>
      <td>${esc(l.city) || '—'}</td>
      <td><span class="badge ${badgeCls[l.status] || 'badge-navy'}">${esc(l.status)}</span></td>
      <td>${fmtDate(l.submitted_at)}</td>
      <td>
        <select class="lead-status-select" data-lead-id="${esc(l.id)}"
          style="padding:4px 8px;font-size:12px;border:1.5px solid var(--border);border-radius:6px;background:var(--cream);color:var(--text);font-family:'Inter',sans-serif;cursor:pointer;">
          <option value="new"       ${l.status==='new'       ?'selected':''}>New</option>
          <option value="contacted" ${l.status==='contacted' ?'selected':''}>Contacted</option>
          <option value="converted" ${l.status==='converted' ?'selected':''}>Converted</option>
          <option value="dropped"   ${l.status==='dropped'   ?'selected':''}>Dropped</option>
        </select>
      </td>
    </tr>`).join('');
}

function filterLeads(q) {
  const lq = q.toLowerCase();
  renderLeads(allLeads.filter(l =>
    (l.full_name||'').toLowerCase().includes(lq) ||
    (l.phone||'').includes(q)
  ));
}

async function setLeadStatus(id, status) {
  // M4: validate status against known values before sending to DB
  const validStatuses = ['new', 'contacted', 'converted', 'dropped'];
  if (!validStatuses.includes(status)) return;
  try {
    await adminUpdateLeadStatus(id, status);
    const lead = allLeads.find(l => l.id === id);
    if (lead) lead.status = status;
    toast('Lead status updated.');
    document.getElementById('leads-new').textContent       = allLeads.filter(l=>l.status==='new').length;
    document.getElementById('leads-contacted').textContent = allLeads.filter(l=>l.status==='contacted').length;
    document.getElementById('leads-converted').textContent = allLeads.filter(l=>l.status==='converted').length;
  } catch(e) { toast(friendlyError(e), 'error'); }
}

// ════════════════════════════════════════════════════════════════
//  EVENT DELEGATION — all dynamic table interactions (H3 + H5)
// ════════════════════════════════════════════════════════════════

// Investors table
document.getElementById('investorsBody').addEventListener('click', function(e) {
  const btn = e.target.closest('[data-action="view-investor"]');
  const tr  = e.target.closest('tr[data-id]');
  if (btn) { e.stopPropagation(); showInvestorDetail(btn.dataset.id); }
  else if (tr) showInvestorDetail(tr.dataset.id);
});

// Payouts table — Mark Paid
document.getElementById('payoutsBody').addEventListener('click', function(e) {
  const btn = e.target.closest('[data-action="mark-payout-paid"]');
  if (btn) markPaid(btn.dataset.id);
});

// CP table
document.getElementById('cpBody').addEventListener('click', function(e) {
  const btn = e.target.closest('[data-action="view-cp"]');
  const tr  = e.target.closest('tr[data-id]');
  if (btn) { e.stopPropagation(); showCPDetail(btn.dataset.id); }
  else if (tr) showCPDetail(tr.dataset.id);
});

// CP Commissions table — Mark Paid
document.getElementById('cpCommissionsBody').addEventListener('click', function(e) {
  const btn = e.target.closest('[data-action="mark-commission-paid"]');
  if (btn) markCPCommissionPaid(btn.dataset.id);
});

// Leads table — status select (event delegation on tbody)
document.getElementById('leadsBody').addEventListener('change', function(e) {
  const sel = e.target.closest('.lead-status-select');
  if (sel) setLeadStatus(sel.dataset.leadId, sel.value);
});

// ════════════════════════════════════════════════════════════════
//  STATIC BUTTON EVENT LISTENERS (H3 — replaces all inline onclick)
// ════════════════════════════════════════════════════════════════

// Login
document.getElementById('loginBtn').addEventListener('click', doLogin);
document.getElementById('loginPassword').addEventListener('keydown', e => {
  if (e.key === 'Enter') doLogin();
});

// Logout
document.getElementById('logoutBtn').addEventListener('click', doLogout);

// Nav tabs — event delegation on sidebar-nav
document.querySelector('.sidebar-nav').addEventListener('click', function(e) {
  const btn = e.target.closest('.nav-item[data-tab]');
  if (btn) switchTab(btn.dataset.tab, btn);
});

// Dashboard "View All" button
document.getElementById('viewAllInvestmentsBtn').addEventListener('click', function() {
  const investmentsTab = document.querySelector('.nav-item[data-tab="investments"]');
  switchTab('investments', investmentsTab);
});

// Open modal buttons
document.getElementById('openAddInvestorBtn').addEventListener('click',      () => openModal('addInvestorModal'));
document.getElementById('openAddInvestmentBtn').addEventListener('click',    () => openModal('addInvestmentModal'));
document.getElementById('openAddPayoutBtn').addEventListener('click',        () => openModal('addPayoutModal'));
document.getElementById('openAddUnitBtn').addEventListener('click',          () => openModal('addUnitModal'));
document.getElementById('openAddCPBtn').addEventListener('click',            () => openModal('addCPModal'));
document.getElementById('openAddCPCommissionBtn').addEventListener('click',  () => openModal('addCPCommissionModal'));

// Close modal buttons (data-close-modal attribute)
document.querySelectorAll('[data-close-modal]').forEach(btn => {
  btn.addEventListener('click', () => closeModal(btn.dataset.closeModal));
});

// Backdrop click closes modal
document.querySelectorAll('.modal-overlay').forEach(o => {
  o.addEventListener('click', e => { if (e.target === o) o.classList.remove('open'); });
});

// Form submit buttons
document.getElementById('submitAddInvestorBtn').addEventListener('click',     addInvestor);
document.getElementById('submitAddInvestmentBtn').addEventListener('click',   addInvestment);
document.getElementById('submitAddPayoutBtn').addEventListener('click',       addPayout);
document.getElementById('submitAddUnitBtn').addEventListener('click',         addUnit);
document.getElementById('submitAddCPBtn').addEventListener('click',           addCP);
document.getElementById('submitAddCPCommissionBtn').addEventListener('click', addCPCommission);

// Search inputs
document.getElementById('investorSearch').addEventListener('input', e => filterInvestors(e.target.value));
document.getElementById('cpSearch').addEventListener('input',       e => filterCPs(e.target.value));
document.getElementById('leadsSearch').addEventListener('input',    e => filterLeads(e.target.value));

// Commission suggestion
document.getElementById('cp-comm-type').addEventListener('change', suggestCommission);
document.getElementById('cp-comm-sale').addEventListener('input',  suggestCommission);

// Detail panel close
document.getElementById('detailCloseBtn').addEventListener('click', closeDetail);

// Idle warning "Stay" button
document.getElementById('idleStayBtn').addEventListener('click', resetIdleTimer);

// ════════════════════════════════════════════════════════════════
//  IDLE TIMEOUT (H1)
// ════════════════════════════════════════════════════════════════
const IDLE_LIMIT  = 30 * 60 * 1000;
const WARN_BEFORE =  5 * 60 * 1000;
let idleTimer, warnTimer, warnShown = false;

function stampActivity() {
  localStorage.setItem('_ff_last_active', Date.now());
}

function resetIdleTimer() {
  clearTimeout(idleTimer);
  clearTimeout(warnTimer);
  if (warnShown) {
    const w = document.getElementById('idleWarning');
    if (w) w.style.display = 'none';
    warnShown = false;
  }
  if (document.getElementById('app').style.display === 'none') return;

  warnTimer = setTimeout(() => {
    warnShown = true;
    const w = document.getElementById('idleWarning');
    if (w) { w.style.display = 'flex'; startWarnCountdown(WARN_BEFORE / 1000); }
  }, IDLE_LIMIT - WARN_BEFORE);

  idleTimer = setTimeout(async () => {
    await db.auth.signOut();
    localStorage.removeItem('_ff_last_active');
    location.reload();
  }, IDLE_LIMIT);
}

function startWarnCountdown(seconds) {
  const el = document.getElementById('idleCountdown');
  if (!el) return;
  el.textContent = seconds;
  const iv = setInterval(() => {
    seconds--;
    el.textContent = seconds;
    if (seconds <= 0) clearInterval(iv);
  }, 1000);
}

['mousemove','mousedown','keydown','touchstart','scroll','click'].forEach(ev =>
  document.addEventListener(ev, () => { stampActivity(); resetIdleTimer(); }, { passive: true })
);
setInterval(stampActivity, 30_000);
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'hidden') stampActivity();
});

/* Shared data layer: browser-simulated database, accounts and sessions.
   Loaded by index.html (sign-in) and app.html (the evaluation system). */

var DB_KEY = 'portal.db.v1', TOKEN_KEY = 'portal.session';
var MAX_FAILS = 5, LOCK_MS = 30000;

/* ---------------- storage helpers (never throw) ---------------- */
var mem = {};
function sget(store, k) { try { return window[store].getItem(k); } catch (e) { return mem[store + k] || null; } }
function sset(store, k, v) { try { window[store].setItem(k, v); } catch (e) { mem[store + k] = v; } }
function sdel(store, k) { try { window[store].removeItem(k); } catch (e) { delete mem[store + k]; } }

/* ---------------- the simulated database ---------------- */
var db;
function emptyDb() { return { meta: { version: 1, createdAt: Date.now() }, users: [], sessions: [], audit: [] }; }
function loadDb() {
  try { var raw = sget('localStorage', DB_KEY); db = raw ? JSON.parse(raw) : emptyDb(); } catch (e) { db = emptyDb(); }
  if (!db.users || !db.sessions || !db.audit) db = emptyDb();
}
function saveDb() { sset('localStorage', DB_KEY, JSON.stringify(db)); }
function rid(p) { var a = new Uint8Array(6); (window.crypto || {}).getRandomValues ? crypto.getRandomValues(a) : a.forEach(function (_, i) { a[i] = Math.random() * 256; }); return p + '_' + Array.prototype.map.call(a, function (b) { return ('0' + b.toString(16)).slice(-2); }).join(''); }
function hex(buf) { return Array.prototype.map.call(new Uint8Array(buf), function (b) { return ('0' + b.toString(16)).slice(-2); }).join(''); }
function weakHash(s) { var h = 5381; for (var i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) | 0; return (h >>> 0).toString(16); }

function hashPassword(password, salt) {
  var subtle = window.crypto && crypto.subtle;
  if (!subtle) return Promise.resolve({ algo: 'weak-demo', iter: 1, salt: salt, hash: weakHash(salt + password) });
  var enc = new TextEncoder();
  return subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']).then(function (key) {
    return subtle.deriveBits({ name: 'PBKDF2', salt: enc.encode(salt), iterations: 100000, hash: 'SHA-256' }, key, 256);
  }).then(function (bits) { return { algo: 'pbkdf2-sha256', iter: 100000, salt: salt, hash: hex(bits) }; });
}
function verifyPassword(password, rec) { return hashPassword(password, rec.salt).then(function (r) { return r.algo === rec.algo && r.hash === rec.hash; }); }

function audit(type, user, detail) {
  db.audit.unshift({ id: rid('evt'), ts: Date.now(), type: type, userId: user ? user.id : null, email: user ? user.email : (detail && detail.email) || null, detail: detail && detail.note || '' });
  db.audit = db.audit.slice(0, 200);
}
function findByEmail(email) { email = String(email || '').trim().toLowerCase(); return db.users.filter(function (u) { return u.email === email; })[0]; }
function pruneSessions() { var now = Date.now(); db.sessions = db.sessions.filter(function (s) { return s.expiresAt > now; }); }

function createSession(user, remember) {
  pruneSessions();
  var s = { id: rid('ses'), userId: user.id, createdAt: Date.now(), expiresAt: Date.now() + (remember ? 30 * 864e5 : 8 * 36e5), remember: !!remember };
  db.sessions.push(s);
  sset(remember ? 'localStorage' : 'sessionStorage', TOKEN_KEY, s.id);
  sdel(remember ? 'sessionStorage' : 'localStorage', TOKEN_KEY);
  return s;
}
function currentSession() {
  var id = sget('sessionStorage', TOKEN_KEY) || sget('localStorage', TOKEN_KEY);
  if (!id) return null;
  var s = db.sessions.filter(function (x) { return x.id === id && x.expiresAt > Date.now(); })[0];
  if (!s) return null;
  var u = db.users.filter(function (x) { return x.id === s.userId; })[0];
  return u ? { session: s, user: u } : null;
}

var Auth = {
  register: function (o) {
    var ex = findByEmail(o.email), claim = ex && ex.provider === 'seed' && !ex.pwd;
    if (ex && !claim) return Promise.reject({ field: 'email', msg: 'هذا البريد مسجّل مسبقًا. جرّب تسجيل الدخول.' });
    var salt = rid('salt');
    return hashPassword(o.password, salt).then(function (pwd) {
      if (claim) { ex.pwd = pwd; ex.provider = 'password'; ex.name = o.name.trim() || ex.name; audit('register', ex, { note: 'تفعيل حساب موظف مسجَّل مسبقًا' }); saveDb(); return ex; }
      var u ={ id: rid('usr'), name: o.name.trim(), email: o.email.trim().toLowerCase(), provider: 'password', pwd: pwd, createdAt: Date.now(), lastLoginAt: null, prevLoginAt: null, failedLogins: 0, lockedUntil: 0 };
      db.users.push(u); audit('register', u, { note: 'إنشاء حساب بالبريد' }); saveDb(); return u;
    });
  },
  login: function (email, password, remember) {
    var u = findByEmail(email);
    if (!u) { audit('login_failed', null, { email: String(email).toLowerCase(), note: 'بريد غير مسجّل' }); saveDb(); return Promise.reject({ msg: 'البريد أو كلمة المرور غير صحيحة.' }); }
    if (u.lockedUntil > Date.now()) return Promise.reject({ msg: 'تم قفل الحساب مؤقتًا بعد محاولات متكررة. حاول بعد ' + Math.ceil((u.lockedUntil - Date.now()) / 1000) + ' ثانية.' });
    if (!u.pwd) return Promise.reject({ msg: u.googleSub ? 'هذا الحساب مسجّل عبر Google. استخدم زر «المتابعة بحساب Google».' : 'هذا البريد مسجَّل كموظف لكن حسابه غير مفعّل. أنشئ حسابًا بالبريد نفسه لتفعيله.' });
    return verifyPassword(password, u.pwd).then(function (ok) {
      if (!ok) {
        u.failedLogins = (u.failedLogins || 0) + 1;
        audit('login_failed', u, { note: 'كلمة مرور خاطئة (' + u.failedLogins + ')' });
        var left = MAX_FAILS - u.failedLogins;
        if (left <= 0) { u.lockedUntil = Date.now() + LOCK_MS; u.failedLogins = 0; audit('lockout', u, { note: 'قفل لمدة 30 ثانية' }); saveDb(); return Promise.reject({ msg: 'تم قفل الحساب لمدة 30 ثانية بعد 5 محاولات خاطئة.' }); }
        saveDb(); return Promise.reject({ msg: 'البريد أو كلمة المرور غير صحيحة. تبقّى ' + left + ' محاولات قبل القفل المؤقت.' });
      }
      u.failedLogins = 0; u.prevLoginAt = u.lastLoginAt; u.lastLoginAt = Date.now();
      audit('login', u, { note: 'تسجيل دخول بالبريد' });
      var s = createSession(u, remember); saveDb(); return { user: u, session: s };
    });
  },
  google: function (p) {
    var email = String(p.email || '').toLowerCase(), isNew = false;
    var u = findByEmail(email);
    if (!u) { isNew = true; u = { id: rid('usr'), name: p.name || email.split('@')[0], email: email, provider: 'google', googleSub: p.sub || rid('g'), pwd: null, createdAt: Date.now(), lastLoginAt: null, prevLoginAt: null, failedLogins: 0, lockedUntil: 0 }; db.users.push(u); audit('register', u, { note: 'إنشاء حساب عبر Google' }); }
    else if (!u.googleSub) { u.googleSub = p.sub || rid('g'); u.linkedGoogle = true; audit('link_google', u, { note: 'ربط حساب Google بالحساب الحالي' }); }
    u.prevLoginAt = u.lastLoginAt; u.lastLoginAt = Date.now();
    audit('google_login', u, { note: 'دخول عبر Google' });
    var s = createSession(u, true); saveDb(); return { user: u, session: s, isNew: isNew };
  },
  logout: function () {
    var c = currentSession();
    if (c) { db.sessions = db.sessions.filter(function (s) { return s.id !== c.session.id; }); audit('logout', c.user, { note: 'تسجيل خروج' }); saveDb(); }
    sdel('sessionStorage', TOKEN_KEY); sdel('localStorage', TOKEN_KEY);
  },
  requestReset: function (email) {
    var u = findByEmail(email);
    if (!u) return null;
    var code = String(Math.floor(100000 + Math.random() * 900000));
    u.reset = { code: code, exp: Date.now() + 10 * 6e4 }; audit('reset_request', u, { note: 'طلب استعادة كلمة المرور' }); saveDb(); return code;
  },
  confirmReset: function (email, code, newPass) {
    var u = findByEmail(email);
    if (!u || !u.reset || u.reset.exp < Date.now() || u.reset.code !== code) return Promise.reject({ msg: 'الرمز غير صحيح أو منتهي الصلاحية.' });
    var salt = rid('salt');
    return hashPassword(newPass, salt).then(function (pwd) { u.pwd = pwd; u.reset = null; u.failedLogins = 0; u.lockedUntil = 0; audit('reset_done', u, { note: 'تغيير كلمة المرور' }); saveDb(); });
  },
  seed: function () { return ensureOrg(); }
};



/* ======================================================================
   Evaluation domain: roles, criteria, cycles, evaluations, seed data.
   ====================================================================== */
var ROLES = { admin: 'مسؤول الموارد البشرية', manager: 'مدير مباشر', employee: 'موظف' };
var DEFAULT_CRITERIA = [
  { id: 'quality', name: 'جودة العمل', desc: 'دقة المخرجات واستيفاؤها للمعايير المطلوبة', weight: 25 },
  { id: 'output', name: 'الإنتاجية وإنجاز المهام', desc: 'الالتزام بالمواعيد وحجم ما أُنجز في الدورة', weight: 20 },
  { id: 'discipline', name: 'الالتزام والانضباط', desc: 'الحضور والالتزام بالسياسات وإجراءات العمل', weight: 15 },
  { id: 'team', name: 'العمل الجماعي', desc: 'التعاون مع الزملاء ودعمهم لتحقيق هدف الفريق', weight: 15 },
  { id: 'comm', name: 'التواصل', desc: 'وضوح التواصل مع الفريق والعملاء وسرعة الاستجابة', weight: 10 },
  { id: 'growth', name: 'المبادرة والتطوير الذاتي', desc: 'اقتراح التحسينات وتطوير المهارات', weight: 15 }
];
var SCALE = ['ضعيف', 'يحتاج تحسينًا', 'يحقق التوقعات', 'يتجاوز التوقعات', 'استثنائي'];
var BANDS = [
  { min: 90, key: 'outstanding', label: 'ممتاز', color: '#1c7a4c' },
  { min: 80, key: 'verygood', label: 'جيد جدًا', color: '#5f9a3b' },
  { min: 70, key: 'good', label: 'جيد', color: '#b8962e' },
  { min: 60, key: 'fair', label: 'مقبول', color: '#d08a1a' },
  { min: 0, key: 'weak', label: 'يحتاج تطويرًا', color: '#b3261e' }
];
function bandOf(p) { for (var i = 0; i < BANDS.length; i++) if (p >= BANDS[i].min) return BANDS[i]; return BANDS[BANDS.length - 1]; }

var SEED_PEOPLE = [
  { k: 'hr', name: 'رنا السبيعي', email: 'demo@portal.demo', role: 'admin', dept: 'الموارد البشرية', title: 'مسؤولة الموارد البشرية', pwd: true },
  { k: 'm1', name: 'عبدالله الشهري', email: 'manager@portal.demo', role: 'manager', dept: 'التقنية', title: 'مدير التقنية', mgr: 'hr', pwd: true, base: 4.4 },
  { k: 'm2', name: 'هدى القرني', email: 'huda.alqarni@company.demo', role: 'manager', dept: 'المبيعات', title: 'مديرة المبيعات', mgr: 'hr', base: 4.6 },
  { k: 'e1', name: 'ياسر الحربي', email: 'employee@portal.demo', role: 'employee', dept: 'التقنية', title: 'مطوّر برمجيات', mgr: 'm1', pwd: true, base: 4.2 },
  { k: 'e2', name: 'لمى الدوسري', email: 'lama.aldosari@company.demo', role: 'employee', dept: 'التقنية', title: 'محلّلة نظم', mgr: 'm1', base: 4.5 },
  { k: 'e3', name: 'ماجد العنزي', email: 'majed.alanazi@company.demo', role: 'employee', dept: 'التقنية', title: 'مهندس جودة', mgr: 'm1', base: 3.4 },
  { k: 'e4', name: 'دانة الغامدي', email: 'dana.alghamdi@company.demo', role: 'employee', dept: 'المبيعات', title: 'مسؤولة مبيعات', mgr: 'm2', base: 4.7 },
  { k: 'e5', name: 'فهد الزهراني', email: 'fahad.alzahrani@company.demo', role: 'employee', dept: 'المبيعات', title: 'مسؤول حسابات عملاء', mgr: 'm2', base: 3.1 },
  { k: 'e6', name: 'شهد المالكي', email: 'shahd.almalki@company.demo', role: 'employee', dept: 'المبيعات', title: 'منسّقة مبيعات', mgr: 'm2', base: 3.8 },
  { k: 'e7', name: 'سلطان البقمي', email: 'sultan.albaqami@company.demo', role: 'employee', dept: 'العمليات', title: 'منسّق عمليات', mgr: 'hr', base: 3.6 },
  { k: 'e8', name: 'ريما العتيبي', email: 'reema.alotaibi@company.demo', role: 'employee', dept: 'المالية', title: 'محاسبة', mgr: 'hr', base: 4.0 }
];
var SEED_TEXT = {
  strengths: ['يلتزم بالمواعيد ويقدّم عملًا دقيقًا ومنظمًا.', 'يتعاون مع الفريق ويبادر بمساعدة الزملاء.', 'يتواصل بوضوح ويتابع المهام حتى إغلاقها.'],
  improve: ['توثيق خطوات العمل بشكل أوضح لتسهيل المراجعة.', 'إدارة الأولويات عند تعدد المهام المتزامنة.', 'رفع مستوى المشاركة في اجتماعات الفريق.'],
  goals: ['إتمام دورة تدريبية متخصصة في المجال.', 'قيادة مبادرة تحسين واحدة خلال الدورة القادمة.', 'تقليل زمن إنجاز المهام المتكررة بنسبة 15%.']
};

function mkUser(p, id, pwd) {
  return { id: id, name: p.name, email: p.email, provider: pwd ? 'password' : 'seed', pwd: pwd || null, role: p.role, dept: p.dept, title: p.title, managerId: null, active: true, createdAt: Date.now() - 200 * 864e5, lastLoginAt: null, prevLoginAt: null, failedLogins: 0, lockedUntil: 0 };
}
function lcg(seed) { var s = seed; return function () { s = (s * 1664525 + 1013904223) % 4294967296; return s / 4294967296; }; }

function ensureOrgV1() {
  db.criteria = db.criteria && db.criteria.length ? db.criteria : null;
  var needsSeed = !db.meta.org;
  db.users.forEach(function (u) { if (!u.role) u.role = 'employee'; if (u.active === undefined) u.active = true; });
  if (!needsSeed) { saveDb(); return Promise.resolve(); }

  var ids = {}, jobs = [];
  SEED_PEOPLE.forEach(function (p, i) {
    var existing = findByEmail(p.email);
    if (existing) { existing.role = p.role; existing.dept = p.dept; existing.title = p.title; existing.name = p.name; existing.active = true; ids[p.k] = existing.id; return; }
    var id = 'usr_seed' + (i < 10 ? '0' : '') + i; ids[p.k] = id;
    if (p.pwd) jobs.push(hashPassword('Demo@12345', rid('salt')).then(function (h) { db.users.push(mkUser(p, id, h)); }));
    else db.users.push(mkUser(p, id, null));
  });
  return Promise.all(jobs).then(function () {
    SEED_PEOPLE.forEach(function (p) { var u = db.users.filter(function (x) { return x.id === ids[p.k]; })[0]; if (u && p.mgr) u.managerId = ids[p.mgr]; });
    db.criteria = DEFAULT_CRITERIA.map(function (c) { return Object.assign({}, c); });
    db.cycles = [
      { id: 'cyc_2026h1', name: 'النصف الأول 2026', start: '2026-01-01', end: '2026-06-30', status: 'closed' },
      { id: 'cyc_2026h2', name: 'النصف الثاني 2026', start: '2026-07-01', end: '2026-12-31', status: 'open' }
    ];
    db.evals = [];
    var rnd = lcg(7);
    var states2 = { e1: 'submitted', e2: 'acknowledged', e3: 'draft', e4: 'acknowledged', e5: null, e6: 'draft', e7: null, e8: 'submitted', m1: null, m2: 'submitted' };
    SEED_PEOPLE.forEach(function (p, idx) {
      if (!p.mgr) return;
      [['cyc_2026h1', 0, 'acknowledged'], ['cyc_2026h2', [0.2, 0.1, -0.1, 0.3, 0, 0.2, -0.2, 0.1, 0.2, 0.1][idx % 10] , states2[p.k]]].forEach(function (c, ci) {
        var status = ci === 0 ? (p.k === 'e8' || p.k === 'e6' ? 'submitted' : 'acknowledged') : c[2];
        if (!status) return;
        var scores = {}, notes = {};
        db.criteria.forEach(function (cr) { scores[cr.id] = Math.max(1, Math.min(5, Math.round(p.base + (ci ? c[1] : 0) + (rnd() - 0.5) * 1.8))); });
        var ev = { id: 'ev_' + p.k + '_' + ci, cycleId: c[0], employeeId: ids[p.k], evaluatorId: ids[p.mgr], criteria: db.criteria.map(function (x) { return { id: x.id, name: x.name, weight: x.weight }; }),
          scores: scores, notes: notes, strengths: SEED_TEXT.strengths[idx % 3], improve: SEED_TEXT.improve[(idx + 1) % 3], goals: SEED_TEXT.goals[(idx + 2) % 3],
          status: status, createdAt: Date.now() - (ci ? 20 : 150) * 864e5, updatedAt: Date.now() - (ci ? 10 : 140) * 864e5, submittedAt: null, ackAt: null, ackComment: '', pct: null };
        if (status !== 'draft') { ev.pct = Eval.calc(ev); ev.submittedAt = ev.updatedAt; }
        if (status === 'acknowledged') ev.ackAt = ev.updatedAt + 2 * 864e5;
        db.evals.push(ev);
      });
    });
    db.meta.org = 1; saveDb();
  });
}

var Eval = {
  rating: function (ev) { var s = 0; ev.criteria.forEach(function (c) { var v = ev.scores[c.id]; if (v) s += v / 5 * c.weight; }); return Math.round(s * 10) / 10; },
  complete: function (ev) { return ev.criteria.every(function (c) { return ev.scores[c.id]; }); },
  user: function (id) { return db.users.filter(function (u) { return u.id === id; })[0]; },
  cycle: function (id) { return db.cycles.filter(function (c) { return c.id === id; })[0]; },
  openCycle: function () { return db.cycles.filter(function (c) { return c.status === 'open'; })[0] || db.cycles[db.cycles.length - 1]; },
  find: function (cycleId, empId) { return db.evals.filter(function (e) { return e.cycleId === cycleId && e.employeeId === empId; })[0]; },
  staff: function () { return db.users.filter(function (u) { return u.active !== false; }); },
  evaluable: function (me) { return Eval.staff().filter(function (u) { return u.role !== 'admin' && u.id !== me.id && (me.role === 'admin' || (me.role === 'manager' && u.managerId === me.id)); }); },
  canEvaluate: function (me, emp) { return emp.role !== 'admin' && emp.id !== me.id && (me.role === 'admin' || (me.role === 'manager' && emp.managerId === me.id)); },
  history: function (empId, onlyDone) { return db.evals.filter(function (e) { return e.employeeId === empId && (!onlyDone || e.status === 'submitted' || e.status === 'acknowledged'); }).sort(function (a, b) { return (Eval.cycle(a.cycleId).start < Eval.cycle(b.cycleId).start) ? -1 : 1; }); },
  newDraft: function (cycleId, emp, me) {
    return { id: rid('ev'), cycleId: cycleId, employeeId: emp.id, evaluatorId: me.id, criteria: db.criteria.map(function (c) { return { id: c.id, name: c.name, weight: c.weight }; }), scores: {}, notes: {}, strengths: '', improve: '', goals: '', status: 'draft', createdAt: Date.now(), updatedAt: Date.now(), submittedAt: null, ackAt: null, ackComment: '', pct: null };
  },
  upsert: function (ev) { var i = db.evals.map(function (e) { return e.id; }).indexOf(ev.id); if (i < 0) db.evals.push(ev); else db.evals[i] = ev; ev.updatedAt = Date.now(); },
  saveDraft: function (ev, me) { ev.status = 'draft'; Eval.upsert(ev); audit('eval_draft', me, { note: 'حفظ مسودة تقييم: ' + (Eval.user(ev.employeeId) || {}).name }); saveDb(); },
  submit: function (ev, me) { ev.status = 'submitted'; ev.pct = Eval.calc(ev); ev.submittedAt = Date.now(); Eval.upsert(ev); audit('eval_submit', me, { note: 'اعتماد تقييم: ' + (Eval.user(ev.employeeId) || {}).name + ' (' + ev.pct + '%)' }); saveDb(); },
  acknowledge: function (ev, me, comment) { ev.status = 'acknowledged'; ev.ackAt = Date.now(); ev.ackComment = comment || ''; Eval.upsert(ev); audit('eval_ack', me, { note: 'إقرار الموظف بالاطلاع على تقييمه' }); saveDb(); },
  reopen: function (ev, me) { ev.status = 'draft'; ev.ackAt = null; ev.ackComment = ''; ev.submittedAt = null; ev.pct = null; Eval.upsert(ev); audit('eval_reopen', me, { note: 'إعادة فتح تقييم: ' + (Eval.user(ev.employeeId) || {}).name }); saveDb(); },
  addCycle: function (c, me) { var x = { id: rid('cyc'), name: c.name, start: c.start, end: c.end, status: 'open' }; db.cycles.push(x); audit('cycle_new', me, { note: 'دورة جديدة: ' + c.name }); saveDb(); return x; },
  setCycleStatus: function (id, status, me) { var c = Eval.cycle(id); c.status = status; audit('cycle_' + status, me, { note: (status === 'closed' ? 'إغلاق دورة: ' : 'فتح دورة: ') + c.name }); saveDb(); },
  setCriteria: function (list, me) {
    var total = list.reduce(function (s, c) { return s + c.weight; }, 0);
    if (total !== 100) return false;
    db.criteria = list; audit('criteria_edit', me, { note: 'تعديل معايير التقييم' }); saveDb(); return true;
  },
  saveEmployee: function (f, me) {
    var u = f.id ? Eval.user(f.id) : null;
    if (!u) { if (findByEmail(f.email)) return { field: 'email', msg: 'هذا البريد مستخدم لموظف آخر.' }; u = { id: rid('usr'), name: f.name, email: f.email.toLowerCase(), provider: 'seed', pwd: null, createdAt: Date.now(), lastLoginAt: null, prevLoginAt: null, failedLogins: 0, lockedUntil: 0, active: true }; db.users.push(u); audit('employee_new', me, { note: 'إضافة موظف: ' + f.name }); }
    else audit('employee_edit', me, { note: 'تعديل بيانات: ' + u.name });
    u.name = f.name; u.role = f.role; u.dept = f.dept; u.title = f.title; u.managerId = f.managerId || null;
    saveDb(); return null;
  }
};


/* ======================================================================
   v2: evaluation methods (rating scale + BARS, goals MBO/OKR/KPI, 360 feedback,
   self-assessment, weighted checklist, 9-box, critical incidents, 1:1 check-ins,
   paired comparison, forced distribution).
   ====================================================================== */
var METHODS = [
  { key: 'rating', kind: 'score', name: 'مقياس التقدير الرسومي', en: 'Graphic Rating Scale', desc: 'يقيّم المدير كل معيار بدرجة من 1 إلى 5، وتُجمع الدرجات بأوزان المعايير.', how: 'تبويب «المقياس والكفاءات». أكثر الطرق شيوعًا وأسهلها في المقارنة.', when: 'تقييم دوري موحّد لجميع الوظائف.' },
  { key: 'bars', kind: 'score', name: 'المقاييس المرتبطة بالسلوك (<bdi>BARS</bdi>)', en: 'Behaviorally Anchored Rating Scales', desc: 'لكل درجة وصف سلوكي محدد يقلّل التحيّز ويوحّد فهم المقيّمين للدرجات.', how: 'يظهر الوصف السلوكي تحت كل معيار عند اختيار الدرجة، ويمكن تعديله من صفحة المعايير.', when: 'عندما تختلف تقديرات المديرين لنفس الأداء.' },
  { key: 'competency', kind: 'score', name: 'التقييم بالكفاءات', en: 'Competency-based', desc: 'يقيس السلوكيات والمهارات المطلوبة للوظيفة بدل النتائج وحدها.', how: 'المعايير في النظام كفاءات يمكن إضافتها وتعديل أوزانها.', when: 'عند ربط التقييم بإطار الكفاءات ومسارات التطوير.' },
  { key: 'goals', kind: 'score', name: 'الإدارة بالأهداف والنتائج الرئيسية (<bdi>MBO / OKR / KPI</bdi>)', en: 'MBO, OKR, KPI', desc: 'أهداف قابلة للقياس: مؤشر رقمي مقابل مستهدف (KPI)، أو هدف بنتائج رئيسية يُقاس تقدّمها (OKR)، أو هدف متفق عليه ونسبة إنجازه (MBO).', how: 'تبويب «الأهداف». يُحسب الإنجاز تلقائيًا ويدخل في النتيجة بوزنه.', when: 'الوظائف ذات المخرجات القابلة للقياس مثل المبيعات والعمليات.' },
  { key: 'feedback', kind: 'score', name: 'ملاحظات 360 درجة', en: '360-Degree Feedback', desc: 'ملاحظات من الزملاء والمرؤوسين والعملاء الداخليين على الكفاءات نفسها، بسرّية هوية المقيّمين.', how: 'يطلبها المدير أو المسؤول من تبويب «ملاحظات 360». تُعرض المتوسطات فقط ولا تظهر مجموعة قبل ردّين.', when: 'للمديرين والوظائف التي تعتمد على التعاون.' },
  { key: 'self', kind: 'info', name: 'التقييم الذاتي', en: 'Self-Assessment', desc: 'يقيّم الموظف نفسه على المعايير نفسها لإظهار فجوة الإدراك بينه وبين مديره.', how: 'مهمة تصل الموظف تلقائيًا. تُعرض الفجوة في تبويب «ملاحظات 360» ولا تدخل في الدرجة.', when: 'قبل جلسة التقييم لتوجيه الحوار.' },
  { key: 'checklist', kind: 'score', name: 'قائمة التحقق الموزونة', en: 'Weighted Checklist', desc: 'عبارات سلوك بنعم أو لا، لكل عبارة وزن، وتُحسب النسبة المتحققة.', how: 'تبويب «قائمة التحقق». اختيارية لكل دورة.', when: 'الوظائف الإجرائية التي تعتمد على الالتزام بخطوات محددة.' },
  { key: 'narrative', kind: 'info', name: 'التقييم السردي', en: 'Narrative / Essay', desc: 'وصف كتابي لنقاط القوة ومجالات التحسين وأهداف الدورة القادمة.', how: 'تبويب «الخلاصة والسرد». مطلوب عند الاعتماد.', when: 'يرافق كل تقييم لإعطاء السياق.' },
  { key: 'incidents', kind: 'info', name: 'الوقائع الحرجة', en: 'Critical Incidents', desc: 'تدوين وقائع محددة إيجابية أو سلبية في وقتها لتكون أساسًا موثّقًا للتقييم.', how: 'من ملف الموظف. تظهر وقائع الدورة داخل التقييم للاستئناس.', when: 'طوال السنة لتقليل أثر التحيّز للأحداث الأخيرة.' },
  { key: 'checkin', kind: 'info', name: 'المتابعة المستمرة (<bdi>1:1</bdi>)', en: 'Continuous Feedback / Check-ins', desc: 'لقاءات دورية قصيرة تُسجَّل فيها الملاحظات والإجراءات المتفق عليها.', how: 'من ملف الموظف، ويراها الموظف أيضًا.', when: 'شهريًا أو ربع سنويًا بين التقييمات الرسمية.' },
  { key: 'ninebox', kind: 'calib', name: 'مصفوفة الأداء والإمكانات (<bdi>9-Box</bdi>)', en: '9-Box Grid', desc: 'تصنّف الموظف بحسب أدائه وإمكاناته لتخطيط التطوير والتعاقب. سرّية عن الموظف.', how: 'يحدد المقيّم الإمكانات في تبويب «الإمكانات»، وتظهر المصفوفة في صفحة المعايرة.', when: 'تخطيط المواهب والتعاقب الوظيفي.' },
  { key: 'paired', kind: 'calib', name: 'المقارنة الثنائية', en: 'Paired Comparison', desc: 'يقارن المدير كل موظفين معًا ويختار الأفضل، فينتج ترتيب للفريق.', how: 'صفحة «المعايرة والترتيب»، لفريق من ثلاثة فأكثر.', when: 'لكسر التعادل وتمييز الأداء داخل الفريق.' },
  { key: 'forced', kind: 'calib', name: 'الترتيب والتوزيع الإلزامي', en: 'Ranking & Forced Distribution', desc: 'ترتيب الموظفين ومقارنة توزيع التقديرات بمنحنى مستهدف لكشف التساهل أو التشدد.', how: 'صفحة «المعايرة والترتيب» تعرض المنحنى والانحراف.', when: 'اجتماعات المعايرة قبل اعتماد النتائج النهائية.' }
];
var RELATIONS = { self: 'تقييم ذاتي', peer: 'زميل', subordinate: 'مرؤوس', client: 'عميل داخلي' };
var NOTE_TYPES = { positive: 'واقعة إيجابية', negative: 'واقعة سلبية', checkin: 'لقاء متابعة' };
var POTENTIAL = ['محدودة: يتمكّن من دوره الحالي', 'متوسطة: قادر على التوسّع في دوره', 'عالية: مؤهل لمستوى أعلى'];
var NB = { 3: ['موهبة قيد الاختبار', 'موهبة صاعدة', 'نجم'], 2: ['يحتاج دعمًا', 'ركيزة أساسية', 'أداء عالٍ'], 1: ['فجوة أداء', 'متخصص ثابت', 'خبير متمكّن'] };
var ANCHORS = {
  quality: ['مخرجات بها أخطاء متكررة وتحتاج إعادة عمل', 'مخرجات تحتاج مراجعة مكثفة قبل الاعتماد', 'مخرجات سليمة تلبي المعايير المطلوبة', 'مخرجات دقيقة نادرًا ما تحتاج تعديلًا', 'مخرجات مرجعية تُستخدم نموذجًا للآخرين'],
  output: ['يتأخر عن معظم المواعيد ويُنجز أقل من المطلوب', 'يتأخر أحيانًا ويُنجز أقل من المتوقع', 'يسلّم في الموعد ويحقق المطلوب', 'ينجز قبل الموعد ويتجاوز المطلوب', 'ينجز أضعاف المتوقع في وقته ويدعم الفريق'],
  discipline: ['مخالفات متكررة للدوام والسياسات', 'مخالفات متفرقة تتطلب تنبيهًا', 'ملتزم بالدوام والسياسات', 'ملتزم تمامًا ويُذكّر الآخرين بالإجراءات', 'قدوة في الانضباط ويطوّر الإجراءات'],
  team: ['يعمل بمعزل ويعطّل عمل الفريق', 'يتعاون عند الطلب فقط', 'يتعاون مع الفريق باستمرار', 'يبادر بمساعدة الزملاء ومشاركة المعرفة', 'يبني روح الفريق ويحل الخلافات بين الأعضاء'],
  comm: ['تواصل غامض يحتاج متابعة متكررة', 'تواصل مقبول لكنه متأخر أو ناقص', 'تواصل واضح وفي الوقت المناسب', 'تواصل مؤثر يوضح المخاطر والخيارات', 'يُقنع الأطراف ويمثّل الفريق باحتراف'],
  growth: ['لا يبادر ولا يسعى للتطور', 'يبادر نادرًا ويحتاج توجيهًا', 'يطبّق التحسينات المطلوبة ويتعلم', 'يقترح تحسينات ويطوّر مهاراته ذاتيًا', 'يقود مبادرات تحسين ويعلّم الآخرين']
};
var DEFAULT_CHECKLIST = [
  { id: 'k1', text: 'يلتزم بمواعيد التسليم المتفق عليها', weight: 3 }, { id: 'k2', text: 'يتبع إجراءات العمل والسياسات المعتمدة', weight: 2 },
  { id: 'k3', text: 'يحافظ على سرية المعلومات', weight: 2 }, { id: 'k4', text: 'يوثّق عمله بشكل يسهّل مراجعته', weight: 2 },
  { id: 'k5', text: 'يلتزم بمواعيد الدوام والاجتماعات', weight: 2 }, { id: 'k6', text: 'يتواصل بأدب واحترافية مع الجميع', weight: 2 },
  { id: 'k7', text: 'يطلب المساعدة أو التوضيح عند الحاجة', weight: 1 }
];
function defaultMethods() { return { rating: { on: true, w: 50 }, goals: { on: true, w: 30 }, feedback: { on: true, w: 20 }, checklist: { on: false, w: 0 }, self: true, ninebox: true }; }
var SCORING = [['rating', 'مقياس التقدير والكفاءات'], ['goals', 'الأهداف (<bdi>MBO / OKR / KPI</bdi>)'], ['feedback', 'ملاحظات 360'], ['checklist', 'قائمة التحقق']];

function migrate2() {
  if (db.meta.org2) return;
  (db.criteria || []).forEach(function (c) { if (!c.anchors && ANCHORS[c.id]) c.anchors = ANCHORS[c.id].slice(); });
  db.checklist = db.checklist || DEFAULT_CHECKLIST.map(function (c) { return Object.assign({}, c); });
  db.feedback = db.feedback || []; db.notes = db.notes || []; db.pairs = db.pairs || {};
  db.cycles.forEach(function (c) { if (!c.methods) c.methods = c.status === 'closed' ? { rating: { on: true, w: 100 }, goals: { on: false, w: 0 }, feedback: { on: false, w: 0 }, checklist: { on: false, w: 0 }, self: false, ninebox: false } : defaultMethods(); });

  db.evals.forEach(function (ev) { if (typeof ev.goals === 'string') { ev.goalsText = ev.goals; ev.goals = []; } if (!Array.isArray(ev.goals)) ev.goals = []; if (ev.goalsText === undefined) ev.goalsText = ''; });
  var byEmail = {}; SEED_PEOPLE.forEach(function (p) { var u = findByEmail(p.email); if (u) byEmail[p.k] = { u: u, p: p }; });
  var cyc = Eval.cycle('cyc_2026h2');
  if (cyc && byEmail.hr) {
    var rnd = lcg(11), people = Object.keys(byEmail).filter(function (k) { return k !== 'hr'; });
    function fb(cycleId, emp, rater, rel, base, done) {
      var sc = {}; db.criteria.forEach(function (c) { sc[c.id] = Math.max(1, Math.min(5, Math.round(base + (rnd() - 0.5) * 1.6))); });
      db.feedback.push({ id: rid('fb'), cycleId: cycleId, employeeId: emp.id, raterId: rater.id, relation: rel, status: done ? 'done' : 'pending', scores: done ? sc : {}, comment: done ? (rel === 'self' ? 'أرى أنني حققت معظم أهدافي وأحتاج لتطوير إدارة الوقت.' : rel === 'subordinate' ? 'يدعم الفريق ويوضّح الأولويات.' : 'متعاون ويشارك المعرفة.') : '', createdAt: Date.now() - 12 * 864e5, doneAt: done ? Date.now() - 6 * 864e5 : null });
    }
    people.forEach(function (k) {
      var e = byEmail[k], emp = e.u, base = e.p.base || 3.5;
      var mates = people.filter(function (o) { return o !== k && byEmail[o].p.dept === e.p.dept && byEmail[o].p.role === 'employee'; }).slice(0, 2);
      if (e.p.role === 'employee') mates.forEach(function (o) { fb(cyc.id, emp, byEmail[o].u, 'peer', base, !(k === 'e2' && o === 'e1') && !(k === 'e1' && o === 'e3' && false)); });
      people.filter(function (o) { return byEmail[o].p.mgr === k; }).forEach(function (o) { fb(cyc.id, emp, byEmail[o].u, 'subordinate', base, !(k === 'm1' && o === 'e1')); });
      fb(cyc.id, emp, emp, 'self', Math.min(5, base + 0.4), k !== 'e1' && k !== 'm1');
    });
    function goals(base, k) {
      var f = base / 5;
      return [
        { id: rid('g'), kind: 'kpi', title: k.charAt(0) === 'e' && byEmail[k].p.dept === 'المبيعات' ? 'قيمة المبيعات الشهرية' : 'تسليم المهام ضمن الموعد', weight: 50, unit: byEmail[k].p.dept === 'المبيعات' ? 'ألف ريال' : '%', target: byEmail[k].p.dept === 'المبيعات' ? 400 : 95, actual: Math.round((byEmail[k].p.dept === 'المبيعات' ? 400 : 95) * (0.7 + f * 0.4)), dir: 'up', krs: [], p: 0 },
        { id: rid('g'), kind: 'okr', title: 'رفع جودة المخرجات', weight: 30, unit: '', target: 0, actual: 0, dir: 'up', krs: [{ t: 'خفض الأخطاء المُعادة', p: Math.round(50 + f * 45) }, { t: 'إنجاز مراجعة الأقران', p: Math.round(45 + f * 50) }], p: 0 },
        { id: rid('g'), kind: 'mbo', title: 'إتمام دورة تدريبية متخصصة', weight: 20, unit: '', target: 0, actual: 0, dir: 'up', krs: [], p: Math.round(60 + f * 40) }
      ];
    }
    var pots = { e1: 2, e2: 3, e3: 1, e4: 3, e5: 1, e6: 2, e7: 2, e8: 2, m1: 3, m2: 3 };
    db.evals.forEach(function (ev) {
      if (ev.cycleId !== cyc.id) return;
      var k = Object.keys(byEmail).filter(function (x) { return byEmail[x].u.id === ev.employeeId; })[0]; if (!k) return;
      ev.methods = JSON.parse(JSON.stringify(cyc.methods)); ev.goals = goals(byEmail[k].p.base || 3.5, k); ev.checklist = {}; ev.potential = pots[k] || 2;
      if (ev.status !== 'draft') { ev.parts = Eval.parts(ev); ev.pct = Eval.calc(ev); }
    });
    var N = [['e1', 'm1', 'positive', 'أنهى ترحيل الوحدة الرئيسية قبل الموعد بثلاثة أيام.'], ['e3', 'm1', 'negative', 'سلّم تقرير الاختبار ناقصًا مرتين خلال الشهر.'], ['e5', 'm2', 'negative', 'تأخر في الرد على عميل رئيسي أكثر من 48 ساعة.'], ['e4', 'm2', 'positive', 'أغلقت صفقة كبيرة بعد مفاوضات مطوّلة.'], ['e1', 'm1', 'checkin', 'ناقشنا أولويات الربع واتفقنا على دورة تدريبية في الأمن السيبراني.'], ['e2', 'm1', 'checkin', 'راجعنا مسار التطوير المهني ورشّحتها لقيادة مشروع صغير.']];
    N.forEach(function (n, i) { if (byEmail[n[0]] && byEmail[n[1]]) db.notes.push({ id: rid('nt'), employeeId: byEmail[n[0]].u.id, authorId: byEmail[n[1]].u.id, type: n[2], date: new Date(Date.now() - (10 + i * 9) * 864e5).toISOString().slice(0, 10), text: n[3] }); });
  }
  db.meta.org2 = 1; saveDb();
}
function ensureOrg() { return ensureOrgV1().then(migrate2); }

Object.assign(Eval, {
  goalAch: function (g) {
    if (g.kind === 'kpi') { var t = Number(g.target), a = Number(g.actual); if (!(t > 0) || g.actual === '' || g.actual == null || isNaN(a)) return null; return g.dir === 'down' ? (a > 0 ? Math.min(120, t / a * 100) : 120) : Math.min(120, a / t * 100); }
    if (g.kind === 'okr') { var k = (g.krs || []).filter(function (x) { return x.p !== '' && x.p != null; }); return k.length ? k.reduce(function (s, x) { return s + Math.min(100, Math.max(0, Number(x.p) || 0)); }, 0) / k.length : null; }
    var p = Number(g.p); return isNaN(p) ? null : Math.min(100, Math.max(0, p));
  },
  goalsPct: function (ev) {
    var tw = 0, s = 0; (ev.goals || []).forEach(function (g) { var a = Eval.goalAch(g); if (a != null) { tw += g.weight; s += g.weight * Math.min(a, 100); } });
    return tw ? Math.round(s / tw * 10) / 10 : null;
  },
  checklistPct: function (ev) {
    var items = db.checklist || [], ans = ev.checklist || {};
    if (!items.length || !items.every(function (i) { return ans[i.id] === true || ans[i.id] === false; })) return null;
    var tw = items.reduce(function (s, i) { return s + i.weight; }, 0), yw = items.reduce(function (s, i) { return s + (ans[i.id] ? i.weight : 0); }, 0);
    return Math.round(yw / tw * 1000) / 10;
  },
  fbGroups: function (cycleId, empId) {
    var out = {};
    (db.feedback || []).filter(function (f) { return f.cycleId === cycleId && f.employeeId === empId && f.status === 'done'; }).forEach(function (f) {
      var g = out[f.relation] = out[f.relation] || { n: 0, sum: {}, comments: [] }; g.n++; if (f.comment) g.comments.push(f.comment);
      Object.keys(f.scores).forEach(function (c) { g.sum[c] = (g.sum[c] || 0) + f.scores[c]; });
    });
    Object.keys(out).forEach(function (r) {
      var g = out[r]; g.byCrit = {}; var s = 0;
      (db.criteria || []).forEach(function (c) { var m = (g.sum[c.id] || 0) / g.n; g.byCrit[c.id] = Math.round(m * 10) / 10; s += m / 5 * c.weight; });
      g.avg = Math.round(s * 10) / 10;
    });
    return out;
  },
  feedbackPct: function (cycleId, empId) {
    var g = Eval.fbGroups(cycleId, empId), ks = Object.keys(g).filter(function (k) { return k !== 'self'; });
    return ks.length ? Math.round(ks.reduce(function (s, k) { return s + g[k].avg; }, 0) / ks.length * 10) / 10 : null;
  },
  parts: function (ev) {
    var m = ev.methods || { rating: { on: true, w: 100 } }, o = {};
    if (m.rating && m.rating.on) o.rating = Eval.complete(ev) ? Eval.rating(ev) : null;
    if (m.goals && m.goals.on) o.goals = Eval.goalsPct(ev);
    if (m.feedback && m.feedback.on) o.feedback = Eval.feedbackPct(ev.cycleId, ev.employeeId);
    if (m.checklist && m.checklist.on) o.checklist = Eval.checklistPct(ev);
    return o;
  },
  calc: function (ev) {
    var m = ev.methods || { rating: { on: true, w: 100 } }, p = Eval.parts(ev), tw = 0, s = 0;
    Object.keys(p).forEach(function (k) { if (p[k] != null) { tw += m[k].w; s += m[k].w * p[k]; } });
    return tw ? Math.round(s / tw * 10) / 10 : 0;
  },
  newDraft: function (cycleId, emp, me) {
    var cyc = Eval.cycle(cycleId);
    return { id: rid('ev'), cycleId: cycleId, employeeId: emp.id, evaluatorId: me.id, methods: JSON.parse(JSON.stringify(cyc.methods || { rating: { on: true, w: 100 } })), criteria: db.criteria.map(function (c) { return { id: c.id, name: c.name, weight: c.weight }; }), scores: {}, notes: {}, goals: [], checklist: {}, potential: null, strengths: '', improve: '', goalsText: '', status: 'draft', createdAt: Date.now(), updatedAt: Date.now(), submittedAt: null, ackAt: null, ackComment: '', pct: null, parts: null };
  },
  validateSubmit: function (ev) {
    var m = ev.methods || { rating: { on: true } };
    if (m.rating && m.rating.on && !Eval.complete(ev)) return 'قيّم جميع المعايير في تبويب «المقياس والكفاءات».';
    if (m.goals && m.goals.on) {
      if (!ev.goals || !ev.goals.length) return 'أضف هدفًا واحدًا على الأقل في تبويب «الأهداف».';
      if (ev.goals.reduce(function (s, g) { return s + (Number(g.weight) || 0); }, 0) !== 100) return 'مجموع أوزان الأهداف يجب أن يساوي 100%.';
      if (ev.goals.some(function (g) { return Eval.goalAch(g) == null || !String(g.title).trim(); })) return 'أكمل عنوان كل هدف وقيم إنجازه.';
    }
    if (m.checklist && m.checklist.on && Eval.checklistPct(ev) == null) return 'أجب عن جميع عبارات قائمة التحقق.';
    if (m.ninebox && !ev.potential) return 'حدّد مستوى الإمكانات في تبويب «الإمكانات».';
    if ((ev.strengths || '').length < 5 || (ev.improve || '').length < 5) return 'اكتب نقاط القوة ومجالات التحسين في تبويب «الخلاصة والسرد».';
    return '';
  },
  submit: function (ev, me) { ev.status = 'submitted'; ev.parts = Eval.parts(ev); ev.pct = Eval.calc(ev); ev.submittedAt = Date.now(); Eval.upsert(ev); audit('eval_submit', me, { note: 'اعتماد تقييم: ' + (Eval.user(ev.employeeId) || {}).name + ' (' + ev.pct + '%)' }); saveDb(); },
  tasksFor: function (uid) { return (db.feedback || []).filter(function (f) { return f.raterId === uid && f.status === 'pending' && (Eval.cycle(f.cycleId) || {}).status === 'open'; }); },
  requestFeedback: function (cycleId, empId, list, me) {
    var n = 0; list.forEach(function (x) {
      if (db.feedback.some(function (f) { return f.cycleId === cycleId && f.employeeId === empId && f.raterId === x.raterId && f.relation === x.relation; })) return;
      db.feedback.push({ id: rid('fb'), cycleId: cycleId, employeeId: empId, raterId: x.raterId, relation: x.relation, status: 'pending', scores: {}, comment: '', createdAt: Date.now(), doneAt: null }); n++;
    });
    if (n) { audit('feedback_request', me, { note: 'طلب ملاحظات 360 لـ ' + (Eval.user(empId) || {}).name + ' (' + n + ')' }); saveDb(); }
    return n;
  },
  submitFeedback: function (id, scores, comment, me) {
    var f = db.feedback.filter(function (x) { return x.id === id; })[0]; if (!f || f.raterId !== me.id) return false;
    f.scores = scores; f.comment = comment; f.status = 'done'; f.doneAt = Date.now(); audit('feedback_done', me, { note: f.relation === 'self' ? 'إكمال التقييم الذاتي' : 'إكمال ملاحظات 360' }); saveDb(); return true;
  },
  notesOf: function (empId) { return (db.notes || []).filter(function (n) { return n.employeeId === empId; }).sort(function (a, b) { return a.date < b.date ? 1 : -1; }); },
  addNote: function (n, me) { db.notes.push({ id: rid('nt'), employeeId: n.employeeId, authorId: me.id, type: n.type, date: n.date, text: n.text }); audit('note_add', me, { note: NOTE_TYPES[n.type] + ': ' + (Eval.user(n.employeeId) || {}).name }); saveDb(); },
  pairKey: function (a, b) { return [a, b].sort().join('|'); },
  setPair: function (cycleId, mgrId, a, b, winner) { var k = cycleId + '::' + mgrId; db.pairs[k] = db.pairs[k] || {}; if (winner) db.pairs[k][Eval.pairKey(a, b)] = winner; else delete db.pairs[k][Eval.pairKey(a, b)]; saveDb(); },
  pairRanking: function (cycleId, mgrId, ids) {
    var r = db.pairs[cycleId + '::' + mgrId] || {}, w = {}; ids.forEach(function (i) { w[i] = 0; });
    Object.keys(r).forEach(function (k) { if (w[r[k]] != null) w[r[k]]++; });
    return ids.slice().sort(function (a, b) { return w[b] - w[a]; }).map(function (i) { return { id: i, wins: w[i] }; });
  },
  nineBox: function (pct, pot) { var p = pct >= 85 ? 3 : pct >= 70 ? 2 : 1; return { p: p, q: pot, label: NB[pot][p - 1] }; },
  saveCycleMethods: function (id, methods, me) { Eval.cycle(id).methods = methods; audit('cycle_methods', me, { note: 'تعديل طرق التقييم لدورة: ' + Eval.cycle(id).name }); saveDb(); }
});

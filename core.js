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

function ensureOrg() {
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
  calc: function (ev) { var s = 0; ev.criteria.forEach(function (c) { var v = ev.scores[c.id]; if (v) s += v / 5 * c.weight; }); return Math.round(s * 10) / 10; },
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

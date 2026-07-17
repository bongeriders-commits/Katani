/* ===================================================================
   Katani Main Stage — Auth (demo / front-end prototype)
   -------------------------------------------------------------------
   This is a CLIENT-SIDE demo of member login + role routing, built to
   show how the login gate / admin vs member flow should behave.
   It stores members in localStorage and is NOT secure — a real
   deployment must move registration, login and the "email sensor"
   (role lookup) to a proper backend with hashed passwords.
=================================================================== */
(function (window) {
  var USERS_KEY = 'kms_users';
  var SESSION_KEY = 'kms_session';

  // Emails in this list are automatically recognised as committee /
  // administrator accounts the moment they log in or register —
  // this is the "email sensor" that decides admin vs member routing.
  var ADMIN_EMAILS = [
    'admin@katanimainstage.co.ke',
    'chairman@katanimainstage.co.ke',
    'treasurer@katanimainstage.co.ke'
  ];

  function seed() {
    if (!localStorage.getItem(USERS_KEY)) {
      localStorage.setItem(USERS_KEY, JSON.stringify([]));
    }
  }

  function getUsers() {
    try { return JSON.parse(localStorage.getItem(USERS_KEY)) || []; }
    catch (e) { return []; }
  }
  function saveUsers(list) { localStorage.setItem(USERS_KEY, JSON.stringify(list)); }

  function isAdminEmail(email) {
    return ADMIN_EMAILS.indexOf(String(email).trim().toLowerCase()) !== -1;
  }

  function nextMemberId() {
    return 'KMS-' + Math.floor(100000 + Math.random() * 899999);
  }

  // ---- Registration -------------------------------------------------
  function registerMember(data) {
    var users = getUsers();
    var email = String(data.email || '').trim().toLowerCase();
    if (!email || !data.password) {
      return { success: false, message: 'Email and password are required.' };
    }
    if (users.some(function (u) { return u.email.toLowerCase() === email; })) {
      return { success: false, message: 'An account with this email already exists. Please log in instead.' };
    }
    var user = {
      name: data.name || 'New Member',
      email: email,
      password: data.password,
      role: isAdminEmail(email) ? 'admin' : 'member',
      phone: data.phone || '',
      altPhone: data.altPhone || '',
      memberId: nextMemberId(),
      memberSince: data.memberSince || new Date().toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }),
      stage: data.stage || 'Katani Main Stage',
      status: data.status || (getSettings().requireApproval ? 'pending' : 'active'),
      dob: data.dob || '',
      gender: data.gender || '',
      nationalId: data.nationalId || '',
      residence: data.address || data.residence || '',
      photo: data.photo || '',
      motorcycle: {
        plate: (data.motorcycle && data.motorcycle.plate) || data.plate || '',
        model: (data.motorcycle && data.motorcycle.model) || data.bikeModel || '',
        color: (data.motorcycle && data.motorcycle.color) || data.bikeColor || '',
        chassis: (data.motorcycle && data.motorcycle.chassis) || data.chassisNo || ''
      },
      nextOfKin: {
        name: (data.nextOfKin && data.nextOfKin.name) || data.kinName || '',
        relationship: (data.nextOfKin && data.nextOfKin.relationship) || data.kinRelation || '',
        phone: (data.nextOfKin && data.nextOfKin.phone) || data.kinPhone || ''
      }
    };
    users.push(user);
    saveUsers(users);
    setSession(user);
    return { success: true, user: user };
  }

  // ---- Admin-added member (does NOT log the admin in as the new member) ----
  function addMember(data) {
    var users = getUsers();
    var email = String(data.email || '').trim().toLowerCase();
    if (!email) {
      return { success: false, message: 'Email is required.' };
    }
    if (users.some(function (u) { return u.email.toLowerCase() === email; })) {
      return { success: false, message: 'A member with this email already exists.' };
    }
    var user = {
      name: data.name || 'New Member',
      email: email,
      password: data.password || Math.random().toString(36).slice(-8),
      role: isAdminEmail(email) ? 'admin' : 'member',
      phone: data.phone || '',
      altPhone: data.altPhone || '',
      memberId: nextMemberId(),
      memberSince: data.memberSince || new Date().toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }),
      stage: data.stage || 'Katani Main Stage',
      status: data.status || 'active',
      dob: data.dob || '',
      gender: data.gender || '',
      nationalId: data.nationalId || '',
      residence: data.residence || '',
      photo: data.photo || '',
      motorcycle: {
        plate: (data.motorcycle && data.motorcycle.plate) || '',
        model: (data.motorcycle && data.motorcycle.model) || '',
        color: (data.motorcycle && data.motorcycle.color) || '',
        chassis: (data.motorcycle && data.motorcycle.chassis) || ''
      },
      nextOfKin: {
        name: (data.nextOfKin && data.nextOfKin.name) || '',
        relationship: (data.nextOfKin && data.nextOfKin.relationship) || '',
        phone: (data.nextOfKin && data.nextOfKin.phone) || ''
      }
    };
    users.push(user);
    saveUsers(users);
    return { success: true, user: user };
  }

  // ---- Login / session -----------------------------------------------
  function login(email, password) {
    var users = getUsers();
    var email_l = String(email).trim().toLowerCase();
    var user = users.find(function (u) { return u.email.toLowerCase() === email_l; });
    if (!user) {
      return { success: false, message: 'No registered member found with this email. Please Join Now to register.' };
    }
    if (user.password !== password) {
      return { success: false, message: 'Incorrect password. Please try again.' };
    }
    // Email sensor: re-checks the admin list every login so role changes apply instantly.
    user.role = isAdminEmail(user.email) ? 'admin' : (user.role === 'admin' ? 'admin' : 'member');
    saveUsers(users);
    setSession(user);
    return { success: true, user: user };
  }

  function setSession(user) {
    localStorage.setItem(SESSION_KEY, JSON.stringify({ email: user.email, role: user.role, ts: Date.now() }));
  }

  function logout() {
    localStorage.removeItem(SESSION_KEY);
  }

  function getSession() {
    try { return JSON.parse(localStorage.getItem(SESSION_KEY)); }
    catch (e) { return null; }
  }

  function getCurrentUser() {
    var s = getSession();
    if (!s) return null;
    var users = getUsers();
    return users.find(function (u) { return u.email === s.email; }) || null;
  }

  // Redirects to the correct home page for the logged-in role.
  function routeToHome() {
    var s = getSession();
    if (!s) { window.location.href = 'index.html'; return; }
    window.location.href = s.role === 'admin' ? 'admin-dashboard.html' : 'members-portal.html';
  }

  // Guards a page: pass an array of allowed roles, e.g. ['admin'] or ['admin','member'].
  // Redirects to the login gate if there is no valid session for this page.
  function requireRole(roles) {
    var s = getSession();
    if (!s || roles.indexOf(s.role) === -1) {
      window.location.href = 'index.html';
      return null;
    }
    return getCurrentUser();
  }

  seed();

  // ---- Collections & Payments (member contributions, registration fees, fines, other income) ----
  var COLLECTIONS_KEY = 'kms_collections';

  function getCollections() {
    try { return JSON.parse(localStorage.getItem(COLLECTIONS_KEY)) || []; }
    catch (e) { return []; }
  }
  function saveCollections(list) { localStorage.setItem(COLLECTIONS_KEY, JSON.stringify(list)); }

  function nextCollectionId() {
    return 'TXN-' + Date.now().toString(36).toUpperCase().slice(-6) + Math.floor(10 + Math.random() * 89);
  }

  // type: 'contribution' | 'registration' | 'fine' | 'other'
  function addCollection(data) {
    var amount = Number(data.amount);
    if (!amount || amount <= 0) {
      return { success: false, message: 'Enter a valid amount greater than zero.' };
    }
    var type = data.type || 'other';
    if (type === 'contribution' && !data.memberId) {
      return { success: false, message: 'Select the member this contribution is from.' };
    }
    if (type !== 'contribution' && !String(data.source || '').trim()) {
      return { success: false, message: 'Enter a description for this collection.' };
    }
    var list = getCollections();
    var record = {
      id: nextCollectionId(),
      type: type,
      memberId: data.memberId || '',
      memberName: data.memberName || '',
      source: data.source || '',
      amount: amount,
      method: data.method || 'Cash',
      reference: data.reference || '',
      date: data.date || new Date().toISOString().slice(0, 10),
      note: data.note || '',
      createdAt: Date.now()
    };
    list.unshift(record);
    saveCollections(list);
    return { success: true, record: record };
  }

  // ---- Shared analytics helpers (payment status, leaderboard, trends) ----

  function ymd(d) { return d.toISOString().slice(0, 10); }
  function monthOf(dateStr) { return (dateStr || '').slice(0, 7); }

  // Best-effort parse of memberSince (stored as a locale date string like "16 Jul 2026").
  function parseMemberSince(str) {
    if (!str) return null;
    var d = new Date(str);
    return isNaN(d.getTime()) ? null : d;
  }

  // Classifies each active member as paid / pending / defaulter for the given
  // reference date's calendar month, based on 'contribution' collections:
  //   paid      - has a contribution recorded this month
  //   pending   - no contribution yet this month, but paid last month
  //               (or joined this month, so not yet due)
  //   defaulter - no contribution this month AND none last month either
  function getPaymentSummary(refDate) {
    refDate = refDate || new Date();
    var thisMonth = monthOf(ymd(refDate));
    var lastMonthDate = new Date(refDate.getFullYear(), refDate.getMonth() - 1, 1);
    var lastMonth = monthOf(ymd(lastMonthDate));

    var users = getUsers().filter(function (u) { return u.role === 'member' && (u.status || 'active') === 'active'; });
    var txns = getCollections().filter(function (t) { return t.type === 'contribution'; });

    var paidThisMonth = {}, paidLastMonth = {};
    txns.forEach(function (t) {
      var m = monthOf(t.date);
      if (m === thisMonth && t.memberId) paidThisMonth[t.memberId] = true;
      if (m === lastMonth && t.memberId) paidLastMonth[t.memberId] = true;
    });

    var paid = [], pending = [], defaulters = [];
    users.forEach(function (u) {
      var joined = parseMemberSince(u.memberSince);
      var joinedThisMonth = joined && monthOf(ymd(joined)) === thisMonth;
      if (paidThisMonth[u.memberId]) paid.push(u);
      else if (paidLastMonth[u.memberId] || joinedThisMonth) pending.push(u);
      else defaulters.push(u);
    });

    return { total: users.length, paid: paid, pending: pending, defaulters: defaulters, month: thisMonth };
  }

  // Top contributors within a given month (defaults to current month).
  function getTopCollectors(limit, monthStr) {
    limit = limit || 5;
    monthStr = monthStr || monthOf(ymd(new Date()));
    var users = getUsers();
    var byId = {};
    users.forEach(function (u) { byId[u.memberId] = u; });

    var totals = {};
    getCollections().forEach(function (t) {
      if (t.type !== 'contribution' || monthOf(t.date) !== monthStr || !t.memberId) return;
      if (!totals[t.memberId]) totals[t.memberId] = { memberId: t.memberId, memberName: t.memberName || (byId[t.memberId] && byId[t.memberId].name) || 'Member', total: 0, count: 0 };
      totals[t.memberId].total += t.amount;
      totals[t.memberId].count += 1;
    });

    var list = Object.keys(totals).map(function (k) { return totals[k]; });
    list.sort(function (a, b) { return b.total - a.total; });
    return list.slice(0, limit);
  }

  // Daily collection totals for the last `days` days ending today (inclusive).
  // Returns { labels: ['16 Jul', ...], values: [1200, 0, ...], dates: ['2026-07-01', ...] }
  function getDailyTotals(days, endDate) {
    days = days || 18;
    endDate = endDate || new Date();
    var txns = getCollections();
    var byDate = {};
    txns.forEach(function (t) { byDate[t.date] = (byDate[t.date] || 0) + t.amount; });

    var labels = [], values = [], dates = [];
    for (var i = days - 1; i >= 0; i--) {
      var d = new Date(endDate.getFullYear(), endDate.getMonth(), endDate.getDate() - i);
      var key = ymd(d);
      dates.push(key);
      values.push(byDate[key] || 0);
      labels.push(d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short' }));
    }
    return { labels: labels, values: values, dates: dates };
  }

  // ---- Group Settings (admin-editable, drives Group Overview + Payment Due + more) ----
  var SETTINGS_KEY = 'kms_settings';
  var DEFAULT_SETTINGS = {
    // Contributions & fines
    foundingYear: 2015,   // used to compute "Years of Unity"
    monthlyDue: 500,      // KSh expected per member per month
    dueDay: 5,             // day-of-month contributions are due
    fineLate: 100,         // KSh fine for a late contribution
    fineAbsence: 50,       // KSh fine for missing a meeting
    // Group identity
    groupName: 'Katani Main Stage',
    stageLocation: 'Katani, Machakos County',
    motto: 'United Riders. Stronger Together.',
    logo: '',
    // Contact details
    officePhone: '0712 345 678',
    officeEmail: 'admin@katanimainstage.co.ke',
    meetingPoint: 'Katani Main Stage Office',
    // Membership
    requireApproval: false,
    // Notifications
    notifyNewRegistration: true,
    notifyPaymentReceived: true,
    notifyFineIssued: true
  };

  function getSettings() {
    try {
      var s = JSON.parse(localStorage.getItem(SETTINGS_KEY));
      return Object.assign({}, DEFAULT_SETTINGS, s || {});
    } catch (e) { return Object.assign({}, DEFAULT_SETTINGS); }
  }
  function saveSettings(data) {
    var current = getSettings();
    var num = function (v, fallback) { var n = Number(v); return isNaN(n) ? fallback : n; };
    var str = function (v, fallback) { return (v === undefined || v === null) ? fallback : String(v); };
    var bool = function (v, fallback) { return (v === undefined) ? fallback : !!v; };
    var merged = {
      foundingYear: num(data.foundingYear, current.foundingYear),
      monthlyDue: num(data.monthlyDue, current.monthlyDue),
      dueDay: Math.min(28, Math.max(1, num(data.dueDay, current.dueDay))),
      fineLate: num(data.fineLate, current.fineLate),
      fineAbsence: num(data.fineAbsence, current.fineAbsence),
      groupName: str(data.groupName, current.groupName).trim() || current.groupName,
      stageLocation: str(data.stageLocation, current.stageLocation),
      motto: str(data.motto, current.motto),
      logo: str(data.logo, current.logo),
      officePhone: str(data.officePhone, current.officePhone),
      officeEmail: str(data.officeEmail, current.officeEmail),
      meetingPoint: str(data.meetingPoint, current.meetingPoint),
      requireApproval: bool(data.requireApproval, current.requireApproval),
      notifyNewRegistration: bool(data.notifyNewRegistration, current.notifyNewRegistration),
      notifyPaymentReceived: bool(data.notifyPaymentReceived, current.notifyPaymentReceived),
      notifyFineIssued: bool(data.notifyFineIssued, current.notifyFineIssued)
    };
    localStorage.setItem(SETTINGS_KEY, JSON.stringify(merged));
    return merged;
  }

  // ---- Computed: Group Overview stats (Registered Members, Active Riders, Payment Compliance, Years of Unity) ----
  function getGroupStats(refDate) {
    var settings = getSettings();
    var members = getUsers().filter(function (u) { return u.role === 'member'; });
    var active = members.filter(function (u) { return (u.status || 'active') === 'active'; });

    var summary = getPaymentSummary(refDate);
    var compliance = summary.total ? Math.round((summary.paid.length / summary.total) * 100) : 0;

    return {
      totalMembers: members.length,
      activeRiders: active.length,
      paymentCompliance: compliance,
      yearsOfUnity: Math.max(0, new Date().getFullYear() - settings.foundingYear)
    };
  }

  // ---- Computed: one member's payment summary (Total Paid, Pending, Total Due, Fines) ----
  function getMemberPaymentSummary(memberId) {
    var settings = getSettings();
    var monthStr = monthOf(ymd(new Date()));
    var totalPaid = 0, paidThisMonth = 0, fines = 0;
    getCollections().forEach(function (t) {
      if (t.memberId !== memberId) return;
      if (t.type === 'contribution') {
        totalPaid += t.amount;
        if (monthOf(t.date) === monthStr) paidThisMonth += t.amount;
      } else if (t.type === 'fine') {
        fines += t.amount;
      }
    });
    var totalDue = settings.monthlyDue;
    var pending = Math.max(0, totalDue - paidThisMonth);
    return { totalPaid: totalPaid, pending: pending, totalDue: totalDue, fines: fines, paidThisMonth: paidThisMonth };
  }

  // ---- Computed: next payment due date + status for one member ----
  function getNextPaymentDue(memberId) {
    var settings = getSettings();
    var summary = getMemberPaymentSummary(memberId);
    var now = new Date();
    var upToDate = summary.pending <= 0;
    var dueDate = upToDate
      ? new Date(now.getFullYear(), now.getMonth() + 1, settings.dueDay)
      : new Date(now.getFullYear(), now.getMonth(), settings.dueDay);
    var overdue = !upToDate && now.getDate() > settings.dueDay;
    return {
      date: dueDate,
      label: dueDate.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }),
      upToDate: upToDate,
      overdue: overdue,
      amount: summary.pending
    };
  }

  // ---- Computed: a member's contributions grouped by day (for the Payment History popup) ----
  function getMemberPaymentsByDay(memberId) {
    var byDay = {};
    getCollections().forEach(function (t) {
      if (t.type !== 'contribution' || t.memberId !== memberId) return;
      var d = t.date || 'Unknown date';
      if (!byDay[d]) byDay[d] = { amount: 0, count: 0 };
      byDay[d].amount += t.amount;
      byDay[d].count += 1;
    });
    return Object.keys(byDay).sort().reverse().map(function (d) {
      return { date: d, amount: byDay[d].amount, count: byDay[d].count };
    });
  }

  // ---- Admin Access: create admins & change roles (Group Settings items 1 & 2) ----
  function createAdmin(data) {
    var users = getUsers();
    var email = String(data.email || '').trim().toLowerCase();
    if (!email) return { success: false, message: 'Email is required.' };
    if (!data.name || !String(data.name).trim()) return { success: false, message: 'Name is required.' };
    if (users.some(function (u) { return u.email.toLowerCase() === email; })) {
      return { success: false, message: 'A user with this email already exists.' };
    }
    var tempPassword = data.password || Math.random().toString(36).slice(-8);
    var user = {
      name: data.name.trim(),
      email: email,
      password: tempPassword,
      role: 'admin',
      phone: data.phone || '',
      altPhone: '',
      memberId: nextMemberId(),
      memberSince: new Date().toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }),
      stage: getSettings().groupName,
      status: 'active',
      dob: '', gender: '', nationalId: '', residence: '', photo: '',
      motorcycle: { plate: '', model: '', color: '', chassis: '' },
      nextOfKin: { name: '', relationship: '', phone: '' }
    };
    users.push(user);
    saveUsers(users);
    return { success: true, user: user, tempPassword: tempPassword };
  }

  function setUserRole(email, role) {
    var users = getUsers();
    var email_l = String(email).trim().toLowerCase();
    var user = users.find(function (u) { return u.email.toLowerCase() === email_l; });
    if (!user) return { success: false, message: 'User not found.' };
    user.role = (role === 'admin') ? 'admin' : 'member';
    saveUsers(users);
    return { success: true, user: user };
  }

  function getAdmins() {
    return getUsers().filter(function (u) { return u.role === 'admin'; });
  }

  // ---- Pending Registrations: approve/reject when Membership Approval Mode is on ----
  function getPendingMembers() {
    return getUsers().filter(function (u) { return u.role === 'member' && u.status === 'pending'; });
  }
  function approveMember(memberId) {
    var users = getUsers();
    var user = users.find(function (u) { return u.memberId === memberId; });
    if (!user) return { success: false, message: 'Member not found.' };
    user.status = 'active';
    saveUsers(users);
    return { success: true, user: user };
  }
  function rejectMember(memberId) {
    var users = getUsers();
    var idx = users.findIndex(function (u) { return u.memberId === memberId; });
    if (idx === -1) return { success: false, message: 'Member not found.' };
    var removed = users.splice(idx, 1)[0];
    saveUsers(users);
    return { success: true, user: removed };
  }

  // ---- Backup / Export & Reset (Group Settings items 8 & 9) ----
  function exportAllData() {
    return {
      exportedAt: new Date().toISOString(),
      settings: getSettings(),
      users: getUsers().map(function (u) { var c = Object.assign({}, u); delete c.password; return c; }),
      collections: getCollections()
    };
  }
  function resetAllData() {
    localStorage.removeItem(USERS_KEY);
    localStorage.removeItem(COLLECTIONS_KEY);
    localStorage.removeItem(SETTINGS_KEY);
    localStorage.removeItem(SESSION_KEY);
    seed();
    return { success: true };
  }

  window.KatiniAuth = {
    seed: seed,
    getUsers: getUsers,
    isAdminEmail: isAdminEmail,
    registerMember: registerMember,
    addMember: addMember,
    login: login,
    logout: logout,
    getSession: getSession,
    getCurrentUser: getCurrentUser,
    routeToHome: routeToHome,
    requireRole: requireRole,
    getCollections: getCollections,
    addCollection: addCollection,
    getPaymentSummary: getPaymentSummary,
    getTopCollectors: getTopCollectors,
    getDailyTotals: getDailyTotals,
    getSettings: getSettings,
    saveSettings: saveSettings,
    getGroupStats: getGroupStats,
    getMemberPaymentSummary: getMemberPaymentSummary,
    getNextPaymentDue: getNextPaymentDue,
    getMemberPaymentsByDay: getMemberPaymentsByDay,
    createAdmin: createAdmin,
    setUserRole: setUserRole,
    getAdmins: getAdmins,
    getPendingMembers: getPendingMembers,
    approveMember: approveMember,
    rejectMember: rejectMember,
    exportAllData: exportAllData,
    resetAllData: resetAllData
  };
})(window);

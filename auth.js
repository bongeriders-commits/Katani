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
      status: data.status || 'active',
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
    getDailyTotals: getDailyTotals
  };
})(window);

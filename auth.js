/* ===================================================================
   Katani Main Stage — Auth & Data (Firebase Authentication + Cloud Firestore)
   -------------------------------------------------------------------
   Every KatiniAuth.* call reads/writes real Firebase Auth + Firestore
   (project configured in firebase-config.js). Data model matches
   firestore.rules exactly:
     /users/{uid}          one doc per member/admin, doc id == Auth uid
     /collections/{id}     payment / fee / fine records (admin-entered)
     /minutes/{id}         meeting minutes (admin-only)
     /announcements/{id}   admin -> members broadcasts, with readBy[]
     /settings/group       single group-settings document

   All functions are async and return Promises (or plain values for the
   handful of purely synchronous cache reads noted below) — every page
   already awaits these calls.
=================================================================== */
(function (window) {
  var cfg = window.FIREBASE_CONFIG;
  var app = firebase.initializeApp(cfg);
  // A second, independent Firebase App instance is used whenever an
  // admin creates ANOTHER account (a member via "Add Member", or a new
  // admin via "Create Admin"). Firebase Auth's client SDK signs in as
  // whichever account it just created — without a second app, that
  // would silently kick the acting admin out of their own session.
  var secondaryApp = firebase.initializeApp(cfg, 'Secondary');

  var auth = app.auth();
  var secondaryAuth = secondaryApp.auth();
  var db = app.firestore();

  var usersCol = db.collection('users');
  var collectionsCol = db.collection('collections');
  var minutesCol = db.collection('minutes');
  var announcementsCol = db.collection('announcements');
  var documentsCol = db.collection('documents');
  var settingsDocRef = db.collection('settings').doc('group');

  var RESERVED_ADMIN_EMAILS = (window.RESERVED_ADMIN_EMAILS || []).map(function (e) {
    return String(e).trim().toLowerCase();
  });

  function isAdminEmail(email) {
    return RESERVED_ADMIN_EMAILS.indexOf(String(email).trim().toLowerCase()) !== -1;
  }

  function nextMemberId() {
    return 'KMS-' + Math.floor(100000 + Math.random() * 899999);
  }
  function nextCollectionId() {
    return 'TXN-' + Date.now().toString(36).toUpperCase().slice(-6) + Math.floor(10 + Math.random() * 89);
  }
  function nextMinutesId() {
    return 'MIN-' + Date.now().toString(36).toUpperCase().slice(-6) + Math.floor(10 + Math.random() * 89);
  }
  function nextAnnouncementId() {
    return 'ANN-' + Date.now().toString(36).toUpperCase().slice(-6) + Math.floor(10 + Math.random() * 89);
  }
  function nextDocumentId() {
    return 'DOC-' + Date.now().toString(36).toUpperCase().slice(-6) + Math.floor(10 + Math.random() * 89);
  }

  // SECURITY: shared escaper. Member names, announcement text, notes, etc.
  // are all user-supplied and get rendered via innerHTML across the app —
  // anything interpolated into innerHTML without this is a stored-XSS risk.
  function escapeHtml(str) {
    return String(str === undefined || str === null ? '' : str)
      .replace(/[&<>"']/g, function (c) {
        return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
      });
  }

  // ---- small binary helper, used by the WebAuthn (fingerprint) code below ----
  function b64urlToBuf(b64url) {
    var b64 = String(b64url).replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4) b64 += '=';
    var str = window.atob(b64);
    var bytes = new Uint8Array(str.length);
    for (var i = 0; i < str.length; i++) bytes[i] = str.charCodeAt(i);
    return bytes.buffer;
  }
  function randomChallenge() {
    var arr = new Uint8Array(32);
    window.crypto.getRandomValues(arr);
    return arr;
  }

  function firebaseErrorMessage(e) {
    var code = e && e.code;
    var map = {
      'auth/email-already-in-use': 'An account with this email already exists. Please log in instead.',
      'auth/invalid-email': 'Please enter a valid email address.',
      'auth/weak-password': 'Password should be at least 6 characters.',
      'auth/wrong-password': 'Incorrect password. Please try again.',
      'auth/user-not-found': 'No registered member found with this email. Please Join Now to register.',
      'auth/invalid-credential': 'Incorrect email or password. Please try again.',
      'auth/too-many-requests': 'Too many attempts. Please wait a moment and try again.',
      'auth/network-request-failed': 'Network error — check your connection and try again.',
      'auth/invalid-action-code': 'This sign-in link has expired or already been used. Please request a new one.',
      'auth/expired-action-code': 'This sign-in link has expired. Please request a new one.',
      'permission-denied': 'You do not have permission to do that.'
    };
    return (code && map[code]) || (e && e.message) || 'Something went wrong. Please try again.';
  }

  function docToUser(docSnap) {
    return Object.assign({ uid: docSnap.id }, docSnap.data());
  }

  // ---- In-memory session cache -----------------------------------------
  // `ready` resolves once Firebase has restored (or confirmed there is no)
  // persisted login session for this browser, so pages that do
  // `await KatiniAuth.ready` before calling the synchronous getSession()
  // never see a false "logged out" flash on reload.
  var cachedUser = null;
  var readyResolved = false;
  var resolveReady;
  var readyPromise = new Promise(function (res) { resolveReady = res; });

  auth.onAuthStateChanged(function (fbUser) {
    var finish = function () {
      if (!readyResolved) { readyResolved = true; resolveReady(); }
    };
    if (!fbUser) {
      cachedUser = null;
      finish();
      return;
    }
    usersCol.doc(fbUser.uid).get().then(function (snap) {
      cachedUser = snap.exists ? docToUser(snap) : null;
    }).catch(function () {
      cachedUser = null;
    }).then(finish);
  });

  function getSession() {
    if (!cachedUser) return null;
    return { email: cachedUser.email, role: cachedUser.role, uid: cachedUser.uid, committeeRole: cachedUser.committeeRole || '' };
  }

  function getCurrentUser() {
    return cachedUser;
  }

  async function logout() {
    cachedUser = null;
    try { await auth.signOut(); } catch (e) { /* ignore */ }
  }

  async function routeToHome() {
    await readyPromise;
    var s = getSession();
    if (!s) { window.location.href = 'index.html'; return; }
    if (s.role === 'admin') { window.location.href = 'admin-dashboard.html'; return; }
    var user = getCurrentUser();
    if (user && (user.committeeRole === 'secretary' || user.committeeRole === 'treasurer')) {
      window.location.href = 'role-select.html';
      return;
    }
    window.location.href = 'members-portal.html';
  }

  // Sends the signed-in Secretary/Treasurer straight to their dashboard,
  // bypassing the role-select chooser — used by "Switch Role" links and by
  // role-select.html itself once the person taps a choice.
  function goToCommitteeDashboard(role) {
    if (role === 'secretary') { window.location.href = 'secretary-dashboard.html'; return; }
    if (role === 'treasurer') { window.location.href = 'treasurer-dashboard.html'; return; }
    window.location.href = 'members-portal.html';
  }

  // Used by the bottom-nav "Dashboard" button on shared pages (Members
  // Directory, Minutes, Collections, Welfare Contributions) that Secretary/
  // Treasurer can now also reach — sends each signed-in user back to the
  // right home screen for their role instead of always assuming admin.
  function goDashboard() {
    var user = getCurrentUser();
    if (!user) { window.location.href = 'index.html'; return; }
    if (user.role === 'admin') { window.location.href = 'admin-dashboard.html'; return; }
    if (user.committeeRole === 'secretary') { window.location.href = 'secretary-dashboard.html'; return; }
    if (user.committeeRole === 'treasurer') { window.location.href = 'treasurer-dashboard.html'; return; }
    window.location.href = 'members-portal.html';
  }

  // ---- Fingerprint / Face ID device unlock ---------------------------------
  // This is a LOCAL, per-device convenience layer on top of the Firebase
  // session that already persists across app opens (see onAuthStateChanged
  // above) — it never talks to Firebase or Firestore, and it never
  // replaces finalizeSession()'s server-side "registered members only"
  // check. What it adds: once enabled on a phone, that phone won't reveal
  // an already-signed-in member's content again until they pass a
  // fingerprint/Face ID prompt (via the Web Authentication API's platform
  // authenticator) — so someone who picks up an unlocked phone can't just
  // open the installed app and land in the Members Space.
  var WEBAUTHN_KEY_PREFIX = 'kms_webauthn_';
  var UNLOCK_SESSION_PREFIX = 'kms_biometric_unlocked_';

  function isWebAuthnSupported() {
    return !!(window.PublicKeyCredential && navigator.credentials);
  }

  async function isPlatformAuthenticatorAvailable() {
    if (!isWebAuthnSupported()) return false;
    try { return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable(); }
    catch (e) { return false; }
  }

  function isBiometricEnabled(uid) {
    try { return !!window.localStorage.getItem(WEBAUTHN_KEY_PREFIX + uid); }
    catch (e) { return false; }
  }

  // Registers a platform (fingerprint/Face ID) credential for the
  // currently signed-in user, scoped to this device/browser only.
  async function enableBiometricUnlock() {
    if (!cachedUser) return { success: false, message: 'Please log in first.' };
    if (!isWebAuthnSupported()) return { success: false, message: 'Fingerprint/Face ID unlock is not supported in this browser.' };
    if (!(await isPlatformAuthenticatorAvailable())) {
      return { success: false, message: 'No fingerprint/Face ID sensor was found on this device.' };
    }
    try {
      var uidBytes = new TextEncoder().encode(cachedUser.uid);
      var cred = await navigator.credentials.create({
        publicKey: {
          challenge: randomChallenge(),
          rp: { name: 'Katani Main Stage' },
          user: { id: uidBytes, name: cachedUser.email, displayName: cachedUser.name || cachedUser.email },
          pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
          authenticatorSelection: { authenticatorAttachment: 'platform', userVerification: 'required', residentKey: 'preferred' },
          timeout: 60000
        }
      });
      if (!cred) return { success: false, message: 'Could not set up fingerprint unlock.' };
      try { window.localStorage.setItem(WEBAUTHN_KEY_PREFIX + cachedUser.uid, cred.id); } catch (e) { /* ignore */ }
      markUnlockedThisSession(cachedUser.uid);
      return { success: true };
    } catch (e) {
      return { success: false, message: 'Could not set up fingerprint unlock' + (e && e.message ? (': ' + e.message) : '.') };
    }
  }

  function disableBiometricUnlock() {
    if (!cachedUser) return;
    try { window.localStorage.removeItem(WEBAUTHN_KEY_PREFIX + cachedUser.uid); } catch (e) { /* ignore */ }
    try { window.sessionStorage.removeItem(UNLOCK_SESSION_PREFIX + cachedUser.uid); } catch (e) { /* ignore */ }
  }

  function hasUnlockedThisSession(uid) {
    try { return window.sessionStorage.getItem(UNLOCK_SESSION_PREFIX + uid) === '1'; }
    catch (e) { return true; } // fail open — never lock someone out over sessionStorage being unavailable
  }
  function markUnlockedThisSession(uid) {
    try { window.sessionStorage.setItem(UNLOCK_SESSION_PREFIX + uid, '1'); } catch (e) { /* ignore */ }
  }

  // Call once per protected page load (index.html's "already logged in"
  // branch, and requireRole() below both do). Resolves true if either
  // biometric unlock isn't enabled, was already satisfied earlier this
  // browser session, or the device doesn't support it (graceful
  // fallback) — false only when it's enabled, required, and the person
  // failed or cancelled the prompt.
  async function requireBiometricUnlock(uid) {
    if (!isBiometricEnabled(uid)) return true;
    if (hasUnlockedThisSession(uid)) return true;
    if (!isWebAuthnSupported()) return true;
    var credId = null;
    try { credId = window.localStorage.getItem(WEBAUTHN_KEY_PREFIX + uid); } catch (e) { /* ignore */ }
    if (!credId) return true;
    try {
      var assertion = await navigator.credentials.get({
        publicKey: {
          challenge: randomChallenge(),
          allowCredentials: [{ id: b64urlToBuf(credId), type: 'public-key' }],
          userVerification: 'required',
          timeout: 60000
        }
      });
      if (!assertion) return false;
      markUnlockedThisSession(uid);
      return true;
    } catch (e) {
      return false;
    }
  }

  // Guards a page: pass an array of allowed roles, e.g. ['admin'] or ['admin','member'].
  // Always re-fetches the caller's profile fresh from Firestore (not just the
  // cache) so an admin suspending/rejecting someone takes effect immediately,
  // even if that member still has the page open in another tab.
  async function requireRole(roles) {
    await readyPromise;
    var fbUser = auth.currentUser;
    if (!fbUser) {
      window.location.href = 'index.html';
      return null;
    }
    var user = null;
    try {
      var snap = await usersCol.doc(fbUser.uid).get();
      user = snap.exists ? docToUser(snap) : null;
    } catch (e) { user = null; }
    cachedUser = user;
    if (!user) {
      window.location.href = 'index.html';
      return null;
    }
    var effectiveRoles = [user.role];
    if (user.role === 'member' && (user.committeeRole === 'secretary' || user.committeeRole === 'treasurer')) {
      effectiveRoles.push(user.committeeRole);
    }
    var allowed = roles.some(function (r) { return effectiveRoles.indexOf(r) !== -1; });
    if (!allowed) {
      window.location.href = 'index.html';
      return null;
    }
    if (user.role === 'member' && user.status && user.status !== 'active') {
      await logout();
      window.location.href = 'index.html';
      return null;
    }
    // If this device has fingerprint/Face ID unlock enabled for this
    // account and it hasn't been satisfied yet this browser session,
    // bounce to the login gate — index.html will prompt for it and
    // route back in once it succeeds.
    if (!(await requireBiometricUnlock(user.uid))) {
      window.location.href = 'index.html';
      return null;
    }
    // A temporary, admin-set password (new member, or an existing member
    // whose password an admin just reset) only ever gets this member as far
    // as this blocking screen — nothing else in the app renders behind it
    // until they set their own password.
    if (user.mustChangePassword) {
      await showForcePasswordChangeModal();
      user.mustChangePassword = false;
    }
    return user;
  }

  // ---- Blocking "set your new password" screen ------------------------
  // Built and injected purely in JS so every page gets it for free just by
  // including auth.js — no markup needs to be copy-pasted onto each page.
  function showForcePasswordChangeModal() {
    return new Promise(function (resolve) {
      var overlay = document.createElement('div');
      overlay.setAttribute('style',
        'position:fixed;inset:0;z-index:9999;background:rgba(10,20,40,0.82);' +
        'display:flex;align-items:center;justify-content:center;padding:20px;font-family:"Segoe UI",Roboto,-apple-system,BlinkMacSystemFont,sans-serif;');
      overlay.innerHTML =
        '<div style="width:100%;max-width:380px;background:#f4f6f9;border-radius:18px;padding:24px 20px;box-shadow:0 20px 50px rgba(0,0,0,0.4);">' +
          '<h3 style="font-size:16.5px;font-weight:800;color:#0d2140;margin-bottom:6px;">Set Your New Password</h3>' +
          '<p style="font-size:12.5px;color:#6b7685;margin-bottom:16px;line-height:1.5;">You logged in with a temporary password. For your account\'s security, choose a new password now &mdash; it only takes a moment.</p>' +
          '<div style="margin-bottom:10px;">' +
            '<label style="display:block;font-size:11.5px;font-weight:700;color:#6b7685;margin-bottom:6px;">New Password</label>' +
            '<input type="password" id="fpc-new" placeholder="At least 6 characters" style="width:100%;border:1.5px solid #e3e7ee;border-radius:10px;padding:10px 12px;font-size:13px;color:#0d2140;outline:none;background:#fff;box-sizing:border-box;">' +
          '</div>' +
          '<div style="margin-bottom:6px;">' +
            '<label style="display:block;font-size:11.5px;font-weight:700;color:#6b7685;margin-bottom:6px;">Confirm Password</label>' +
            '<input type="password" id="fpc-confirm" placeholder="Re-enter password" style="width:100%;border:1.5px solid #e3e7ee;border-radius:10px;padding:10px 12px;font-size:13px;color:#0d2140;outline:none;background:#fff;box-sizing:border-box;">' +
          '</div>' +
          '<div id="fpc-error" style="color:#c0392b;font-size:11.5px;margin:8px 0 0;display:none;"></div>' +
          '<button id="fpc-save" style="width:100%;background:#0d2140;color:#fff;border:none;border-radius:12px;padding:14px;font-size:13.5px;font-weight:800;cursor:pointer;margin-top:16px;">Save New Password</button>' +
        '</div>';
      document.body.appendChild(overlay);

      var btn = overlay.querySelector('#fpc-save');
      var err = overlay.querySelector('#fpc-error');
      btn.addEventListener('click', async function () {
        var p1 = overlay.querySelector('#fpc-new').value;
        var p2 = overlay.querySelector('#fpc-confirm').value;
        if (p1 !== p2) {
          err.textContent = 'Passwords do not match.';
          err.style.display = 'block';
          return;
        }
        btn.disabled = true;
        btn.textContent = 'Saving…';
        var result = await changePassword(p1);
        if (!result.success) {
          err.textContent = result.message;
          err.style.display = 'block';
          btn.disabled = false;
          btn.textContent = 'Save New Password';
          return;
        }
        document.body.removeChild(overlay);
        resolve();
      });
    });
  }

  // ---- Registration ------------------------------------------------------
  async function registerMember(data) {
    var email = String(data.email || '').trim().toLowerCase();
    if (!email || !data.password) {
      return { success: false, message: 'Email and password are required.' };
    }
    // SECURITY: public self-registration must never grant admin. Without this
    // check, anyone who knew (or guessed) one of the reserved committee
    // addresses could register with it. Admin accounts may only be created
    // by an existing admin via createAdmin().
    if (isAdminEmail(email)) {
      return { success: false, message: 'This email is reserved for committee use. Please contact an administrator.' };
    }
    var settings = await getSettings();
    var status = data.status || (settings.requireApproval ? 'pending' : 'active');
    try {
      var cred = await auth.createUserWithEmailAndPassword(email, data.password);
      var uid = cred.user.uid;
      var user = {
        name: data.name || 'New Member',
        email: email,
        role: 'member',
        committeeRole: '',
        phone: data.phone || '',
        altPhone: data.altPhone || '',
        memberId: nextMemberId(),
        memberSince: data.memberSince || new Date().toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }),
        stage: data.stage || 'Katani Main Stage',
        status: status,
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
      await usersCol.doc(uid).set(user);
      var full = Object.assign({ uid: uid }, user);
      // BUG FIX (kept from the old version): a member registering while
      // "Membership Approval Mode" is on should NOT be left signed in —
      // otherwise they could reach the Members Space before approval.
      if (status === 'active') {
        cachedUser = full;
      } else {
        await auth.signOut();
        cachedUser = null;
      }
      return { success: true, user: full, pendingApproval: status === 'pending' };
    } catch (e) {
      return { success: false, message: firebaseErrorMessage(e) };
    }
  }

  // ---- Admin-added member (does NOT log the admin in as the new member) ----
  // The password the admin sets here is a TEMPORARY, one-time credential:
  // mustChangePassword is stamped onto the profile, and requireRole() (see
  // below) will block every page behind a forced "set your new password"
  // screen the moment this member's very first login lands, before they can
  // see or do anything else in the app. See changePassword() for the other
  // half of that flow.
  async function addMember(data) {
    var email = String(data.email || '').trim().toLowerCase();
    if (!email) return { success: false, message: 'Email is required.' };
    var password = data.password || Math.random().toString(36).slice(-8);
    try {
      var cred = await secondaryAuth.createUserWithEmailAndPassword(email, password);
      var uid = cred.user.uid;
      var user = {
        name: data.name || 'New Member',
        email: email,
        role: 'member',
        committeeRole: '',
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
        saccoNumber: data.saccoNumber || '',
        mustChangePassword: true,
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
      // Written via the PRIMARY app's Firestore instance, so this create is
      // authorized by the acting admin's own session (isAdmin() in the
      // rules) — not by the brand-new secondary-app account.
      await usersCol.doc(uid).set(user);
      await secondaryAuth.signOut();
      // tempPassword is handed back so the caller (Members Directory) can
      // show it once and offer to send it over WhatsApp. It is never
      // written to Firestore in plain text.
      return { success: true, user: Object.assign({ uid: uid }, user), tempPassword: password };
    } catch (e) {
      try { await secondaryAuth.signOut(); } catch (e2) { /* ignore */ }
      return { success: false, message: firebaseErrorMessage(e) };
    }
  }

  // ---- Admin edits an existing member's profile (no password/email/auth
  // account changes here — those go through resetMemberPassword()). ----
  async function editMember(uid, data) {
    if (!uid) return { success: false, message: 'Missing member id.' };
    try {
      var ref = usersCol.doc(uid);
      var snap = await ref.get();
      if (!snap.exists) return { success: false, message: 'Member not found.' };
      var updates = {
        name: data.name || '',
        phone: data.phone || '',
        status: data.status || snap.data().status || 'active',
        dob: data.dob || '',
        gender: data.gender || '',
        nationalId: data.nationalId || '',
        residence: data.residence || '',
        saccoNumber: data.saccoNumber || '',
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
      if (typeof data.photo === 'string' && data.photo) updates.photo = data.photo;
      await ref.update(updates);
      return { success: true, user: Object.assign({ uid: uid }, snap.data(), updates) };
    } catch (e) {
      return { success: false, message: firebaseErrorMessage(e) };
    }
  }

  // ---- Admin deletes a member ----------------------------------------
  // Same limitation as rejectMember(): this removes the Firestore profile
  // (so they vanish from the directory and finalizeSession() refuses their
  // next login attempt), but it cannot delete the underlying Firebase
  // Authentication account from client-side JS — that needs the Admin SDK
  // (Firebase console, or the reset-member-password serverless function's
  // service account, extended to also support delete).
  async function deleteMember(uid) {
    if (!uid) return { success: false, message: 'Missing member id.' };
    try {
      var ref = usersCol.doc(uid);
      var snap = await ref.get();
      if (!snap.exists) return { success: false, message: 'Member not found.' };
      var removed = Object.assign({ uid: uid }, snap.data());
      await ref.delete();
      return { success: true, user: removed };
    } catch (e) {
      return { success: false, message: firebaseErrorMessage(e) };
    }
  }

  // ---- Admin resets an existing member's password ---------------------
  // Firebase's client SDK can only ever change the password of whichever
  // account is CURRENTLY signed in — there is no client-side call that lets
  // one signed-in user (the admin) set another user's password. Doing that
  // for an existing account needs the Admin SDK, which only runs server
  // side. This calls a small serverless function (see
  // /api/reset-member-password.js) that does exactly that and nothing else:
  // it checks the caller is a real admin, then sets the new temp password
  // and re-flags mustChangePassword so the member is forced through the
  // same one-time-password screen as a brand new member.
  async function resetMemberPassword(uid) {
    if (!uid) return { success: false, message: 'Missing member id.' };
    var fbUser = auth.currentUser;
    if (!fbUser) return { success: false, message: 'You must be signed in as an admin.' };
    var newPassword = Math.random().toString(36).slice(-8);
    try {
      var idToken = await fbUser.getIdToken();
      var res = await fetch('/api/reset-member-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ idToken: idToken, uid: uid, newPassword: newPassword })
      });
      var body = await res.json().catch(function () { return {}; });
      if (!res.ok || !body.success) {
        return { success: false, message: body.message || 'Password reset isn\'t set up yet — see /api/reset-member-password.js.' };
      }
      await usersCol.doc(uid).update({ mustChangePassword: true });
      return { success: true, tempPassword: newPassword };
    } catch (e) {
      return { success: false, message: 'Password reset isn\'t set up yet — see /api/reset-member-password.js.' };
    }
  }

  // ---- Member sets their own password (first-login forced change, or a
  // voluntary change later). Requires the member to already be signed in,
  // which is always true right after login/registration. ----
  async function changePassword(newPassword) {
    var fbUser = auth.currentUser;
    if (!fbUser) return { success: false, message: 'You must be signed in.' };
    if (!newPassword || String(newPassword).length < 6) {
      return { success: false, message: 'Password must be at least 6 characters.' };
    }
    try {
      await fbUser.updatePassword(newPassword);
      await usersCol.doc(fbUser.uid).update({ mustChangePassword: false });
      if (cachedUser) cachedUser.mustChangePassword = false;
      return { success: true };
    } catch (e) {
      if (e && e.code === 'auth/requires-recent-login') {
        return { success: false, message: 'For security, please log out and log back in with your temporary password, then try again.' };
      }
      return { success: false, message: firebaseErrorMessage(e) };
    }
  }

  // ---- WhatsApp handoff (best-effort, no backend/API keys required) ----
  // There's no way to silently auto-send a WhatsApp message from a plain
  // static web app — WhatsApp's Business Cloud API needs server credentials
  // and Meta approval. Instead this opens wa.me with the message pre-filled
  // so the admin just taps Send in WhatsApp — one tap, no typing.
  function toWhatsAppNumber(phone) {
    var digits = String(phone || '').replace(/[^\d]/g, '');
    if (!digits) return '';
    if (digits.charAt(0) === '0') digits = '254' + digits.slice(1);
    else if (digits.length <= 9) digits = '254' + digits;
    return digits;
  }

  function buildWhatsAppLink(phone, message) {
    var num = toWhatsAppNumber(phone);
    var text = encodeURIComponent(message || '');
    return num ? ('https://wa.me/' + num + '?text=' + text) : ('https://wa.me/?text=' + text);
  }

  // ---- Login -------------------------------------------------------------
  // Shared post-authentication gate: used by every sign-in method (password
  // AND email link). This is what actually enforces "registered members
  // only" — a Firebase Auth session with no matching Firestore /users doc
  // (or a not-yet-approved / suspended one) is signed straight back out,
  // regardless of how the person authenticated. So even if a stranger types
  // an arbitrary email into the email-link form, the link Firebase sends
  // them can sign them into Firebase Auth, but it can never get them past
  // this check into a member's data.
  async function finalizeSession(uid) {
    var snap = await usersCol.doc(uid).get();
    if (!snap.exists) {
      await auth.signOut();
      return { success: false, message: 'This email is not registered as a member. Please Join Now to register, or contact an administrator.' };
    }
    var user = docToUser(snap);
    if (user.role === 'member' && user.status === 'pending') {
      await auth.signOut();
      return { success: false, message: 'Your registration is still awaiting committee approval.' };
    }
    if (user.role === 'member' && user.status && user.status !== 'active') {
      await auth.signOut();
      return { success: false, message: 'Your account is not active. Please contact an administrator.' };
    }
    cachedUser = user;
    return { success: true, user: user };
  }

  async function login(email, password) {
    var emailL = String(email).trim().toLowerCase();
    try {
      var cred = await auth.signInWithEmailAndPassword(emailL, password);
      return await finalizeSession(cred.user.uid);
    } catch (e) {
      return { success: false, message: firebaseErrorMessage(e) };
    }
  }

  // ---- Email link (passwordless) login ------------------------------------
  // An alternative to password login for already-registered members. Does
  // NOT touch the Firestore rules or the "members only" guarantee above —
  // finalizeSession() still runs after every successful link sign-in and
  // signs out anyone without a real member profile.
  //
  // Console setup required (one-time): Authentication -> Sign-in method ->
  // enable "Email link (passwordless sign-in)" alongside Email/Password.
  var EMAIL_FOR_SIGN_IN_KEY = 'kms_emailForSignIn';

  function emailLinkSettings() {
    // Points back at whichever page sends the link, so long as that page
    // also calls completeEmailLinkSignIn() on load (index.html does, below).
    return {
      url: window.location.href.split('#')[0].split('?')[0],
      handleCodeInApp: true
    };
  }

  async function sendLoginLink(email) {
    var emailL = String(email).trim().toLowerCase();
    if (!emailL) return { success: false, message: 'Enter your email address.' };
    try {
      await auth.sendSignInLinkToEmail(emailL, emailLinkSettings());
      try { window.localStorage.setItem(EMAIL_FOR_SIGN_IN_KEY, emailL); } catch (e) { /* ignore */ }
      return { success: true };
    } catch (e) {
      return { success: false, message: firebaseErrorMessage(e) };
    }
  }

  // ---- Forgot password (self-service, no admin required) -----------------
  // Sends Firebase's built-in "reset your password" email. Firebase only
  // sends it for emails that actually have an Auth account — an unknown
  // email surfaces as auth/user-not-found here (unless the Firebase
  // project has Email Enumeration Protection turned on, in which case
  // Firebase always reports success without revealing whether the email
  // exists, which is also safe to show to the member as-is).
  async function sendPasswordReset(email) {
    var emailL = String(email || '').trim().toLowerCase();
    if (!emailL) return { success: false, message: 'Enter your email address.' };
    try {
      await auth.sendPasswordResetEmail(emailL, emailLinkSettings());
      return { success: true };
    } catch (e) {
      return { success: false, message: firebaseErrorMessage(e) };
    }
  }

  function isEmailLinkSignIn() {
    try { return auth.isSignInWithEmailLink(window.location.href); }
    catch (e) { return false; }
  }

  // Call this on page load whenever isEmailLinkSignIn() is true. If the
  // link is opened on a different device/browser than it was requested
  // from, there's no saved email to read back — pass promptedEmail (ask
  // the user to re-type the email they used) in that case.
  async function completeEmailLinkSignIn(promptedEmail) {
    if (!isEmailLinkSignIn()) return null;
    var email = null;
    try { email = window.localStorage.getItem(EMAIL_FOR_SIGN_IN_KEY); } catch (e) { /* ignore */ }
    email = email || promptedEmail;
    if (!email) return { success: false, needEmail: true };
    try {
      var cred = await auth.signInWithEmailLink(String(email).trim().toLowerCase(), window.location.href);
      try { window.localStorage.removeItem(EMAIL_FOR_SIGN_IN_KEY); } catch (e) { /* ignore */ }
      // Strip the one-time sign-in params out of the URL so refreshing or
      // re-sharing this exact link can't replay it.
      window.history.replaceState({}, document.title, window.location.pathname);
      return await finalizeSession(cred.user.uid);
    } catch (e) {
      return { success: false, message: firebaseErrorMessage(e) };
    }
  }

  // ---- Collections & Payments (member contributions, registration fees, fines, other income) ----
  // type: 'contribution' | 'registration' | 'fine' | 'other'
  async function addCollection(data) {
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
    var record = {
      id: nextCollectionId(),
      type: type,
      memberId: data.memberId || '',
      memberUid: data.memberUid || '',
      memberName: data.memberName || '',
      source: data.source || '',
      amount: amount,
      method: data.method || 'Cash',
      reference: data.reference || '',
      date: data.date || new Date().toISOString().slice(0, 10),
      note: data.note || '',
      createdAt: Date.now()
    };
    try {
      await collectionsCol.doc(record.id).set(record);
      return { success: true, record: record };
    } catch (e) {
      return { success: false, message: firebaseErrorMessage(e) };
    }
  }

  async function getCollections() {
    try {
      var snap = await collectionsCol.orderBy('createdAt', 'desc').get();
      return snap.docs.map(function (d) { return d.data(); });
    } catch (e) { return []; }
  }

  // Returns only the collections belonging to the currently logged-in member.
  async function getMyCollections() {
    var user = getCurrentUser();
    if (!user) return [];
    try {
      var snap = await collectionsCol.where('memberUid', '==', user.uid).get();
      var list = snap.docs.map(function (d) { return d.data(); });
      list.sort(function (a, b) { return (b.createdAt || 0) - (a.createdAt || 0); });
      return list;
    } catch (e) { return []; }
  }

  // ---- Meeting Minutes ----
  async function getMinutes() {
    try {
      var snap = await minutesCol.orderBy('createdAt', 'desc').get();
      return snap.docs.map(function (d) { return d.data(); });
    } catch (e) { return []; }
  }

  // data: { meetingDate, title, membersPresent: [{memberId,name}], agenda: [{title,details}], recordedBy }
  async function addMinutes(data) {
    if (!data.meetingDate) {
      return { success: false, message: 'Enter the date of the meeting.' };
    }
    if (!data.title || !String(data.title).trim()) {
      return { success: false, message: 'Enter a title for the meeting.' };
    }
    var record = {
      id: nextMinutesId(),
      meetingDate: data.meetingDate,
      title: data.title,
      membersPresent: data.membersPresent || [],
      agenda: data.agenda || [],
      recordedBy: data.recordedBy || '',
      createdAt: Date.now()
    };
    try {
      await minutesCol.doc(record.id).set(record);
      return { success: true, record: record };
    } catch (e) {
      return { success: false, message: firebaseErrorMessage(e) };
    }
  }

  async function getMinutesById(id) {
    try {
      var snap = await minutesCol.doc(id).get();
      return snap.exists ? snap.data() : null;
    } catch (e) { return null; }
  }

  async function deleteMinutes(id) {
    try {
      await minutesCol.doc(id).delete();
      return { success: true };
    } catch (e) {
      return { success: false, message: firebaseErrorMessage(e) };
    }
  }

  // ---- Announcements (admin -> members broadcast, with per-member read tracking) ----
  async function getAnnouncements() {
    try {
      var snap = await announcementsCol.orderBy('createdAt', 'desc').get();
      return snap.docs.map(function (d) { return d.data(); });
    } catch (e) { return []; }
  }

  // Sends (creates) a new announcement. data: { title, message, sentBy (email), sentByName }
  async function sendAnnouncement(data) {
    var title = String(data.title || '').trim();
    var message = String(data.message || '').trim();
    if (!title) return { success: false, message: 'Enter an announcement title.' };
    if (!message) return { success: false, message: 'Enter the announcement message.' };
    var record = {
      id: nextAnnouncementId(),
      title: title,
      message: message,
      sentBy: data.sentBy || '',
      sentByName: data.sentByName || 'Committee',
      date: new Date().toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }),
      createdAt: Date.now(),
      readBy: []
    };
    try {
      await announcementsCol.doc(record.id).set(record);
      return { success: true, announcement: record };
    } catch (e) {
      return { success: false, message: firebaseErrorMessage(e) };
    }
  }

  // Unread count for a given member/admin email (announcements they have not opened yet).
  async function getUnreadAnnouncementCount(email) {
    var emailL = String(email || '').trim().toLowerCase();
    if (!emailL) return 0;
    var list = await getAnnouncements();
    return list.filter(function (a) { return (a.readBy || []).indexOf(emailL) === -1; }).length;
  }

  async function markAnnouncementRead(id, email) {
    var emailL = String(email || '').trim().toLowerCase();
    if (!emailL) return;
    try {
      await announcementsCol.doc(id).update({ readBy: firebase.firestore.FieldValue.arrayUnion(emailL) });
    } catch (e) { /* ignore */ }
  }

  async function markAllAnnouncementsRead(email) {
    var emailL = String(email || '').trim().toLowerCase();
    if (!emailL) return;
    var list = await getAnnouncements();
    var unread = list.filter(function (a) { return (a.readBy || []).indexOf(emailL) === -1; });
    if (!unread.length) return;
    try {
      var batch = db.batch();
      unread.forEach(function (a) {
        batch.update(announcementsCol.doc(a.id), { readBy: firebase.firestore.FieldValue.arrayUnion(emailL) });
      });
      await batch.commit();
    } catch (e) { /* ignore */ }
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

  async function getUsers() {
    try {
      var snap = await usersCol.get();
      return snap.docs.map(docToUser);
    } catch (e) { return []; }
  }

  // Classifies each active member as paid / pending / defaulter for the given
  // reference date's calendar month, based on 'contribution' collections:
  //   paid      - has a contribution recorded this month
  //   pending   - no contribution yet this month, but paid last month
  //               (or joined this month, so not yet due)
  //   defaulter - no contribution this month AND none last month either
  async function getPaymentSummary(refDate) {
    refDate = refDate || new Date();
    var thisMonth = monthOf(ymd(refDate));
    var lastMonthDate = new Date(refDate.getFullYear(), refDate.getMonth() - 1, 1);
    var lastMonth = monthOf(ymd(lastMonthDate));

    var users = (await getUsers()).filter(function (u) { return u.role === 'member' && (u.status || 'active') === 'active'; });
    var txns = (await getCollections()).filter(function (t) { return t.type === 'contribution'; });

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
  async function getTopCollectors(limit, monthStr) {
    limit = limit || 5;
    monthStr = monthStr || monthOf(ymd(new Date()));
    var users = await getUsers();
    var byId = {};
    users.forEach(function (u) { byId[u.memberId] = u; });

    var totals = {};
    (await getCollections()).forEach(function (t) {
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
  async function getDailyTotals(days, endDate) {
    days = days || 18;
    endDate = endDate || new Date();
    var txns = await getCollections();
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
    // ID Card
    idStageName: 'Katani Main Stage',
    idStageNumber: '',
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

  async function getSettings() {
    try {
      var snap = await settingsDocRef.get();
      return Object.assign({}, DEFAULT_SETTINGS, snap.exists ? snap.data() : {});
    } catch (e) { return Object.assign({}, DEFAULT_SETTINGS); }
  }

  async function saveSettings(data) {
    var current = await getSettings();
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
      idStageName: str(data.idStageName, current.idStageName).trim() || current.idStageName,
      idStageNumber: str(data.idStageNumber, current.idStageNumber),
      officePhone: str(data.officePhone, current.officePhone),
      officeEmail: str(data.officeEmail, current.officeEmail),
      meetingPoint: str(data.meetingPoint, current.meetingPoint),
      requireApproval: bool(data.requireApproval, current.requireApproval),
      notifyNewRegistration: bool(data.notifyNewRegistration, current.notifyNewRegistration),
      notifyPaymentReceived: bool(data.notifyPaymentReceived, current.notifyPaymentReceived),
      notifyFineIssued: bool(data.notifyFineIssued, current.notifyFineIssued)
    };
    await settingsDocRef.set(merged);
    return merged;
  }

  // ---- Computed: Group Overview stats (Registered Members, Active Riders, Payment Compliance, Years of Unity) ----
  async function getGroupStats(refDate) {
    var settings = await getSettings();
    var members = (await getUsers()).filter(function (u) { return u.role === 'member'; });
    var active = members.filter(function (u) { return (u.status || 'active') === 'active'; });

    var summary = await getPaymentSummary(refDate);
    var compliance = summary.total ? Math.round((summary.paid.length / summary.total) * 100) : 0;

    return {
      totalMembers: members.length,
      activeRiders: active.length,
      paymentCompliance: compliance,
      yearsOfUnity: Math.max(0, new Date().getFullYear() - settings.foundingYear)
    };
  }

  // ---- Computed: one member's payment summary (Total Paid, Pending, Total Due, Fines) ----
  async function getMemberPaymentSummary(memberId) {
    var settings = await getSettings();
    var monthStr = monthOf(ymd(new Date()));
    var totalPaid = 0, paidThisMonth = 0, fines = 0;
    (await getCollections()).forEach(function (t) {
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
  async function getNextPaymentDue(memberId) {
    var settings = await getSettings();
    var summary = await getMemberPaymentSummary(memberId);
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
  async function getMemberPaymentsByDay(memberId) {
    var byDay = {};
    (await getCollections()).forEach(function (t) {
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

  // ---- Group Documents (Certificate / License / Constitution / Fiscal Plans) ----
  // No Firebase Storage here on purpose — Storage now requires linking a
  // billing card even for $0 actual usage, which isn't an option for this
  // group. Instead each PDF is base64-encoded and stored directly on its
  // /documents/{id} Firestore doc (see firestore.rules for read/write
  // access). Firestore caps a single document at ~1MiB, and base64 inflates
  // a file by ~1.37x, so the practical raw-file ceiling is well under 1MB.
  var DOCUMENT_CATEGORIES = ['certificate', 'license', 'constitution', 'fiscal_plan'];
  var MAX_DOCUMENT_BYTES = 700 * 1024; // ~700KB raw -> ~960KB base64, safely under Firestore's 1MiB doc limit

  function fileToBase64(file, onProgress) {
    return new Promise(function (resolve, reject) {
      var reader = new FileReader();
      reader.onprogress = function (evt) {
        if (typeof onProgress === 'function' && evt.lengthComputable) {
          onProgress(Math.round((evt.loaded / evt.total) * 100));
        }
      };
      reader.onerror = function () { reject(reader.error); };
      reader.onload = function () {
        // reader.result is a data URL ("data:application/pdf;base64,...."),
        // which is exactly the string the UI needs for its download links.
        resolve(reader.result);
      };
      reader.readAsDataURL(file);
    });
  }

  async function uploadGroupDocument(category, file, onProgress) {
    if (DOCUMENT_CATEGORIES.indexOf(category) === -1) {
      return { success: false, message: 'Unknown document category.' };
    }
    if (!file || file.type !== 'application/pdf') {
      return { success: false, message: 'Only PDF files are allowed.' };
    }
    if (file.size > MAX_DOCUMENT_BYTES) {
      return { success: false, message: 'File is too large — please keep PDFs under ' + Math.round(MAX_DOCUMENT_BYTES / 1024) + 'KB (try compressing it first).' };
    }
    var user = getCurrentUser();
    if (!user) {
      return { success: false, message: 'You must be signed in.' };
    }
    try {
      var dataUrl = await fileToBase64(file, onProgress);
      var id = nextDocumentId();
      var record = {
        id: id,
        category: category,
        title: file.name,
        fileName: String(file.name).replace(/[^a-zA-Z0-9_.-]/g, '_').slice(-120),
        url: dataUrl,
        size: file.size,
        uploadedByUid: user.uid,
        uploadedByName: user.name || 'Committee',
        uploadedAt: Date.now()
      };
      await documentsCol.doc(id).set(record);
      return { success: true, record: record };
    } catch (e) {
      return { success: false, message: firebaseErrorMessage(e) };
    }
  }

  async function getGroupDocuments() {
    try {
      var snap = await documentsCol.orderBy('uploadedAt', 'desc').get();
      return snap.docs.map(function (d) { return d.data(); });
    } catch (e) { return []; }
  }

  async function deleteGroupDocument(doc) {
    try {
      await documentsCol.doc(doc.id).delete();
      return { success: true };
    } catch (e) {
      return { success: false, message: firebaseErrorMessage(e) };
    }
  }


  // accountType: 'admin' (default) | 'secretary' | 'treasurer'. Secretary/Treasurer
  // accounts stay ordinary members (role 'member') so they keep showing up in the
  // Members Directory and can log in and view their own profile like any other
  // member — committeeRole is what grants their extra Secretary/Treasurer screens
  // (see requireRole above and role-select.html).
  async function createAdmin(data) {
    var email = String(data.email || '').trim().toLowerCase();
    if (!email) return { success: false, message: 'Email is required.' };
    if (!data.name || !String(data.name).trim()) return { success: false, message: 'Name is required.' };
    var accountType = ['secretary', 'treasurer'].indexOf(data.accountType) !== -1 ? data.accountType : 'admin';
    var tempPassword = data.password || Math.random().toString(36).slice(-8);
    try {
      var cred = await secondaryAuth.createUserWithEmailAndPassword(email, tempPassword);
      var uid = cred.user.uid;
      var settings = await getSettings();
      var user = {
        name: data.name.trim(),
        email: email,
        role: accountType === 'admin' ? 'admin' : 'member',
        committeeRole: accountType === 'admin' ? '' : accountType,
        phone: data.phone || '',
        altPhone: '',
        memberId: nextMemberId(),
        memberSince: new Date().toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }),
        stage: settings.groupName,
        status: 'active',
        dob: '', gender: '', nationalId: '', residence: '', photo: '',
        motorcycle: { plate: '', model: '', color: '', chassis: '' },
        nextOfKin: { name: '', relationship: '', phone: '' }
      };
      await usersCol.doc(uid).set(user);
      await secondaryAuth.signOut();
      return { success: true, user: Object.assign({ uid: uid }, user), tempPassword: tempPassword };
    } catch (e) {
      try { await secondaryAuth.signOut(); } catch (e2) { /* ignore */ }
      return { success: false, message: firebaseErrorMessage(e) };
    }
  }

  // setUserRole is called with the target user's uid (see admin-dashboard.html).
  async function setUserRole(uid, role) {
    try {
      var ref = usersCol.doc(uid);
      var snap = await ref.get();
      if (!snap.exists) return { success: false, message: 'User not found.' };
      var newRole = (role === 'admin') ? 'admin' : 'member';
      await ref.update({ role: newRole });
      return { success: true, user: Object.assign({ uid: uid }, snap.data(), { role: newRole }) };
    } catch (e) {
      return { success: false, message: firebaseErrorMessage(e) };
    }
  }

  // Promotes/demotes an existing member to Secretary or Treasurer, or clears
  // it (pass '' to revoke). Does not touch their base role — they remain 'member'.
  async function setCommitteeRole(uid, committeeRole) {
    var value = ['secretary', 'treasurer'].indexOf(committeeRole) !== -1 ? committeeRole : '';
    try {
      var ref = usersCol.doc(uid);
      var snap = await ref.get();
      if (!snap.exists) return { success: false, message: 'Member not found.' };
      await ref.update({ committeeRole: value });
      return { success: true, user: Object.assign({ uid: uid }, snap.data(), { committeeRole: value }) };
    } catch (e) {
      return { success: false, message: firebaseErrorMessage(e) };
    }
  }

  async function getCommitteeMembers() {
    try {
      var users = await getUsers();
      return users.filter(function (u) {
        return u.role === 'member' && (u.committeeRole === 'secretary' || u.committeeRole === 'treasurer');
      });
    } catch (e) { return []; }
  }

  async function getAdmins() {
    try {
      var snap = await usersCol.where('role', '==', 'admin').get();
      return snap.docs.map(docToUser);
    } catch (e) { return []; }
  }

  // ---- Pending Registrations: approve/reject when Membership Approval Mode is on ----
  async function getPendingMembers() {
    try {
      var snap = await usersCol.where('role', '==', 'member').where('status', '==', 'pending').get();
      return snap.docs.map(docToUser);
    } catch (e) { return []; }
  }

  // approveMember / rejectMember are called with the target member's uid
  // (see admin-dashboard.html's handleApprove/handleReject).
  async function approveMember(uid) {
    try {
      var ref = usersCol.doc(uid);
      var snap = await ref.get();
      if (!snap.exists) return { success: false, message: 'Member not found.' };
      await ref.update({ status: 'active' });
      return { success: true, user: Object.assign({ uid: uid }, snap.data(), { status: 'active' }) };
    } catch (e) {
      return { success: false, message: firebaseErrorMessage(e) };
    }
  }

  async function rejectMember(uid) {
    try {
      var ref = usersCol.doc(uid);
      var snap = await ref.get();
      if (!snap.exists) return { success: false, message: 'Member not found.' };
      var removed = Object.assign({ uid: uid }, snap.data());
      // NOTE: this removes their Firestore profile (so they disappear from
      // the directory and can no longer log in — login() rejects any Auth
      // account with no matching /users/{uid} doc). Deleting the underlying
      // Firebase Authentication account itself requires the Admin SDK /
      // Firebase console and can't be done from client-side JS.
      await ref.delete();
      return { success: true, user: removed };
    } catch (e) {
      return { success: false, message: firebaseErrorMessage(e) };
    }
  }

  // ---- Backup / Export & Reset (Group Settings items 8 & 9) ----
  async function exportAllData() {
    return {
      exportedAt: new Date().toISOString(),
      settings: await getSettings(),
      users: await getUsers(),
      collections: await getCollections()
    };
  }

  async function resetAllData() {
    try {
      var cols = [usersCol, collectionsCol, minutesCol, announcementsCol];
      for (var i = 0; i < cols.length; i++) {
        var snap = await cols[i].get();
        if (snap.empty) continue;
        var batch = db.batch();
        snap.docs.forEach(function (d) { batch.delete(d.ref); });
        await batch.commit();
      }
      try { await settingsDocRef.delete(); } catch (e) { /* ignore */ }
      await logout();
      return {
        success: true,
        message: 'All member, collection, minutes and announcement records were deleted. Note: this cannot delete the underlying Firebase Authentication accounts — remove those from the Firebase console if you want those emails to be reusable.'
      };
    } catch (e) {
      return { success: false, message: firebaseErrorMessage(e) };
    }
  }

  window.KatiniAuth = {
    ready: readyPromise,
    isAdminEmail: isAdminEmail,
    escapeHtml: escapeHtml,
    getUsers: getUsers,
    registerMember: registerMember,
    addMember: addMember,
    editMember: editMember,
    deleteMember: deleteMember,
    resetMemberPassword: resetMemberPassword,
    changePassword: changePassword,
    buildWhatsAppLink: buildWhatsAppLink,
    login: login,
    sendLoginLink: sendLoginLink,
    sendPasswordReset: sendPasswordReset,
    isEmailLinkSignIn: isEmailLinkSignIn,
    completeEmailLinkSignIn: completeEmailLinkSignIn,
    isWebAuthnSupported: isWebAuthnSupported,
    isPlatformAuthenticatorAvailable: isPlatformAuthenticatorAvailable,
    isBiometricEnabled: isBiometricEnabled,
    enableBiometricUnlock: enableBiometricUnlock,
    disableBiometricUnlock: disableBiometricUnlock,
    requireBiometricUnlock: requireBiometricUnlock,
    logout: logout,
    getSession: getSession,
    getCurrentUser: getCurrentUser,
    routeToHome: routeToHome,
    goToCommitteeDashboard: goToCommitteeDashboard,
    goDashboard: goDashboard,
    requireRole: requireRole,
    getCollections: getCollections,
    getMyCollections: getMyCollections,
    addCollection: addCollection,
    getMinutes: getMinutes,
    addMinutes: addMinutes,
    getMinutesById: getMinutesById,
    deleteMinutes: deleteMinutes,
    getAnnouncements: getAnnouncements,
    sendAnnouncement: sendAnnouncement,
    getUnreadAnnouncementCount: getUnreadAnnouncementCount,
    markAnnouncementRead: markAnnouncementRead,
    markAllAnnouncementsRead: markAllAnnouncementsRead,
    getPaymentSummary: getPaymentSummary,
    getTopCollectors: getTopCollectors,
    getDailyTotals: getDailyTotals,
    getSettings: getSettings,
    saveSettings: saveSettings,
    getGroupStats: getGroupStats,
    getMemberPaymentSummary: getMemberPaymentSummary,
    getNextPaymentDue: getNextPaymentDue,
    getMemberPaymentsByDay: getMemberPaymentsByDay,
    uploadGroupDocument: uploadGroupDocument,
    getGroupDocuments: getGroupDocuments,
    deleteGroupDocument: deleteGroupDocument,
    createAdmin: createAdmin,
    setUserRole: setUserRole,
    setCommitteeRole: setCommitteeRole,
    getCommitteeMembers: getCommitteeMembers,
    getAdmins: getAdmins,
    getPendingMembers: getPendingMembers,
    approveMember: approveMember,
    rejectMember: rejectMember,
    exportAllData: exportAllData,
    resetAllData: resetAllData
  };
})(window);

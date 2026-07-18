// /api/reset-member-password.js
// ---------------------------------------------------------------------
// Vercel serverless function (Node.js runtime).
//
// WHY THIS EXISTS
// Firebase's client SDK can only change the password of whichever account
// is currently signed in. There is no client-side call that lets a signed-
// in admin set a DIFFERENT member's password — that requires the Firebase
// Admin SDK, which needs a service-account key and must run server-side.
// This function is that (very small, single-purpose) server side.
//
// SETUP (one-time)
// 1. In the Firebase console: Project settings -> Service accounts ->
//    "Generate new private key". This downloads a JSON file — keep it
//    secret, never commit it to the repo.
// 2. In your Vercel project: Settings -> Environment Variables, add:
//      FIREBASE_SERVICE_ACCOUNT   = the full contents of that JSON file
//        (paste as one line/string — Vercel accepts multi-line values too)
// 3. Add "firebase-admin" as a dependency (package.json):
//      npm install firebase-admin
//    Vercel will install it automatically on deploy since this file sits
//    under /api.
// 4. Deploy. That's it — no other code changes are needed; auth.js's
//    resetMemberPassword() already calls this endpoint and fails
//    gracefully with a clear message if it isn't set up yet.
//
// SECURITY
// The caller must send a valid Firebase ID token for an account whose own
// Firestore /users/{uid} doc has role == 'admin' — this function verifies
// both the token AND the admin role server-side before touching anything,
// so it can't be called by a member or a stranger with a crafted request.
// ---------------------------------------------------------------------

const admin = require('firebase-admin');

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(
      JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT)
    )
  });
}

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    res.status(405).json({ success: false, message: 'Method not allowed.' });
    return;
  }

  try {
    const { idToken, uid, newPassword } = req.body || {};
    if (!idToken || !uid || !newPassword) {
      res.status(400).json({ success: false, message: 'Missing idToken, uid or newPassword.' });
      return;
    }
    if (String(newPassword).length < 6) {
      res.status(400).json({ success: false, message: 'Password must be at least 6 characters.' });
      return;
    }

    // 1. Verify the caller is who they claim to be.
    const decoded = await admin.auth().verifyIdToken(idToken);

    // 2. Verify the caller is an admin (reads their OWN profile — mirrors
    //    the isAdmin() check in firestore.rules).
    const callerSnap = await admin.firestore().collection('users').doc(decoded.uid).get();
    if (!callerSnap.exists || callerSnap.data().role !== 'admin') {
      res.status(403).json({ success: false, message: 'Only admins can reset member passwords.' });
      return;
    }

    // 3. Set the new password on the TARGET member's Auth account.
    await admin.auth().updateUser(uid, { password: newPassword });

    res.status(200).json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message || 'Password reset failed.' });
  }
};

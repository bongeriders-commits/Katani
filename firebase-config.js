/* ===================================================================
   Katani Main Stage — Firebase config
   -------------------------------------------------------------------
   These are client identifiers, not secrets — safe to deploy publicly.
   Your data is protected by firestore.rules, not by hiding this file.
   See FIREBASE_SETUP.md for the rest of the setup steps.
=================================================================== */
window.FIREBASE_CONFIG = {
  apiKey: "AIzaSyBYWhD205uK1JTBltlCnVAnOE4rSHQM4bQ",
  authDomain: "katani-main-stage.firebaseapp.com",
  projectId: "katani-main-stage",
  storageBucket: "katani-main-stage.firebasestorage.app",
  messagingSenderId: "220892403551",
  appId: "1:220892403551:web:575d8bd0b40751144848ea"
};

/* Emails that are allowed to be promoted to admin via the
   "Create Admin" flow and that are treated as reserved (cannot be
   used for public self-registration). Keep this in sync with the
   ADMIN-only bootstrap email you create by hand the first time
   (see FIREBASE_SETUP.md, step 6) — after that, all further admins
   should be created from the Admin Dashboard, not by editing this list.
   EDIT THESE to the real committee email(s) for your group. */
window.RESERVED_ADMIN_EMAILS = [
  'admin@katanimainstage.co.ke',
  'chairman@katanimainstage.co.ke',
  'treasurer@katanimainstage.co.ke'
];

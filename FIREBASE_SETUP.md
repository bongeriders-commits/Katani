# Katani Main Stage — Firebase Setup

This app now uses **Firebase Authentication** (for passwords) and
**Cloud Firestore** (for member/payment/minutes/announcement data)
instead of `localStorage`. Follow these steps once, in order.

## 1. Create the Firebase project
1. Go to https://console.firebase.google.com and click **Add project**.
2. Name it (e.g. "Katani Main Stage"), finish the wizard.

## 2. Register a Web app
1. In the project, click the **</>** (Web) icon to add a web app.
2. Give it a nickname (e.g. "katani-web"). You don't need Firebase Hosting.
3. Copy the `firebaseConfig` object it shows you.
4. Paste those values into `firebase-config.js` in place of the
   `REPLACE_WITH_...` placeholders.

## 3. Enable Authentication
1. In the console sidebar: **Build -> Authentication -> Get started**.
2. Under **Sign-in method**, enable **Email/Password**.
3. On that same **Sign-in method** screen, also enable **Email link
   (passwordless sign-in)** — this powers the "Email Link" tab on the
   login screen. It only lets *already-registered* members in: the app
   signs anyone without a matching Firestore profile straight back out
   after they click the link (see `finalizeSession()` in `auth.js`).

## 4. Create Firestore
1. In the console sidebar: **Build -> Firestore Database -> Create database**.
2. Choose **Production mode** (the rules file below is the real protection —
   don't use test mode, it's wide open to anyone).
3. Pick a region close to Kenya (e.g. `europe-west1` or `eur3`).

## 5. Deploy the security rules
The rules live in `firestore.rules` and are what actually protects your
data — `firebase-config.js` is not a secret and doesn't need to be hidden.

**Easiest way (console):**
1. Firestore Database -> **Rules** tab.
2. Paste the contents of `firestore.rules` in, replacing what's there.
3. Click **Publish**.

**Or with the Firebase CLI**, if you prefer version-controlled rules:
```
npm install -g firebase-tools
firebase login
firebase init firestore   # point it at this project, keep the existing firestore.rules
firebase deploy --only firestore:rules
```

## 6. Create your first admin (bootstrap)
The app can only create new admins from an *existing* admin's dashboard —
so the very first one has to be made by hand:

1. Authentication -> **Add user** -> enter one of the emails from
   `RESERVED_ADMIN_EMAILS` in `firebase-config.js` (e.g.
   `admin@katanimainstage.co.ke`) and a password. Copy the **User UID**
   it generates.
2. Firestore Database -> **Start collection** -> collection ID `users`.
3. Add a document with **Document ID = the UID you just copied**, and these fields:

   | field | type | value |
   |---|---|---|
   | name | string | e.g. `Committee Admin` |
   | email | string | the same email, lowercase |
   | role | string | `admin` |
   | status | string | `active` |
   | memberId | string | e.g. `KMS-100001` |
   | phone | string | `` (blank is fine) |

4. Log in to the app with that email/password — you should land on the Admin Dashboard.
   From there, use **Create Admin** to add any further committee accounts properly.

## 7. Load the app locally / deploy
The app is still a static site — same Vercel/GitHub deploy flow as before.
Just make sure these load, in this order, on every page (already wired up
in the HTML): the Firebase SDK scripts, then `firebase-config.js`, then `auth.js`.

If you use the Email Link login option, make sure your live domain (e.g.
`your-project.vercel.app`, and any custom domain) is listed under
**Authentication -> Settings -> Authorized domains** — Firebase refuses to
complete an email-link sign-in on a domain that isn't on that list.
`localhost` is there by default for local testing.

## Fingerprint / Face ID unlock (no extra setup needed)
After logging in (password or email link), the app offers to enable
fingerprint/Face ID unlock on that phone via the browser's built-in Web
Authentication API. This is entirely local to the device — nothing to
configure in Firebase, no server involved. It only requires HTTPS (which
Vercel already gives you) and a phone with a fingerprint/Face sensor. If a
member's phone doesn't support it, the prompt is simply skipped and they
keep using password/email-link login as normal.

## What changed vs. the old localStorage version
- Passwords are no longer stored anywhere in your data — Firebase Auth
  hashes and owns them entirely. `exportAllData()` no longer includes a
  password field at all.
- Every `KatiniAuth.*` call is now **async** — pages `await` it instead of
  reading a return value directly.
- Access control is enforced **server-side** by `firestore.rules`, not
  just by JavaScript running in the browser.

## Known limitation: rejecting a pending member
`rejectMember()` deletes the member's Firestore profile (so they lose
portal access), but a client app cannot delete another user's Firebase
Auth account — that requires the Admin SDK. If you want "Reject" to fully
remove the login too, add a small Cloud Function (or do it by hand once in
a while in Authentication -> Users) that deletes any Auth user with no
matching Firestore profile.

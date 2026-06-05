# 🔒 ShieldGate - Secure Authentication System

ShieldGate is a full-stack, state-of-the-art secure authentication web application built using Node.js, Express, SQLite, and vanilla frontend technologies (HTML5, CSS3, and JavaScript). 

It showcases standard industry best practices in web application security, brute-force mitigation, session management, and two-factor authentication (2FA).

---

## 🚀 Key Features

### 🛡️ Core Security Architecture
* **SQL Injection Protection**: Built strictly using prepared statements and parameterized queries for all database operations (zero dynamic query concatenation).
* **Cryptographic Hashing**: User passwords are secure-hashed using `bcryptjs` with `12` salt rounds.
* **Dual-Tiered Rate Limiting**: 
  * General API Limiter: Prevents API scraping and DDoS attacks (100 requests / 15 mins).
  * Strict Auth Limiter: Protects login, registration, and password changes from brute-force and credential stuffing (5 requests / 15 mins).
* **Helmet & Secure HTTP Headers**: Integrated Content Security Policy (CSP), HTTP Strict Transport Security (HSTS), and XSS protections using `helmet`.

### 🔑 Session Management (Anti-Hijack & Revocation)
* **HttpOnly Cookies**: Session cookies are delivered via `HttpOnly`, `SameSite=Lax` parameters to prevent XSS-based reading.
* **User-Agent Pinning**: Sessions are bound to the client's browser signature. If the User-Agent changes on an active cookie, the session is revoked immediately and flagged as a security warning.
* **SHA-256 Session Alias**: Raw session secret tokens are never sent back to the browser in session lists. Instead, they are represented via a SHA-256 hash. Revocation commands match this hash on the backend, safeguarding session IDs.
* **Remote Session Revocation**: A dashboard panel listing all active devices with the ability to log out other devices remotely.

### 🧩 Advanced Defenses & 2FA
* **Account Lockout Policy**: Temporary account lockout for **15 minutes** after **5 failed login attempts**.
* **Timing Attack Mitigation**: Runs a dummy bcrypt comparison if a user is not found to consume the same processing time as checking a valid user.
* **TOTP Two-Factor Authentication**: Integrates Time-based One-Time Passwords (compatible with Google Authenticator, Authy, etc.) using dynamic QR code generation.
* **Hashed Recovery Backup Codes**: Generates **5 backup codes** when 2FA is enabled. The codes are hashed in SQLite using `bcrypt` and can be used for single-use recovery.
* **Session Termination on Password Update**: Changing a password automatically invalidates all *other* active sessions.

### 🎨 Visual & Auditing Elements
* **Security Audit Logs**: Interactive table detailing real-time actions (e.g., successful/failed login, 2FA toggle, session revocation) with client IP and User-Agent details.
* **Live Password Strength Meter**: Interactive entropic strength progress bar checking for length, case combinations, numbers, and special characters.
* **Premium Theme Styles**: Glassmorphic panels, CSS-animated ambient backgrounds, micro-transitions, toast notification alerts, and a fluid dark/light theme switch.

---

## 📂 Project Structure

```text
secure-login-system/
├── package.json         # Dependencies and dev scripts
├── .env                 # Environment configurations
├── server.js            # Express server entry point
├── database.js          # SQLite connection and database schema tables
├── verify_security.js   # Custom security test suite
├── middleware/
│   ├── auth.js          # Session parsing & User-Agent verification middleware
│   └── rateLimiter.js   # General and Auth rate limiter setups
├── routes/
│   ├── auth.js          # Registration, Login, Logout controllers
│   └── user.js          # Profile metadata, Sessions, and 2FA controllers
└── public/              # Static Frontend assets
    ├── index.html       # Client Single Page Application (SPA)
    ├── css/
    │   └── style.css    # Premium Vanilla CSS stylesheet
    └── js/
        ├── api.js       # Client API wrapper (Fetch integration)
        └── app.js       # UI state, live strength meter, and forms controller
```

---

## 🛠️ Getting Started

### Prerequisites
* [Node.js](https://nodejs.org/) (v18 or higher recommended)
* `npm` (Node Package Manager)

### Installation

1. Clone or copy the project files to your local system and open the directory:
   ```bash
   cd secure-login-system
   ```

2. Install the required Node.js dependencies:
   ```bash
   npm install
   ```

3. Configure your environment. Copy or create a `.env` file in the root directory:
   ```env
   PORT=3000
   NODE_ENV=development
   COOKIE_SECURE=false
   SESSION_SECRET=f3b1db88e5d0f6222bce3cd3199c0dcfd5eb77f2bcdeea7ff8cf085b1a82f3ef
   ```
   *(Note: Set `COOKIE_SECURE=true` in production environments when serving over HTTPS).*

### Running the Application

* To run the server in **development mode** (with hot-reload watch enabled):
  ```bash
  npm run dev
  ```

* To start the server in **production mode**:
  ```bash
  npm start
  ```

Once started, open your browser and navigate to:
```text
http://localhost:3000
```

---

## 🧪 Security Verification Tests

We have included an automated test script to verify database constraints, SQL injection resistance, and account lockout thresholds.

To run the verification suite:
```bash
node verify_security.js
```

### Expected Output:
```text
===================================================
🧪 Starting Security Verification Tests
===================================================

✅ SQLite Database Connection: Success
✅ Seeded Test User: "securesandbox" with Password: "Password123!"

--- Test 1: SQL Injection Protection Check ---
Injecting payload into username lookup: "' OR '1'='1"
✅ Success: Prepared statements successfully mitigated SQL injection.

--- Test 2: Password Verification Check ---
Bcrypt compare correct password: ✅ Passed
Bcrypt compare incorrect password returns false: ✅ Passed

--- Test 3: Lockout Tracking Simulation ---
Initial failed attempts count: 0
Simulating 5 consecutive failed login attempts...
Failed attempts after simulation: 5
Lockout timestamp set: ✅ Yes
✅ Lockout enforcement check: Account is active-locked as expected.
Cleanup: Test user login metrics reset.

===================================================
🏁 Security Verification Complete
===================================================
```

---

## 📜 License
This project is open-source and intended for educational and security demonstration purposes. Built with best practices in fullstack software engineering.

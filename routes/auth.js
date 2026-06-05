const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const speakeasy = require('speakeasy');
const { getDatabase, logSecurityEvent } = require('../database');
const { authLimiter } = require('../middleware/rateLimiter');

// Password strength validation regex
// - At least 8 characters
// - At least 1 uppercase letter
// - At least 1 lowercase letter
// - At least 1 number
// - At least 1 special character
const PASSWORD_REGEX = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const USERNAME_REGEX = /^[a-zA-Z0-9_-]{3,20}$/;

// REGISTER ENDPOINT
router.post('/register', authLimiter, async (req, res) => {
  const { username, email, password } = req.body;

  // 1. Basic Input Validation (Protection from SQL Injection is handled via prepared statements below)
  if (!username || !email || !password) {
    return res.status(400).json({ success: false, error: 'All fields are required' });
  }

  if (!USERNAME_REGEX.test(username)) {
    return res.status(400).json({ 
      success: false, 
      error: 'Username must be 3-20 characters long and contain only alphanumeric characters, underscores, or hyphens.' 
    });
  }

  if (!EMAIL_REGEX.test(email)) {
    return res.status(400).json({ success: false, error: 'Please provide a valid email address.' });
  }

  if (!PASSWORD_REGEX.test(password)) {
    return res.status(400).json({ 
      success: false, 
      error: 'Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character.' 
    });
  }

  try {
    const db = await getDatabase();

    // Check if username or email already exists (using parameterized queries)
    const existingUser = await db.get(
      'SELECT id FROM users WHERE username = ? OR email = ?',
      [username, email]
    );

    if (existingUser) {
      // Return a slightly ambiguous message to deter account enumeration, 
      // but clear enough for UX under rate-limiting.
      return res.status(400).json({ 
        success: false, 
        error: 'Username or email already registered' 
      });
    }

    // 2. Password Hashing
    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);

    // 3. Save to database using parameterized query (SQL Injection Protection)
    const result = await db.run(
      'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
      [username, email, passwordHash]
    );

    const newUserId = result.lastID;
    await logSecurityEvent(newUserId, 'registration_success', req);

    res.status(201).json({ 
      success: true, 
      message: 'Registration successful! You can now log in.' 
    });

  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// LOGIN ENDPOINT
router.post('/login', authLimiter, async (req, res) => {
  const { usernameOrEmail, password, twoFactorCode } = req.body;

  if (!usernameOrEmail || !password) {
    return res.status(400).json({ success: false, error: 'Username/Email and password are required' });
  }

  try {
    const db = await getDatabase();

    // Retrieve user by username or email
    const user = await db.get(
      'SELECT * FROM users WHERE username = ? OR email = ?',
      [usernameOrEmail, usernameOrEmail]
    );

    // Timing attack mitigation: if user does not exist, run a dummy bcrypt compare
    // to consume roughly the same time as a valid user comparison.
    if (!user) {
      // Dummy hash of "password" is: $2a$12$LRYuN8v8W.s5kGk6a2Zp.O3N33f0p.i7jF/BwD0z2o4lM9R9H1J4m
      await bcrypt.compare(password, '$2a$12$LRYuN8v8W.s5kGk6a2Zp.O3N33f0p.i7jF/BwD0z2o4lM9R9H1J4m');
      return res.status(401).json({ success: false, error: 'Invalid username/email or password' });
    }

    // Check Account Lockout
    const now = new Date();
    if (user.lockout_until) {
      const lockoutTime = new Date(user.lockout_until);
      if (now < lockoutTime) {
        const remainingMinutes = Math.ceil((lockoutTime - now) / 60000);
        return res.status(403).json({ 
          success: false, 
          error: `Account is temporarily locked due to too many failed login attempts. Try again in ${remainingMinutes} minutes.` 
        });
      } else {
        // Lockout expired, reset counters in db
        await db.run(
          'UPDATE users SET failed_login_attempts = 0, lockout_until = NULL WHERE id = ?',
          [user.id]
        );
        user.failed_login_attempts = 0;
        user.lockout_until = null;
      }
    }

    // Verify Password
    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatch) {
      // Increment failed attempts
      const newFailedAttempts = user.failed_login_attempts + 1;
      let lockoutUntil = null;
      
      if (newFailedAttempts >= 5) {
        // Lock for 15 minutes
        lockoutUntil = new Date(now.getTime() + 15 * 60 * 1000).toISOString();
        await db.run(
          'UPDATE users SET failed_login_attempts = ?, lockout_until = ? WHERE id = ?',
          [newFailedAttempts, lockoutUntil, user.id]
        );
        await logSecurityEvent(user.id, 'account_lockout', req);
        return res.status(403).json({ 
          success: false, 
          error: 'Too many failed login attempts. Your account has been locked for 15 minutes.' 
        });
      } else {
        await db.run(
          'UPDATE users SET failed_login_attempts = ? WHERE id = ?',
          [newFailedAttempts, user.id]
        );
        await logSecurityEvent(user.id, 'failed_login_attempt', req);
        return res.status(401).json({ success: false, error: 'Invalid username/email or password' });
      }
    }

    // Password matches! Reset failed attempts
    await db.run(
      'UPDATE users SET failed_login_attempts = 0, lockout_until = NULL WHERE id = ?',
      [user.id]
    );

    // Two-Factor Authentication Check
    if (user.two_factor_enabled === 1) {
      if (!twoFactorCode) {
        // Inform frontend that 2FA code is required
        return res.status(200).json({ 
          success: true, 
          requires2FA: true, 
          userId: user.id,
          message: 'Two-factor authentication code required'
        });
      }

      // Check standard TOTP
      let isVerified = speakeasy.totp.verify({
        secret: user.two_factor_secret,
        encoding: 'base32',
        token: twoFactorCode,
        window: 1 // Allow 30s drift before or after
      });

      let backupCodeUsed = false;

      // If TOTP verification fails, check backup codes
      if (!isVerified) {
        const codes = await db.all('SELECT * FROM backup_codes WHERE user_id = ? AND used = 0', [user.id]);
        for (const c of codes) {
          const match = await bcrypt.compare(twoFactorCode, c.code_hash);
          if (match) {
            isVerified = true;
            backupCodeUsed = true;
            // Mark code as used
            await db.run('UPDATE backup_codes SET used = 1 WHERE id = ?', [c.id]);
            await logSecurityEvent(user.id, 'backup_code_used', req);
            break;
          }
        }
      }

      if (!isVerified) {
        await logSecurityEvent(user.id, 'failed_2fa_verification', req);
        return res.status(401).json({ success: false, error: 'Invalid 2FA code' });
      }
    }

    // CREATE SESSION
    const sessionToken = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(now.getTime() + 24 * 60 * 60 * 1000).toISOString(); // 24 hours absolute life
    const ipAddress = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
    const userAgent = req.headers['user-agent'] || 'unknown';

    await db.run(
      `INSERT INTO sessions (id, user_id, user_agent, ip_address, expires_at) 
       VALUES (?, ?, ?, ?, ?)`,
      [sessionToken, user.id, userAgent, ipAddress, expiresAt]
    );

    await logSecurityEvent(user.id, 'login_success', req);

    // Set secure cookie
    const isSecure = process.env.COOKIE_SECURE === 'true';
    res.cookie('session_id', sessionToken, {
      httpOnly: true, // Crucial for XSS prevention
      secure: isSecure, // Send only over HTTPS
      sameSite: 'lax', // Protects against CSRF
      maxAge: 24 * 60 * 60 * 1000 // 1 day
    });

    return res.status(200).json({
      success: true,
      user: {
        username: user.username,
        email: user.email,
        twoFactorEnabled: user.two_factor_enabled === 1
      }
    });

  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// LOGOUT ENDPOINT
router.post('/logout', async (req, res) => {
  const sessionId = req.cookies.session_id;

  if (sessionId) {
    try {
      const db = await getDatabase();
      const session = await db.get('SELECT user_id FROM sessions WHERE id = ?', [sessionId]);
      if (session) {
        await db.run('DELETE FROM sessions WHERE id = ?', [sessionId]);
        await logSecurityEvent(session.user_id, 'logout_success', req);
      }
    } catch (err) {
      console.error('Logout error:', err);
    }
  }

  res.clearCookie('session_id');
  res.status(200).json({ success: true, message: 'Logged out successfully' });
});

module.exports = router;

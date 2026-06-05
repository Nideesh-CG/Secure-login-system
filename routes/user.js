const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const { getDatabase, logSecurityEvent } = require('../database');
const { requireAuth } = require('../middleware/auth');
const { authLimiter } = require('../middleware/rateLimiter');

// Regex for validation
const PASSWORD_REGEX = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

// Helper to hash session IDs to avoid exposing raw session tokens to JavaScript
function hashSessionId(id) {
  return crypto.createHash('sha256').update(id).digest('hex');
}

// Apply authentication middleware to all routes in this router
router.use(requireAuth);

// GET USER PROFILE
router.get('/profile', (req, res) => {
  res.status(200).json({
    success: true,
    user: {
      username: req.user.username,
      email: req.user.email,
      twoFactorEnabled: req.user.twoFactorEnabled
    }
  });
});

// GET ACTIVE SESSIONS
router.get('/sessions', async (req, res) => {
  try {
    const db = await getDatabase();
    
    // Retrieve all active sessions for the logged-in user
    const sessions = await db.all(
      'SELECT id, user_agent, ip_address, created_at, last_active_at FROM sessions WHERE user_id = ?',
      [req.user.id]
    );

    // Map sessions to hide the raw secret session ID from the client,
    // exposing a secure SHA-256 hash/alias of the ID instead.
    const mappedSessions = sessions.map(s => {
      const sHash = hashSessionId(s.id);
      return {
        hash: sHash,
        userAgent: s.user_agent,
        ipAddress: s.ip_address,
        createdAt: s.created_at,
        lastActiveAt: s.last_active_at,
        isCurrent: s.id === req.session.id
      };
    });

    res.status(200).json({ success: true, sessions: mappedSessions });
  } catch (err) {
    console.error('Fetch sessions error:', err);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// REVOKE A SESSION (Logout remote device)
router.post('/sessions/revoke', async (req, res) => {
  const { sessionHash } = req.body;

  if (!sessionHash) {
    return res.status(400).json({ success: false, error: 'Session hash required' });
  }

  try {
    const db = await getDatabase();
    
    // Find all sessions for this user
    const sessions = await db.all('SELECT id FROM sessions WHERE user_id = ?', [req.user.id]);
    
    // Find the session that matches the hashed session token
    const targetSession = sessions.find(s => hashSessionId(s.id) === sessionHash);

    if (!targetSession) {
      return res.status(404).json({ success: false, error: 'Session not found' });
    }

    // Revoke target session
    await db.run('DELETE FROM sessions WHERE id = ?', [targetSession.id]);
    
    // Log the revocation event
    await logSecurityEvent(req.user.id, 'session_revoked', req);

    // If revoking current session, clear cookie
    if (targetSession.id === req.session.id) {
      res.clearCookie('session_id');
      return res.status(200).json({ success: true, loggedOutCurrent: true, message: 'Current session revoked' });
    }

    res.status(200).json({ success: true, message: 'Session revoked successfully' });
  } catch (err) {
    console.error('Revoke session error:', err);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// GET SECURITY AUDIT LOGS
router.get('/security-logs', async (req, res) => {
  try {
    const db = await getDatabase();
    
    // Retrieve last 30 logs for this user
    const logs = await db.all(
      'SELECT event_type, ip_address, user_agent, created_at FROM security_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT 30',
      [req.user.id]
    );

    res.status(200).json({ success: true, logs });
  } catch (err) {
    console.error('Fetch security logs error:', err);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// SETUP TWO-FACTOR AUTH (Generate TOTP secret & QR code)
router.post('/setup-2fa', async (req, res) => {
  try {
    const db = await getDatabase();

    // Verify 2FA isn't already enabled
    if (req.user.twoFactorEnabled) {
      return res.status(400).json({ success: false, error: '2FA is already enabled' });
    }

    // Generate a secure, unique TOTP secret
    const secret = speakeasy.generateSecret({
      name: `SecureLogin:${req.user.email}`,
      length: 20
    });

    // Save the secret in the database temporarily (unverified status)
    await db.run(
      'UPDATE users SET two_factor_secret = ?, two_factor_enabled = 0 WHERE id = ?',
      [secret.base32, req.user.id]
    );

    // Generate QR Code URL
    const qrCodeDataUrl = await qrcode.toDataURL(secret.otpauth_url);

    res.status(200).json({
      success: true,
      secret: secret.base32,
      qrCode: qrCodeDataUrl
    });

  } catch (err) {
    console.error('2FA setup error:', err);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// ENABLE TWO-FACTOR AUTH (Verify token, activate, generate recovery codes)
router.post('/enable-2fa', authLimiter, async (req, res) => {
  const { code } = req.body;

  if (!code) {
    return res.status(400).json({ success: false, error: 'Verification code is required' });
  }

  try {
    const db = await getDatabase();

    // Fetch fresh user details to check secret
    const user = await db.get('SELECT two_factor_secret, two_factor_enabled FROM users WHERE id = ?', [req.user.id]);

    if (!user || !user.two_factor_secret) {
      return res.status(400).json({ success: false, error: 'Two-factor authentication has not been set up yet' });
    }

    if (user.two_factor_enabled === 1) {
      return res.status(400).json({ success: false, error: '2FA is already enabled' });
    }

    // Verify TOTP Code
    const isVerified = speakeasy.totp.verify({
      secret: user.two_factor_secret,
      encoding: 'base32',
      token: code,
      window: 1
    });

    if (!isVerified) {
      await logSecurityEvent(req.user.id, 'failed_2fa_setup_attempt', req);
      return res.status(400).json({ success: false, error: 'Invalid verification code. Please check your app.' });
    }

    // 2FA Verified! Activate in database
    await db.run('UPDATE users SET two_factor_enabled = 1 WHERE id = ?', [req.user.id]);

    // Generate 5 Backup Recovery Codes
    const rawBackupCodes = [];
    const hashedCodesToInsert = [];

    for (let i = 0; i < 5; i++) {
      // 10 character alphanumeric code
      const rawCode = crypto.randomBytes(5).toString('hex');
      rawBackupCodes.push(rawCode);
      
      const salt = await bcrypt.genSalt(10);
      const hashedCode = await bcrypt.hash(rawCode, salt);
      hashedCodesToInsert.push(hashedCode);
    }

    // Clear any previous unused backup codes and insert new ones
    await db.run('DELETE FROM backup_codes WHERE user_id = ?', [req.user.id]);
    for (const hCode of hashedCodesToInsert) {
      await db.run(
        'INSERT INTO backup_codes (user_id, code_hash) VALUES (?, ?)',
        [req.user.id, hCode]
      );
    }

    await logSecurityEvent(req.user.id, '2fa_enabled', req);

    res.status(200).json({
      success: true,
      message: 'Two-factor authentication successfully enabled!',
      backupCodes: rawBackupCodes
    });

  } catch (err) {
    console.error('Enable 2FA error:', err);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// DISABLE TWO-FACTOR AUTH
router.post('/disable-2fa', authLimiter, async (req, res) => {
  try {
    const db = await getDatabase();

    // Disable in db, delete secrets and backup codes
    await db.run(
      'UPDATE users SET two_factor_enabled = 0, two_factor_secret = NULL WHERE id = ?',
      [req.user.id]
    );
    await db.run('DELETE FROM backup_codes WHERE user_id = ?', [req.user.id]);

    await logSecurityEvent(req.user.id, '2fa_disabled', req);

    res.status(200).json({ success: true, message: 'Two-factor authentication has been disabled.' });
  } catch (err) {
    console.error('Disable 2FA error:', err);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// CHANGE PASSWORD (with logout of other devices)
router.post('/change-password', authLimiter, async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword) {
    return res.status(400).json({ success: false, error: 'Current password and new password are required' });
  }

  if (!PASSWORD_REGEX.test(newPassword)) {
    return res.status(400).json({ 
      success: false, 
      error: 'New password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character.' 
    });
  }

  try {
    const db = await getDatabase();

    // Fetch current password hash from db
    const user = await db.get('SELECT password_hash FROM users WHERE id = ?', [req.user.id]);

    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    // Verify current password matches
    const isMatch = await bcrypt.compare(currentPassword, user.password_hash);
    if (!isMatch) {
      await logSecurityEvent(req.user.id, 'failed_password_change_attempt', req);
      return res.status(400).json({ success: false, error: 'Current password is incorrect' });
    }

    // Hash the new password
    const salt = await bcrypt.genSalt(12);
    const newPasswordHash = await bcrypt.hash(newPassword, salt);

    // Update password in db
    await db.run('UPDATE users SET password_hash = ? WHERE id = ?', [newPasswordHash, req.user.id]);

    // Revoke all other sessions for this user (Defense in Depth: terminate other sessions upon password change)
    await db.run('DELETE FROM sessions WHERE user_id = ? AND id != ?', [req.user.id, req.session.id]);

    await logSecurityEvent(req.user.id, 'password_change', req);

    res.status(200).json({ 
      success: true, 
      message: 'Password updated successfully! All other active sessions have been invalidated.' 
    });

  } catch (err) {
    console.error('Password change error:', err);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

module.exports = router;

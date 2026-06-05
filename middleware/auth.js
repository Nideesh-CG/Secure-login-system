const { getDatabase, logSecurityEvent } = require('../database');

async function requireAuth(req, res, next) {
  const sessionId = req.cookies.session_id;

  if (!sessionId) {
    return res.status(401).json({ success: false, error: 'Unauthorized: No session cookie' });
  }

  try {
    const db = await getDatabase();
    
    // Look up session and join with user info
    const session = await db.get(
      `SELECT s.*, u.username, u.email, u.two_factor_enabled, u.two_factor_secret
       FROM sessions s 
       JOIN users u ON s.user_id = u.id 
       WHERE s.id = ?`,
      [sessionId]
    );

    if (!session) {
      // Clear invalid cookie
      res.clearCookie('session_id');
      return res.status(401).json({ success: false, error: 'Unauthorized: Invalid session' });
    }

    // Check expiration
    const now = new Date();
    const expiresAt = new Date(session.expires_at);
    if (now > expiresAt) {
      // Session expired, clean up
      await db.run('DELETE FROM sessions WHERE id = ?', [sessionId]);
      res.clearCookie('session_id');
      await logSecurityEvent(session.user_id, 'session_expired', req);
      return res.status(401).json({ success: false, error: 'Unauthorized: Session expired' });
    }

    // Security Check: User-Agent Pinning to mitigate session hijacking
    const currentUserAgent = req.headers['user-agent'] || 'unknown';
    if (session.user_agent !== currentUserAgent) {
      // Potential session hijacking! Revoke session and log security warning.
      await db.run('DELETE FROM sessions WHERE id = ?', [sessionId]);
      res.clearCookie('session_id');
      await logSecurityEvent(session.user_id, 'session_hijack_warning', req);
      return res.status(401).json({ 
        success: false, 
        error: 'Unauthorized: Session security check failed (User-Agent mismatch)' 
      });
    }

    // Optional: Log IP change without immediately revoking session
    const currentIp = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
    if (session.ip_address !== currentIp) {
      await logSecurityEvent(session.user_id, 'session_ip_changed', req);
    }

    // Idle timeout extension (e.g., extend by 30 minutes from now)
    const newExpiresAt = new Date(now.getTime() + 30 * 60 * 1000).toISOString();
    await db.run(
      'UPDATE sessions SET last_active_at = ?, expires_at = ? WHERE id = ?',
      [now.toISOString(), newExpiresAt, sessionId]
    );

    // Attach user and session details to req
    req.user = {
      id: session.user_id,
      username: session.username,
      email: session.email,
      twoFactorEnabled: session.two_factor_enabled === 1,
      twoFactorSecret: session.two_factor_secret
    };
    req.session = {
      id: session.id,
      userAgent: session.user_agent,
      ipAddress: session.ip_address,
      createdAt: session.created_at,
      lastActiveAt: session.last_active_at,
      expiresAt: newExpiresAt
    };

    next();
  } catch (err) {
    console.error('Auth middleware error:', err);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
}

module.exports = {
  requireAuth
};

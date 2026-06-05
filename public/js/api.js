/* ==========================================================================
   ShieldGate API Client Library
   ========================================================================== */

const API_BASE = '/api';

async function handleResponse(response) {
  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.error || 'Something went wrong. Please try again.');
  }
  return data;
}

const SecureAPI = {
  // --- AUTH ENDPOINTS ---
  auth: {
    async register(username, email, password) {
      const response = await fetch(`${API_BASE}/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, email, password })
      });
      return handleResponse(response);
    },

    async login(usernameOrEmail, password, twoFactorCode = '') {
      const response = await fetch(`${API_BASE}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ usernameOrEmail, password, twoFactorCode })
      });
      return handleResponse(response);
    },

    async logout() {
      const response = await fetch(`${API_BASE}/auth/logout`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });
      return handleResponse(response);
    }
  },

  // --- USER PROFILE & CONFIG ENDPOINTS ---
  user: {
    async getProfile() {
      const response = await fetch(`${API_BASE}/user/profile`, {
        method: 'GET',
        headers: { 'Accept': 'application/json' }
      });
      return handleResponse(response);
    },

    async getSessions() {
      const response = await fetch(`${API_BASE}/user/sessions`, {
        method: 'GET',
        headers: { 'Accept': 'application/json' }
      });
      return handleResponse(response);
    },

    async revokeSession(sessionHash) {
      const response = await fetch(`${API_BASE}/user/sessions/revoke`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sessionHash })
      });
      return handleResponse(response);
    },

    async getSecurityLogs() {
      const response = await fetch(`${API_BASE}/user/security-logs`, {
        method: 'GET',
        headers: { 'Accept': 'application/json' }
      });
      return handleResponse(response);
    },

    async setup2FA() {
      const response = await fetch(`${API_BASE}/user/setup-2fa`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });
      return handleResponse(response);
    },

    async enable2FA(code) {
      const response = await fetch(`${API_BASE}/user/enable-2fa`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code })
      });
      return handleResponse(response);
    },

    async disable2FA() {
      const response = await fetch(`${API_BASE}/user/disable-2fa`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });
      return handleResponse(response);
    },

    async changePassword(currentPassword, newPassword) {
      const response = await fetch(`${API_BASE}/user/change-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ currentPassword, newPassword })
      });
      return handleResponse(response);
    }
  }
};

// Export to window scope
window.SecureAPI = SecureAPI;

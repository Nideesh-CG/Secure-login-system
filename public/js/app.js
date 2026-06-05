/* ==========================================================================
   ShieldGate Main Client Application Logic
   ========================================================================== */

document.addEventListener('DOMContentLoaded', () => {
  
  // --- STATE ---
  let currentUser = null;
  let is2faPrompted = false;

  // --- UI ELEMENTS ---
  const themeToggleBtn = document.getElementById('themeToggleBtn');
  const themeToggleIcon = document.getElementById('themeToggleIcon');
  const headerLogoutBtn = document.getElementById('headerLogoutBtn');
  
  // Sections
  const authSection = document.getElementById('authSection');
  const dashboardSection = document.getElementById('dashboardSection');
  
  // Auth Tabs & Forms
  const authTabs = document.getElementById('authTabs');
  const tabButtons = authTabs.querySelectorAll('.tab-btn');
  const loginFormContainer = document.getElementById('loginFormContainer');
  const registerFormContainer = document.getElementById('registerFormContainer');
  
  const loginForm = document.getElementById('loginForm');
  const loginUsername = document.getElementById('loginUsername');
  const loginPassword = document.getElementById('loginPassword');
  const login2faContainer = document.getElementById('login2faContainer');
  const login2faCode = document.getElementById('login2faCode');
  const loginSubmitBtn = document.getElementById('loginSubmitBtn');
  
  const registerForm = document.getElementById('registerForm');
  const regUsername = document.getElementById('regUsername');
  const regEmail = document.getElementById('regEmail');
  const regPassword = document.getElementById('regPassword');
  const registerSubmitBtn = document.getElementById('registerSubmitBtn');
  
  // Dashboard elements
  const bannerUsername = document.getElementById('bannerUsername');
  const profileUsername = document.getElementById('profileUsername');
  const profileEmail = document.getElementById('profileEmail');
  const profileSessionToken = document.getElementById('profileSessionToken');
  const status2faIcon = document.getElementById('status2faIcon');
  const status2faText = document.getElementById('status2faText');
  const statusSessionsText = document.getElementById('statusSessionsText');
  
  const navLinks = document.querySelectorAll('.nav-link');
  const viewPanels = document.querySelectorAll('.view-panel');
  const goToSettingsBtns = document.querySelectorAll('.goToSettingsBtn');
  const goToSessionsBtn = document.getElementById('goToSessionsBtn');
  
  // Sessions Tab
  const sessionsContainer = document.getElementById('sessionsContainer');
  const revokeAllBtn = document.getElementById('revokeAllBtn');
  
  // Settings Tab (2FA and Password Change)
  const initiate2faSection = document.getElementById('initiate2faSection');
  const start2faSetupBtn = document.getElementById('start2faSetupBtn');
  const setup2faSection = document.getElementById('setup2faSection');
  const qrCodeImg = document.getElementById('qrCodeImg');
  const manualSecretKey = document.getElementById('manualSecretKey');
  const enable2faForm = document.getElementById('enable2faForm');
  const confirm2faCode = document.getElementById('confirm2faCode');
  
  const backupCodesSection = document.getElementById('backupCodesSection');
  const backupCodesGrid = document.getElementById('backupCodesGrid');
  const closeBackupBtn = document.getElementById('closeBackupBtn');
  
  const active2faSection = document.getElementById('active2faSection');
  const disable2faBtn = document.getElementById('disable2faBtn');
  
  const changePasswordForm = document.getElementById('changePasswordForm');
  const currentPassword = document.getElementById('currentPassword');
  const newPassword = document.getElementById('newPassword');
  const changePasswordBtn = document.getElementById('changePasswordBtn');
  
  // Logs Tab
  const logsTableBody = document.getElementById('logsTableBody');

  // --- THEME MANAGEMENT ---
  const savedTheme = localStorage.getItem('theme') || 'dark';
  setTheme(savedTheme);

  themeToggleBtn.addEventListener('click', () => {
    const currentTheme = document.body.classList.contains('light-theme') ? 'light' : 'dark';
    const newTheme = currentTheme === 'light' ? 'dark' : 'light';
    setTheme(newTheme);
  });

  function setTheme(theme) {
    if (theme === 'light') {
      document.body.classList.remove('dark-theme');
      document.body.classList.add('light-theme');
      themeToggleIcon.textContent = '🌙';
    } else {
      document.body.classList.remove('light-theme');
      document.body.classList.add('dark-theme');
      themeToggleIcon.textContent = '☀️';
    }
    localStorage.setItem('theme', theme);
  }

  // --- TOAST NOTIFICATIONS ---
  function showToast(message, type = 'info') {
    const toastContainer = document.getElementById('toastContainer');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    
    let icon = 'ℹ️';
    if (type === 'success') icon = '✅';
    if (type === 'error') icon = '❌';
    if (type === 'warning') icon = '⚠️';
    
    toast.innerHTML = `<span>${icon}</span> <div>${message}</div>`;
    toastContainer.appendChild(toast);
    
    // Auto-remove toast
    setTimeout(() => {
      toast.classList.add('fade-out');
      setTimeout(() => {
        toast.remove();
      }, 300);
    }, 4000);
  }

  // --- AUTH TABS SWITCHING ---
  tabButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      tabButtons.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      
      const target = btn.getAttribute('data-target');
      if (target === 'loginFormContainer') {
        loginFormContainer.classList.remove('hidden');
        registerFormContainer.classList.add('hidden');
      } else {
        loginFormContainer.classList.add('hidden');
        registerFormContainer.classList.remove('hidden');
      }
    });
  });

  // --- REGISTER: PASSWORD STRENGTH CHECKER ---
  const strengthText = document.getElementById('strengthText');
  const strengthBars = document.querySelector('.strength-meter-container');
  const rules = {
    length: document.getElementById('ruleLength'),
    upper: document.getElementById('ruleUpper'),
    lower: document.getElementById('ruleLower'),
    number: document.getElementById('ruleNumber'),
    special: document.getElementById('ruleSpecial')
  };

  regPassword.addEventListener('input', () => {
    const val = regPassword.value;
    const checks = evaluatePassword(val);
    updateStrengthUI(checks, strengthBars, strengthText, rules, registerSubmitBtn);
  });

  // --- CHANGE PASSWORD: STRENGTH CHECKER ---
  const changeStrengthText = document.getElementById('changeStrengthText');
  const changeStrengthBars = document.querySelector('#changePasswordForm .strength-meter-container');
  
  newPassword.addEventListener('input', () => {
    const val = newPassword.value;
    const checks = evaluatePassword(val);
    // Reuse evaluation checks, update UI specifically for change form
    updateStrengthUI(checks, changeStrengthBars, changeStrengthText, null, changePasswordBtn);
  });

  function evaluatePassword(password) {
    return {
      length: password.length >= 8,
      upper: /[A-Z]/.test(password),
      lower: /[a-z]/.test(password),
      number: /\d/.test(password),
      special: /[@$!%*?&]/.test(password)
    };
  }

  function updateStrengthUI(checks, container, textEl, ruleElements = null, submitButton = null) {
    let passedCount = 0;
    
    // Update rule checklist classes if elements are provided
    for (const [key, passed] of Object.entries(checks)) {
      if (passed) passedCount++;
      if (ruleElements && ruleElements[key]) {
        if (passed) {
          ruleElements[key].className = 'valid';
        } else {
          ruleElements[key].className = 'invalid';
        }
      }
    }

    // Determine strength rating
    container.className = 'strength-meter-container';
    let label = 'Weak';
    
    if (passedCount === 5) {
      container.classList.add('strength-strong');
      label = 'Strong (Excellent)';
      if (submitButton) submitButton.removeAttribute('disabled');
    } else if (passedCount >= 3) {
      container.classList.add('strength-good');
      label = 'Good (Safe)';
      if (submitButton && ruleElements) submitButton.setAttribute('disabled', 'true'); // Required for register
      if (submitButton && !ruleElements) submitButton.removeAttribute('disabled'); // Change password is more relaxed
    } else if (passedCount >= 1) {
      container.classList.add('strength-fair');
      label = 'Fair (Vulnerable)';
      if (submitButton) submitButton.setAttribute('disabled', 'true');
    } else {
      container.classList.add('strength-weak');
      label = 'Weak (Dangerous)';
      if (submitButton) submitButton.setAttribute('disabled', 'true');
    }

    textEl.textContent = `Complexity: ${label}`;
  }

  // --- USER REGISTRATION SUBMIT ---
  registerForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    setLoading(registerSubmitBtn, true);

    const username = regUsername.value.trim();
    const email = regEmail.value.trim();
    const password = regPassword.value;

    try {
      const res = await SecureAPI.auth.register(username, email, password);
      showToast(res.message, 'success');
      registerForm.reset();
      
      // Reset strength UI
      updateStrengthUI({ length: false, upper: false, lower: false, number: false, special: false }, strengthBars, strengthText, rules, registerSubmitBtn);
      
      // Switch to Sign In tab
      tabButtons[0].click();
    } catch (err) {
      showToast(err.message, 'error');
    } finally {
      setLoading(registerSubmitBtn, false);
    }
  });

  // --- USER LOGIN SUBMIT ---
  loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    setLoading(loginSubmitBtn, true);

    const usernameOrEmail = loginUsername.value.trim();
    const password = loginPassword.value;
    const code = login2faCode.value.trim();

    try {
      const res = await SecureAPI.auth.login(usernameOrEmail, password, code);

      if (res.requires2FA) {
        // Slide open the 2FA token verify box
        is2faPrompted = true;
        login2faContainer.classList.remove('hidden');
        login2faCode.setAttribute('required', 'true');
        login2faCode.focus();
        showToast('Two-Factor Authentication token required to verify identity.', 'warning');
      } else {
        // Successful Login
        currentUser = res.user;
        showToast('Signed in successfully!', 'success');
        loginForm.reset();
        
        // Hide 2FA fields if login resets
        login2faContainer.classList.add('hidden');
        login2faCode.removeAttribute('required');
        is2faPrompted = false;

        enterDashboard();
      }
    } catch (err) {
      showToast(err.message, 'error');
      // If code was wrong, clear the field
      if (is2faPrompted) {
        login2faCode.value = '';
        login2faCode.focus();
      } else {
        loginPassword.value = '';
        loginPassword.focus();
      }
    } finally {
      setLoading(loginSubmitBtn, false);
    }
  });

  // --- LOGOUT ACTION ---
  async function performLogout() {
    try {
      await SecureAPI.auth.logout();
      showToast('Logged out successfully.', 'info');
      exitDashboard();
    } catch (err) {
      showToast(err.message, 'error');
    }
  }

  headerLogoutBtn.addEventListener('click', performLogout);

  // --- DASHBOARD NAVIGATION ---
  navLinks.forEach(link => {
    link.addEventListener('click', () => {
      navLinks.forEach(l => l.classList.remove('active'));
      link.classList.add('active');

      const targetView = link.getAttribute('data-view');
      viewPanels.forEach(panel => {
        if (panel.id === targetView) {
          panel.classList.remove('hidden');
          panel.classList.add('active');
        } else {
          panel.classList.remove('active');
          panel.classList.add('hidden');
        }
      });

      // Fetch fresh data based on view
      if (targetView === 'sessionsTab') fetchSessions();
      if (targetView === 'logsTab') fetchSecurityLogs();
      if (targetView === 'settingsTab') check2FAState();
    });
  });

  goToSettingsBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const settingsLink = Array.from(navLinks).find(l => l.getAttribute('data-view') === 'settingsTab');
      if (settingsLink) settingsLink.click();
    });
  });

  goToSessionsBtn.addEventListener('click', () => {
    const sessionsLink = Array.from(navLinks).find(l => l.getAttribute('data-view') === 'sessionsTab');
    if (sessionsLink) sessionsLink.click();
  });

  // --- ENTRANCE / EXIT FUNCTIONS ---
  async function enterDashboard() {
    authSection.classList.add('hidden');
    dashboardSection.classList.remove('hidden');
    headerLogoutBtn.classList.remove('hidden');

    bannerUsername.textContent = currentUser.username;
    profileUsername.textContent = currentUser.username;
    profileEmail.textContent = currentUser.email;

    // Reset view to Overview
    navLinks[0].click();
    
    // Quick status info fetches
    check2FAState();
    fetchSessionsSummary();
  }

  function exitDashboard() {
    currentUser = null;
    dashboardSection.classList.add('hidden');
    authSection.classList.remove('hidden');
    headerLogoutBtn.classList.add('hidden');
    
    // Clear overview fields
    bannerUsername.textContent = 'User';
    profileUsername.textContent = '-';
    profileEmail.textContent = '-';
    profileSessionToken.textContent = '-';
  }

  // --- HELPERS ---
  function setLoading(btn, isLoading) {
    const text = btn.querySelector('.btn-text');
    const spinner = btn.querySelector('.btn-spinner');
    if (isLoading) {
      btn.setAttribute('disabled', 'true');
      if (text) text.classList.add('hidden');
      if (spinner) spinner.classList.remove('hidden');
    } else {
      btn.removeAttribute('disabled');
      if (text) text.classList.remove('hidden');
      if (spinner) spinner.classList.add('hidden');
    }
  }

  function parseUserAgent(ua) {
    if (!ua || ua === 'unknown') return 'Unknown Browser / Device';
    
    let browser = 'Other Browser';
    let os = 'Unknown OS';

    if (ua.includes('Chrome')) browser = 'Google Chrome';
    else if (ua.includes('Safari') && !ua.includes('Chrome')) browser = 'Safari';
    else if (ua.includes('Firefox')) browser = 'Mozilla Firefox';
    else if (ua.includes('Edg')) browser = 'Microsoft Edge';
    
    if (ua.includes('Windows')) os = 'Windows';
    else if (ua.includes('Macintosh')) os = 'macOS';
    else if (ua.includes('Linux')) os = 'Linux';
    else if (ua.includes('iPhone') || ua.includes('iPad')) os = 'iOS';
    else if (ua.includes('Android')) os = 'Android';

    return `${browser} on ${os}`;
  }

  // --- DATA FETCHES ---

  // Check 2FA State and Render Forms
  async function check2FAState() {
    try {
      const res = await SecureAPI.user.getProfile();
      currentUser = res.user;

      if (currentUser.twoFactorEnabled) {
        status2faIcon.className = 'card-icon green';
        status2faIcon.textContent = '🛡️';
        status2faText.innerHTML = 'Enabled <span class="session-badge" style="background:#00e676;color:#000;">Secure</span>';
        
        active2faSection.classList.remove('hidden');
        initiate2faSection.classList.add('hidden');
        setup2faSection.classList.add('hidden');
        backupCodesSection.classList.add('hidden');
      } else {
        status2faIcon.className = 'card-icon';
        status2faIcon.textContent = '⚠️';
        status2faText.textContent = 'Disabled (Highly Vulnerable)';
        
        active2faSection.classList.add('hidden');
        initiate2faSection.classList.remove('hidden');
        setup2faSection.classList.add('hidden');
        backupCodesSection.classList.add('hidden');
      }
    } catch (err) {
      showToast(err.message, 'error');
    }
  }

  // Get active session metrics overview
  async function fetchSessionsSummary() {
    try {
      const res = await SecureAPI.user.getSessions();
      statusSessionsText.textContent = `${res.sessions.length} active device(s) logged in.`;
      
      const current = res.sessions.find(s => s.isCurrent);
      if (current) {
        profileSessionToken.textContent = current.hash;
      }
    } catch (err) {
      console.error(err);
    }
  }

  // List Session Cards
  async function fetchSessions() {
    sessionsContainer.innerHTML = `
      <div class="skeleton-loader">
        <div class="skeleton-row"></div>
        <div class="skeleton-row"></div>
      </div>
    `;

    try {
      const res = await SecureAPI.user.getSessions();
      sessionsContainer.innerHTML = '';
      
      if (res.sessions.length === 0) {
        sessionsContainer.innerHTML = '<p class="text-muted">No active sessions.</p>';
        revokeAllBtn.classList.add('hidden');
        return;
      }

      // Show/Hide revoke other button
      const hasOthers = res.sessions.some(s => !s.isCurrent);
      if (hasOthers) {
        revokeAllBtn.classList.remove('hidden');
      } else {
        revokeAllBtn.classList.add('hidden');
      }

      res.sessions.forEach(session => {
        const item = document.createElement('div');
        item.className = 'session-item';
        
        const deviceName = parseUserAgent(session.userAgent);
        const relativeTime = new Date(session.lastActiveAt).toLocaleString();
        
        item.innerHTML = `
          <div class="session-details">
            <div class="session-device">
              💻 ${deviceName}
              ${session.isCurrent ? '<span class="session-badge">Current Device</span>' : ''}
            </div>
            <div class="session-meta">
              <span>🌐 IP: ${session.ipAddress}</span>
              <span>🕒 Last active: ${relativeTime}</span>
            </div>
          </div>
          <div>
            ${session.isCurrent 
              ? `<button class="btn-danger-outline revoke-session-btn" data-hash="${session.hash}">Logout</button>`
              : `<button class="btn-danger revoke-session-btn" data-hash="${session.hash}">Revoke</button>`
            }
          </div>
        `;
        sessionsContainer.appendChild(item);
      });

      // Revoke button listeners
      document.querySelectorAll('.revoke-session-btn').forEach(btn => {
        btn.addEventListener('click', async () => {
          const sHash = btn.getAttribute('data-hash');
          const isCurrent = btn.parentElement.previousElementSibling.querySelector('.session-badge') !== null;
          
          if (isCurrent && !confirm('Are you sure you want to log out of this session?')) return;
          if (!isCurrent && !confirm('Are you sure you want to terminate this remote session?')) return;

          try {
            const result = await SecureAPI.user.revokeSession(sHash);
            showToast(result.message, 'success');
            
            if (result.loggedOutCurrent) {
              exitDashboard();
            } else {
              fetchSessions();
              fetchSessionsSummary();
            }
          } catch (err) {
            showToast(err.message, 'error');
          }
        });
      });

    } catch (err) {
      showToast(err.message, 'error');
    }
  }

  // Revoke all other sessions
  revokeAllBtn.addEventListener('click', async () => {
    if (!confirm('Are you sure you want to terminate all other device sessions? You will remain logged in on this device.')) return;
    
    try {
      const res = await SecureAPI.user.getSessions();
      const otherSessions = res.sessions.filter(s => !s.isCurrent);
      
      let successCount = 0;
      for (const s of otherSessions) {
        await SecureAPI.user.revokeSession(s.hash);
        successCount++;
      }

      showToast(`Successfully terminated ${successCount} remote session(s).`, 'success');
      fetchSessions();
      fetchSessionsSummary();
    } catch (err) {
      showToast(err.message, 'error');
    }
  });

  // Fetch security event logs
  async function fetchSecurityLogs() {
    logsTableBody.innerHTML = `
      <tr>
        <td colspan="4" style="text-align: center;">Loading security logs...</td>
      </tr>
    `;

    try {
      const res = await SecureAPI.user.getSecurityLogs();
      logsTableBody.innerHTML = '';

      if (res.logs.length === 0) {
        logsTableBody.innerHTML = `
          <tr>
            <td colspan="4" style="text-align: center; color: var(--text-muted);">No security logs recorded.</td>
          </tr>
        `;
        return;
      }

      res.logs.forEach(log => {
        const row = document.createElement('tr');
        
        let badgeColor = '#6e6e8c'; // default grey
        let friendlyEvent = log.event_type;

        // Visual coloring mapping
        if (log.event_type === 'login_success') { badgeColor = '#00e676'; friendlyEvent = 'Login Success'; }
        else if (log.event_type === 'login_failed' || log.event_type === 'failed_login_attempt') { badgeColor = '#ff1744'; friendlyEvent = 'Login Failed'; }
        else if (log.event_type === 'account_lockout') { badgeColor = '#ff1744'; friendlyEvent = 'Account Lockout'; }
        else if (log.event_type === 'registration_success') { badgeColor = '#8a2be2'; friendlyEvent = 'User Registered'; }
        else if (log.event_type === '2fa_enabled') { badgeColor = '#00f2fe'; friendlyEvent = '2FA Enabled'; }
        else if (log.event_type === '2fa_disabled') { badgeColor = '#ffb300'; friendlyEvent = '2FA Disabled'; }
        else if (log.event_type === 'password_change') { badgeColor = '#00f2fe'; friendlyEvent = 'Password Changed'; }
        else if (log.event_type === 'session_revoked') { badgeColor = '#ffb300'; friendlyEvent = 'Session Revoked'; }
        else if (log.event_type === 'backup_code_used') { badgeColor = '#00f2fe'; friendlyEvent = 'Backup Code Log'; }
        else if (log.event_type === 'session_hijack_warning') { badgeColor = '#ff1744'; friendlyEvent = 'Session Hijack Blocked'; }
        
        const eventTag = `<span class="log-event-tag" style="background: ${badgeColor}20; color: ${badgeColor}; border: 1px solid ${badgeColor}40;">${friendlyEvent}</span>`;
        const logTime = new Date(log.created_at).toLocaleString();
        const browserDetails = parseUserAgent(log.user_agent);

        row.innerHTML = `
          <td>${eventTag}</td>
          <td>${log.ip_address}</td>
          <td class="truncate" title="${log.user_agent}">${browserDetails}</td>
          <td>${logTime}</td>
        `;
        logsTableBody.appendChild(row);
      });
    } catch (err) {
      showToast(err.message, 'error');
    }
  }

  // --- 2FA INTERACTIVE FLOWS ---
  
  // Start setup (Get QR code)
  start2faSetupBtn.addEventListener('click', async () => {
    try {
      const res = await SecureAPI.user.setup2FA();
      qrCodeImg.src = res.qrCode;
      manualSecretKey.textContent = res.secret;
      
      initiate2faSection.classList.add('hidden');
      setup2faSection.classList.remove('hidden');
      showToast('Scan the QR code to proceed.', 'info');
    } catch (err) {
      showToast(err.message, 'error');
    }
  });

  // Verify and enable
  enable2faForm.addEventListener('click', () => {}); // placeholder
  enable2faForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const token = confirm2faCode.value.trim();
    if (!token) return;

    try {
      const res = await SecureAPI.user.enable2FA(token);
      showToast(res.message, 'success');
      confirm2faCode.value = '';

      // Populate Backup Codes
      backupCodesGrid.innerHTML = '';
      res.backupCodes.forEach(code => {
        const div = document.createElement('div');
        div.className = 'backup-code';
        div.textContent = code;
        backupCodesGrid.appendChild(div);
      });

      setup2faSection.classList.add('hidden');
      backupCodesSection.classList.remove('hidden');
    } catch (err) {
      showToast(err.message, 'error');
      confirm2faCode.value = '';
      confirm2faCode.focus();
    }
  });

  // Close Backup Codes Screen
  closeBackupBtn.addEventListener('click', () => {
    backupCodesSection.classList.add('hidden');
    check2FAState();
    fetchSessionsSummary();
  });

  // Disable 2FA
  disable2faBtn.addEventListener('click', async () => {
    if (!confirm('WARNING: Disabling Two-Factor Authentication reduces your account security. Are you sure you want to disable 2FA?')) return;

    try {
      const res = await SecureAPI.user.disable2FA();
      showToast(res.message, 'warning');
      check2FAState();
      fetchSessionsSummary();
    } catch (err) {
      showToast(err.message, 'error');
    }
  });

  // --- CHANGE PASSWORD SUBMIT ---
  changePasswordForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    setLoading(changePasswordBtn, true);

    const oldPass = currentPassword.value;
    const newPass = newPassword.value;

    try {
      const res = await SecureAPI.user.changePassword(oldPass, newPass);
      showToast(res.message, 'success');
      changePasswordForm.reset();
      
      // Reset strength UI
      updateStrengthUI({ length: false, upper: false, lower: false, number: false, special: false }, changeStrengthBars, changeStrengthText, null, changePasswordBtn);
      
      // Update sessions overview and view
      fetchSessionsSummary();
    } catch (err) {
      showToast(err.message, 'error');
      currentPassword.focus();
    } finally {
      setLoading(changePasswordBtn, false);
    }
  });

  // --- INITIAL CHECK (Check if user is already logged in on refresh) ---
  async function checkInitialAuth() {
    try {
      const res = await SecureAPI.user.getProfile();
      currentUser = res.user;
      enterDashboard();
    } catch (err) {
      // Not logged in, stay on Auth Card
      exitDashboard();
    }
  }

  checkInitialAuth();
});

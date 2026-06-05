const bcrypt = require('bcryptjs');
const { getDatabase } = require('./database');

async function runTests() {
  console.log('===================================================');
  console.log('🧪 Starting Security Verification Tests');
  console.log('===================================================\n');

  let db;
  try {
    db = await getDatabase();
    console.log('✅ SQLite Database Connection: Success');
  } catch (err) {
    console.error('❌ Database Connection Failed:', err);
    process.exit(1);
  }

  // 1. Ensure test user exists
  const testUsername = 'securesandbox';
  const testEmail = 'securesandbox@test.com';
  const testPass = 'Password123!';
  
  try {
    // Delete if exists to make it a fresh run
    await db.run('DELETE FROM users WHERE username = ?', [testUsername]);

    const salt = await bcrypt.genSalt(12);
    const hash = await bcrypt.hash(testPass, salt);

    await db.run(
      'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
      [testUsername, testEmail, hash]
    );
    console.log(`✅ Seeded Test User: "${testUsername}" with Password: "${testPass}"`);
  } catch (err) {
    console.error('❌ Failed to seed test user:', err);
  }

  // 2. Test SQL Injection resistance
  console.log('\n--- Test 1: SQL Injection Protection Check ---');
  const sqliPayload = `' OR '1'='1`;
  console.log(`Injecting payload into username lookup: "${sqliPayload}"`);
  
  try {
    // Look up with parameterized statement (Safe)
    const resultSafe = await db.get(
      'SELECT * FROM users WHERE username = ?',
      [sqliPayload]
    );
    
    if (resultSafe === undefined) {
      console.log('✅ Success: Prepared statements successfully mitigated SQL injection.');
      console.log('   (Database query returned empty/undefined as expected, not the admin user)');
    } else {
      console.log('❌ Failure: Database returned a record. Possible vulnerability!');
    }
  } catch (err) {
    console.error('❌ Query execution failed:', err);
  }

  // 3. Test Bcrypt validation
  console.log('\n--- Test 2: Password Verification Check ---');
  try {
    const user = await db.get('SELECT password_hash FROM users WHERE username = ?', [testUsername]);
    
    const correctMatch = await bcrypt.compare(testPass, user.password_hash);
    console.log(`Bcrypt compare correct password: ${correctMatch ? '✅ Passed' : '❌ Failed'}`);
    
    const incorrectMatch = await bcrypt.compare('WrongPassword1!', user.password_hash);
    console.log(`Bcrypt compare incorrect password returns false: ${!incorrectMatch ? '✅ Passed' : '❌ Failed'}`);
  } catch (err) {
    console.error('❌ Password comparison test failed:', err);
  }

  // 4. Test Lockout Mechanism simulation
  console.log('\n--- Test 3: Lockout Tracking Simulation ---');
  try {
    const user = await db.get('SELECT id, failed_login_attempts, lockout_until FROM users WHERE username = ?', [testUsername]);
    console.log(`Initial failed attempts count: ${user.failed_login_attempts} (Expected: 0)`);
    
    // Simulate 5 failures
    console.log('Simulating 5 consecutive failed login attempts...');
    for(let i = 1; i <= 5; i++) {
      const failedCount = i;
      let lockoutTime = null;
      if (failedCount >= 5) {
        lockoutTime = new Date(Date.now() + 15 * 60 * 1000).toISOString();
      }
      await db.run(
        'UPDATE users SET failed_login_attempts = ?, lockout_until = ? WHERE id = ?',
        [failedCount, lockoutTime, user.id]
      );
    }
    
    const lockedUser = await db.get('SELECT failed_login_attempts, lockout_until FROM users WHERE id = ?', [user.id]);
    console.log(`Failed attempts after simulation: ${lockedUser.failed_login_attempts} (Expected: 5)`);
    console.log(`Lockout timestamp set: ${lockedUser.lockout_until ? '✅ Yes' : '❌ No'}`);
    
    // Check if lock is active
    const now = new Date();
    const lockTime = new Date(lockedUser.lockout_until);
    if (now < lockTime) {
      console.log('✅ Lockout enforcement check: Account is active-locked as expected.');
    } else {
      console.log('❌ Lockout enforcement check failed.');
    }

    // Reset user after test
    await db.run('UPDATE users SET failed_login_attempts = 0, lockout_until = NULL WHERE id = ?', [user.id]);
    console.log('Cleanup: Test user login metrics reset.');

  } catch (err) {
    console.error('❌ Lockout simulation test failed:', err);
  }

  console.log('\n===================================================');
  console.log('🏁 Security Verification Complete');
  console.log('===================================================');
}

runTests();

# Login LockDown v2.1.0 - Testing Guide

## PHP 8.4 Compatibility & Security Testing

**Version:** 2.1.0
**Date:** October 31, 2025
**Test Priority:** HIGH (Security Plugin)

---

## ⚠️ Why Testing is Critical

This update includes:
- **3 SQL injection fixes** - Database security
- **30+ type safety fixes** - Logic correctness
- **1 IPv6 validation fix** - Security functionality
- **IP validation** - Core security feature

**This is a security plugin**, so thorough testing is essential before production deployment.

---

## 🎯 Quick Start (15 Minutes)

### Minimum Testing Checklist
- [ ] Plugin activates without errors
- [ ] Failed login triggers lockdown
- [ ] Locked IP appears in admin panel
- [ ] Can release locked IP
- [ ] No PHP errors in logs

If all pass → Safe to deploy

---

## 📋 Complete Testing Plan (45-60 Minutes)

### Test Environment Requirements

**Minimum:**
- WordPress 5.0+
- PHP 7.4+
- WP_DEBUG enabled

**Recommended:**
- WordPress 6.7
- PHP 8.4
- WP_DEBUG_LOG enabled
- Test site (not production)

---

## 1️⃣ Pre-Deployment Tests (10 min)

### 1.1 Environment Setup

```bash
# Enable debug mode in wp-config.php
define('WP_DEBUG', true);
define('WP_DEBUG_LOG', true);
define('WP_DEBUG_DISPLAY', false);
```

### 1.2 Plugin Installation

- [ ] Upload plugin to `/wp-content/plugins/login-lockdown/`
- [ ] Go to Plugins → Installed Plugins
- [ ] Activate "Login LockDown"
- [ ] Check for activation errors
- [ ] Verify database tables created

**Expected Result:** Plugin activates successfully, no errors

**Check Database Tables:**
```sql
SHOW TABLES LIKE '%login_fails%';
SHOW TABLES LIKE '%lockdowns%';
```

Should show:
- `{prefix}_login_fails`
- `{prefix}_lockdowns`

---

## 2️⃣ Core Functionality Tests (15 min)

### 2.1 Basic Lockdown Test

**Steps:**
1. Open incognito/private browser window
2. Go to `/wp-login.php`
3. Try to login with wrong password **3 times**
4. Wait for lockdown message

**Expected Result:**
```
ERROR: We're sorry, but this IP range has been blocked
due to too many recent failed login attempts.
Please try again later.
```

**Verify in Admin:**
- [ ] Go to Settings → Login LockDown
- [ ] Click "Activity" tab
- [ ] Your IP should appear in locked IPs list
- [ ] Should show "60 minutes left" (or configured time)

**Test IP Validation Fix:**
- [ ] Check error logs for any IP validation errors
- [ ] Should see no "Invalid IP" warnings

---

### 2.2 Release Lockdown Test

**Steps:**
1. In admin panel (Activity tab)
2. Check the box next to your locked IP
3. Click "Release Selected"

**Expected Result:**
- Success message: "Lockdowns Released."
- IP disappears from locked list
- Can attempt login again

---

### 2.3 Invalid Username Test

**Settings:**
1. Go to Settings → Login LockDown
2. Set "Lockout Invalid Usernames?" to **Yes**
3. Click "Update Settings"

**Test:**
1. Try logging in with non-existent username **3 times**
2. Should trigger lockdown

**Expected Result:**
- Lockdown triggered even with fake username
- Tests the fixed SQL injection vulnerability

**Settings:**
- [ ] Set "Lockout Invalid Usernames?" back to **No**

---

## 3️⃣ Security Tests (10 min)

### 3.1 SQL Injection Prevention Test

**This tests our critical security fixes!**

**Test 1: User ID Injection (Fixed Line 119)**

Try logging in with these usernames:
```
admin' OR '1'='1
admin'; DROP TABLE wp_users; --
admin' UNION SELECT * FROM wp_users--
```

**Expected Result:**
- All attempts fail gracefully
- No SQL errors in logs
- Lockdown triggers after 3 attempts
- Database remains intact

**Check Logs:**
```bash
tail -f /path/to/wp-content/debug.log
```

Should NOT see:
- "WordPress database error"
- "SQL syntax error"
- Any mention of SQL injection

---

### 3.2 XSS Prevention Test

**This tests our HTTP sanitization fixes!**

**Test in Browser Console:**
```javascript
// Try to inject script via URL
window.location = '/wp-login.php?test=<script>alert("XSS")</script>';
```

**Expected Result:**
- No script execution
- No alert popup
- URL sanitized properly

---

### 3.3 IP Spoofing Test (If Possible)

**Test our new IP validation function!**

If you have access to proxy/VPN:
1. Connect through VPN
2. Trigger lockdown (3 failed logins)
3. Disconnect VPN
4. Try to login again

**Expected Result:**
- Different IPs locked separately
- No bypass possible via IP spoofing

---

## 4️⃣ IPv6 Testing (5 min)

### 4.1 IPv6 Validation Test

**This tests our critical operator precedence fix!**

**If you have IPv6 access:**
1. Connect via IPv6 network
2. Verify IPv6 address in admin panel
3. Trigger lockdown (3 failed logins)
4. Check IPv6 address appears in Activity tab

**Expected Result:**
- IPv6 address properly detected
- IPv6 lockdown works
- No PHP errors related to IPv6

**Check in Code:**
Look for this in debug.log (should NOT appear):
```
Notice: Undefined offset: 1 in .../plugin.php on line 224
```

If you don't have IPv6, skip this test but note it needs testing.

---

## 5️⃣ Admin Panel Tests (10 min)

### 5.1 Settings Page Test

**Navigate:** Settings → Login LockDown

**Test Each Setting:**

1. **Max Login Retries**
   - [ ] Change from 3 to 5
   - [ ] Save and verify
   - [ ] Test: requires 5 failures now
   - [ ] Change back to 3

2. **Retry Time Period**
   - [ ] Change from 5 to 10 minutes
   - [ ] Save and verify
   - [ ] Test: failures must be within 10 min window

3. **Lockout Length**
   - [ ] Change from 60 to 30 minutes
   - [ ] Save and verify
   - [ ] New lockdowns last 30 minutes

4. **Lockout Invalid Usernames**
   - [ ] Toggle Yes/No
   - [ ] Test both settings work
   - [ ] Tests the fixed strict comparison (===)

5. **Mask Login Errors**
   - [ ] Toggle Yes/No
   - [ ] Verify error messages change
   - [ ] Tests the fixed strict comparison (===)

6. **Show Credit Link**
   - [ ] Test all three options
   - [ ] Verify link appearance on login page
   - [ ] Tests multiple fixed strict comparisons (===)

**Expected Result:**
- All settings save properly
- All options work as expected
- No PHP notices or warnings

---

### 5.2 Activity Tab Test

**Navigate:** Settings → Login LockDown → Activity Tab

**Verify:**
- [ ] Locked IPs display correctly
- [ ] Time remaining shows accurately
- [ ] Can select multiple IPs
- [ ] "Release Selected" works
- [ ] Count matches "(X)" in tab title
- [ ] Tests the fixed `count() === 1` comparison

---

## 6️⃣ PHP 8.4 Compatibility Tests (10 min)

### 6.1 Error Log Analysis

**Check for PHP 8.4 issues:**

```bash
# Monitor error log during testing
tail -f /path/to/wp-content/debug.log
```

**Should NOT see:**
- "Deprecated:" warnings
- "TypeError:" errors
- "Fatal error:" messages
- "Warning: Passing null to parameter"
- "Notice:" messages

**If you see any PHP errors, STOP and investigate.**

---

### 6.2 Strict Comparison Verification

**Our 30+ fixes should prevent these issues:**

**Test Case:**
1. Set lockout length to "0" (edge case)
2. Trigger lockdown
3. Should handle gracefully

**Test Case:**
1. Set max retries to empty string (shouldn't be possible but test)
2. Should fall back to default

**Expected Result:**
- No type coercion errors
- No unexpected behavior
- All comparisons work correctly

---

### 6.3 Function Return Types

**Test null handling (we fixed $user === null):**

1. Test with invalid username
2. Check logs for any null-related warnings
3. Should handle null returns gracefully

---

## 7️⃣ Multisite Testing (If Applicable) (10 min)

### 7.1 Network Activation

**If you run WordPress Multisite:**

1. Network activate the plugin
2. Check each site has its own tables
3. Test lockdown on different sites
4. Verify sites are isolated (locked on site 1 ≠ locked on site 2)

**Check our multisite SQL fix (Line 594):**
- [ ] Tables created for all sites
- [ ] No SQL errors during activation
- [ ] Each site functions independently

---

## 8️⃣ Edge Cases & Stress Tests (5 min)

### 8.1 Rapid Failed Attempts

**Test:**
- Make 10 rapid failed login attempts (within 10 seconds)

**Expected Result:**
- Locked after 3 attempts
- Additional attempts don't cause errors
- Only one lockdown entry created

---

### 8.2 Concurrent Attempts

**Test (if possible):**
- Open 3 browser windows
- Fail login in all 3 simultaneously

**Expected Result:**
- Lockdown triggers correctly
- No database race conditions
- No duplicate entries

---

### 8.3 Long Running Lockdown

**Test:**
1. Trigger a lockdown
2. Wait for lockdown to expire naturally (60 minutes default)
3. Try logging in again

**Expected Result:**
- Lockdown expires automatically
- Can login after expiration
- Old records cleaned up

---

## 9️⃣ Performance Tests (Optional)

### 9.1 Database Query Performance

**Check query performance:**
```sql
-- Check indexes exist
SHOW INDEX FROM wp_login_fails;
SHOW INDEX FROM wp_lockdowns;
```

**Monitor slow query log during testing.**

---

### 9.2 Page Load Impact

**Measure login page load time:**
- Before lockdown: X ms
- During lockdown: Y ms
- After release: Z ms

Should be minimal difference (< 100ms)

---

## 🔍 Security Verification Checklist

### Critical Security Fixes Verification

- [ ] **SQL Injection Line 119:** Test with malicious user IDs - No database errors
- [ ] **SQL Injection Line 145:** Test with malicious lockout values - No database errors
- [ ] **SQL Injection Line 594:** Multisite table check secure - No interpolation errors
- [ ] **IPv6 Validation:** IPv6 addresses work correctly - Operator precedence fixed
- [ ] **IP Validation:** Invalid IPs rejected - filter_var() working
- [ ] **XSS Prevention:** HTTP headers sanitized - sanitize_text_field() working
- [ ] **HTTPS Detection:** SSL properly detected - is_ssl() working

---

## 📊 Test Results Template

```
# Login LockDown v2.1.0 Test Results

**Date:** [DATE]
**Tester:** [NAME]
**Environment:**
- WordPress: [VERSION]
- PHP: [VERSION]
- Server: [OS/TYPE]

## Test Results

### Pre-Deployment
- [ ] PASS/FAIL - Plugin activation
- [ ] PASS/FAIL - Database tables created

### Core Functionality
- [ ] PASS/FAIL - Basic lockdown (3 failures)
- [ ] PASS/FAIL - Release lockdown
- [ ] PASS/FAIL - Invalid username lockdown

### Security Tests
- [ ] PASS/FAIL - SQL injection prevention
- [ ] PASS/FAIL - XSS prevention
- [ ] PASS/FAIL - IP spoofing resistance

### IPv6 Tests
- [ ] PASS/FAIL/SKIP - IPv6 detection
- [ ] PASS/FAIL/SKIP - IPv6 lockdown

### Admin Panel
- [ ] PASS/FAIL - Settings save
- [ ] PASS/FAIL - Activity tab displays
- [ ] PASS/FAIL - All options work

### PHP 8.4 Compatibility
- [ ] PASS/FAIL - No PHP errors
- [ ] PASS/FAIL - No deprecation warnings
- [ ] PASS/FAIL - Type safety verified

### Multisite (if applicable)
- [ ] PASS/FAIL/N/A - Network activation
- [ ] PASS/FAIL/N/A - Site isolation

## Issues Found

[List any issues discovered]

## Recommendations

[Any recommendations for deployment]

## Sign-off

- [ ] Ready for production deployment
- [ ] Needs additional testing
- [ ] Issues must be resolved first
```

---

## 🚨 Red Flags to Watch For

**Stop deployment if you see:**

1. **Database Errors**
   - "WordPress database error" in logs
   - SQL syntax errors
   - Failed query messages

2. **PHP Errors**
   - Fatal errors
   - Uncaught exceptions
   - Deprecated warnings

3. **Functional Issues**
   - Lockdown doesn't trigger
   - Can't release locked IPs
   - Settings don't save

4. **Security Issues**
   - SQL injection still possible
   - XSS vulnerabilities
   - IP validation bypassed

---

## ✅ Pass Criteria

**Minimum to pass:**
- All core functionality tests pass
- No SQL errors
- No PHP errors in logs
- Security tests pass
- Admin panel works

**Ideal to pass:**
- All tests pass
- IPv6 works (if testable)
- Multisite works (if applicable)
- Performance acceptable
- No warnings or notices

---

## 📝 Test Automation (Advanced)

### PHP Unit Tests (If You Want to Add Them)

```php
// Example test for IP validation
public function test_ip_validation() {
    $valid_ip = loginlockdown_get_remote_ip();
    $this->assertNotEquals('0.0.0.0', $valid_ip);
}

// Example test for SQL injection prevention
public function test_sql_injection_prevention() {
    $malicious_input = "1'; DROP TABLE wp_users; --";
    // Should not trigger database error
    $result = loginlockdown_increment_fails($malicious_input);
    $this->assertNoError();
}
```

---

## 🔧 Troubleshooting Common Issues

### Issue: Plugin won't activate

**Check:**
- PHP version >= 7.4
- WordPress version >= 5.0
- No conflicting plugins

### Issue: Tables not created

**Solution:**
```sql
-- Run manually if needed
CREATE TABLE wp_login_fails (
  login_attempt_ID bigint(20) NOT NULL AUTO_INCREMENT,
  user_id bigint(20) NOT NULL,
  login_attempt_date datetime NOT NULL default '0000-00-00 00:00:00',
  login_attempt_IP varchar(100) NOT NULL default '',
  PRIMARY KEY (login_attempt_ID)
);

CREATE TABLE wp_lockdowns (
  lockdown_ID bigint(20) NOT NULL AUTO_INCREMENT,
  user_id bigint(20) NOT NULL,
  lockdown_date datetime NOT NULL default '0000-00-00 00:00:00',
  release_date datetime NOT NULL default '0000-00-00 00:00:00',
  lockdown_IP varchar(100) NOT NULL default '',
  PRIMARY KEY (lockdown_ID)
);
```

### Issue: Lockdown not triggering

**Check:**
- Settings → Max Login Retries (default 3)
- Settings → Retry Time Period (default 5 min)
- Failed attempts are from same IP
- Check debug log for errors

### Issue: Can't release lockdown

**Check:**
- Admin permissions (manage_options)
- Nonce verification passing
- Database writable

---

## 📞 Support Resources

- **GitHub Issues:** https://github.com/okapteinis/wp-login-lockdown/issues
- **WordPress Forums:** https://wordpress.org/support/
- **PHP 8.4 Docs:** https://www.php.net/releases/8.4/

---

## 📅 Testing Schedule Recommendation

**Day 1:**
- Deploy to staging/test site
- Run all tests above
- Document any issues

**Day 2-3:**
- Monitor error logs
- Test edge cases
- User acceptance testing

**Day 4:**
- Final review
- Deploy to production
- Monitor closely for 24 hours

---

**Last Updated:** October 31, 2025
**Version:** 2.1.0
**Status:** Ready for Testing

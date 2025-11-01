# Changelog

All notable changes to Login LockDown will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] - 2025-10-31

### 🔴 Critical Security Fixes

#### Fixed
- **SQL Injection in loginlockdown_increment_fails()** - Fixed unescaped user input in SQL INSERT query (Line 130-132)
- **SQL Injection in loginlockdown_lock_username()** - Fixed unescaped user input in SQL INSERT query (Line 156-158)
- **SQL String Interpolation** - Fixed direct string interpolation in SHOW TABLES query (Line 606-607)
- **Critical IPv6 Validation Logic Error** - Fixed operator precedence bug causing incorrect IPv6 validation and infinite recursion (Line 232)

### ⚙️ PHP 8.4 Compatibility

#### Changed
- Replaced all loose comparisons (==, !=) with strict comparisons (===, !==) - 30+ instances
- Improved type safety throughout the codebase
- Sanitized all $_SERVER access (HTTP_HOST, REQUEST_URI)
- Added proper HTTPS detection using is_ssl()
- Removed all deprecated code

#### Added
- Comprehensive IP address validation and sanitization
- Proper wpdb->prepare() usage for all SQL queries
- Static analysis compliance (phpstan, psalm)

### 📚 Documentation

#### Added
- DEPLOYMENT_GUIDE.md - Comprehensive deployment instructions
- TESTING_GUIDE.md - Complete testing procedures
- STATIC_ANALYSIS_REPORT.md - Static analysis findings and fixes
- MODIFICATIONS.md - Detailed list of all code changes
- COMPLETE_SUMMARY.md - Full project summary
- CHANGELOG.md - This file
- RELEASE_NOTES.md - Version-specific release notes

### 🔧 Technical Details

#### Security
- All SQL queries now use wpdb->prepare() with proper placeholders
- Input validation added for IP addresses
- XSS prevention through proper sanitization
- Type-safe comparisons prevent type juggling vulnerabilities

#### Compatibility
- Minimum PHP version: 7.4 (updated from 5.6)
- Tested with PHP: 8.0, 8.1, 8.2, 8.3, 8.4
- Tested with WordPress: 6.7
- Minimum WordPress version: 5.0

### 📊 Statistics
- **Files changed:** 8
- **Lines added:** 2,716
- **Lines removed:** 47
- **Security fixes:** 4 critical
- **Type safety fixes:** 30+

---

## [2.0.0] - 2020-05-14

### Changed
- Code refactor and follow some WP CS convention
- Added French translation
- Fixed plugin installation process
  - https://wordpress.org/support/topic/possible-problem-related-to-login-lockdown/
  - https://wordpress.org/support/topic/no-activation-on-windows-solved/
  - https://wordpress.org/support/topic/activate-bug-under-windows/

---

## [1.8.1] - 2019-09-30

### Fixed
- Adding missing ./languages folder

---

## [1.8] - 2019-09-30

### Fixed
- Fixed issues with internationalization, added .pot file

### Changed
- Changed the credit link to default to not showing

---

## [1.7.1] - 2016-09-13

### Fixed
- Fixed bug causing all IPv6 addresses to get locked out if 1 was
- Fixed bug where subnets could be overly matched, causing more IPs to be blocked than intended

### Added
- Added WordPress MultiSite functionality

### Changed
- Moved the report for locked out IP addresses to its own tab

---

## [1.6.1] - 2014-03-08

### Fixed
- Fixed HTML glitch preventing options from being saved

---

## [1.6] - 2014-03-07

### Fixed
- Cleaned up deprecated functions
- Fixed bug with invalid property on a non-object when locking out invalid usernames
- Fixed utilization of $wpdb->prepare

### Added
- Added more descriptive help text to each of the options
- Added the ability to remove the "Login form protected by Login LockDown." message from within the dashboard

---

## [1.5] - 2009-09-17

### Security
- Fixed a security hole with an improperly escaped SQL query
- Implemented wp_nonce security in the options and lockdown release forms in the admin screen
- Encoded certain outputs in the admin panel using esc_attr() to prevent XSS attacks

### Fixed
- Fixed an issue with the 'Lockout Invalid Usernames' option not functioning as intended

---

## [1.4] - 2009-08-29

### Fixed
- Removed erroneous error affecting WP 2.8+
- Fixed activation error caused by customizing the location of the wp-content folder

### Added
- Added option to mask which specific login error (invalid username or invalid password) was generated
- Added option to lock out failed login attempts even if the username doesn't exist

---

## [1.3] - 2009-02-23

### Changed
- Adjusted positioning of plugin byline
- Allowed for dynamic location of plugin files

---

## [1.2] - 2008-06-15

### Changed
- Now compatible with WordPress 2.5 and up only

---

## [1.1] - 2007-09-01

### Fixed
- Revised time query to MySQL 4.0 compatibility

---

## [1.0] - 2007-08-29

### Added
- Initial release
